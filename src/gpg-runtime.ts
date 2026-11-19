import { type ChildProcess, spawn } from "node:child_process"
import { createHash, randomBytes, randomUUID } from "node:crypto"
import {
  chmodSync,
  copyFileSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs"
import net from "node:net"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { PinentryBridge } from "./bridge.ts"
import type { PinentryCoordinator } from "./coordinator.ts"
import {
  assertMaxSocketPathLength,
  assertSafeConfigFilePath,
  createSecureRuntimeRoot,
  isSecureScdaemonSocket,
  sanitizeDisplayText,
  verifySecureSocketDir,
} from "./protocol.ts"
import type { UnlockInput, UnlockOutput, YubiKeyCardStatus } from "./rpc.ts"
import {
  execCommand,
  parseCardStatusOutput,
  reloadDedicatedGpgAgent,
  resolveTrustedScdaemonExecutable,
} from "./yubikey.ts"

const MAX_ASSUAN_PROXY_LINE_BYTES = 16 * 1024
const FORBIDDEN_ASSUAN_LINE = "ERR 67109115 Forbidden <oc-yubikey>\n"
const CANCELLED_ASSUAN_LINE = "ERR 83886179 Operation cancelled <Pinentry>\n"

export const ALLOWED_CLIENT_ASSUAN_VERBS: ReadonlySet<string> = new Set([
  "RESET",
  "OPTION",
  "GETINFO",
  "KEYINFO",
  "HAVEKEY",
  "READKEY",
  "LEARN",
  "SIGKEY",
  "SETHASH",
  "SETKEYDESC",
  "PKSIGN",
  "PKDECRYPT",
  "PKAUTH",
  "BYE",
])

export const ALLOWED_CLIENT_SCD_SUBCOMMANDS: ReadonlySet<string> = new Set([
  "GETINFO",
  "SERIALNO",
  "GETATTR",
  "LEARN",
  "READKEY",
  "READCERT",
])

export type CryptoAssuanVerb = "PKSIGN" | "PKDECRYPT" | "PKAUTH"

export type ClientAssuanDecision =
  | {
      readonly action: "forward"
      readonly line: string
      readonly cryptoVerb?: CryptoAssuanVerb
    }
  | { readonly action: "reply-ok" }
  | { readonly action: "forbid" }

function classifyOptionLine(line: string, rest: string): ClientAssuanDecision {
  const modeMatch = rest.match(/^pinentry-mode(?:=|\s+)(.+)$/i)
  if (modeMatch) {
    const mode = modeMatch[1]?.trim().toLowerCase()
    return mode === "ask" || mode === "default" ? { action: "forward", line } : { action: "forbid" }
  }
  const lower = rest.toLowerCase()
  if (lower.startsWith("pinentry-user-data") || lower.startsWith("putenv=pinentry_user_data")) {
    return { action: "reply-ok" }
  }
  return { action: "forward", line }
}

export function classifyClientAssuanLine(rawLine: string): ClientAssuanDecision {
  if (/[\r\n\0]/.test(rawLine)) return { action: "forbid" }
  const line = rawLine.trim()
  if (!line || line.startsWith("#")) return { action: "reply-ok" }

  const spaceIdx = line.indexOf(" ")
  const verb = (spaceIdx === -1 ? line : line.slice(0, spaceIdx)).toUpperCase()
  const rest = spaceIdx === -1 ? "" : line.slice(spaceIdx + 1).trim()

  if (verb === "OPTION") return classifyOptionLine(line, rest)
  if (verb === "SCD") {
    const subVerb = rest.split(/\s+/)[0]?.toUpperCase() ?? ""
    return ALLOWED_CLIENT_SCD_SUBCOMMANDS.has(subVerb)
      ? { action: "forward", line }
      : { action: "forbid" }
  }
  if (!ALLOWED_CLIENT_ASSUAN_VERBS.has(verb)) return { action: "forbid" }
  if (verb === "PKSIGN" || verb === "PKDECRYPT" || verb === "PKAUTH") {
    return { action: "forward", line, cryptoVerb: verb }
  }
  return { action: "forward", line }
}

export function resolveTrustedInterpreterPath(execPath = process.execPath): string {
  const resolved = realpathSync(execPath)
  assertSafeConfigFilePath(resolved, "interpreter")
  const uid = typeof process.getuid === "function" ? process.getuid() : 0
  const stat = lstatSync(resolved)
  if (!stat.isFile()) {
    throw new Error(`Interpreter path is not a regular file: ${resolved}`)
  }
  if (typeof process.getuid === "function" && stat.uid !== 0 && stat.uid !== uid) {
    throw new Error(`Refusing interpreter owned by uid ${stat.uid}: ${resolved}`)
  }
  if ((stat.mode & 0o002) !== 0) {
    throw new Error(`Refusing world-writable interpreter: ${resolved}`)
  }
  return resolved
}

function buildCleanGpgEnv(gnupgHome?: string): Record<string, string | undefined> {
  return {
    HOME: os.homedir(),
    PATH: "/opt/homebrew/bin:/usr/local/MacGPG2/bin:/usr/local/bin:/usr/bin:/bin",
    GNUPGHOME: gnupgHome,
    GPG_TTY: undefined,
    PINENTRY_USER_DATA: undefined,
    OC_YUBIKEY_COMMAND: undefined,
    OC_YUBIKEY_SOCK: undefined,
    OC_YUBIKEY_TOKEN: undefined,
  }
}

function writeReadOnlyGpgConf(gnupgDir: string): void {
  const confPath = path.join(gnupgDir, "gpg.conf")
  if (existsSync(confPath)) chmodSync(confPath, 0o600)
  writeFileSync(confPath, "no-tty\n", { mode: 0o600 })
  chmodSync(confPath, 0o400)
}

function copyKeyringArtifacts(agentHome: string, clientHome: string): void {
  for (const filename of ["pubring.kbx", "pubring.gpg", "trustdb.gpg"]) {
    const src = path.join(agentHome, filename)
    if (existsSync(src)) copyFileSync(src, path.join(clientHome, filename))
  }
  const stubsSrc = path.join(agentHome, "private-keys-v1.d")
  if (existsSync(stubsSrc)) {
    const stubsDest = path.join(clientHome, "private-keys-v1.d")
    mkdirSync(stubsDest, { recursive: true, mode: 0o700 })
    cpSync(stubsSrc, stubsDest, { recursive: true, force: true })
    chmodSync(stubsDest, 0o700)
  }
}

function parseUifStatusLine(
  line: string,
): { readonly slot: "sign" | "decrypt" | "auth"; readonly enabled: boolean } | undefined {
  const match = line.match(/^S\s+UIF-([123])\s+(.+)$/i)
  if (!match) return undefined
  const slot = match[1] === "1" ? "sign" : match[1] === "2" ? "decrypt" : "auth"
  const rawVal = match[2]?.trim() ?? ""
  if (!rawVal) return undefined
  const firstByte = rawVal.charCodeAt(0)
  const enabled =
    rawVal.startsWith("1") ||
    rawVal.startsWith("2") ||
    (firstByte > 0x00 && firstByte < 0x20 && firstByte !== 0xff)
  return { slot, enabled }
}

function cryptoVerbToUifSlot(verb: CryptoAssuanVerb): "sign" | "decrypt" | "auth" {
  if (verb === "PKSIGN") return "sign"
  if (verb === "PKDECRYPT") return "decrypt"
  return "auth"
}

function shellSingleQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

async function listenUnixSocket(server: net.Server, socketPath: string): Promise<void> {
  assertMaxSocketPathLength(socketPath)
  rmSync(socketPath, { force: true })
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject)
    server.listen(socketPath, () => {
      chmodSync(socketPath, 0o600)
      resolve()
    })
  })
}

function closeNetServer(server: net.Server | undefined, socketPath: string): Promise<void> {
  if (!server) {
    rmSync(socketPath, { force: true })
    return Promise.resolve()
  }
  return new Promise<void>((resolve) => {
    server.close(() => {
      rmSync(socketPath, { force: true })
      resolve()
    })
  })
}

function drainBufferLines(buffer: Buffer, onLine: (rawLine: Buffer) => void): Buffer {
  let offset = 0
  let idx = buffer.indexOf(0x0a, offset)
  while (idx !== -1) {
    const end = idx > offset && buffer[idx - 1] === 0x0d ? idx - 1 : idx
    onLine(buffer.subarray(offset, end))
    offset = idx + 1
    idx = buffer.indexOf(0x0a, offset)
  }
  return offset > 0 ? buffer.subarray(offset) : buffer
}

export interface SessionInvocationMetadata {
  readonly sessionID: string
  readonly command?: string
}

export interface SessionGpgClient {
  readonly sessionID: string
  readonly gnupgHome: string
  readonly socketPath: string
}

export interface GpgRuntimeOptions {
  readonly coordinator: PinentryCoordinator
  readonly runtimeRoot?: string
  readonly sourceGnupgHome?: string
  readonly systemScdaemonSock?: string
  readonly scdaemonBin?: string
  readonly pinentrySocketPath?: string
  readonly pinentrySecret?: string
  readonly cacheTtlSeconds?: number
  readonly getCardStatus?: () => Promise<YubiKeyCardStatus>
  readonly isSessionUnlocked?: (sessionID: string) => boolean
  readonly onSessionUnlocked?: (sessionID: string) => void
  readonly authorizeSessionOperation?: (
    sessionID: string,
    command: string | undefined,
  ) => Promise<boolean>
}

interface ScdaemonConnectionState {
  greeted: boolean
  activeSlot?: "sign" | "decrypt" | "auth"
  inquiring: boolean
  activeTouchID?: string
}

interface ScdaemonProxyDeps {
  readonly scdProxySocketPath: string
  readonly coordinator: PinentryCoordinator
  readonly uifState: { sign: boolean; decrypt: boolean; auth: boolean }
  readonly getCardMeta: () => { serial?: string; holder?: string }
  readonly getLatestInvocation: () => SessionInvocationMetadata | undefined
  readonly onBlockedReset: () => void
  readonly onSharingViolation: () => void
}

function clearScdaemonTouch(
  state: ScdaemonConnectionState,
  coordinator: PinentryCoordinator,
  confirm: boolean,
): void {
  if (!state.activeTouchID) return
  const id = state.activeTouchID
  state.activeTouchID = undefined
  if (confirm) coordinator.confirmTouch(id)
  else coordinator.cancel(id, "scdaemon-settled")
}

function maybeStartScdaemonTouch(
  state: ScdaemonConnectionState,
  deps: ScdaemonProxyDeps,
  upstream: net.Socket,
  clientSocket: net.Socket,
): void {
  if (!state.activeSlot || state.inquiring || state.activeTouchID) return
  if (!deps.uifState[state.activeSlot]) return
  const reqID = randomUUID()
  state.activeTouchID = reqID
  const inv = deps.getLatestInvocation()
  const meta = deps.getCardMeta()
  void deps.coordinator
    .requestTouch(
      {
        title: "Touch Your YubiKey",
        description: inv?.command
          ? `Confirm user presence on your YubiKey for "${inv.command}"`
          : "Confirm user presence on your YubiKey to complete the smartcard operation.",
        prompt: "Touch YubiKey",
        serial: meta.serial,
        holder: meta.holder,
        command: inv?.command,
      },
      { requestID: reqID },
    )
    .then((res) => {
      if (res.cancelled && state.activeTouchID === reqID) {
        state.activeTouchID = undefined
        state.activeSlot = undefined
        upstream.destroy()
        if (!clientSocket.destroyed) clientSocket.write(CANCELLED_ASSUAN_LINE)
      }
    })
}

function localScdaemonInterceptReply(line: string, deps: ScdaemonProxyDeps): string | undefined {
  if (/^OPTION\s+event-signal=/i.test(line)) return "OK\n"
  if (/^GETINFO\s+socket_name/i.test(line)) return `D ${deps.scdProxySocketPath}\nOK\n`
  if (/^(KILLSCDAEMON|RESTART|RESET)$/i.test(line)) {
    deps.onBlockedReset()
    return "OK\n"
  }
  return undefined
}

function handleClientScdaemonLine(
  line: string,
  state: ScdaemonConnectionState,
  deps: ScdaemonProxyDeps,
  upstream: net.Socket,
  clientSocket: net.Socket,
): void {
  const localReply = localScdaemonInterceptReply(line, deps)
  if (localReply !== undefined) {
    if (!clientSocket.destroyed) clientSocket.write(localReply)
    return
  }

  const upperVerb = line.split(/\s+/)[0]?.toUpperCase()
  if (state.inquiring && (upperVerb === "END" || upperVerb === "CAN")) {
    state.inquiring = false
    if (upperVerb === "END") maybeStartScdaemonTouch(state, deps, upstream, clientSocket)
  } else if (upperVerb === "PKSIGN" || upperVerb === "PKDECRYPT" || upperVerb === "PKAUTH") {
    state.activeSlot = cryptoVerbToUifSlot(upperVerb)
    maybeStartScdaemonTouch(state, deps, upstream, clientSocket)
  }
  if (!upstream.destroyed) upstream.write(`${line}\n`)
}

function handleUpstreamScdaemonLine(
  line: string,
  state: ScdaemonConnectionState,
  deps: ScdaemonProxyDeps,
): void {
  const uifUpdate = parseUifStatusLine(line)
  if (uifUpdate) deps.uifState[uifUpdate.slot] = uifUpdate.enabled
  if (line.startsWith("INQUIRE ")) {
    state.inquiring = true
    clearScdaemonTouch(state, deps.coordinator, false)
  } else if (line.startsWith("OK")) {
    state.activeSlot = undefined
    state.inquiring = false
    clearScdaemonTouch(state, deps.coordinator, true)
  } else if (line.startsWith("ERR ")) {
    if (line.includes("100696144")) deps.onSharingViolation()
    state.activeSlot = undefined
    state.inquiring = false
    clearScdaemonTouch(state, deps.coordinator, false)
  }
}

function teardownScdaemonPair(
  state: ScdaemonConnectionState,
  coordinator: PinentryCoordinator,
  clientSocket: net.Socket,
  upstream: net.Socket,
): void {
  clearScdaemonTouch(state, coordinator, false)
  clientSocket.destroy()
  upstream.destroy()
}

function attachScdaemonProxyPair(
  clientSocket: net.Socket,
  upstream: net.Socket,
  deps: ScdaemonProxyDeps,
): void {
  const state: ScdaemonConnectionState = { greeted: false, inquiring: false }
  const pendingClientLines: string[] = []
  let clientBuf = Buffer.alloc(0)
  let upstreamBuf = Buffer.alloc(0)

  upstream.on("data", (chunk: Buffer) => {
    if (!clientSocket.destroyed) clientSocket.write(chunk)
    upstreamBuf = drainBufferLines(Buffer.concat([upstreamBuf, chunk]), (rawLine) => {
      const line = rawLine.toString("utf8")
      if (!state.greeted && line.startsWith("OK")) {
        state.greeted = true
        for (const queued of pendingClientLines) {
          handleClientScdaemonLine(queued, state, deps, upstream, clientSocket)
        }
        pendingClientLines.length = 0
      } else {
        handleUpstreamScdaemonLine(line, state, deps)
      }
    })
  })

  clientSocket.on("data", (chunk: Buffer) => {
    clientBuf = Buffer.concat([clientBuf, chunk])
    if (clientBuf.length > MAX_ASSUAN_PROXY_LINE_BYTES) {
      teardownScdaemonPair(state, deps.coordinator, clientSocket, upstream)
      return
    }
    clientBuf = drainBufferLines(clientBuf, (rawLine) => {
      const line = rawLine.toString("utf8").trim()
      if (!line) return
      if (!state.greeted) pendingClientLines.push(line)
      else handleClientScdaemonLine(line, state, deps, upstream, clientSocket)
    })
  })

  for (const sock of [clientSocket, upstream]) {
    sock.on("close", () => teardownScdaemonPair(state, deps.coordinator, clientSocket, upstream))
    sock.on("error", () => teardownScdaemonPair(state, deps.coordinator, clientSocket, upstream))
  }
}

interface SessionEntry {
  readonly sessionID: string
  readonly shortId: string
  readonly gnupgHome: string
  readonly socketPath: string
  readonly server: net.Server
  latestCommand?: string
}

interface SessionChannelContext {
  greeted: boolean
  upstreamInquiring: boolean
  swallowInternalReplies: number
  readonly session: SessionEntry
  readonly clientSocket: net.Socket
  readonly upstream: net.Socket
  readonly authorizeCrypto: (sessionID: string, command: string | undefined) => Promise<boolean>
  readonly buildUserDataPayload: (meta: SessionInvocationMetadata) => string
}

const NEWLINE_BYTE = Buffer.from("\n", "ascii")

async function processSessionClientLine(
  rawLineBuf: Buffer,
  ctx: SessionChannelContext,
): Promise<void> {
  if (ctx.upstreamInquiring) {
    const trimmed = rawLineBuf.toString("ascii").trim().toUpperCase()
    if (trimmed === "END" || trimmed === "CAN") ctx.upstreamInquiring = false
    ctx.upstream.write(Buffer.concat([rawLineBuf, NEWLINE_BYTE]))
    return
  }

  const decision = classifyClientAssuanLine(rawLineBuf.toString("utf8"))
  if (decision.action === "forbid") {
    ctx.clientSocket.write(FORBIDDEN_ASSUAN_LINE)
    return
  }
  if (decision.action === "reply-ok") {
    ctx.clientSocket.write("OK\n")
    return
  }
  if (decision.cryptoVerb) {
    const allowed = await ctx.authorizeCrypto(ctx.session.sessionID, ctx.session.latestCommand)
    if (!allowed) {
      if (!ctx.clientSocket.destroyed) ctx.clientSocket.write(CANCELLED_ASSUAN_LINE)
      return
    }
    const payload = ctx.buildUserDataPayload({
      sessionID: ctx.session.sessionID,
      command: ctx.session.latestCommand,
    })
    ctx.swallowInternalReplies += 1
    ctx.upstream.write(`OPTION pinentry-user-data=${payload}\n`)
  }
  ctx.upstream.write(`${decision.line}\n`)
}

function processUpstreamAgentLine(
  rawLineBuf: Buffer,
  ctx: SessionChannelContext,
  onGreeted: () => void,
): void {
  const prefix = rawLineBuf.subarray(0, Math.min(rawLineBuf.length, 16)).toString("ascii")
  if (!ctx.greeted) {
    ctx.greeted = true
    if (!ctx.clientSocket.destroyed) {
      ctx.clientSocket.write(Buffer.concat([rawLineBuf, NEWLINE_BYTE]))
    }
    onGreeted()
    return
  }
  if (
    ctx.swallowInternalReplies > 0 &&
    (prefix.startsWith("OK") || prefix.startsWith("ERR"))
  ) {
    ctx.swallowInternalReplies -= 1
    return
  }
  if (prefix.startsWith("INQUIRE ")) ctx.upstreamInquiring = true
  else if (prefix.startsWith("OK") || prefix.startsWith("ERR")) ctx.upstreamInquiring = false
  if (!ctx.clientSocket.destroyed) {
    ctx.clientSocket.write(Buffer.concat([rawLineBuf, NEWLINE_BYTE]))
  }
}

function attachSessionAssuanPair(ctx: SessionChannelContext): void {
  const clientQueue: Buffer[] = []
  let clientBuf = Buffer.alloc(0)
  let upstreamBuf = Buffer.alloc(0)
  let draining = false

  const drainQueue = async (): Promise<void> => {
    if (draining || !ctx.greeted) return
    draining = true
    while (clientQueue.length > 0 && !ctx.clientSocket.destroyed && !ctx.upstream.destroyed) {
      await processSessionClientLine(clientQueue.shift()!, ctx)
    }
    draining = false
  }

  ctx.upstream.on("data", (chunk: Buffer) => {
    upstreamBuf = drainBufferLines(Buffer.concat([upstreamBuf, chunk]), (rawLine) => {
      processUpstreamAgentLine(rawLine, ctx, () => void drainQueue())
    })
  })

  ctx.clientSocket.on("data", (chunk: Buffer) => {
    clientBuf = Buffer.concat([clientBuf, chunk])
    if (clientBuf.length > MAX_ASSUAN_PROXY_LINE_BYTES) {
      ctx.clientSocket.destroy()
      ctx.upstream.destroy()
      return
    }
    clientBuf = drainBufferLines(clientBuf, (rawLine) => {
      if (rawLine.length > 0) clientQueue.push(Buffer.from(rawLine))
    })
    void drainQueue()
  })

  for (const sock of [ctx.clientSocket, ctx.upstream]) {
    sock.on("close", () => {
      ctx.clientSocket.destroy()
      ctx.upstream.destroy()
    })
    sock.on("error", () => {
      ctx.clientSocket.destroy()
      ctx.upstream.destroy()
    })
  }
}

function writeExecutableScript(filePath: string, lines: readonly string[]): void {
  writeFileSync(filePath, `${lines.join("\n")}\n`, { mode: 0o700 })
  chmodSync(filePath, 0o700)
}

function writeAgentConfigAndTrampolines(options: {
  readonly agentHome: string
  readonly pinentrySocketPath: string
  readonly pinentrySecret: string
  readonly scdProxySocketPath: string
  readonly scdaemonBin: string | undefined
  readonly cacheTtlSeconds: number
}): void {
  const interpreter = resolveTrustedInterpreterPath()
  const cliScript = assertSafeConfigFilePath(
    fileURLToPath(new URL("./cli.ts", import.meta.url)),
    "cli script",
  )
  const pinentrySh = assertSafeConfigFilePath(
    path.join(options.agentHome, "pinentry.sh"),
    "pinentry trampoline",
  )
  const scdaemonSh = assertSafeConfigFilePath(
    path.join(options.agentHome, "scdaemon.sh"),
    "scdaemon trampoline",
  )

  writeExecutableScript(pinentrySh, [
    "#!/bin/sh",
    `export OC_YUBIKEY_PINENTRY_SOCK=${shellSingleQuote(options.pinentrySocketPath)}`,
    `export OC_YUBIKEY_PINENTRY_SECRET=${shellSingleQuote(options.pinentrySecret)}`,
    `exec ${shellSingleQuote(interpreter)} ${shellSingleQuote(cliScript)} "$@"`,
  ])

  writeExecutableScript(scdaemonSh, [
    "#!/bin/sh",
    `export OC_YUBIKEY_SCD_SOCK=${shellSingleQuote(options.scdProxySocketPath)}`,
    ...(options.scdaemonBin
      ? [`export OC_YUBIKEY_SCDAEMON_BIN=${shellSingleQuote(options.scdaemonBin)}`]
      : []),
    `exec ${shellSingleQuote(interpreter)} ${shellSingleQuote(cliScript)} --scdaemon-bridge "$@"`,
  ])

  writeFileSync(path.join(options.agentHome, "gpg.conf"), "no-tty\n", { mode: 0o600 })
  writeFileSync(
    path.join(options.agentHome, "gpg-agent.conf"),
    [
      `pinentry-program ${pinentrySh}`,
      `scdaemon-program ${scdaemonSh}`,
      "allow-loopback-pinentry",
      `default-cache-ttl ${options.cacheTtlSeconds}`,
      `max-cache-ttl ${options.cacheTtlSeconds}`,
      "",
    ].join("\n"),
    { mode: 0o600 },
  )
}

export class GpgRuntime {
  private readonly coordinator: PinentryCoordinator
  private readonly ownsRuntimeRoot: boolean
  readonly runtimeRoot: string
  readonly agentHome: string
  readonly agentSocketPath: string
  readonly scdProxySocketPath: string
  readonly pinentrySocketPath: string
  readonly pinentrySecret: string
  private readonly ownedBridge?: PinentryBridge
  private readonly sourceGnupgHome: string | undefined
  private readonly systemScdaemonSock: string
  private readonly scdaemonBin: string | undefined
  private readonly cacheTtlSeconds: number
  private readonly options: GpgRuntimeOptions

  private scdProxyServer?: net.Server
  private fallbackScdProcess?: ChildProcess
  private fallbackScdSock?: string
  private readonly sessions = new Map<string, SessionEntry>()
  private readonly usedShortIds = new Set<string>()
  private readonly invocations = new Map<string, SessionInvocationMetadata>()
  private latestInvocation?: SessionInvocationMetadata
  private readonly uifState = { sign: false, decrypt: false, auth: false }
  private cachedCard?: YubiKeyCardStatus
  private locked = false
  private started = false
  private stopped = false
  blockedScdaemonResets = 0

  constructor(options: GpgRuntimeOptions) {
    this.options = options
    this.coordinator = options.coordinator
    if (options.runtimeRoot) {
      mkdirSync(options.runtimeRoot, { recursive: true, mode: 0o700 })
      verifySecureSocketDir(options.runtimeRoot)
      this.runtimeRoot = options.runtimeRoot
      this.ownsRuntimeRoot = false
    } else {
      this.runtimeRoot = createSecureRuntimeRoot()
      this.ownsRuntimeRoot = true
    }

    this.agentHome = path.join(this.runtimeRoot, "a")
    mkdirSync(this.agentHome, { recursive: true, mode: 0o700 })
    this.agentSocketPath = assertMaxSocketPathLength(path.join(this.agentHome, "S.gpg-agent"))
    assertMaxSocketPathLength(path.join(this.agentHome, "S.gpg-agent.browser"))
    this.scdProxySocketPath = assertMaxSocketPathLength(path.join(this.agentHome, "S.scd"))

    if (options.pinentrySocketPath && options.pinentrySecret) {
      this.pinentrySocketPath = assertMaxSocketPathLength(options.pinentrySocketPath)
      this.pinentrySecret = options.pinentrySecret
    } else {
      const bridge = new PinentryBridge({
        coordinator: options.coordinator,
        socketDir: this.agentHome,
        getCardStatus: () =>
          options.getCardStatus
            ? options.getCardStatus()
            : this.cachedCard?.connected
              ? Promise.resolve(this.cachedCard)
              : this.refreshCardStatus(),
      })
      this.ownedBridge = bridge
      this.pinentrySocketPath = assertMaxSocketPathLength(bridge.socketPath)
      this.pinentrySecret = bridge.token
    }

    this.sourceGnupgHome = options.sourceGnupgHome
    this.systemScdaemonSock =
      options.systemScdaemonSock ?? path.join(os.homedir(), ".gnupg", "S.scdaemon")
    this.scdaemonBin = options.scdaemonBin
    this.cacheTtlSeconds = options.cacheTtlSeconds ?? 28_800
  }

  get isLocked(): boolean {
    return this.locked
  }

  registerInvocation(metadata: SessionInvocationMetadata): string {
    const ref = randomBytes(32).toString("hex")
    this.invocations.set(ref, metadata)
    this.latestInvocation = metadata
    if (this.invocations.size > 256) {
      const oldest = this.invocations.keys().next().value
      if (oldest) this.invocations.delete(oldest)
    }
    return ref
  }

  lookupInvocation(ref: string): SessionInvocationMetadata | undefined {
    return this.invocations.get(ref)
  }

  async start(): Promise<void> {
    if (this.started || this.stopped) return
    if (this.ownedBridge) {
      await this.ownedBridge.start()
    }

    const scdServer = net.createServer((sock) => {
      void this.openScdaemonConnection(sock)
    })
    await listenUnixSocket(scdServer, this.scdProxySocketPath)
    this.scdProxyServer = scdServer

    writeAgentConfigAndTrampolines({
      agentHome: this.agentHome,
      pinentrySocketPath: this.pinentrySocketPath,
      pinentrySecret: this.pinentrySecret,
      scdProxySocketPath: this.scdProxySocketPath,
      scdaemonBin: this.scdaemonBin,
      cacheTtlSeconds: this.cacheTtlSeconds,
    })
    await this.syncPublicKeyring()
    await execCommand("gpgconf", ["--launch", "gpg-agent"], {
      env: buildCleanGpgEnv(this.agentHome),
      timeoutMs: 10_000,
    })
    await this.refreshCardStatus()
    this.started = true
  }

  async syncPublicKeyring(): Promise<void> {
    const sourceEnv = buildCleanGpgEnv(this.sourceGnupgHome)
    const destEnv = buildCleanGpgEnv(this.agentHome)

    const exportedKeys = await execCommand("gpg", ["--batch", "--armor", "--export"], {
      env: sourceEnv,
      timeoutMs: 10_000,
    })
    if (exportedKeys.code === 0 && exportedKeys.stdout.trim()) {
      await execCommand("gpg", ["--batch", "--no-autostart", "--quiet", "--import"], {
        env: destEnv,
        input: exportedKeys.stdout,
        timeoutMs: 10_000,
      })
    }

    const exportedTrust = await execCommand("gpg", ["--batch", "--export-ownertrust"], {
      env: sourceEnv,
      timeoutMs: 10_000,
    })
    if (exportedTrust.code === 0 && exportedTrust.stdout.trim()) {
      await execCommand("gpg", ["--batch", "--no-autostart", "--quiet", "--import-ownertrust"], {
        env: destEnv,
        input: exportedTrust.stdout,
        timeoutMs: 10_000,
      })
    }

    for (const [, entry] of this.sessions) {
      copyKeyringArtifacts(this.agentHome, entry.gnupgHome)
    }
  }

  async refreshCardStatus(): Promise<YubiKeyCardStatus> {
    const res = await execCommand("gpg", ["--batch", "--card-status"], {
      env: buildCleanGpgEnv(this.agentHome),
      timeoutMs: 10_000,
    })
    const card =
      res.code !== 0 && !res.stdout.trim()
        ? ({ connected: false } as const)
        : parseCardStatusOutput(res.stdout)
    this.cachedCard = card
    if (card.connected && card.uif) {
      this.uifState.sign = card.uif.sign !== "off"
      this.uifState.decrypt = card.uif.decrypt !== "off"
      this.uifState.auth = card.uif.auth !== "off"
    }
    if (card.connected) {
      for (const [, entry] of this.sessions) {
        copyKeyringArtifacts(this.agentHome, entry.gnupgHome)
      }
    }
    return card
  }

  private allocateShortSessionId(sessionID: string): string {
    const digest = createHash("sha256").update(sessionID).digest("hex")
    for (let offset = 0; offset <= digest.length - 6; offset += 2) {
      const candidate = digest.slice(offset, offset + 6)
      if (!this.usedShortIds.has(candidate)) {
        this.usedShortIds.add(candidate)
        return candidate
      }
    }
    const fallback = randomBytes(3).toString("hex")
    this.usedShortIds.add(fallback)
    return fallback
  }

  async ensureSessionClient(sessionID: string, command?: string): Promise<SessionGpgClient> {
    await this.start()
    const existing = this.sessions.get(sessionID)
    if (existing) {
      if (command !== undefined) existing.latestCommand = sanitizeDisplayText(command, 80)
      return {
        sessionID: existing.sessionID,
        gnupgHome: existing.gnupgHome,
        socketPath: existing.socketPath,
      }
    }

    const shortId = this.allocateShortSessionId(sessionID)
    const gnupgHome = path.join(this.runtimeRoot, `c-${shortId}`, "g")
    mkdirSync(gnupgHome, { recursive: true, mode: 0o700 })
    const socketPath = assertMaxSocketPathLength(path.join(gnupgHome, "S.gpg-agent"))

    const entry: SessionEntry = {
      sessionID,
      shortId,
      gnupgHome,
      socketPath,
      latestCommand: sanitizeDisplayText(command, 80),
      server: net.createServer((clientSock) => {
        const upstream = net.createConnection({ path: this.agentSocketPath })
        attachSessionAssuanPair({
          greeted: false,
          upstreamInquiring: false,
          swallowInternalReplies: 0,
          session: entry,
          clientSocket: clientSock,
          upstream,
          authorizeCrypto: (sid, cmd) => this.authorizeCryptoOperation(sid, cmd),
          buildUserDataPayload: (meta) => {
            const ref = this.registerInvocation(meta)
            return JSON.stringify({
              sock: this.pinentrySocketPath,
              token: this.pinentrySecret,
              cmd: meta.command,
              ref,
            })
          },
        })
      }),
    }

    await listenUnixSocket(entry.server, socketPath)
    copyKeyringArtifacts(this.agentHome, gnupgHome)
    writeReadOnlyGpgConf(gnupgHome)
    this.sessions.set(sessionID, entry)

    return { sessionID, gnupgHome, socketPath }
  }

  private async ensureFallbackScdaemonSocket(): Promise<string> {
    if (this.fallbackScdSock && existsSync(this.fallbackScdSock) && this.fallbackScdProcess) {
      return this.fallbackScdSock
    }
    const fbDir = path.join(this.agentHome, "scd-fb")
    mkdirSync(fbDir, { recursive: true, mode: 0o700 })
    const sockPath = assertMaxSocketPathLength(path.join(fbDir, "S.scdaemon"))
    rmSync(sockPath, { force: true })

    const scdBin = resolveTrustedScdaemonExecutable(this.scdaemonBin)
    const child = spawn(
      scdBin,
      [
        "--multi-server",
        "--homedir",
        fbDir,
        "--disable-ccid",
        "--pcsc-shared",
        "--card-timeout",
        "5",
      ],
      { env: buildCleanGpgEnv(fbDir), stdio: ["pipe", "pipe", "ignore"] },
    )
    this.fallbackScdProcess = child
    this.fallbackScdSock = sockPath

    await new Promise<void>((resolve, reject) => {
      let buf = ""
      const timer = setTimeout(() => reject(new Error("Timed out starting fallback scdaemon")), 5_000)
      child.stdout.on("data", (chunk: Buffer | string) => {
        buf += String(chunk)
        if (buf.includes("OK") && !buf.includes("D ")) child.stdin.write("GETINFO socket_name\n")
        const match = buf.match(/D\s+([^\r\n]+)\r?\nOK/)
        if (match?.[1]) {
          clearTimeout(timer)
          this.fallbackScdSock = match[1].trim()
          resolve()
        }
      })
      child.once("error", (err) => {
        clearTimeout(timer)
        reject(err)
      })
      child.once("close", () => {
        clearTimeout(timer)
        this.fallbackScdProcess = undefined
        if (!existsSync(sockPath)) reject(new Error("Fallback scdaemon exited early"))
      })
    })
    return this.fallbackScdSock
  }

  private stopFallbackScdaemon(): void {
    if (this.fallbackScdProcess) {
      this.fallbackScdProcess.stdin.end()
      this.fallbackScdProcess.kill("SIGTERM")
      this.fallbackScdProcess = undefined
    }
    this.fallbackScdSock = undefined
  }

  private async openScdaemonConnection(clientSocket: net.Socket): Promise<void> {
    const upstreamPath = isSecureScdaemonSocket(this.systemScdaemonSock)
      ? (this.stopFallbackScdaemon(), this.systemScdaemonSock)
      : await this.ensureFallbackScdaemonSocket().catch(() => "")
    if (!upstreamPath) {
      clientSocket.end("ERR 100663356 No SmartCard daemon <SCD>\n")
      return
    }
    const upstream = net.createConnection({ path: upstreamPath })
    attachScdaemonProxyPair(clientSocket, upstream, {
      scdProxySocketPath: this.scdProxySocketPath,
      coordinator: this.coordinator,
      uifState: this.uifState,
      getCardMeta: () => ({ serial: this.cachedCard?.serial, holder: this.cachedCard?.holder }),
      getLatestInvocation: () => this.latestInvocation,
      onBlockedReset: () => {
        this.blockedScdaemonResets += 1
      },
      onSharingViolation: () => {
        if (isSecureScdaemonSocket(this.systemScdaemonSock)) this.stopFallbackScdaemon()
      },
    })
  }

  private async authorizeCryptoOperation(
    sessionID: string,
    command: string | undefined,
  ): Promise<boolean> {
    if (this.locked) {
      const unlockRes = await this.unlock({
        reason: command ? `Unlock YubiKey for "${command}"` : "Unlock YubiKey in OpenCode",
        allowRetry: true,
      })
      if (!unlockRes.ok) return false
      this.options.onSessionUnlocked?.(sessionID)
      return true
    }
    if (this.options.isSessionUnlocked && !this.options.isSessionUnlocked(sessionID)) {
      if (!this.options.authorizeSessionOperation) return false
      const allowed = await this.options.authorizeSessionOperation(sessionID, command)
      if (allowed) this.options.onSessionUnlocked?.(sessionID)
      return allowed
    }
    return true
  }

  async unlock(
    input: UnlockInput = {},
    options: { signal?: AbortSignal } = {},
  ): Promise<UnlockOutput> {
    await this.start()
    const res = await this.coordinator.unlock(input, options)
    if (res.ok) this.locked = false
    return res
  }

  async lock(options?: { signal?: AbortSignal }): Promise<{ ok: boolean; message: string }> {
    this.locked = true
    if (!existsSync(this.agentSocketPath)) {
      return {
        ok: true,
        message: "Locked OpenCode YubiKey runtime and cleared dedicated gpg-agent cache.",
      }
    }
    return reloadDedicatedGpgAgent({
      socketPath: this.agentSocketPath,
      gnupgHome: this.agentHome,
      signal: options?.signal,
    })
  }

  async stop(): Promise<void> {
    if (this.stopped) return
    this.stopped = true

    const sessionCloses = [...this.sessions.values()].map((entry) =>
      closeNetServer(entry.server, entry.socketPath),
    )
    this.sessions.clear()
    await Promise.allSettled(sessionCloses)

    if (existsSync(this.agentHome)) {
      const env = buildCleanGpgEnv(this.agentHome)
      await execCommand("gpgconf", ["--kill", "gpg-agent"], { env, timeoutMs: 5_000 })
      await execCommand("gpgconf", ["--kill", "keyboxd"], { env, timeoutMs: 5_000 })
    }

    this.stopFallbackScdaemon()
    await Promise.allSettled([
      closeNetServer(this.scdProxyServer, this.scdProxySocketPath),
      this.ownedBridge ? this.ownedBridge.close() : Promise.resolve(),
    ])
    this.scdProxyServer = undefined

    if (this.ownsRuntimeRoot) {
      rmSync(this.runtimeRoot, { recursive: true, force: true })
    }
  }
}
