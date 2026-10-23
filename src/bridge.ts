import { spawn } from "node:child_process"
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto"
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs"
import net from "node:net"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import type { PinentryCoordinator } from "./coordinator.ts"
import {
  type AskpassClassification,
  type SshFingerprint,
  type SshKeyType,
  classifyAskpassPrompt,
  getRuntimeSocketDirPath,
  parseJsonObject,
  verifySecureSocketDir,
} from "./protocol.ts"
import type { PromptTouchInput, PromptTouchOutput, YubiKeyCardStatus } from "./rpc.ts"
import { resolveTrustedExecutable } from "./yubikey.ts"

export { type AskpassClassification, type SshFingerprint, type SshKeyType, classifyAskpassPrompt }

export const SSH_AGENT_MSG = {
  FAILURE: 5,
  IDENTITIES_ANSWER: 12,
  SIGN_REQUEST: 13,
  SIGN_RESPONSE: 14,
} as const satisfies Record<string, number>

const MAX_IPC_LINE_BYTES = 64 * 1024
const MAX_SSH_AGENT_FRAME_BYTES = 256 * 1024
const MAX_SSH_PROXIES = 16

export function isAppleAgentSocket(socketPath: string): boolean {
  return /com\.apple\.launchd\.[^/]+\/Listeners$/.test(socketPath)
}

export { isAppleAgentSocket as isAppleLaunchdSshAgentSocket }

/**
 * Filters an `SSH2_AGENT_IDENTITIES_ANSWER` (type 12) payload `[uint32 nkeys][entries...]`.
 * Used when proxying macOS's built-in launchd `/usr/bin/ssh-agent` (whose `/usr/libexec/ssh-sk-helper`
 * is compiled without `libfido2` and fails with `internal security key support not enabled`), so
 * Homebrew OpenSSH (`/opt/homebrew/bin/ssh`) falls back to the local `~/.ssh/id_*_sk` key file
 * with Homebrew's `ssh-sk-helper` + `SSH_ASKPASS` (`oc-yubikey`).
 */
export function filterSshAgentIdentitiesAnswer(
  payload: Buffer,
  keepKeyType: (keyTypeRaw: string) => boolean,
): Buffer | undefined {
  if (payload.length < 4) return undefined
  const nkeys = payload.readUInt32BE(0)
  if (nkeys === 0 || nkeys > 1024) return undefined

  let offset = 4
  const keptEntries: Buffer[] = []
  let droppedAny = false

  for (let i = 0; i < nkeys; i++) {
    if (offset + 4 > payload.length) return undefined
    const blobLen = payload.readUInt32BE(offset)
    const blobStart = offset + 4
    const blobEnd = blobStart + blobLen
    if (blobLen < 4 || blobEnd + 4 > payload.length) return undefined

    const keyBlob = payload.subarray(blobStart, blobEnd)
    const typeLen = keyBlob.readUInt32BE(0)
    if (typeLen <= 0 || typeLen > 256 || 4 + typeLen > keyBlob.length) return undefined
    const keyTypeRaw = keyBlob.subarray(4, 4 + typeLen).toString("utf8")

    const commentLen = payload.readUInt32BE(blobEnd)
    const entryEnd = blobEnd + 4 + commentLen
    if (commentLen < 0 || entryEnd > payload.length) return undefined

    if (keepKeyType(keyTypeRaw)) {
      keptEntries.push(payload.subarray(offset, entryEnd))
    } else {
      droppedAny = true
    }
    offset = entryEnd
  }

  if (!droppedAny) return undefined

  const bodyLen = keptEntries.reduce((acc, buf) => acc + buf.length, 0)
  const frame = Buffer.alloc(4 + 1 + 4 + bodyLen)
  frame.writeUInt32BE(1 + 4 + bodyLen, 0)
  frame[4] = SSH_AGENT_MSG.IDENTITIES_ANSWER
  frame.writeUInt32BE(keptEntries.length, 5)
  let writeOffset = 9
  for (const entry of keptEntries) {
    entry.copy(frame, writeOffset)
    writeOffset += entry.length
  }
  return frame
}

export interface ParsedSshSignRequest {
  readonly keyTypeRaw: string
  readonly keyType: SshKeyType
  readonly fingerprint: SshFingerprint
  readonly isSecurityKey: boolean
}

export function formatFriendlySshKeyType(raw: string): {
  readonly keyType: SshKeyType
  readonly isSecurityKey: boolean
} {
  const lower = raw.toLowerCase()
  if (lower.startsWith("sk-ssh-ed25519")) {
    return { keyType: "ED25519-SK", isSecurityKey: true }
  }
  if (lower.startsWith("sk-ecdsa-")) {
    return { keyType: "ECDSA-SK", isSecurityKey: true }
  }
  if (lower.startsWith("sk-")) {
    return { keyType: raw.toUpperCase(), isSecurityKey: true }
  }
  if (lower === "ssh-ed25519" || lower.startsWith("ssh-ed25519-cert")) {
    return { keyType: "ED25519", isSecurityKey: false }
  }
  if (lower === "ssh-rsa" || lower.startsWith("rsa-sha2-") || lower.startsWith("ssh-rsa-cert")) {
    return { keyType: "RSA", isSecurityKey: false }
  }
  if (lower.startsWith("ecdsa-")) {
    return { keyType: "ECDSA", isSecurityKey: false }
  }
  return { keyType: raw, isSecurityKey: false }
}

/**
 * Parses an `SSH2_AGENTC_SIGN_REQUEST` (type 13) frame payload `[uint32 blobLen][blob...]`
 * to extract the SSH key type and SHA256 fingerprint.
 */
export function parseSshAgentSignRequest(payload: Buffer): ParsedSshSignRequest | undefined {
  if (payload.length < 8) return undefined
  const blobLen = payload.readUInt32BE(0)
  if (blobLen <= 4 || payload.length < 4 + blobLen) return undefined
  const keyBlob = payload.subarray(4, 4 + blobLen)
  const typeLen = keyBlob.readUInt32BE(0)
  if (typeLen <= 0 || typeLen > 256 || keyBlob.length < 4 + typeLen) return undefined
  const keyTypeRaw = keyBlob.subarray(4, 4 + typeLen).toString("utf8")
  const digest = createHash("sha256").update(keyBlob).digest("base64").replace(/=+$/, "")
  const fingerprint: SshFingerprint = `SHA256:${digest}`
  const { keyType, isSecurityKey } = formatFriendlySshKeyType(keyTypeRaw)
  return {
    keyTypeRaw,
    keyType,
    fingerprint,
    isSecurityKey,
  }
}

export function getRuntimeSocketDir(): string {
  const dir = getRuntimeSocketDirPath()
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  verifySecureSocketDir(dir)
  return dir
}

export function resolvePinentryCliPath(binName = "oc-yubikey"): string {
  const currentDir = path.dirname(fileURLToPath(import.meta.url))
  return path.resolve(currentDir, "..", "bin", binName)
}

export function resolveGpgWrapperPath(): string {
  return resolvePinentryCliPath("oc-yubikey-gpg")
}

const PROCESS_ENV_SNAPSHOT_KEYS = [
  "PATH",
  "OC_YUBIKEY_SOCK",
  "OC_YUBIKEY_TOKEN",
  "OC_YUBIKEY_COMMAND",
  "GPG_TTY",
  "SSH_ASKPASS",
  "SSH_ASKPASS_REQUIRE",
  "DISPLAY",
  "PINENTRY_USER_DATA",
  "SSH_AUTH_SOCK",
  "GIT_CONFIG_COUNT",
] as const

const PREFERRED_MAC_BIN_DIRS = [
  "/opt/homebrew/bin",
  "/usr/local/MacGPG2/bin",
  "/usr/local/bin",
] as const

function ensurePreferredBinDirsOnPath(currentPath: string | undefined): string {
  const existing = PREFERRED_MAC_BIN_DIRS.filter((dir) => existsSync(dir))
  if (existing.length === 0) return currentPath ?? ""
  const parts = (currentPath ?? "").split(":").filter(Boolean)
  const usrBinIdx = parts.indexOf("/usr/bin")
  const allPreceding = existing.every((dir) => {
    const idx = parts.indexOf(dir)
    return idx !== -1 && (usrBinIdx === -1 || idx < usrBinIdx)
  })
  if (allPreceding) return currentPath ?? existing.join(":")
  const remaining = parts.filter(
    (dir) => !existing.includes(dir as (typeof PREFERRED_MAC_BIN_DIRS)[number]),
  )
  return [...existing, ...remaining].join(":")
}

const ACTIVE_BRIDGES = new Set<PinentryBridge>()
let initialProcessEnvSnapshot: Map<string, string | undefined> | undefined
let originalBunSpawn: ((...args: unknown[]) => unknown) | undefined
let originalBunSpawnSync: ((...args: unknown[]) => unknown) | undefined

function isOcSshProxySocketPath(socketPath: string | undefined, socketDir: string): boolean {
  return (
    socketPath !== undefined &&
    path.resolve(path.dirname(socketPath)) === path.resolve(socketDir) &&
    path.basename(socketPath).startsWith("ssh-")
  )
}

function captureEnvKeys(
  snapshot: Map<string, string | undefined>,
  keys: readonly string[],
): void {
  for (const key of keys) {
    if (!snapshot.has(key)) {
      snapshot.set(key, process.env[key])
    }
  }
}

function normalizeCwdPath(cwd: unknown): string | undefined {
  if (typeof cwd === "string" && cwd.length > 0) {
    return path.resolve(cwd)
  }
  if (cwd instanceof URL) {
    try {
      return path.resolve(fileURLToPath(cwd))
    } catch {
      return undefined
    }
  }
  return undefined
}

function isDirectoryMatch(bridgeDir: string, targetCwd: string): boolean {
  const rel = path.relative(path.resolve(bridgeDir), path.resolve(targetCwd))
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel))
}

function findBestDirectoryBridge(
  active: readonly PinentryBridge[],
  cwdPath: string,
): PinentryBridge | undefined {
  let bestMatch: PinentryBridge | undefined
  let bestLen = -1
  for (const bridge of active) {
    if (!bridge.directory) continue
    const resolvedDir = path.resolve(bridge.directory)
    if (isDirectoryMatch(resolvedDir, cwdPath) && resolvedDir.length >= bestLen) {
      bestMatch = bridge
      bestLen = resolvedDir.length
    }
  }
  return bestMatch
}

function selectBridgeForSpawn(cwd: unknown): PinentryBridge | undefined {
  const active = [...ACTIVE_BRIDGES]
  if (active.length === 0) return undefined

  const cwdPath = normalizeCwdPath(cwd)
  const byDir = cwdPath ? findBestDirectoryBridge(active, cwdPath) : undefined
  if (byDir) return byDir

  const currentSock = process.env.OC_YUBIKEY_SOCK
  return (
    (currentSock ? active.find((bridge) => bridge.socketPath === currentSock) : undefined) ??
    active[active.length - 1]
  )
}

function deriveCommandFromSpawnArgv(cmd: unknown): string | undefined {
  if (!Array.isArray(cmd) || cmd.length === 0) return undefined
  const first = typeof cmd[0] === "string" ? path.basename(cmd[0]) : ""
  if (first === "oc-yubikey" || first === "oc-yubikey-gpg") return undefined
  const parts = cmd.filter((part): part is string => typeof part === "string")
  return parts.length > 0 ? parts.join(" ") : undefined
}

function buildInjectedSpawnEnv(
  cwd: unknown,
  cmd: unknown,
): Record<string, string | undefined> | undefined {
  const bridge = selectBridgeForSpawn(cwd)
  if (!bridge) return undefined
  const env: Record<string, string | undefined> = { ...process.env }
  bridge.applyEnvSync(env, deriveCommandFromSpawnArgv(cmd))
  return env
}

function withInjectedBunSpawnArgs(args: unknown[]): unknown[] {
  if (ACTIVE_BRIDGES.size === 0) return args
  const first = args[0]

  if (Array.isArray(first)) {
    const rawOpts =
      typeof args[1] === "object" && args[1] !== null
        ? (args[1] as Record<string, unknown>)
        : undefined
    if (rawOpts?.env !== undefined) return args
    const env = buildInjectedSpawnEnv(rawOpts?.cwd, first)
    return env ? [first, { ...(rawOpts ?? {}), env }, ...args.slice(2)] : args
  }

  if (typeof first === "object" && first !== null) {
    const rawOpts = first as Record<string, unknown>
    if (rawOpts.env !== undefined) return args
    const env = buildInjectedSpawnEnv(rawOpts.cwd, rawOpts.cmd)
    return env ? [{ ...rawOpts, env }, ...args.slice(1)] : args
  }

  return args
}

function installBunSpawnInterceptor(): void {
  if (typeof Bun === "undefined" || !Bun) return
  const bunObj = Bun as unknown as {
    spawn?: (...args: unknown[]) => unknown
    spawnSync?: (...args: unknown[]) => unknown
  }
  if (!originalBunSpawn && typeof bunObj.spawn === "function") {
    const realSpawn = bunObj.spawn.bind(Bun)
    originalBunSpawn = realSpawn
    bunObj.spawn = (...args: unknown[]) => realSpawn(...withInjectedBunSpawnArgs(args))
  }
  if (!originalBunSpawnSync && typeof bunObj.spawnSync === "function") {
    const realSpawnSync = bunObj.spawnSync.bind(Bun)
    originalBunSpawnSync = realSpawnSync
    bunObj.spawnSync = (...args: unknown[]) => realSpawnSync(...withInjectedBunSpawnArgs(args))
  }
}

function uninstallBunSpawnInterceptor(): void {
  if (typeof Bun === "undefined" || !Bun) return
  const bunObj = Bun as unknown as {
    spawn?: (...args: unknown[]) => unknown
    spawnSync?: (...args: unknown[]) => unknown
  }
  if (originalBunSpawn) {
    bunObj.spawn = originalBunSpawn
    originalBunSpawn = undefined
  }
  if (originalBunSpawnSync) {
    bunObj.spawnSync = originalBunSpawnSync
    originalBunSpawnSync = undefined
  }
}

function resolveUpstreamSshAuthSock(
  env: Record<string, string | undefined>,
  socketDir: string,
  fallbackSock: string | undefined,
): string | undefined {
  if (env.SSH_AUTH_SOCK && !isOcSshProxySocketPath(env.SSH_AUTH_SOCK, socketDir)) {
    return env.SSH_AUTH_SOCK
  }
  if (process.env.SSH_AUTH_SOCK && !isOcSshProxySocketPath(process.env.SSH_AUTH_SOCK, socketDir)) {
    return process.env.SSH_AUTH_SOCK
  }
  if (fallbackSock && !isOcSshProxySocketPath(fallbackSock, socketDir)) {
    return fallbackSock
  }
  const initialSock = initialProcessEnvSnapshot?.get("SSH_AUTH_SOCK")
  if (initialSock && !isOcSshProxySocketPath(initialSock, socketDir)) {
    return initialSock
  }
  return undefined
}

function populateShellEnvRecord(
  env: Record<string, string | undefined>,
  options: {
    readonly ipcSocketPath: string
    readonly authToken: string
    readonly effectiveCmd: string | undefined
    readonly proxySocketPath: string | undefined
    readonly onBeforeMutateKeys: (keys: readonly string[]) => void
  },
): void {
  const updatedPath = ensurePreferredBinDirsOnPath(env.PATH ?? process.env.PATH)
  if (updatedPath) {
    env.PATH = updatedPath
  }
  env.OC_YUBIKEY_SOCK = options.ipcSocketPath
  env.OC_YUBIKEY_TOKEN = options.authToken
  if (options.effectiveCmd) {
    env.OC_YUBIKEY_COMMAND = options.effectiveCmd
  } else {
    delete env.OC_YUBIKEY_COMMAND
  }

  env.GPG_TTY = "/dev/null"

  const cliPath = resolvePinentryCliPath()
  if (existsSync(cliPath)) {
    env.SSH_ASKPASS = cliPath
    if (!env.SSH_ASKPASS_REQUIRE) {
      env.SSH_ASKPASS_REQUIRE = "force"
    }
    if (!env.DISPLAY) {
      env.DISPLAY = "oc-yubikey:0"
    }
  }

  const gpgWrapperPath = resolveGpgWrapperPath()
  if (existsSync(gpgWrapperPath)) {
    injectGitGpgProgramConfig(env, gpgWrapperPath, options.onBeforeMutateKeys)
  }

  env.PINENTRY_USER_DATA = JSON.stringify({
    sock: options.ipcSocketPath,
    token: options.authToken,
    cmd: options.effectiveCmd,
  })

  if (options.proxySocketPath) {
    env.SSH_AUTH_SOCK = options.proxySocketPath
  }
}

function injectGitGpgProgramConfig(
  env: Record<string, string | undefined>,
  gpgWrapperPath: string,
  onBeforeMutateKeys?: (keys: readonly string[]) => void,
): void {
  const rawCount = env.GIT_CONFIG_COUNT
  const parsedCount = rawCount !== undefined ? Number.parseInt(rawCount, 10) : 0
  const count = Number.isInteger(parsedCount) && parsedCount >= 0 ? parsedCount : 0

  for (let i = 0; i < count; i++) {
    if (env[`GIT_CONFIG_KEY_${i}`] === "gpg.program") {
      onBeforeMutateKeys?.([`GIT_CONFIG_KEY_${i}`, `GIT_CONFIG_VALUE_${i}`])
      env[`GIT_CONFIG_VALUE_${i}`] = gpgWrapperPath
      return
    }
  }

  onBeforeMutateKeys?.([
    "GIT_CONFIG_COUNT",
    `GIT_CONFIG_KEY_${count}`,
    `GIT_CONFIG_VALUE_${count}`,
  ])
  env.GIT_CONFIG_COUNT = String(count + 1)
  env[`GIT_CONFIG_KEY_${count}`] = "gpg.program"
  env[`GIT_CONFIG_VALUE_${count}`] = gpgWrapperPath
}

export function findSshSecurityKeyFile(
  sshDir = path.join(os.homedir(), ".ssh"),
): string | undefined {
  try {
    if (!existsSync(sshDir)) return undefined
    const uid = typeof process.getuid === "function" ? process.getuid() : 0
    const preferred = ["id_ed25519_sk", "id_ecdsa_sk"]
    const extras = readdirSync(sshDir).filter(
      (name) => /^id_.*_sk(?:_rk)?$/.test(name) && !preferred.includes(name),
    )
    for (const name of [...preferred, ...extras]) {
      const fullPath = path.join(sshDir, name)
      try {
        const stat = lstatSync(fullPath)
        if (
          !stat.isSymbolicLink() &&
          stat.isFile() &&
          (typeof process.getuid !== "function" || stat.uid === uid)
        ) {
          return fullPath
        }
      } catch {
        // Ignore unreadable candidate
      }
    }
  } catch {
    // Ignore unreadable .ssh directory
  }
  return undefined
}

export interface IpcRequestMessage {
  readonly token?: string
  readonly type: "touch" | "pin"
  readonly title?: string
  readonly description?: string
  readonly prompt?: string
  readonly error?: string
  readonly serial?: string
  readonly holder?: string
  readonly keyType?: string
  readonly fingerprint?: string
  readonly command?: string
}

export interface IpcResponseMessage {
  readonly ok: boolean
  readonly cancelled: boolean
  readonly confirmed?: boolean
  readonly pin?: string
}

export interface PinentryBridgeOptions {
  readonly coordinator: PinentryCoordinator
  readonly socketDir?: string
  readonly directory?: string
  readonly securityKeyDebounceMs?: number
  readonly hardwareAgentDebounceMs?: number
  readonly getCardStatus?: () => Promise<YubiKeyCardStatus>
}

function summarizeCommand(rawCommand: string | undefined): string | undefined {
  if (!rawCommand) return undefined
  const firstLine = rawCommand.trim().split(/\r?\n/)[0]?.trim()
  if (!firstLine) return undefined
  return firstLine.length > 80 ? `${firstLine.slice(0, 77)}...` : firstLine
}

interface SshAgentFrame {
  readonly rawFrame: Buffer
  readonly msgType: number
  readonly payload: Buffer
}

function readSshAgentFrames(buffer: Buffer): {
  readonly frames: readonly SshAgentFrame[]
  readonly remaining: Buffer
  readonly overflow: boolean
} {
  const frames: SshAgentFrame[] = []
  let offset = 0
  while (buffer.length - offset >= 5) {
    const frameLen = buffer.readUInt32BE(offset)
    if (frameLen < 1 || frameLen > MAX_SSH_AGENT_FRAME_BYTES) {
      return { frames, remaining: Buffer.alloc(0), overflow: true }
    }
    const frameEnd = offset + 4 + frameLen
    if (buffer.length < frameEnd) {
      break
    }
    frames.push({
      rawFrame: buffer.subarray(offset, frameEnd),
      msgType: buffer[offset + 4]!,
      payload: buffer.subarray(offset + 5, frameEnd),
    })
    offset = frameEnd
  }
  return {
    frames,
    remaining: offset > 0 ? buffer.subarray(offset) : buffer,
    overflow: false,
  }
}

function buildHardwareTouchRequest(
  input: PromptTouchInput,
  promptLine?: string,
): PromptTouchInput {
  const classified = promptLine ? classifyAskpassPrompt(promptLine) : undefined
  return {
    title: input.title || "Touch Your YubiKey",
    description:
      input.description ||
      classified?.description ||
      "Confirm user presence on your YubiKey to continue.",
    prompt: input.prompt || "Touch YubiKey",
    keyType: input.keyType ?? classified?.keyType,
    fingerprint: input.fingerprint ?? classified?.fingerprint,
    command: input.command || "yubikey touch",
  }
}

function spawnSshKeygenSign(skKeyPath: string) {
  const sshKeygenBin = resolveTrustedExecutable("ssh-keygen")
  const env: Record<string, string | undefined> = {
    ...process.env,
    SSH_AUTH_SOCK: undefined,
    SSH_ASKPASS: undefined,
    SSH_ASKPASS_REQUIRE: undefined,
  }
  const child = spawn(sshKeygenBin, ["-Y", "sign", "-f", skKeyPath, "-n", "oc-yubikey-touch"], {
    env,
    stdio: ["pipe", "pipe", "pipe"],
  })
  child.stdin.write("oc-yubikey-touch-challenge\n")
  child.stdin.end()
  return child
}

export class PinentryBridge {
  private readonly coordinator: PinentryCoordinator
  private readonly socketDir: string
  readonly directory?: string
  private readonly id: string
  private readonly authToken: string
  private readonly ipcSocketPath: string
  private readonly activePointerPath: string
  private readonly securityKeyDebounceMs: number
  private readonly hardwareAgentDebounceMs: number
  private readonly getCardStatus?: () => Promise<YubiKeyCardStatus>
  private ipcServer?: net.Server
  private readonly sshProxies = new Map<
    string,
    {
      readonly proxySocketPath: string
      readonly server: net.Server
    }
  >()
  private savedProcessEnv?: Map<string, string | undefined>
  private initialUpstreamSshSock?: string
  private latestCommand?: string
  private closed = false

  constructor(options: PinentryBridgeOptions) {
    this.coordinator = options.coordinator
    this.socketDir = options.socketDir ?? getRuntimeSocketDir()
    this.directory = options.directory
    mkdirSync(this.socketDir, { recursive: true, mode: 0o700 })
    verifySecureSocketDir(this.socketDir)
    this.id = randomBytes(4).toString("hex")
    this.authToken = randomBytes(32).toString("hex")
    this.ipcSocketPath = path.join(this.socketDir, `ipc-${this.id}.sock`)
    this.activePointerPath = path.join(this.socketDir, "active.json")
    this.securityKeyDebounceMs = options.securityKeyDebounceMs ?? 40
    this.hardwareAgentDebounceMs = options.hardwareAgentDebounceMs ?? 150
    this.getCardStatus = options.getCardStatus
    const candidateUpstreamSock =
      process.env.SSH_AUTH_SOCK &&
      !isOcSshProxySocketPath(process.env.SSH_AUTH_SOCK, this.socketDir)
        ? process.env.SSH_AUTH_SOCK
        : initialProcessEnvSnapshot?.get("SSH_AUTH_SOCK")
    if (
      candidateUpstreamSock &&
      !isOcSshProxySocketPath(candidateUpstreamSock, this.socketDir)
    ) {
      this.initialUpstreamSshSock = candidateUpstreamSock
    }
  }

  get socketPath(): string {
    return this.ipcSocketPath
  }

  get token(): string {
    return this.authToken
  }

  private isValidToken(candidate: unknown): boolean {
    if (typeof candidate !== "string") return false
    const a = Buffer.from(candidate, "utf8")
    const b = Buffer.from(this.authToken, "utf8")
    if (a.length !== b.length) return false
    return timingSafeEqual(a, b)
  }

  async start(): Promise<void> {
    if (this.ipcServer) return
    verifySecureSocketDir(this.socketDir)
    rmSync(this.ipcSocketPath, { force: true })

    const server = net.createServer((socket: net.Socket) => {
      this.handleIpcConnection(socket)
    })

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject)
      server.listen(this.ipcSocketPath, () => {
        try {
          chmodSync(this.ipcSocketPath, 0o600)
        } catch {
          // Ignore chmod error
        }
        resolve()
      })
    })

    this.ipcServer = server
    try {
      const tmpPointerPath = `${this.activePointerPath}.${this.id}.tmp`
      rmSync(tmpPointerPath, { force: true })
      writeFileSync(
        tmpPointerPath,
        JSON.stringify({
          socketPath: this.ipcSocketPath,
          token: this.authToken,
          pid: process.pid,
          updatedAt: Date.now(),
        }),
        { mode: 0o600, flag: "wx" },
      )
      chmodSync(tmpPointerPath, 0o600)
      renameSync(tmpPointerPath, this.activePointerPath)
    } catch {
      // Ignore pointer write failure
    }
  }

  private async readCardForIpcPin(msg: IpcRequestMessage): Promise<YubiKeyCardStatus | undefined> {
    if (!this.getCardStatus || msg.keyType?.toUpperCase().endsWith("-SK")) return undefined
    const card = await this.getCardStatus().catch(() => undefined)
    return card?.connected ? card : undefined
  }

  private async dispatchIpcPinRequest(
    msg: IpcRequestMessage,
    command: string | undefined,
    requestID: string,
  ): Promise<IpcResponseMessage> {
    const card = await this.readCardForIpcPin(msg)
    const retriesLeft = card?.pinRetries?.user
    if (!msg.keyType && retriesLeft !== undefined && retriesLeft <= 0) {
      return { ok: false, cancelled: true }
    }
    const warning =
      retriesLeft === 1
        ? "Warning: Only 1 PIN attempt remaining before YubiKey PIN is blocked!"
        : undefined
    const res = await this.coordinator.requestPin(
      {
        title: msg.title || "YubiKey PIN Entry",
        description: msg.description,
        prompt: msg.prompt || "PIN:",
        error: msg.error ?? warning,
        serial: msg.serial ?? card?.serial,
        holder: msg.holder ?? card?.holder,
        pinPolicy: card?.pinPolicy,
        retriesLeft,
        command,
      },
      { requestID },
    )
    return {
      ok: !res.cancelled && Boolean(res.pin),
      cancelled: res.cancelled,
      ...(res.pin !== undefined ? { pin: res.pin } : {}),
    }
  }

  private async dispatchIpcRequest(
    msg: IpcRequestMessage,
    requestID: string,
  ): Promise<IpcResponseMessage> {
    const command = summarizeCommand(this.latestCommand ?? msg.command)
    if (msg.type === "touch") {
      const description =
        msg.description ||
        (command
          ? `Confirm user presence on your YubiKey for "${command}"`
          : "Confirm user presence on your YubiKey to continue.")
      const res = await this.coordinator.requestTouch(
        {
          title: msg.title || "Touch Your YubiKey",
          description,
          prompt: msg.prompt || "Touch YubiKey",
          serial: msg.serial,
          holder: msg.holder,
          keyType: msg.keyType,
          fingerprint: msg.fingerprint,
          command,
        },
        { requestID },
      )
      return {
        ok: !res.cancelled && res.confirmed,
        cancelled: res.cancelled,
        confirmed: res.confirmed,
      }
    }
    return this.dispatchIpcPinRequest(msg, command, requestID)
  }

  private handleIpcConnection(socket: net.Socket): void {
    let buffer = ""
    let requestReceived = false
    let activeRequestID: string | undefined
    let activeKind: "touch" | "pin" | undefined
    let settled = false

    const handleLine = async (line: string) => {
      let msg: IpcRequestMessage
      try {
        msg = JSON.parse(line) as IpcRequestMessage
      } catch {
        socket.end(`${JSON.stringify({ ok: false, cancelled: true })}\n`)
        return
      }

      if (!this.isValidToken(msg.token)) {
        socket.end(`${JSON.stringify({ ok: false, cancelled: true })}\n`)
        return
      }

      const requestID = randomUUID()
      activeRequestID = requestID
      activeKind = msg.type === "touch" ? "touch" : "pin"

      const response = await this.dispatchIpcRequest(msg, requestID)
      settled = true
      if (!socket.destroyed) {
        socket.end(`${JSON.stringify(response)}\n`)
      }
    }

    socket.on("data", (chunk: Buffer | string) => {
      if (requestReceived) return
      buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8")
      if (buffer.length > MAX_IPC_LINE_BYTES) {
        socket.destroy()
        return
      }
      const idx = buffer.indexOf("\n")
      if (idx !== -1) {
        const line = buffer.slice(0, idx).trim()
        buffer = ""
        if (line) {
          requestReceived = true
          void handleLine(line)
        }
      }
    })

    const onDisconnect = () => {
      if (settled || !activeRequestID) return
      settled = true
      if (activeKind === "touch") {
        // When ssh (SSH_ASKPASS) or gpg-agent (CONFIRM) finishes waiting for physical YubiKey touch,
        // it terminates the helper process, closing this socket. Confirm & dismiss the modal immediately.
        this.coordinator.confirmTouch(activeRequestID)
      } else {
        this.coordinator.cancel(activeRequestID, "ipc-disconnected")
      }
    }

    socket.on("close", onDisconnect)
    socket.on("error", onDisconnect)
  }

  /**
   * Returns a proxy `SSH_AUTH_SOCK` path that forwards to `upstreamSocketPath` while monitoring
   * `SSH2_AGENTC_SIGN_REQUEST` frames so OpenCode can display the Touch YubiKey modal in the TUI.
   */
  async ensureSshAgentProxy(upstreamSocketPath: string, command?: string): Promise<string> {
    this.latestCommand = summarizeCommand(command)
    const existing = this.sshProxies.get(upstreamSocketPath)
    if (existing) {
      return existing.proxySocketPath
    }
    if (this.sshProxies.size >= MAX_SSH_PROXIES) {
      return upstreamSocketPath
    }

    verifySecureSocketDir(this.socketDir)
    const hash = createHash("sha256").update(upstreamSocketPath).digest("hex").slice(0, 6)
    const proxySocketPath = path.join(this.socketDir, `ssh-${this.id}-${hash}.sock`)
    rmSync(proxySocketPath, { force: true })

    const server = net.createServer((clientSocket: net.Socket) => {
      this.handleSshProxyConnection(clientSocket, upstreamSocketPath)
    })

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject)
      server.listen(proxySocketPath, () => {
        try {
          chmodSync(proxySocketPath, 0o600)
        } catch {
          // Ignore chmod error
        }
        resolve()
      })
    })

    this.sshProxies.set(upstreamSocketPath, { proxySocketPath, server })
    return proxySocketPath
  }

  private scheduleSshTouchPrompt(
    parsed: ParsedSshSignRequest | undefined,
    isActive: () => boolean,
    onAssignRequest: (requestID: string) => void,
    onCancelledByUser: () => void,
  ): ReturnType<typeof setTimeout> {
    const delayMs = parsed?.isSecurityKey ? this.securityKeyDebounceMs : this.hardwareAgentDebounceMs
    const command = summarizeCommand(this.latestCommand)
    return setTimeout(() => {
      if (!isActive() || this.coordinator.listPending().length > 0) return
      const requestID = randomUUID()
      onAssignRequest(requestID)
      const keyLabel = parsed?.keyType ?? "YubiKey SSH"
      const description = command
        ? `Confirm user presence on your YubiKey for "${command}"`
        : `Confirm user presence on your YubiKey for ${keyLabel} authentication`

      void this.coordinator
        .requestTouch(
          {
            title: "Touch Your YubiKey",
            description,
            prompt: "Touch YubiKey",
            keyType: parsed?.keyType,
            fingerprint: parsed?.fingerprint,
            command,
          },
          { requestID },
        )
        .then((res) => {
          if (res.cancelled && isActive()) {
            onCancelledByUser()
          }
        })
        .catch(() => {})
    }, delayMs)
  }

  private handleSshProxyConnection(clientSocket: net.Socket, upstreamSocketPath: string): void {
    const upstreamSocket = net.createConnection({ path: upstreamSocketPath })

    let clientBuffer = Buffer.alloc(0)
    let upstreamBuffer = Buffer.alloc(0)
    let pendingTouchTimer: ReturnType<typeof setTimeout> | undefined
    let activeTouchRequestID: string | undefined
    let signInFlight = false
    let connectionClosed = false

    const clearPendingTouch = (confirm: boolean) => {
      signInFlight = false
      if (pendingTouchTimer) {
        clearTimeout(pendingTouchTimer)
        pendingTouchTimer = undefined
      }
      if (!activeTouchRequestID) return
      const reqID = activeTouchRequestID
      activeTouchRequestID = undefined
      if (confirm) {
        this.coordinator.confirmTouch(reqID)
      } else {
        this.coordinator.cancel(reqID, "ssh-agent-aborted")
      }
    }

    const cleanup = () => {
      if (connectionClosed) return
      connectionClosed = true
      clearPendingTouch(false)
      clientSocket.destroy()
      upstreamSocket.destroy()
    }

    clientSocket.on("data", (chunk: Buffer) => {
      upstreamSocket.write(chunk)
      const parsedFrames = readSshAgentFrames(Buffer.concat([clientBuffer, chunk]))
      if (parsedFrames.overflow) {
        cleanup()
        return
      }
      clientBuffer = parsedFrames.remaining

      for (const frame of parsedFrames.frames) {
        if (frame.msgType !== SSH_AGENT_MSG.SIGN_REQUEST) continue
        signInFlight = true
        if (pendingTouchTimer) clearTimeout(pendingTouchTimer)
        pendingTouchTimer = this.scheduleSshTouchPrompt(
          parseSshAgentSignRequest(frame.payload),
          () => signInFlight && !connectionClosed,
          (reqID) => {
            activeTouchRequestID = reqID
          },
          () => {
            activeTouchRequestID = undefined
            signInFlight = false
            // Return SSH_AGENT_FAILURE ([0, 0, 0, 1, 5]) to abort the stalled ssh client immediately
            if (!clientSocket.destroyed) {
              clientSocket.write(Buffer.from([0x00, 0x00, 0x00, 0x01, SSH_AGENT_MSG.FAILURE]))
            }
            upstreamSocket.destroy()
          },
        )
      }
    })

    const stripBrokenAppleSk =
      isAppleAgentSocket(upstreamSocketPath) && !process.env.SSH_SK_PROVIDER

    upstreamSocket.on("data", (chunk: Buffer) => {
      const combined = Buffer.concat([upstreamBuffer, chunk])
      const parsedFrames = readSshAgentFrames(combined)
      if (parsedFrames.overflow) {
        cleanup()
        return
      }
      upstreamBuffer = parsedFrames.remaining

      for (const frame of parsedFrames.frames) {
        let outFrame = frame.rawFrame
        if (frame.msgType === SSH_AGENT_MSG.IDENTITIES_ANSWER && stripBrokenAppleSk) {
          outFrame =
            filterSshAgentIdentitiesAnswer(
              frame.payload,
              (keyTypeRaw) => !keyTypeRaw.toLowerCase().startsWith("sk-"),
            ) ?? outFrame
        }
        if (!clientSocket.destroyed) {
          clientSocket.write(outFrame)
        }
        if (frame.msgType === SSH_AGENT_MSG.SIGN_RESPONSE) {
          clearPendingTouch(true)
        } else if (frame.msgType === SSH_AGENT_MSG.FAILURE || signInFlight) {
          clearPendingTouch(false)
        }
      }
    })

    clientSocket.on("close", cleanup)
    clientSocket.on("error", cleanup)
    upstreamSocket.on("close", cleanup)
    upstreamSocket.on("error", cleanup)
  }

  private snapshotProcessEnv(
    env: Record<string, string | undefined>,
    extraKeys: readonly string[] = [],
  ): void {
    if (env !== process.env) return
    const keys = [...PROCESS_ENV_SNAPSHOT_KEYS, ...extraKeys]
    this.savedProcessEnv ??= new Map<string, string | undefined>()
    captureEnvKeys(this.savedProcessEnv, keys)
    initialProcessEnvSnapshot ??= new Map<string, string | undefined>()
    captureEnvKeys(initialProcessEnvSnapshot, keys)
  }

  restoreProcessEnv(): void {
    const wasActive = ACTIVE_BRIDGES.delete(this)
    if (!wasActive && !this.savedProcessEnv) return
    this.savedProcessEnv = undefined

    const remaining = [...ACTIVE_BRIDGES]
    const fallbackBridge = remaining[remaining.length - 1]
    if (fallbackBridge) {
      fallbackBridge.applyEnvSync(process.env)
      return
    }

    uninstallBunSpawnInterceptor()
    if (!initialProcessEnvSnapshot) return
    const snapshot = initialProcessEnvSnapshot
    initialProcessEnvSnapshot = undefined
    for (const [key, originalValue] of snapshot) {
      if (originalValue === undefined) {
        delete process.env[key]
      } else {
        process.env[key] = originalValue
      }
    }
  }

  applyEnvSync(env: Record<string, string | undefined>, command?: string): void {
    if (this.closed) return
    this.snapshotProcessEnv(env)

    const summarizedCmd = summarizeCommand(command)
    if (command !== undefined || env === process.env) {
      this.latestCommand = summarizedCmd
    }
    const effectiveCmd = summarizedCmd ?? this.latestCommand
    const upstreamSshSock = resolveUpstreamSshAuthSock(
      env,
      this.socketDir,
      this.initialUpstreamSshSock,
    )
    const proxySocketPath = upstreamSshSock
      ? this.sshProxies.get(upstreamSshSock)?.proxySocketPath
      : undefined

    populateShellEnvRecord(env, {
      ipcSocketPath: this.ipcSocketPath,
      authToken: this.authToken,
      effectiveCmd,
      proxySocketPath,
      onBeforeMutateKeys: (keys) => this.snapshotProcessEnv(env, keys),
    })
  }

  async prepareShellEnv(
    env: Record<string, string | undefined>,
    command?: string,
  ): Promise<void> {
    if (this.closed) return
    await this.start()

    if (env === process.env) {
      ACTIVE_BRIDGES.delete(this)
      ACTIVE_BRIDGES.add(this)
      installBunSpawnInterceptor()
    }

    const upstreamSshSock = resolveUpstreamSshAuthSock(
      env,
      this.socketDir,
      this.initialUpstreamSshSock,
    )
    if (upstreamSshSock) {
      this.initialUpstreamSshSock ??= upstreamSshSock
      try {
        const uid = typeof process.getuid === "function" ? process.getuid() : 0
        const stat = lstatSync(upstreamSshSock)
        if (
          !stat.isSymbolicLink() &&
          stat.isSocket() &&
          (typeof process.getuid !== "function" || stat.uid === uid)
        ) {
          await this.ensureSshAgentProxy(upstreamSshSock, command)
        }
      } catch {}
    }

    this.applyEnvSync(env, command)
  }

  /**
   * Initiates a real hardware FIDO2 touch verification using `ssh-keygen -Y sign` when a local
   * `~/.ssh/id_*_sk` security key is available, so the YubiKey's physical touch sensor is activated
   * and touching the YubiKey automatically dismisses `TouchModal`. Falls back to `coordinator.requestTouch`
   * when no local security key file is present.
   */
  async verifyHardwareTouch(
    input: PromptTouchInput = {},
    options: { signal?: AbortSignal; sshDir?: string } = {},
  ): Promise<PromptTouchOutput> {
    if (options.signal?.aborted) {
      return { cancelled: true, confirmed: false }
    }
    const skKeyPath = findSshSecurityKeyFile(options.sshDir)
    if (!skKeyPath) {
      return this.coordinator.requestTouch(input, { signal: options.signal })
    }
    return this.runSshKeygenTouchChallenge(skKeyPath, input, options.signal)
  }

  private runSshKeygenTouchChallenge(
    skKeyPath: string,
    input: PromptTouchInput,
    signal?: AbortSignal,
  ): Promise<PromptTouchOutput> {
    const requestID = randomUUID()
    const coordinator = this.coordinator
    return new Promise<PromptTouchOutput>((resolve) => {
      const child = spawnSshKeygenSign(skKeyPath)
      let stdout = ""
      let stderr = ""
      let promptOpened = false
      let settled = false

      const settle = (confirmed: boolean, reason: string) => {
        if (settled) return
        settled = true
        if (promptOpened) {
          if (confirmed) coordinator.confirmTouch(requestID)
          else coordinator.cancel(requestID, reason)
        }
        resolve({ cancelled: !confirmed, confirmed })
      }

      child.stdout.on("data", (chunk: Buffer | string) => {
        stdout += String(chunk)
      })
      child.stderr.on("data", (chunk: Buffer | string) => {
        stderr += String(chunk)
        const match = stderr.match(/Confirm user presence[^\r\n]*/i)
        if (!match || promptOpened || settled) return
        promptOpened = true
        const req = buildHardwareTouchRequest(input, match[0])
        void coordinator.requestTouch(req, { requestID, signal }).then((res) => {
          if (settled) return
          settled = true
          child.kill("SIGTERM")
          resolve(res)
        })
      })
      child.on("error", () => settle(false, "ssh-keygen-error"))
      child.on("close", (code) => {
        settle(code === 0 || stdout.includes("BEGIN SSH SIGNATURE"), "ssh-keygen-failed")
      })
    })
  }

  async close(): Promise<void> {
    this.closed = true
    this.restoreProcessEnv()
    const closes: Promise<void>[] = []

    if (this.ipcServer) {
      const server = this.ipcServer
      this.ipcServer = undefined
      closes.push(
        new Promise<void>((resolve) => {
          server.close(() => resolve())
        }),
      )
    }

    for (const [, entry] of this.sshProxies) {
      closes.push(
        new Promise<void>((resolve) => {
          entry.server.close(() => resolve())
        }),
      )
    }

    await Promise.allSettled(closes)

    rmSync(this.ipcSocketPath, { force: true })
    this.removeActivePointerIfOwned()
    for (const [, entry] of this.sshProxies) {
      rmSync(entry.proxySocketPath, { force: true })
    }
    this.sshProxies.clear()
  }

  private removeActivePointerIfOwned(): void {
    if (!existsSync(this.activePointerPath)) return
    const parsed = parseJsonObject(readFileSync(this.activePointerPath, "utf8"))
    if (parsed?.socketPath === this.ipcSocketPath) {
      rmSync(this.activePointerPath, { force: true })
    }
  }
}
