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

export function resolvePinentryCliPath(): string {
  const currentDir = path.dirname(fileURLToPath(import.meta.url))
  return path.resolve(currentDir, "..", "bin", "oc-yubikey")
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
  const env: Record<string, string | undefined> = { ...process.env, SSH_AUTH_SOCK: undefined }
  const child = spawn(sshKeygenBin, ["-Y", "sign", "-f", skKeyPath, "-n", "oc-yubikey-touch"], {
    env,
    stdio: ["pipe", "pipe", "pipe"],
  })
  child.stdin.write("oc-yubikey-touch-challenge\n")
  child.stdin.end()
  return child
}

/**
 * Manages:
 * 1. An authenticated local IPC Unix socket server for `bin/oc-yubikey` (`SSH_ASKPASS` + GnuPG Assuan `pinentry` shim)
 * 2. An `SSH_AUTH_SOCK` transparent proxy that detects `SSH2_AGENTC_SIGN_REQUEST` waiting on YubiKey touch
 *    (such as `sk-ssh-ed25519@openssh.com` in `ssh-agent` or `gpg-agent`'s SSH socket) and opens
 *    the OpenCode TUI Touch Modal automatically, closing it the instant the user touches the YubiKey.
 */
export class PinentryBridge {
  private readonly coordinator: PinentryCoordinator
  private readonly socketDir: string
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
  private latestCommand?: string
  private closed = false

  constructor(options: PinentryBridgeOptions) {
    this.coordinator = options.coordinator
    this.socketDir = options.socketDir ?? getRuntimeSocketDir()
    mkdirSync(this.socketDir, { recursive: true, mode: 0o700 })
    verifySecureSocketDir(this.socketDir)
    this.id = randomBytes(4).toString("hex")
    this.authToken = randomBytes(32).toString("hex")
    this.ipcSocketPath = path.join(this.socketDir, `ipc-${this.id}.sock`)
    this.activePointerPath = path.join(this.socketDir, "active.json")
    this.securityKeyDebounceMs = options.securityKeyDebounceMs ?? 40
    this.hardwareAgentDebounceMs = options.hardwareAgentDebounceMs ?? 150
    this.getCardStatus = options.getCardStatus
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

  /**
   * Injects `SSH_AUTH_SOCK`, `SSH_ASKPASS`, `SSH_ASKPASS_REQUIRE`, `OC_YUBIKEY_SOCK`,
   * `OC_YUBIKEY_TOKEN`, `PINENTRY_USER_DATA`, and `GPG_TTY=/dev/null` into a shell
   * command environment before execution.
   */
  async prepareShellEnv(
    env: Record<string, string | undefined>,
    command?: string,
  ): Promise<void> {
    if (this.closed) return
    await this.start()

    const summarizedCmd = summarizeCommand(command)
    this.latestCommand = summarizedCmd

    env.OC_YUBIKEY_SOCK = this.ipcSocketPath
    env.OC_YUBIKEY_TOKEN = this.authToken
    if (summarizedCmd) {
      env.OC_YUBIKEY_COMMAND = summarizedCmd
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

    env.PINENTRY_USER_DATA = JSON.stringify({
      sock: this.ipcSocketPath,
      token: this.authToken,
      cmd: summarizedCmd,
    })

    const upstreamSshSock = env.SSH_AUTH_SOCK || process.env.SSH_AUTH_SOCK
    const isAnyOcSshProxy =
      upstreamSshSock !== undefined &&
      path.resolve(path.dirname(upstreamSshSock)) === path.resolve(this.socketDir) &&
      path.basename(upstreamSshSock).startsWith("ssh-")

    if (upstreamSshSock && !isAnyOcSshProxy) {
      try {
        const uid = typeof process.getuid === "function" ? process.getuid() : 0
        const stat = lstatSync(upstreamSshSock)
        if (
          !stat.isSymbolicLink() &&
          stat.isSocket() &&
          (typeof process.getuid !== "function" || stat.uid === uid)
        ) {
          const proxySock = await this.ensureSshAgentProxy(upstreamSshSock, command)
          env.SSH_AUTH_SOCK = proxySock
        }
      } catch {
        // Keep original SSH_AUTH_SOCK if validation or proxy creation fails
      }
    }
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
