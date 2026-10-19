import { spawn } from "node:child_process"
import { existsSync, lstatSync, realpathSync } from "node:fs"
import net from "node:net"
import os from "node:os"
import path from "node:path"
import {
  assuanPercentDecode,
  assuanPercentEncode,
  encodeAssuanData,
  parseAssuanData,
} from "./protocol.js"
import type { YubiKeyCardStatus } from "./rpc.js"

export { assuanPercentDecode, assuanPercentEncode, encodeAssuanData, parseAssuanData }

const MAX_EXEC_OUTPUT_BYTES = 256 * 1024
const MAX_ASSUAN_BUFFER_BYTES = 64 * 1024
const MAX_ASSUAN_LINES = 512

const TRUSTED_BIN_DIRS = [
  "/opt/homebrew/bin",
  "/usr/local/MacGPG2/bin",
  "/usr/local/bin",
  "/usr/bin",
  "/bin",
]

export function resolveTrustedExecutable(command: string): string {
  if (path.isAbsolute(command)) return command
  const uid = typeof process.getuid === "function" ? process.getuid() : 0
  for (const dir of TRUSTED_BIN_DIRS) {
    const candidate = path.join(dir, command)
    try {
      if (!existsSync(candidate)) continue
      const resolved = realpathSync(candidate)
      const stat = lstatSync(resolved)
      if (
        stat.isFile() &&
        (typeof process.getuid !== "function" || stat.uid === 0 || stat.uid === uid) &&
        (stat.mode & 0o002) === 0
      ) {
        return resolved
      }
    } catch {
      // Try next candidate directory
    }
  }
  return command
}

export interface ExecResult {
  readonly code: number
  readonly stdout: string
  readonly stderr: string
}

export interface AssuanCommandResponse {
  readonly ok: boolean
  readonly dataLines: ReadonlyArray<string>
  readonly statusLines: ReadonlyArray<string>
  readonly error?: string
  readonly errorCode?: number
}

export interface VerifyPinResult {
  readonly ok: boolean
  readonly aid?: string
  readonly message: string
  readonly error?: string
  readonly badPin?: boolean
}

export function execCommand(
  command: string,
  args: ReadonlyArray<string>,
  options: {
    env?: Record<string, string | undefined>
    timeoutMs?: number
    signal?: AbortSignal
  } = {},
): Promise<ExecResult> {
  return new Promise<ExecResult>((resolve) => {
    if (options.signal?.aborted) {
      resolve({ code: 130, stdout: "", stderr: "Aborted" })
      return
    }

    const resolvedCommand = resolveTrustedExecutable(command)
    const child = spawn(resolvedCommand, [...args], {
      env: {
        ...process.env,
        ...options.env,
        PATH: `${TRUSTED_BIN_DIRS.join(":")}:${process.env.PATH ?? ""}`,
      },
      stdio: ["ignore", "pipe", "pipe"],
    })

    let stdout = ""
    let stderr = ""
    let settled = false
    let killTimer: ReturnType<typeof setTimeout> | undefined

    const finish = (code: number) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (killTimer) clearTimeout(killTimer)
      options.signal?.removeEventListener("abort", onAbort)
      resolve({ code, stdout, stderr })
    }

    const terminateChild = (exitCode: number) => {
      child.kill("SIGTERM")
      killTimer = setTimeout(() => {
        try {
          child.kill("SIGKILL")
        } catch {
          // Ignore kill errors after process exit
        }
      }, 1_000)
      finish(exitCode)
    }

    const onAbort = () => terminateChild(130)
    options.signal?.addEventListener("abort", onAbort, { once: true })

    const timer = setTimeout(() => terminateChild(124), options.timeoutMs ?? 15_000)

    child.stdout.on("data", (chunk: Buffer | string) => {
      if (settled || stdout.length >= MAX_EXEC_OUTPUT_BYTES) return
      stdout += typeof chunk === "string" ? chunk : chunk.toString("utf8")
    })

    child.stderr.on("data", (chunk: Buffer | string) => {
      if (settled || stderr.length >= MAX_EXEC_OUTPUT_BYTES) return
      stderr += typeof chunk === "string" ? chunk : chunk.toString("utf8")
    })

    child.on("error", (err) => {
      stderr += err.message
      finish(127)
    })

    child.on("close", (code) => {
      finish(code ?? 1)
    })
  })
}

export async function resolveGpgAgentSocketPath(options?: {
  socketPath?: string
  signal?: AbortSignal
}): Promise<string> {
  if (options?.socketPath) return options.socketPath
  if (process.env.OC_GPG_AGENT_SOCK) return process.env.OC_GPG_AGENT_SOCK

  const res = await execCommand("gpgconf", ["--list-dirs", "agent-socket"], {
    timeoutMs: 5_000,
    signal: options?.signal,
  })
  const candidate = res.stdout.trim().split(/\r?\n/)[0]?.trim()
  if (res.code === 0 && candidate) {
    return candidate
  }

  return path.join(os.homedir(), ".gnupg", "S.gpg-agent")
}

function verifySocketOwnership(socketPath: string): void {
  const uid = typeof process.getuid === "function" ? process.getuid() : 0
  const stat = lstatSync(socketPath)
  if (stat.isSymbolicLink() || !stat.isSocket()) {
    throw new Error(`Refusing to connect to non-socket or symlink gpg-agent path: ${socketPath}`)
  }
  if (typeof process.getuid === "function" && stat.uid !== uid) {
    throw new Error(
      `Refusing to connect to gpg-agent socket owned by uid ${stat.uid} (expected ${uid})`,
    )
  }
}

/**
 * Direct in-process Assuan client connected to `gpg-agent`'s Unix domain socket.
 */
export class GpgAgentAssuanClient {
  private readonly socket: net.Socket
  private buffer = ""
  private lineQueue: string[] = []
  private lineWaiters: Array<{
    resolve: (line: string) => void
    reject: (error: Error) => void
  }> = []
  private closed = false
  private closeError?: Error
  private cleanupAbort?: () => void

  private constructor(socket: net.Socket, signal?: AbortSignal) {
    this.socket = socket

    if (signal) {
      const onAbort = () => {
        this.closeError = new Error("Operation aborted")
        this.destroy()
      }
      if (signal.aborted) {
        onAbort()
      } else {
        signal.addEventListener("abort", onAbort, { once: true })
        this.cleanupAbort = () => signal.removeEventListener("abort", onAbort)
      }
    }

    socket.on("data", (chunk: Buffer | string) => {
      this.buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8")
      if (this.buffer.length > MAX_ASSUAN_BUFFER_BYTES) {
        socket.destroy(new Error("gpg-agent Assuan line exceeded maximum buffer size"))
        return
      }
      let idx = this.buffer.indexOf("\n")
      while (idx !== -1) {
        const line = this.buffer.slice(0, idx).replace(/\r$/, "")
        this.buffer = this.buffer.slice(idx + 1)
        const waiter = this.lineWaiters.shift()
        if (waiter) {
          waiter.resolve(line)
        } else if (this.lineQueue.length < MAX_ASSUAN_LINES) {
          this.lineQueue.push(line)
        } else {
          socket.destroy(new Error("gpg-agent Assuan line queue overflow"))
          return
        }
        idx = this.buffer.indexOf("\n")
      }
    })

    socket.on("error", (err) => {
      this.closed = true
      this.closeError = err
      while (this.lineWaiters.length > 0) {
        this.lineWaiters.shift()?.reject(err)
      }
    })

    socket.on("close", () => {
      this.closed = true
      this.cleanupAbort?.()
      this.cleanupAbort = undefined
      const err = this.closeError ?? new Error("gpg-agent Assuan socket closed unexpectedly")
      while (this.lineWaiters.length > 0) {
        this.lineWaiters.shift()?.reject(err)
      }
    })
  }

  static async connect(
    socketPath: string,
    options: { timeoutMs?: number; signal?: AbortSignal } = {},
  ): Promise<GpgAgentAssuanClient> {
    if (options.signal?.aborted) {
      throw new Error("Operation aborted")
    }

    verifySocketOwnership(socketPath)

    const socket = await new Promise<net.Socket>((resolve, reject) => {
      const sock = net.createConnection({ path: socketPath })
      const timer = setTimeout(() => {
        sock.destroy()
        reject(new Error(`Timed out connecting to gpg-agent socket at ${socketPath}`))
      }, options.timeoutMs ?? 10_000)

      const onAbort = () => {
        clearTimeout(timer)
        sock.destroy()
        reject(new Error("Operation aborted"))
      }

      options.signal?.addEventListener("abort", onAbort, { once: true })

      sock.once("connect", () => {
        clearTimeout(timer)
        options.signal?.removeEventListener("abort", onAbort)
        resolve(sock)
      })

      sock.once("error", (err) => {
        clearTimeout(timer)
        options.signal?.removeEventListener("abort", onAbort)
        reject(err)
      })
    })

    const client = new GpgAgentAssuanClient(socket, options.signal)
    const greeting = await client.nextLine(options.timeoutMs ?? 10_000)
    if (!greeting.startsWith("OK")) {
      client.destroy()
      throw new Error(`Unexpected gpg-agent greeting: ${greeting}`)
    }
    return client
  }

  private nextLine(timeoutMs = 30_000): Promise<string> {
    if (this.lineQueue.length > 0) {
      return Promise.resolve(this.lineQueue.shift()!)
    }
    if (this.closed) {
      return Promise.reject(this.closeError ?? new Error("gpg-agent socket is closed"))
    }
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.lineWaiters.indexOf(entry)
        if (idx !== -1) this.lineWaiters.splice(idx, 1)
        reject(new Error("Timed out waiting for gpg-agent Assuan response"))
      }, timeoutMs)

      const entry = {
        resolve: (line: string) => {
          clearTimeout(timer)
          resolve(line)
        },
        reject: (err: Error) => {
          clearTimeout(timer)
          reject(err)
        },
      }
      this.lineWaiters.push(entry)
    })
  }

  private writeLine(line: string): void {
    if (/[\r\n\0]/.test(line)) {
      throw new Error("Invalid control character in Assuan command line")
    }
    this.socket.write(`${line}\n`)
  }

  async command(
    cmd: string,
    options: {
      onInquire?: (keyword: string) => string | undefined | Promise<string | undefined>
      timeoutMs?: number
    } = {},
  ): Promise<AssuanCommandResponse> {
    this.writeLine(cmd)
    const dataLines: string[] = []
    const statusLines: string[] = []

    while (true) {
      const line = await this.nextLine(options.timeoutMs ?? 30_000)
      if (line.startsWith("OK")) {
        return {
          ok: true,
          dataLines,
          statusLines,
        }
      }
      if (line.startsWith("ERR")) {
        const match = line.match(/^ERR\s+(\d+)\s*(.*)$/)
        const errorCode = match ? Number.parseInt(match[1], 10) : undefined
        const errorText = match?.[2]?.trim() || line
        return {
          ok: false,
          dataLines,
          statusLines,
          error: errorText,
          errorCode,
        }
      }
      if (line.startsWith("D ")) {
        if (dataLines.length < MAX_ASSUAN_LINES) {
          dataLines.push(parseAssuanData(line.slice(2)))
        }
        continue
      }
      if (line.startsWith("S ")) {
        if (statusLines.length < MAX_ASSUAN_LINES) {
          statusLines.push(line.slice(2).trim())
        }
        continue
      }
      if (line.startsWith("INQUIRE")) {
        const keyword = line.slice("INQUIRE".length).trim()
        if (!options.onInquire) {
          this.writeLine("CAN")
          continue
        }
        const value = await options.onInquire(keyword)
        if (value === undefined) {
          this.writeLine("CAN")
        } else {
          this.writeLine(`D ${encodeAssuanData(value)}`)
          this.writeLine("END")
        }
      }
    }
  }

  async close(): Promise<void> {
    if (this.closed) return
    try {
      await this.command("BYE", { timeoutMs: 2_000 })
    } catch {
      // Ignore error on closing
    } finally {
      this.destroy()
    }
  }

  destroy(): void {
    this.closed = true
    this.cleanupAbort?.()
    this.cleanupAbort = undefined
    const err = this.closeError ?? new Error("gpg-agent socket destroyed")
    while (this.lineWaiters.length > 0) {
      this.lineWaiters.shift()?.reject(err)
    }
    this.socket.destroy()
  }
}

function parseCleanAssuanError(rawError: string | undefined): { message: string; badPin: boolean } {
  if (!rawError) return { message: "Operation failed in gpg-agent", badPin: false }
  const cleaned = rawError.replace(/\s*<[^>]+>\s*$/, "").trim()
  const badPin = /bad pin|incorrect pin|wrong pin|pin blocked/i.test(cleaned)
  return { message: cleaned || rawError, badPin }
}

async function resolveCardAid(
  client: GpgAgentAssuanClient,
  providedAid?: string,
): Promise<{ aid?: string; error?: string; message?: string }> {
  if (providedAid) return { aid: providedAid }
  const serialRes = await client.command("SCD SERIALNO")
  if (!serialRes.ok) {
    const parsed = parseCleanAssuanError(serialRes.error)
    return {
      message: `No YubiKey OpenPGP smartcard detected (${parsed.message}).`,
      error: parsed.message,
    }
  }
  for (const status of serialRes.statusLines) {
    const match = status.match(/^SERIALNO\s+([0-9A-Fa-f]+)/)
    if (match) {
      return { aid: match[1] }
    }
  }
  return {}
}

async function sendPresetPassphrase(
  client: GpgAgentAssuanClient,
  keygrip: string,
  pin: string,
  ttlSeconds: number,
): Promise<AssuanCommandResponse> {
  const pinBuf = Buffer.from(pin, "utf8")
  try {
    const hexPin = pinBuf.toString("hex").toUpperCase()
    return await client.command(`PRESET_PASSPHRASE ${keygrip} ${ttlSeconds} ${hexPin}`)
  } finally {
    pinBuf.fill(0)
  }
}

/**
 * Unlocks the YubiKey OpenPGP card in `gpg-agent` / `scdaemon` using in-process Assuan
 * loopback mode (`OPTION pinentry-mode=loopback` -> `SCD SERIALNO` -> `SCD CHECKPIN <aid>`).
 */
export async function verifyYubiKeyPinLoopback(
  pin: string,
  options: {
    socketPath?: string
    aid?: string
    keygrip?: string
    signal?: AbortSignal
  } = {},
): Promise<VerifyPinResult> {
  const socketPath = await resolveGpgAgentSocketPath({
    socketPath: options.socketPath,
    signal: options.signal,
  })

  const client = await GpgAgentAssuanClient.connect(socketPath, {
    signal: options.signal,
  })

  try {
    const loopbackRes = await client.command("OPTION pinentry-mode=loopback")
    if (!loopbackRes.ok) {
      const parsed = parseCleanAssuanError(loopbackRes.error)
      return {
        ok: false,
        message: `gpg-agent rejected loopback pinentry mode: ${parsed.message}`,
        error: parsed.message,
      }
    }

    const aidLookup = await resolveCardAid(client, options.aid)
    if (aidLookup.error) {
      return {
        ok: false,
        message: aidLookup.message ?? aidLookup.error,
        error: aidLookup.error,
      }
    }

    const aid = aidLookup.aid
    if (!aid || !/^[0-9A-Fa-f]{16,64}$/.test(aid)) {
      return {
        ok: false,
        message: "Could not determine YubiKey OpenPGP Application ID (SERIALNO).",
        error: "Missing or invalid SERIALNO from scdaemon",
      }
    }

    const checkPinRes = await client.command(`SCD CHECKPIN ${aid}`, {
      onInquire: (keyword) => {
        if (keyword.startsWith("PASSPHRASE") || keyword.startsWith("PIN")) {
          return pin
        }
        return undefined
      },
    })

    if (!checkPinRes.ok) {
      const parsed = parseCleanAssuanError(checkPinRes.error)
      return {
        ok: false,
        aid,
        message: `YubiKey PIN verification failed: ${parsed.message}`,
        error: parsed.message,
        badPin: parsed.badPin,
      }
    }

    if (options.keygrip) {
      if (!/^[0-9A-Fa-f]{16,64}$/.test(options.keygrip)) {
        return {
          ok: false,
          aid,
          message: "Invalid keygrip format for PRESET_PASSPHRASE.",
          error: "Invalid keygrip",
        }
      }
      const presetRes = await sendPresetPassphrase(client, options.keygrip, pin, -1)
      if (!presetRes.ok) {
        const parsed = parseCleanAssuanError(presetRes.error)
        return {
          ok: false,
          aid,
          message: `PRESET_PASSPHRASE failed: ${parsed.message}`,
          error: parsed.message,
        }
      }
    }

    return {
      ok: true,
      aid,
      message: "YubiKey OpenPGP PIN verified and cached in gpg-agent.",
    }
  } finally {
    await client.close()
  }
}

export async function presetPassphraseInAgent(
  keygrip: string,
  pin: string,
  ttlSeconds = -1,
  options: { socketPath?: string; signal?: AbortSignal } = {},
): Promise<{ ok: boolean; message: string }> {
  if (!/^[0-9A-Fa-f]{16,64}$/.test(keygrip)) {
    return { ok: false, message: "Invalid keygrip format." }
  }
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < -1) {
    return { ok: false, message: "Invalid ttlSeconds value." }
  }
  const socketPath = await resolveGpgAgentSocketPath(options)
  const client = await GpgAgentAssuanClient.connect(socketPath, { signal: options.signal })
  try {
    const res = await sendPresetPassphrase(client, keygrip, pin, ttlSeconds)
    if (!res.ok) {
      const parsed = parseCleanAssuanError(res.error)
      return { ok: false, message: `PRESET_PASSPHRASE failed: ${parsed.message}` }
    }
    return { ok: true, message: `Cached passphrase for keygrip ${keygrip} in gpg-agent.` }
  } finally {
    await client.close()
  }
}

export async function lockYubiKey(options?: {
  socketPath?: string
  signal?: AbortSignal
}): Promise<{ ok: boolean; message: string }> {
  try {
    const socketPath = await resolveGpgAgentSocketPath(options)
    if (existsSync(socketPath)) {
      const client = await GpgAgentAssuanClient.connect(socketPath, {
        signal: options?.signal,
        timeoutMs: 5_000,
      })
      try {
        await client.command("SCD RESET")
        const reloadRes = await client.command("RELOADAGENT")
        if (reloadRes.ok) {
          return {
            ok: true,
            message: "Cleared cached YubiKey PIN in scdaemon and reloaded gpg-agent.",
          }
        }
      } finally {
        await client.close()
      }
    }
  } catch {
    // Fall back to gpg-connect-agent CLI if socket connection fails
  }

  const res = await execCommand("gpg-connect-agent", ["SCD RESET", "reloadagent", "/bye"], {
    timeoutMs: 10_000,
    signal: options?.signal,
  })
  if (res.code !== 0) {
    return {
      ok: false,
      message: res.stderr.trim() || "Failed to reset scdaemon / reload gpg-agent.",
    }
  }
  return {
    ok: true,
    message: "Cleared cached YubiKey PIN in scdaemon and reloaded gpg-agent.",
  }
}

export async function checkGpgAgentReady(options?: {
  socketPath?: string
  signal?: AbortSignal
}): Promise<boolean> {
  try {
    const socketPath = await resolveGpgAgentSocketPath(options)
    if (existsSync(socketPath)) {
      const client = await GpgAgentAssuanClient.connect(socketPath, {
        signal: options?.signal,
        timeoutMs: 3_000,
      })
      await client.close()
      return true
    }
  } catch {
    // Fall through to gpg-connect-agent check
  }

  const res = await execCommand("gpg-connect-agent", ["/bye"], {
    timeoutMs: 5_000,
    signal: options?.signal,
  })
  return res.code === 0 && res.stdout.includes("OK")
}

interface MutableCardStatus {
  reader?: string
  applicationID?: string
  serial?: string
  model?: string
  version?: string
  holder?: string
  signatureCount?: number
  pinRetries?: { user: number; reset: number; admin: number }
  uif?: { sign: string; decrypt: string; auth: string }
  sigKey?: string
  encKey?: string
  authKey?: string
}

function parsePinRetriesTriple(
  raw: string,
): { user: number; reset: number; admin: number } | undefined {
  const parts = raw
    .trim()
    .split(/\s+/)
    .map((n) => Number.parseInt(n, 10))
  if (parts.length < 3 || parts.some((n) => Number.isNaN(n))) return undefined
  return { user: parts[0], reset: parts[1], admin: parts[2] }
}

function parseUifValue(raw: string): { sign: string; decrypt: string; auth: string } | undefined {
  const signMatch = raw.match(/Sign=([^\s]+)/i)
  const decryptMatch = raw.match(/Decrypt=([^\s]+)/i)
  const authMatch = raw.match(/Auth=([^\s]+)/i)
  if (!signMatch && !decryptMatch && !authMatch) return undefined
  return {
    sign: (signMatch?.[1] ?? "off").toLowerCase(),
    decrypt: (decryptMatch?.[1] ?? "off").toLowerCase(),
    auth: (authMatch?.[1] ?? "off").toLowerCase(),
  }
}

function normalizeHolderName(raw: string): string {
  return raw.replace(/<+/g, " ").trim()
}

const HUMAN_CARD_FIELD_HANDLERS: Readonly<
  Record<string, (state: MutableCardStatus, val: string) => void>
> = {
  reader: (s, v) => {
    s.reader = v
  },
  "application id": (s, v) => {
    s.applicationID = v
  },
  manufacturer: (s, v) => {
    s.model = v
  },
  version: (s, v) => {
    s.version = v
  },
  "serial number": (s, v) => {
    s.serial = v
  },
  "name of cardholder": (s, v) => {
    s.holder = normalizeHolderName(v)
  },
  "pin retry counter": (s, v) => {
    s.pinRetries = parsePinRetriesTriple(v) ?? s.pinRetries
  },
  "uif setting": (s, v) => {
    s.uif = parseUifValue(v) ?? s.uif
  },
  "signature counter": (s, v) => {
    const parsed = Number.parseInt(v, 10)
    if (!Number.isNaN(parsed)) s.signatureCount = parsed
  },
  "signature key": (s, v) => {
    s.sigKey = v.replace(/\s+/g, "")
  },
  "encryption key": (s, v) => {
    s.encKey = v.replace(/\s+/g, "")
  },
  "authentication key": (s, v) => {
    s.authKey = v.replace(/\s+/g, "")
  },
}

const COLON_CARD_FIELD_HANDLERS: Readonly<
  Record<string, (state: MutableCardStatus, first: string) => void>
> = {
  reader: (s, v) => {
    s.reader ??= v
  },
  aid: (s, v) => {
    s.applicationID ??= v
  },
  serial: (s, v) => {
    s.serial ??= v
  },
  "disp-name": (s, v) => {
    s.holder ??= normalizeHolderName(v)
  },
  pinretry: (s, v) => {
    s.pinRetries ??= parsePinRetriesTriple(v)
  },
  sigcnt: (s, v) => {
    const parsed = Number.parseInt(v, 10)
    if (!Number.isNaN(parsed)) s.signatureCount ??= parsed
  },
}

function applyColonCardLine(state: MutableCardStatus, cols: readonly string[]): void {
  const tag = cols[0]?.toLowerCase()
  if (!tag) return
  if (tag === "fpr") {
    state.sigKey ??= cols[1] || undefined
    state.encKey ??= cols[2] || undefined
    state.authKey ??= cols[3] || undefined
    return
  }
  const first = cols[1]
  if (first) {
    COLON_CARD_FIELD_HANDLERS[tag]?.(state, first)
  }
}

export function parseCardStatusOutput(raw: string): YubiKeyCardStatus {
  const lines = raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)

  if (lines.length === 0) return { connected: false }

  const state: MutableCardStatus = {}

  for (const line of lines) {
    const kvMatch = line.match(/^([A-Za-z ]+?)\s*\.*:\s*(.+)$/)
    if (kvMatch) {
      const key = kvMatch[1].trim().toLowerCase()
      const value = kvMatch[2].trim()
      if (value && value !== "[not set]" && value !== "[none]") {
        HUMAN_CARD_FIELD_HANDLERS[key]?.(state, value)
      }
      continue
    }
    if (line.includes(":")) {
      applyColonCardLine(state, line.split(":"))
    }
  }

  if (!state.serial && state.applicationID && state.applicationID.length >= 28) {
    state.serial = state.applicationID.slice(20, 28)
  }

  if (!state.reader && !state.applicationID && !state.serial && !state.pinRetries) {
    return { connected: false }
  }

  const keys =
    state.sigKey || state.encKey || state.authKey
      ? {
          ...(state.sigKey !== undefined ? { signature: state.sigKey } : {}),
          ...(state.encKey !== undefined ? { encryption: state.encKey } : {}),
          ...(state.authKey !== undefined ? { authentication: state.authKey } : {}),
        }
      : undefined

  return {
    connected: true,
    ...(state.reader !== undefined ? { reader: state.reader } : {}),
    ...(state.serial !== undefined ? { serial: state.serial } : {}),
    ...(state.applicationID !== undefined ? { applicationID: state.applicationID } : {}),
    ...(state.model !== undefined ? { model: state.model } : {}),
    ...(state.version !== undefined ? { version: state.version } : {}),
    ...(state.holder !== undefined ? { holder: state.holder } : {}),
    ...(state.signatureCount !== undefined ? { signatureCount: state.signatureCount } : {}),
    ...(state.pinRetries !== undefined ? { pinRetries: state.pinRetries } : {}),
    ...(state.uif !== undefined ? { uif: state.uif } : {}),
    ...(keys !== undefined ? { keys } : {}),
  }
}

export async function getYubiKeyCardStatus(options?: {
  signal?: AbortSignal
}): Promise<YubiKeyCardStatus> {
  const res = await execCommand("gpg", ["--card-status"], {
    timeoutMs: 10_000,
    signal: options?.signal,
  })
  if (res.code !== 0 && !res.stdout.trim()) {
    return { connected: false }
  }
  const parsed = parseCardStatusOutput(res.stdout)
  if (parsed.connected) {
    return parsed
  }

  const colonsRes = await execCommand("gpg", ["--with-colons", "--card-status"], {
    timeoutMs: 10_000,
    signal: options?.signal,
  })
  return parseCardStatusOutput(colonsRes.stdout)
}
