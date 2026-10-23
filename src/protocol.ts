import { chmodSync, existsSync, lstatSync, readFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"

export type RequestKind = "pin" | "touch"

export type SshFingerprint = `SHA256:${string}`

export type KnownSshSecurityKeyType = "ED25519-SK" | "ECDSA-SK"
export type KnownSshStandardKeyType = "ED25519" | "RSA" | "ECDSA"
export type KnownSshKeyType = KnownSshSecurityKeyType | KnownSshStandardKeyType
export type SshKeyType = KnownSshKeyType | (string & {})

export type AskpassClassification =
  | {
      readonly kind: "touch"
      readonly type: "touch"
      readonly title: string
      readonly description: string
      readonly prompt: string
      readonly keyType?: SshKeyType
      readonly fingerprint?: SshFingerprint
    }
  | {
      readonly kind: "pin"
      readonly type: "pin"
      readonly title: string
      readonly description: string
      readonly prompt: string
      readonly keyType?: SshKeyType
      readonly fingerprint?: SshFingerprint
    }

export interface IpcTargetResolution {
  readonly socketPath: string | undefined
  readonly token: string | undefined
  readonly command: string | undefined
}

export type SecurePathKind = "dir" | "file" | "socket"

/**
 * Encodes values for Assuan `D <data>` lines.
 * In Assuan data lines, `%`, `\r`, `\n`, and control characters are percent-escaped.
 */
export function encodeAssuanData(input: string): string {
  const bytes = new TextEncoder().encode(input)
  let out = ""
  for (const byte of bytes) {
    if (byte === 0x25 || byte === 0x0d || byte === 0x0a || byte < 0x20 || byte >= 0x7f) {
      out += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`
    } else {
      out += String.fromCharCode(byte)
    }
  }
  return out
}

/**
 * Decodes Assuan percent-escaped strings (e.g. %0A, %25, %22, and multi-byte UTF-8 sequences).
 */
export function parseAssuanData(input: string): string {
  if (!input || !input.includes("%")) return input || ""
  const bytes: number[] = []
  const encoder = new TextEncoder()
  for (let i = 0; i < input.length; ) {
    if (input[i] === "%" && i + 2 < input.length) {
      const hex = input.slice(i + 1, i + 3)
      if (/^[0-9a-fA-F]{2}$/.test(hex)) {
        bytes.push(Number.parseInt(hex, 16))
        i += 3
        continue
      }
    }
    const codePoint = input.codePointAt(i)
    if (codePoint === undefined) break
    const char = String.fromCodePoint(codePoint)
    const encoded = encoder.encode(char)
    for (const b of encoded) bytes.push(b)
    i += char.length
  }
  return new TextDecoder().decode(new Uint8Array(bytes))
}

export { encodeAssuanData as assuanPercentEncode, parseAssuanData as assuanPercentDecode }

const PIN_PROMPT_RE = /\b(enter\s+pin|enter\s+passphrase|passphrase\s+for|pin\s+for|password)\b/i
const TOUCH_PROMPT_RE =
  /\b(confirm\s+user\s+presence|touch|presence|security\s+key|allow\s+use\s+of\s+key)\b/i
const KEY_TYPE_RE = /\b((?:ED25519|ECDSA)-SK|RSA|ED25519|ECDSA)\b/i
const FINGERPRINT_RE = /\b(SHA256:[A-Za-z0-9+/=_-]+)\b/

export function parseOptionalInt(raw: string | undefined): number | undefined {
  const parsed = Number.parseInt(raw ?? "", 10)
  return Number.isNaN(parsed) ? undefined : parsed
}

export function isSshFingerprint(value: string): value is SshFingerprint {
  return value.startsWith("SHA256:") && value.length > "SHA256:".length
}

export function sanitizeDisplayText(input: string | undefined, maxLen = 240): string | undefined {
  if (input === undefined) return undefined
  let out = ""
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i)
    const isControl =
      (code >= 0x00 && code <= 0x08) ||
      (code >= 0x0b && code <= 0x1f) ||
      (code >= 0x7f && code <= 0x9f)
    const isBidi = (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069)
    if (!isControl && !isBidi) {
      out += input[i]
    }
  }
  const cleaned = out.trim()
  if (!cleaned) return undefined
  return cleaned.length > maxLen ? `${cleaned.slice(0, maxLen - 3)}...` : cleaned
}

export function classifyAskpassPrompt(rawPrompt: string): AskpassClassification {
  const text = (rawPrompt || "").trim()
  const rawKeyType = text.match(KEY_TYPE_RE)?.[1]?.toUpperCase()
  const rawFpr = text.match(FINGERPRINT_RE)?.[1]
  const fingerprint = rawFpr && isSshFingerprint(rawFpr) ? rawFpr : undefined

  const isPin = PIN_PROMPT_RE.test(text)
  const isTouch = !isPin && (TOUCH_PROMPT_RE.test(text) || Boolean(rawKeyType?.endsWith("-SK")))

  if (isTouch) {
    return {
      kind: "touch",
      type: "touch",
      title: "Touch Your YubiKey",
      description: text || "Confirm user presence on your YubiKey to continue.",
      prompt: "Touch YubiKey",
      ...(rawKeyType ? { keyType: rawKeyType } : {}),
      ...(fingerprint ? { fingerprint } : {}),
    }
  }

  return {
    kind: "pin",
    type: "pin",
    title: rawKeyType ? `YubiKey ${rawKeyType} PIN` : "YubiKey / SSH PIN Entry",
    description: text || "Enter your PIN to continue.",
    prompt: "PIN:",
    ...(rawKeyType ? { keyType: rawKeyType } : {}),
    ...(fingerprint ? { fingerprint } : {}),
  }
}

export function getRuntimeSocketDirPath(): string {
  const uid = typeof process.getuid === "function" ? process.getuid() : 0
  const base = existsSync("/tmp") ? "/tmp" : os.tmpdir()
  return path.join(base, `oc-yk-${uid}`)
}

export function isSecureOwnedPath(targetPath: string, expectType: SecurePathKind): boolean {
  try {
    const uid = typeof process.getuid === "function" ? process.getuid() : 0
    const stat = lstatSync(targetPath)
    if (stat.isSymbolicLink()) return false
    if (typeof process.getuid === "function" && stat.uid !== uid) return false
    if ((stat.mode & 0o077) !== 0) return false
    switch (expectType) {
      case "dir":
        return stat.isDirectory()
      case "file":
        return stat.isFile()
      case "socket":
        return stat.isSocket()
    }
  } catch {
    return false
  }
}

export function verifySecureSocketDir(dir: string): void {
  const uid = typeof process.getuid === "function" ? process.getuid() : 0
  const stat = lstatSync(dir)
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(`Refusing to use non-directory or symlink socket path: ${dir}`)
  }
  if (typeof process.getuid === "function" && stat.uid !== uid) {
    throw new Error(
      `Refusing to use socket directory owned by uid ${stat.uid} (expected ${uid}): ${dir}`,
    )
  }
  if ((stat.mode & 0o077) !== 0) {
    chmodSync(dir, 0o700)
    const recheck = lstatSync(dir)
    if ((recheck.mode & 0o077) !== 0) {
      throw new Error(
        `Socket directory ${dir} has insecure permissions: ${(recheck.mode & 0o777).toString(8)}`,
      )
    }
  }
}

export function parseJsonObject(
  raw: string | undefined,
): Readonly<Record<string, unknown>> | undefined {
  if (!raw) return undefined
  try {
    const parsed: unknown = JSON.parse(raw)
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Readonly<Record<string, unknown>>)
      : undefined
  } catch {
    return undefined
  }
}

interface IpcTargetCandidate {
  readonly socketPath: string | undefined
  readonly token: string | undefined
  readonly command: string | undefined
}

function isLiveIpcSocket(socketPath: string): boolean {
  return (
    isSecureOwnedPath(path.dirname(socketPath), "dir") && isSecureOwnedPath(socketPath, "socket")
  )
}

function readActivePointerCandidate(pointerPath: string): IpcTargetCandidate {
  const dirPath = path.dirname(pointerPath)
  if (!isSecureOwnedPath(dirPath, "dir") || !isSecureOwnedPath(pointerPath, "file")) {
    return { socketPath: undefined, token: undefined, command: undefined }
  }
  try {
    const pointer = parseJsonObject(readFileSync(pointerPath, "utf8"))
    if (typeof pointer?.socketPath !== "string") {
      return { socketPath: undefined, token: undefined, command: undefined }
    }
    return {
      socketPath: pointer.socketPath,
      token: typeof pointer.token === "string" ? pointer.token : undefined,
      command: undefined,
    }
  } catch {
    return { socketPath: undefined, token: undefined, command: undefined }
  }
}

/**
 * Resolves the plugin instance the pinentry shim has to talk to.
 *
 * The socket and the token identify one instance, so they are never taken from
 * different candidates.
 *
 * `PINENTRY_USER_DATA` is the value gpg-agent hands to the pinentry program it
 * launches, derived from the command that triggered the prompt, so it names the
 * instance that owns that command. The ambient `OC_YUBIKEY_*` variables are
 * inherited by the gpg-agent process from the shell that started it and can name
 * an instance that is gone, so they only serve as a fallback. The `active.json`
 * pointer names the most recently started instance.
 */
export function resolveIpcTarget(
  env: Readonly<Record<string, string | undefined>> = process.env,
  pointerPath: string = path.join(getRuntimeSocketDirPath(), "active.json"),
): IpcTargetResolution {
  const userData = parseJsonObject(env.PINENTRY_USER_DATA)
  const candidates: readonly IpcTargetCandidate[] = [
    {
      socketPath: typeof userData?.sock === "string" ? userData.sock : undefined,
      token: typeof userData?.token === "string" ? userData.token : undefined,
      command: typeof userData?.cmd === "string" ? userData.cmd : undefined,
    },
    {
      socketPath: env.OC_YUBIKEY_SOCK,
      token: env.OC_YUBIKEY_TOKEN,
      command: env.OC_YUBIKEY_COMMAND,
    },
    readActivePointerCandidate(pointerPath),
  ]

  for (const candidate of candidates) {
    if (!candidate.socketPath || !candidate.token) continue
    if (!isLiveIpcSocket(candidate.socketPath)) continue
    return {
      socketPath: candidate.socketPath,
      token: candidate.token,
      command: candidate.command ?? env.OC_YUBIKEY_COMMAND,
    }
  }

  return { socketPath: undefined, token: undefined, command: env.OC_YUBIKEY_COMMAND }
}

export interface LocationIdentity {
  readonly directory?: string
  readonly workspaceID?: string
}

export function isMatchingLocation(
  eventLocation: LocationIdentity | undefined,
  activeLocation: LocationIdentity | undefined,
): boolean {
  if (!eventLocation?.directory || !activeLocation?.directory) return false
  if (path.resolve(eventLocation.directory) !== path.resolve(activeLocation.directory)) {
    return false
  }
  if (
    eventLocation.workspaceID !== undefined &&
    activeLocation.workspaceID !== undefined &&
    eventLocation.workspaceID !== activeLocation.workspaceID
  ) {
    return false
  }
  return true
}
