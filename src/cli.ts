import { spawn } from "node:child_process"
import { existsSync, lstatSync, realpathSync } from "node:fs"
import net from "node:net"
import path from "node:path"
import { fileURLToPath } from "node:url"
import {
  classifyAskpassPrompt,
  encodeAssuanData,
  getRuntimeSocketDirPath,
  isSecureOwnedPath,
  parseAssuanData,
  parseOptionalInt,
  resolveIpcTarget,
} from "./protocol.ts"

const MAX_IPC_BUFFER_BYTES = 64 * 1024
const MAX_ASSUAN_LINE_BYTES = 16 * 1024
const MAX_ASSUAN_QUEUE_LEN = 128

interface CliIpcRequestPayload {
  readonly token: string
  readonly type: "touch" | "pin"
  readonly title?: string
  readonly description?: string
  readonly prompt?: string
  readonly error?: string
  readonly keyType?: string
  readonly fingerprint?: string
  readonly command?: string
}

interface CliIpcResponsePayload {
  readonly ok: boolean
  readonly cancelled: boolean
  readonly confirmed?: boolean
  readonly pin?: string
}

interface ActiveIpcHandle {
  readonly promise: Promise<CliIpcResponsePayload>
  close(): void
}

function sendIpcRequest(socketPath: string, payload: CliIpcRequestPayload): ActiveIpcHandle {
  let activeSocket: net.Socket | undefined
  const promise = new Promise<CliIpcResponsePayload>((resolve, reject) => {
    const socket = net.createConnection({ path: socketPath })
    activeSocket = socket
    let buffer = ""

    socket.once("connect", () => {
      socket.write(`${JSON.stringify(payload)}\n`)
    })

    socket.on("data", (chunk: Buffer | string) => {
      buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8")
      if (buffer.length > MAX_IPC_BUFFER_BYTES) {
        socket.destroy(new Error("IPC response exceeded maximum buffer size"))
        return
      }
      const idx = buffer.indexOf("\n")
      if (idx !== -1) {
        const line = buffer.slice(0, idx).trim()
        try {
          resolve(JSON.parse(line) as CliIpcResponsePayload)
        } catch (err) {
          reject(err instanceof Error ? err : new Error(String(err)))
        }
        socket.destroy()
      }
    })

    socket.once("error", reject)
    socket.once("close", () => {
      if (!buffer.includes("\n")) {
        resolve({ ok: false, cancelled: true })
      }
    })
  })

  return {
    promise,
    close() {
      if (activeSocket && !activeSocket.destroyed) {
        activeSocket.destroy()
      }
    },
  }
}

function registerSignalCleanup(onTerminate: () => void): void {
  process.on("SIGTERM", onTerminate)
  process.on("SIGINT", onTerminate)
  process.on("SIGHUP", onTerminate)
}

async function runAskpassMode(promptArg: string): Promise<void> {
  const { socketPath, token, command } = resolveIpcTarget()
  if (!socketPath || !token || !existsSync(socketPath)) {
    process.exit(1)
  }

  const classified = classifyAskpassPrompt(promptArg)
  const req = sendIpcRequest(socketPath, {
    ...classified,
    token,
    ...(command ? { command } : {}),
  })

  registerSignalCleanup(() => {
    req.close()
    process.exit(0)
  })

  try {
    const res = await req.promise
    if (classified.type === "touch") {
      process.exit(res.cancelled ? 1 : 0)
    }
    if (!res.ok || res.cancelled || typeof res.pin !== "string") {
      process.exit(1)
    }
    process.stdout.write(`${res.pin}\n`)
    process.exit(0)
  } catch {
    process.exit(1)
  }
}

function isSafeFallbackExecutable(binPath: string, selfPaths: ReadonlySet<string>): boolean {
  try {
    if (!path.isAbsolute(binPath) || !existsSync(binPath)) return false
    const resolved = realpathSync(binPath)
    if (selfPaths.has(resolved)) return false
    const uid = typeof process.getuid === "function" ? process.getuid() : 0
    const stat = lstatSync(resolved)
    if (!stat.isFile()) return false
    if (typeof process.getuid === "function" && stat.uid !== 0 && stat.uid !== uid) return false
    if ((stat.mode & 0o002) !== 0) return false
    return true
  } catch {
    return false
  }
}

import type { ReadableStream, WritableStream } from "node:stream"

function collectSelfPaths(): Set<string> {
  const cliFile = fileURLToPath(import.meta.url)
  const binDir = path.resolve(path.dirname(cliFile), "..", "bin")
  const candidates = [
    cliFile,
    path.join(binDir, "oc-yubikey"),
    path.join(binDir, "oc-yubikey-gpg"),
    path.join(binDir, "oc-yubikey-ssh"),
  ]
  const selfPaths = new Set<string>()
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      selfPaths.add(realpathSync(candidate))
    }
  }
  return selfPaths
}

function spawnFallbackPinentry(args: readonly string[]): boolean {
  if (process.env.OC_YUBIKEY_FALLBACK_ACTIVE === "1") {
    return false
  }

  const selfPaths = collectSelfPaths()

  const candidates = [
    process.env.OC_FALLBACK_PINENTRY,
    "/opt/homebrew/bin/pinentry-mac",
    "/usr/local/bin/pinentry-mac",
    "/usr/local/MacGPG2/libexec/pinentry-mac.app/Contents/MacOS/pinentry-mac",
    "/opt/homebrew/bin/pinentry",
    "/usr/local/bin/pinentry",
  ].filter((item): item is string => Boolean(item))

  for (const bin of candidates) {
    if (isSafeFallbackExecutable(bin, selfPaths)) {
      const child = spawn(bin, [...args], {
        stdio: "inherit",
        env: { ...process.env, OC_YUBIKEY_FALLBACK_ACTIVE: "1" },
      })
      child.on("exit", (code) => process.exit(code ?? 0))
      child.on("error", () => process.exit(1))
      return true
    }
  }
  return false
}

function resolveRealGpgExecutable(): string {
  const selfPaths = collectSelfPaths()
  const candidates = [
    process.env.OC_YUBIKEY_GPG_BIN,
    "/opt/homebrew/bin/gpg",
    "/usr/local/MacGPG2/bin/gpg",
    "/usr/local/bin/gpg",
    "/usr/bin/gpg",
  ].filter((item): item is string => Boolean(item))

  for (const bin of candidates) {
    if (isSafeFallbackExecutable(bin, selfPaths)) {
      return realpathSync(bin)
    }
  }
  return "gpg"
}

const SSH_MUX_SKIP_FLAGS = new Set<string>(["-V", "-G", "-Q", "-O", "-W", "-M", "-S"])
const SSH_CONTROL_OPT_PREFIX = /^control(?:master|path|persist)(?:=|\s)/i

function hasExplicitSshControlOption(args: readonly string[]): boolean {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    if (!arg || arg === "--") break
    if (SSH_MUX_SKIP_FLAGS.has(arg)) return true
    if (arg === "-o") {
      const next = args[i + 1] ?? ""
      if (SSH_CONTROL_OPT_PREFIX.test(next.trim())) return true
      i += 1
      continue
    }
    if (arg.startsWith("-o") && SSH_CONTROL_OPT_PREFIX.test(arg.slice(2).trim())) {
      return true
    }
  }
  return false
}

function resolveSshControlPath(socketPath: string | undefined): string | undefined {
  if (process.env.OC_YUBIKEY_SSH_MUX === "0") return undefined
  const muxDir =
    process.env.OC_YUBIKEY_MUX_DIR ||
    (socketPath ? path.dirname(socketPath) : getRuntimeSocketDirPath())
  if (!isSecureOwnedPath(muxDir, "dir")) return undefined
  const controlPath = path.join(muxDir, "m-%C")
  if (controlPath.length + 58 >= 104) return undefined
  return controlPath
}

function resolveAskpassSelfScript(): string {
  const cliFile = fileURLToPath(import.meta.url)
  return path.resolve(path.dirname(cliFile), "..", "bin", "oc-yubikey")
}

function runSshWrapperMode(args: readonly string[]): void {
  const selfPaths = collectSelfPaths()
  const sshBin =
    [
      process.env.OC_YUBIKEY_SSH_BIN,
      "/opt/homebrew/bin/ssh",
      "/usr/local/bin/ssh",
      "/usr/bin/ssh",
    ].find(
      (bin): bin is string => typeof bin === "string" && isSafeFallbackExecutable(bin, selfPaths),
    ) ?? "ssh"
  const { socketPath, token, command } = resolveIpcTarget()
  const childEnv: Record<string, string | undefined> = { ...process.env }

  if (socketPath && token && existsSync(socketPath)) {
    const effectiveCmd = command || `ssh ${args.join(" ")}`.slice(0, 80)
    childEnv.OC_YUBIKEY_SOCK = socketPath
    childEnv.OC_YUBIKEY_TOKEN = token
    childEnv.OC_YUBIKEY_COMMAND = effectiveCmd
    childEnv.PINENTRY_USER_DATA = JSON.stringify({
      sock: socketPath,
      token,
      cmd: effectiveCmd,
    })
    const askpassScript = resolveAskpassSelfScript()
    if (!childEnv.SSH_ASKPASS && existsSync(askpassScript)) {
      childEnv.SSH_ASKPASS = askpassScript
    }
    if (!childEnv.SSH_ASKPASS_REQUIRE) {
      childEnv.SSH_ASKPASS_REQUIRE = "force"
    }
    if (!childEnv.DISPLAY) {
      childEnv.DISPLAY = "oc-yubikey:0"
    }
  }
  delete childEnv.OC_YUBIKEY_MODE

  const controlPath = hasExplicitSshControlOption(args)
    ? undefined
    : resolveSshControlPath(socketPath)
  const persistSeconds = parseOptionalInt(process.env.OC_YUBIKEY_SSH_CONTROL_PERSIST) ?? 600
  const sshArgs = controlPath
    ? [
        "-o",
        "ControlMaster=auto",
        "-o",
        `ControlPersist=${persistSeconds}`,
        "-o",
        `ControlPath=${controlPath}`,
        ...args,
      ]
    : [...args]

  const child = spawn(sshBin, sshArgs, { stdio: "inherit", env: childEnv })
  registerSignalCleanup(() => {
    child.kill("SIGTERM")
  })
  child.on("exit", (code) => {
    process.exit(code ?? 0)
  })
  child.on("error", () => process.exit(255))
}

const PASSPHRASE_INPUT_FLAGS = new Set<string>([
  "--command-fd",
  "--passphrase-fd",
  "--passphrase",
  "--passphrase-file",
])

function isPassphraseInputFlag(arg: string): boolean {
  const eqIdx = arg.indexOf("=")
  const flag = eqIdx === -1 ? arg : arg.slice(0, eqIdx)
  return PASSPHRASE_INPUT_FLAGS.has(flag)
}

const GPG_SIGN_FLAGS = new Set<string>(["-s", "--sign", "-b", "--detach-sign", "--clearsign"])

interface InspectedGpgArgs {
  readonly hasCustomPassphraseInput: boolean
  readonly hasPinentryMode: boolean
  readonly isSigning: boolean
  readonly callerStatusFd: number | undefined
}

function inspectGpgWrapperArgs(args: readonly string[]): InspectedGpgArgs {
  let hasCustomPassphraseInput = false
  let hasPinentryMode = false
  let isSigning = false
  let callerStatusFd: number | undefined

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    if (!arg || arg === "--") break
    if (isPassphraseInputFlag(arg)) {
      hasCustomPassphraseInput = true
    } else if (arg === "--pinentry-mode" || arg.startsWith("--pinentry-mode=")) {
      hasPinentryMode = true
    } else if (GPG_SIGN_FLAGS.has(arg) || (/^-[A-Za-z]+$/.test(arg) && /[sb]/.test(arg))) {
      isSigning = true
    } else if (arg === "--status-fd") {
      callerStatusFd = parseOptionalInt(args[i + 1]) ?? callerStatusFd
      i += 1
    } else if (arg.startsWith("--status-fd=")) {
      callerStatusFd = parseOptionalInt(arg.slice("--status-fd=".length)) ?? callerStatusFd
    }
  }

  return { hasCustomPassphraseInput, hasPinentryMode, isSigning, callerStatusFd }
}

function buildWrappedGpgArgs(
  args: readonly string[],
  inspected: InspectedGpgArgs,
  useDedicatedStatusPipe: boolean,
): string[] {
  const gpgArgs: string[] = []
  if (!inspected.hasPinentryMode) {
    gpgArgs.push("--pinentry-mode", "loopback")
  }
  gpgArgs.push("--command-fd", "3")
  if (useDedicatedStatusPipe) {
    gpgArgs.push("--status-fd", "4")
  }
  gpgArgs.push(...args)
  return gpgArgs
}

interface GpgStatusMonitorOptions {
  readonly socketPath: string
  readonly token: string
  readonly command: string | undefined
  readonly isSigning: boolean
  readonly commandStream: WritableStream | undefined
  readonly onActiveRequest: (req: ActiveIpcHandle | null) => void
  readonly onCancelTouch: () => void
}

interface GpgStatusMonitorHandle {
  readonly onChunk: (chunk: Buffer | string) => void
  readonly dispose: () => void
}

async function promptGpgLoopbackPin(
  options: GpgStatusMonitorOptions,
  userIdHint: string | undefined,
  error: string | undefined,
): Promise<boolean> {
  const req = sendIpcRequest(options.socketPath, {
    token: options.token,
    type: "pin",
    title: "YubiKey PIN Entry",
    description: userIdHint
      ? `Enter your YubiKey OpenPGP PIN for ${userIdHint}`
      : "Enter your YubiKey OpenPGP PIN to sign",
    prompt: "PIN:",
    ...(error ? { error } : {}),
    ...(options.command ? { command: options.command } : {}),
  })
  options.onActiveRequest(req)

  const res = await req.promise.catch(
    (): CliIpcResponsePayload => ({ ok: false, cancelled: true }),
  )
  options.onActiveRequest(null)
  if (res.ok && !res.cancelled && typeof res.pin === "string") {
    options.commandStream?.write(`${res.pin}\n`)
    return true
  }
  options.commandStream?.write("\x04\n")
  options.commandStream?.end()
  return false
}

function createGpgStatusMonitor(options: GpgStatusMonitorOptions): GpgStatusMonitorHandle {
  let statusBuffer = ""
  let userIdHint: string | undefined
  let lastError: string | undefined
  let pinInFlight = false
  let sigCompleted = false
  let touchTimer: ReturnType<typeof setTimeout> | undefined
  let activeTouchReq: ActiveIpcHandle | null = null
  const statusQueue: string[] = []
  let draining = false
  const touchDelayMs = parseOptionalInt(process.env.OC_YUBIKEY_GPG_TOUCH_DELAY_MS) ?? 250

  const clearTouchPrompt = (): void => {
    if (touchTimer) {
      clearTimeout(touchTimer)
      touchTimer = undefined
    }
    if (activeTouchReq) {
      activeTouchReq.close()
      activeTouchReq = null
    }
  }

  const scheduleTouchPrompt = (): void => {
    if (!options.isSigning || sigCompleted || pinInFlight || activeTouchReq) return
    if (touchTimer) {
      clearTimeout(touchTimer)
      touchTimer = undefined
    }
    touchTimer = setTimeout(() => {
      if (sigCompleted || pinInFlight || activeTouchReq) return
      const req = sendIpcRequest(options.socketPath, {
        token: options.token,
        type: "touch",
        title: "Touch Your YubiKey",
        description: userIdHint
          ? `Confirm user presence on your YubiKey for ${userIdHint}`
          : "Confirm user presence on your YubiKey to sign",
        prompt: "Touch YubiKey",
        ...(options.command ? { command: options.command } : {}),
      })
      activeTouchReq = req
      void req.promise
        .then((res) => {
          if (res.cancelled && activeTouchReq === req && !sigCompleted) {
            options.onCancelTouch()
          }
        })
        .catch(() => {})
    }, touchDelayMs)
  }

  const handleStatusLine = async (line: string): Promise<void> => {
    const body = line.slice("[GNUPG:] ".length).trim()
    if (body.startsWith("USERID_HINT ")) {
      const firstSpace = body.indexOf(" ", "USERID_HINT ".length)
      userIdHint = firstSpace !== -1 ? body.slice(firstSpace + 1).trim() || undefined : undefined
    } else if (body.startsWith("BAD_PASSPHRASE")) {
      clearTouchPrompt()
      lastError = "Bad PIN"
    } else if (body.startsWith("GET_HIDDEN passphrase.")) {
      clearTouchPrompt()
      pinInFlight = true
      const error = lastError
      lastError = undefined
      const submitted = await promptGpgLoopbackPin(options, userIdHint, error)
      pinInFlight = false
      options.onActiveRequest(null)
      if (submitted) scheduleTouchPrompt()
    } else if (body.startsWith("BEGIN_SIGNING") || body.startsWith("GOT_IT")) {
      scheduleTouchPrompt()
    } else if (body.startsWith("SIG_CREATED ")) {
      sigCompleted = true
      clearTouchPrompt()
    }
  }

  const drain = async (): Promise<void> => {
    if (draining) return
    draining = true
    while (statusQueue.length > 0) {
      const next = statusQueue.shift()
      if (next) await handleStatusLine(next)
    }
    draining = false
  }

  return {
    onChunk: (chunk: Buffer | string): void => {
      statusBuffer += typeof chunk === "string" ? chunk : chunk.toString("utf8")
      let idx = statusBuffer.indexOf("\n")
      while (idx !== -1) {
        const line = statusBuffer.slice(0, idx).replace(/\r$/, "")
        statusBuffer = statusBuffer.slice(idx + 1)
        idx = statusBuffer.indexOf("\n")
        if (line.startsWith("[GNUPG:] ")) {
          statusQueue.push(line)
        }
      }
      void drain()
    },
    dispose: (): void => {
      sigCompleted = true
      clearTouchPrompt()
    },
  }
}

function runGpgWrapperMode(args: readonly string[]): void {
  const gpgBin = resolveRealGpgExecutable()
  const childEnv: Record<string, string | undefined> = { ...process.env }
  delete childEnv.OC_YUBIKEY_MODE

  const { socketPath, token, command } = resolveIpcTarget()
  const inspected = inspectGpgWrapperArgs(args)

  if (!socketPath || !token || !existsSync(socketPath) || inspected.hasCustomPassphraseInput) {
    const child = spawn(gpgBin, [...args], { stdio: "inherit", env: childEnv })
    child.on("exit", (code) => process.exit(code ?? 1))
    child.on("error", () => process.exit(127))
    return
  }

  const useDedicatedStatusPipe = inspected.callerStatusFd !== 1 && inspected.callerStatusFd !== 2
  const gpgArgs = buildWrappedGpgArgs(args, inspected, useDedicatedStatusPipe)
  const child = spawn(gpgBin, gpgArgs, {
    env: childEnv,
    stdio: useDedicatedStatusPipe
      ? ["pipe", "pipe", "pipe", "pipe", "pipe"]
      : ["pipe", "pipe", "pipe", "pipe"],
  })

  let activePinRequest: ActiveIpcHandle | null = null
  const monitor = createGpgStatusMonitor({
    socketPath,
    token,
    command,
    isSigning: inspected.isSigning,
    commandStream: child.stdio[3] as WritableStream | undefined,
    onActiveRequest: (req) => {
      activePinRequest = req
    },
    onCancelTouch: () => {
      child.kill("SIGTERM")
      process.exit(130)
    },
  })

  registerSignalCleanup(() => {
    monitor.dispose()
    activePinRequest?.close()
    child.kill("SIGTERM")
    process.exit(130)
  })

  process.stdin.on("data", (chunk: Buffer | string) => child.stdin.write(chunk))
  process.stdin.on("end", () => child.stdin.end())
  process.stdin.on("error", () => child.stdin.end())

  child.stdout.on("data", (chunk: Buffer | string) => {
    if (inspected.callerStatusFd === 1) monitor.onChunk(chunk)
    process.stdout.write(chunk)
  })
  child.stderr.on("data", (chunk: Buffer | string) => {
    if (inspected.callerStatusFd === 2) monitor.onChunk(chunk)
    process.stderr.write(chunk)
  })
  if (useDedicatedStatusPipe) {
    ;(child.stdio[4] as ReadableStream | undefined)?.on("data", monitor.onChunk)
  }

  child.on("error", () => {
    monitor.dispose()
    activePinRequest?.close()
    process.exit(127)
  })
  child.on("close", (code) => {
    monitor.dispose()
    activePinRequest?.close()
    process.exit(code ?? 1)
  })
}

interface AssuanPinentryState {
  title: string | undefined
  description: string | undefined
  prompt: string | undefined
  error: string | undefined
}

interface AssuanExecutionContext {
  readonly socketPath: string | undefined
  readonly token: string | undefined
  readonly command: string | undefined
  readonly state: AssuanPinentryState
  getTouchRequest(): ActiveIpcHandle | null
  setTouchRequest(req: ActiveIpcHandle | null): void
  closeCurrentTouch(): void
}

const STATE_MUTATORS: Readonly<
  Record<string, (state: AssuanPinentryState, arg: string) => void>
> = {
  SETDESC: (state, arg) => {
    state.description = parseAssuanData(arg)
  },
  SETPROMPT: (state, arg) => {
    state.prompt = `${parseAssuanData(arg).replace(/:$/, "")}:`
  },
  SETTITLE: (state, arg) => {
    state.title = parseAssuanData(arg)
  },
  SETERROR: (state, arg) => {
    state.error = parseAssuanData(arg)
  },
  RESET: (state) => {
    state.title = undefined
    state.description = undefined
    state.prompt = undefined
    state.error = undefined
  },
}

const GETINFO_RESPONSES: Readonly<Record<string, () => string>> = {
  pid: () => `D ${process.pid}\nOK\n`,
  version: () => "D 1.3.1\nOK\n",
  flavor: () => "D oc-yubikey\nOK\n",
}

const CANCELLED_ASSUAN_LINE = "ERR 83886179 Operation cancelled <Pinentry>\n"

async function handleAssuanConfirm(ctx: AssuanExecutionContext): Promise<string> {
  if (!ctx.socketPath || !ctx.token || !existsSync(ctx.socketPath)) {
    return "OK\n"
  }
  const req = sendIpcRequest(ctx.socketPath, {
    token: ctx.token,
    type: "touch",
    title: ctx.state.title || "Touch Your YubiKey",
    description: ctx.state.description || "Please touch your YubiKey to confirm.",
    prompt: "Touch YubiKey",
    ...(ctx.command ? { command: ctx.command } : {}),
  })
  ctx.setTouchRequest(req)
  try {
    const res = await req.promise
    return res.cancelled ? CANCELLED_ASSUAN_LINE : "OK\n"
  } catch {
    return CANCELLED_ASSUAN_LINE
  } finally {
    ctx.setTouchRequest(null)
  }
}

async function handleAssuanGetPin(ctx: AssuanExecutionContext): Promise<string> {
  if (!ctx.socketPath || !ctx.token || !existsSync(ctx.socketPath)) {
    return CANCELLED_ASSUAN_LINE
  }
  const req = sendIpcRequest(ctx.socketPath, {
    token: ctx.token,
    type: "pin",
    title: ctx.state.title || "YubiKey PIN Entry",
    description: ctx.state.description,
    prompt: ctx.state.prompt || "PIN:",
    error: ctx.state.error,
    ...(ctx.command ? { command: ctx.command } : {}),
  })
  ctx.state.error = undefined
  try {
    const res = await req.promise
    if (!res.ok || res.cancelled || typeof res.pin !== "string") {
      return CANCELLED_ASSUAN_LINE
    }
    return `D ${encodeAssuanData(res.pin)}\nOK\n`
  } catch {
    return CANCELLED_ASSUAN_LINE
  }
}

async function executeAssuanCommand(
  cmd: string,
  arg: string,
  ctx: AssuanExecutionContext,
): Promise<string> {
  const mutator = STATE_MUTATORS[cmd]
  if (mutator) {
    mutator(ctx.state, arg)
    return "OK\n"
  }
  if (cmd === "GETINFO") {
    return GETINFO_RESPONSES[arg]?.() ?? "OK\n"
  }
  if (cmd === "CONFIRM" || cmd === "MESSAGE") {
    return handleAssuanConfirm(ctx)
  }
  if (cmd === "GETPIN") {
    return handleAssuanGetPin(ctx)
  }
  if (cmd === "BYE") {
    ctx.closeCurrentTouch()
    process.stdout.write("OK closing connection\n")
    process.exit(0)
  }
  return "OK\n"
}

function createAssuanQueueDrainer(
  queue: string[],
  ctx: AssuanExecutionContext,
): () => Promise<void> {
  let processing = false
  return async () => {
    if (processing) return
    processing = true
    while (queue.length > 0) {
      const line = queue.shift()!
      const spaceIdx = line.indexOf(" ")
      const cmd = (spaceIdx === -1 ? line : line.slice(0, spaceIdx)).toUpperCase()
      const arg = spaceIdx === -1 ? "" : line.slice(spaceIdx + 1).trim()
      const reply = await executeAssuanCommand(cmd, arg, ctx)
      process.stdout.write(reply)
    }
    processing = false
  }
}

function attachAssuanStdinReader(ctx: AssuanExecutionContext): void {
  let buffer = ""
  const queue: string[] = []
  const drainQueue = createAssuanQueueDrainer(queue, ctx)

  process.stdin.on("data", (chunk: Buffer | string) => {
    buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8")
    if (buffer.length > MAX_ASSUAN_LINE_BYTES) {
      ctx.closeCurrentTouch()
      process.stdout.write("ERR 83886140 Line too long <Pinentry>\n")
      buffer = ""
      return
    }
    let idx = buffer.indexOf("\n")
    while (idx !== -1) {
      const line = buffer.slice(0, idx).replace(/\r$/, "").trim()
      buffer = buffer.slice(idx + 1)
      idx = buffer.indexOf("\n")
      if (!line || line.startsWith("#")) continue
      if (line.toUpperCase().startsWith("BYE") && ctx.getTouchRequest()) {
        ctx.closeCurrentTouch()
        process.stdout.write("OK closing connection\n")
        process.exit(0)
      }
      if (queue.length < MAX_ASSUAN_QUEUE_LEN) {
        queue.push(line)
      }
    }
    void drainQueue()
  })

  process.stdin.on("end", () => {
    ctx.closeCurrentTouch()
    process.exit(0)
  })
}

function runAssuanPinentryMode(args: readonly string[]): void {
  const { socketPath, token, command } = resolveIpcTarget()
  if ((!socketPath || !token || !existsSync(socketPath)) && spawnFallbackPinentry(args)) {
    return
  }

  let currentTouchRequest: ActiveIpcHandle | null = null
  const closeCurrentTouch = () => {
    if (currentTouchRequest) {
      currentTouchRequest.close()
      currentTouchRequest = null
    }
  }

  registerSignalCleanup(() => {
    closeCurrentTouch()
    process.exit(0)
  })

  const ctx: AssuanExecutionContext = {
    socketPath,
    token,
    command,
    state: { title: undefined, description: undefined, prompt: undefined, error: undefined },
    getTouchRequest: () => currentTouchRequest,
    setTouchRequest: (req) => {
      currentTouchRequest = req
    },
    closeCurrentTouch,
  }

  process.stdout.write("OK Pleased to meet you\n")
  attachAssuanStdinReader(ctx)
}

const VALUE_FLAGS = new Set<string>([
  "--display",
  "--ttyname",
  "--ttytype",
  "--lc-ctype",
  "--lc-messages",
  "--timeout",
  "-d",
  "-T",
  "-N",
  "-o",
])

function extractPositionalPrompt(args: readonly string[]): string | null {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    if (!arg) continue
    if (VALUE_FLAGS.has(arg)) {
      i += 1
      continue
    }
    if (arg.startsWith("-")) continue
    return arg
  }
  return null
}

const rawArgs = process.argv.slice(2)
const invokedBinName = path.basename(process.argv[1] ?? "")
const isGpgWrapperInvocation =
  process.env.OC_YUBIKEY_MODE === "gpg" ||
  invokedBinName === "oc-yubikey-gpg" ||
  rawArgs[0] === "--gpg-wrapper"
const isSshWrapperInvocation =
  process.env.OC_YUBIKEY_MODE === "ssh" ||
  invokedBinName === "oc-yubikey-ssh" ||
  rawArgs[0] === "--ssh-wrapper"

if (isGpgWrapperInvocation) {
  runGpgWrapperMode(rawArgs[0] === "--gpg-wrapper" ? rawArgs.slice(1) : rawArgs)
} else if (isSshWrapperInvocation) {
  runSshWrapperMode(rawArgs[0] === "--ssh-wrapper" ? rawArgs.slice(1) : rawArgs)
} else {
  const positionalPrompt = extractPositionalPrompt(rawArgs)
  if (positionalPrompt !== null) {
    void runAskpassMode(positionalPrompt)
  } else {
    runAssuanPinentryMode(rawArgs)
  }
}
