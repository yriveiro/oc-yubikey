import { spawn } from "node:child_process"
import { existsSync, lstatSync, realpathSync } from "node:fs"
import net from "node:net"
import path from "node:path"
import { fileURLToPath } from "node:url"
import {
  classifyAskpassPrompt,
  encodeAssuanData,
  parseAssuanData,
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

function spawnFallbackPinentry(args: readonly string[]): boolean {
  if (process.env.OC_YUBIKEY_FALLBACK_ACTIVE === "1") {
    return false
  }

  const selfPaths = new Set<string>()
  try {
    const cliFile = fileURLToPath(import.meta.url)
    selfPaths.add(realpathSync(cliFile))
    selfPaths.add(realpathSync(path.resolve(path.dirname(cliFile), "..", "bin", "oc-yubikey")))
  } catch {
    // Ignore resolution errors
  }

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
const positionalPrompt = extractPositionalPrompt(rawArgs)
if (positionalPrompt !== null) {
  void runAskpassMode(positionalPrompt)
} else {
  runAssuanPinentryMode(rawArgs)
}
