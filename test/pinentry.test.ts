import { describe, expect, it } from "bun:test"
import { spawn } from "node:child_process"
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import net from "node:net"
import os from "node:os"
import path from "node:path"
import {
  type AskpassClassification,
  PinentryBridge,
  type SshFingerprint,
  classifyAskpassPrompt,
  filterSshAgentIdentitiesAnswer,
  findSshSecurityKeyFile,
  isAppleLaunchdSshAgentSocket,
  parseSshAgentSignRequest,
  resolvePinentryCliPath,
} from "../src/bridge.ts"
import { PinentryCoordinator, type PromptOutputByKind } from "../src/coordinator.ts"
import { sanitizeDisplayText } from "../src/protocol.ts"
import type {
  PromptPinOutput,
  PromptTouchOutput,
  RequestSummary,
  ResolvedEvent,
  YubiKeyCardStatus,
} from "../src/rpc.ts"
import {
  assuanPercentDecode,
  assuanPercentEncode,
  lockYubiKey,
  parseCardStatusOutput,
  presetPassphraseInAgent,
  verifyYubiKeyPinLoopback,
} from "../src/yubikey.ts"

type Equal<X, Y> = (<T>() => T extends X ? 1 : 2) extends <T>() => T extends Y ? 1 : 2
  ? true
  : false
type Expect<T extends true> = T

export type TypeLevelInvariantChecks = [
  Expect<Equal<PromptOutputByKind["pin"], PromptPinOutput>>,
  Expect<Equal<PromptOutputByKind["touch"], PromptTouchOutput>>,
  Expect<Equal<Extract<AskpassClassification, { kind: "touch" }>["type"], "touch">>,
  Expect<Equal<Extract<AskpassClassification, { kind: "pin" }>["type"], "pin">>,
  Expect<Equal<`SHA256:${string}` extends SshFingerprint ? true : false, true>>,
]

interface MockAssuanConnectionState {
  awaitingInquire: boolean
  currentInquirePin: string
}

function handleMockInquireLine(
  line: string,
  state: MockAssuanConnectionState,
  expectedPin: string,
  receivedInquireData: string[],
  socket: net.Socket,
): void {
  if (line.startsWith("D ")) {
    state.currentInquirePin += assuanPercentDecode(line.slice(2))
    return
  }
  if (line === "END") {
    state.awaitingInquire = false
    receivedInquireData.push(state.currentInquirePin)
    const ok = state.currentInquirePin === expectedPin
    state.currentInquirePin = ""
    socket.write(ok ? "OK\n" : "ERR 100663404 Bad PIN <SCD>\n")
    return
  }
  if (line === "CAN") {
    state.awaitingInquire = false
    state.currentInquirePin = ""
    socket.write("ERR 83886179 Operation cancelled <Pinentry>\n")
  }
}

function handleMockCommandLine(
  line: string,
  state: MockAssuanConnectionState,
  aid: string,
  socket: net.Socket,
): void {
  if (line === "SCD SERIALNO") {
    socket.write(`S SERIALNO ${aid} 0\nOK\n`)
    return
  }
  if (line.startsWith("SCD CHECKPIN ")) {
    state.awaitingInquire = true
    socket.write("S INQUIRE_MAXLEN 100\nINQUIRE PASSPHRASE\n")
    return
  }
  if (line === "BYE") {
    socket.end("OK closing connection\n")
    return
  }
  socket.write("OK\n")
}

function startMockGpgAgent(options: {
  expectedPin?: string
  aid?: string
  onCommand?: (cmd: string) => void
}) {
  const tmpDir = mkdtempSync(path.join(os.tmpdir(), "oc-mock-gpg-agent-"))
  const socketPath = path.join(tmpDir, "S.gpg-agent")
  const aid = options.aid ?? "D2760001240103040006123456780000"
  const expectedPin = options.expectedPin ?? "123456"
  const receivedCommands: string[] = []
  const receivedInquireData: string[] = []

  const server = net.createServer((socket) => {
    socket.write("OK Pleased to meet you, mock gpg-agent\n")
    let buffer = ""
    const state: MockAssuanConnectionState = {
      awaitingInquire: false,
      currentInquirePin: "",
    }

    socket.on("data", (chunk: Buffer | string) => {
      buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8")
      let idx = buffer.indexOf("\n")
      while (idx !== -1) {
        const line = buffer.slice(0, idx).replace(/\r$/, "")
        buffer = buffer.slice(idx + 1)
        idx = buffer.indexOf("\n")

        if (state.awaitingInquire) {
          handleMockInquireLine(line, state, expectedPin, receivedInquireData, socket)
          continue
        }

        receivedCommands.push(line)
        options.onCommand?.(line)
        handleMockCommandLine(line, state, aid, socket)
      }
    })
  })

  return {
    socketPath,
    receivedCommands,
    receivedInquireData,
    async listen() {
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject)
        server.listen(socketPath, () => resolve())
      })
    },
    async close() {
      await new Promise<void>((resolve) => server.close(() => resolve()))
      rmSync(tmpDir, { recursive: true, force: true })
    },
  }
}

describe("Direct gpg-agent Assuan loopback client", () => {
  it("percent-encodes and decodes Assuan D lines accurately", () => {
    const raw = "p@ss%w0rd\r\n🔑"
    const encoded = assuanPercentEncode(raw)
    expect(encoded).toContain("%25")
    expect(encoded).toContain("%0D%0A")
    expect(assuanPercentDecode(encoded)).toBe(raw)
  })

  it("unlocks YubiKey via OPTION pinentry-mode=loopback -> SCD SERIALNO -> SCD CHECKPIN -> INQUIRE PASSPHRASE", async () => {
    const mockAgent = startMockGpgAgent({ expectedPin: "654321%!" })
    await mockAgent.listen()

    try {
      const res = await verifyYubiKeyPinLoopback("654321%!", {
        socketPath: mockAgent.socketPath,
      })

      expect(res.ok).toBe(true)
      expect(res.aid).toBe("D2760001240103040006123456780000")
      expect(mockAgent.receivedCommands).toEqual([
        "OPTION pinentry-mode=loopback",
        "SCD SERIALNO",
        "SCD CHECKPIN D2760001240103040006123456780000",
        "BYE",
      ])
      expect(mockAgent.receivedInquireData).toEqual(["654321%!"])
    } finally {
      await mockAgent.close()
    }
  })

  it("supports PRESET_PASSPHRASE and SCD RESET + RELOADAGENT for locking", async () => {
    const mockAgent = startMockGpgAgent({})
    await mockAgent.listen()

    try {
      const preset = await presetPassphraseInAgent("ABCDEF1234567890", "123456", -1, {
        socketPath: mockAgent.socketPath,
      })
      expect(preset.ok).toBe(true)

      const locked = await lockYubiKey({ socketPath: mockAgent.socketPath })
      expect(locked.ok).toBe(true)

      expect(mockAgent.receivedCommands).toContain(
        "PRESET_PASSPHRASE ABCDEF1234567890 -1 313233343536",
      )
      expect(mockAgent.receivedCommands).toContain("SCD RESET")
      expect(mockAgent.receivedCommands).toContain("RELOADAGENT")
    } finally {
      await mockAgent.close()
    }
  })
})

describe("PinentryCoordinator & TUI RPC flow", () => {
  it("coordinates TUI PIN prompts, retries on Bad PIN, and unlocks gpg-agent", async () => {
    const mockAgent = startMockGpgAgent({ expectedPin: "888888" })
    await mockAgent.listen()

    const requested: RequestSummary[] = []
    const resolved: ResolvedEvent[] = []
    let currentRetries = 3

    const coordinator = new PinentryCoordinator({
      agentSocketPath: mockAgent.socketPath,
      async getCardStatus(): Promise<YubiKeyCardStatus> {
        return {
          connected: true,
          serial: "12345678",
          applicationID: "D2760001240103040006123456780000",
          holder: "Jane Doe",
          pinRetries: { user: currentRetries, reset: 0, admin: 3 },
        }
      },
      onRequested(summary) {
        requested.push(summary)
        setTimeout(() => {
          if (requested.length === 1) {
            currentRetries = 2
            coordinator.submit(summary.requestID, "wrong-pin")
          } else {
            currentRetries = 3
            coordinator.submit(summary.requestID, "888888")
          }
        }, 10)
      },
      onResolved(event) {
        resolved.push(event)
      },
    })

    try {
      const unlockRes = await coordinator.unlock({
        reason: "Sign git commit",
        allowRetry: true,
      })

      expect(unlockRes.ok).toBe(true)
      expect(unlockRes.message).toContain("YubiKey (12345678) unlocked")
      expect(requested.length).toBe(2)
      expect(requested[0]?.error).toBeUndefined()
      expect(requested[1]?.error).toBe("Bad PIN (2 tries remaining)")
      expect(resolved).toEqual([
        { requestID: requested[0]!.requestID, outcome: "submitted" },
        { requestID: requested[1]!.requestID, outcome: "submitted" },
      ])
    } finally {
      coordinator.close()
      await mockAgent.close()
    }
  })

  it("stops automatic retry loop when only 1 PIN retry remains on the YubiKey", async () => {
    const mockAgent = startMockGpgAgent({ expectedPin: "888888" })
    await mockAgent.listen()

    const requested: RequestSummary[] = []
    let currentRetries = 2

    const coordinator = new PinentryCoordinator({
      agentSocketPath: mockAgent.socketPath,
      async getCardStatus(): Promise<YubiKeyCardStatus> {
        return {
          connected: true,
          serial: "12345678",
          applicationID: "D2760001240103040006123456780000",
          holder: "Jane Doe",
          pinRetries: { user: currentRetries, reset: 0, admin: 3 },
        }
      },
      onRequested(summary) {
        requested.push(summary)
        setTimeout(() => {
          currentRetries = 1
          coordinator.submit(summary.requestID, "wrong-pin")
        }, 10)
      },
    })

    try {
      const unlockRes = await coordinator.unlock({
        reason: "Sign git commit",
        allowRetry: true,
      })

      expect(unlockRes.ok).toBe(false)
      expect(requested.length).toBe(1)
    } finally {
      coordinator.close()
      await mockAgent.close()
    }
  })

  it("cancels pending PIN prompt automatically when AbortSignal aborts and sanitizes control sequences", async () => {
    const requested: RequestSummary[] = []
    const resolved: ResolvedEvent[] = []
    const controller = new AbortController()

    const coordinator = new PinentryCoordinator({
      onRequested(summary) {
        requested.push(summary)
        setTimeout(() => controller.abort(), 15)
      },
      onResolved(event) {
        resolved.push(event)
      },
    })

    const result = await coordinator.requestPin(
      {
        title: "Unlock \u001b[31mYubiKey\u0007\u202e",
        prompt: "PIN:",
      },
      { signal: controller.signal },
    )

    expect( sanitizeDisplayText("Hello\u001b\u0007\u202eWorld") ).toBe("HelloWorld")
    expect(requested[0]?.title).toBe("Unlock [31mYubiKey")
    expect(result).toEqual({ cancelled: true, cancelReason: "aborted" })
    expect(coordinator.listPending()).toEqual([])
    expect(resolved).toEqual([{ requestID: requested[0]!.requestID, outcome: "cancelled" }])
  })
})

describe("parseCardStatusOutput", () => {
  it("parses human-readable and colon-delimited gpg --card-status output", () => {
    const sample = `
Reader ...........: Yubico YubiKey OTP FIDO CCID
Application ID ...: D2760001240103040006123456780000
Application type .: OpenPGP
Version ..........: 3.4
Manufacturer .....: Yubico
Serial number ....: 12345678
Name of cardholder: Doe<<Jane
PIN retry counter : 3 0 3
Signature counter : 128
UIF setting ......: Sign=on Decrypt=off Auth=on
Signature key ....: 1111 2222 3333 4444 5555  6666 7777 8888 9999 AAAA
`
    expect(parseCardStatusOutput(sample)).toEqual({
      connected: true,
      reader: "Yubico YubiKey OTP FIDO CCID",
      applicationID: "D2760001240103040006123456780000",
      serial: "12345678",
      model: "Yubico",
      version: "3.4",
      holder: "Doe Jane",
      pinRetries: { user: 3, reset: 0, admin: 3 },
      signatureCount: 128,
      uif: { sign: "on", decrypt: "off", auth: "on" },
      keys: {
        signature: "111122223333444455556666777788889999AAAA",
      },
    })
  })
})

function buildSshSignRequestPacket(keyTypeStr: string): Buffer {
  const keyTypeBuf = Buffer.from(keyTypeStr, "utf8")
  const fakeKeyData = Buffer.from("0123456789abcdef0123456789abcdef", "utf8")
  const keyBlob = Buffer.alloc(4 + keyTypeBuf.length + fakeKeyData.length)
  keyBlob.writeUInt32BE(keyTypeBuf.length, 0)
  keyTypeBuf.copy(keyBlob, 4)
  fakeKeyData.copy(keyBlob, 4 + keyTypeBuf.length)

  const dataToSign = Buffer.from("git-pull-handshake", "utf8")
  const payload = Buffer.alloc(4 + keyBlob.length + 4 + dataToSign.length + 4)
  let offset = 0
  payload.writeUInt32BE(keyBlob.length, offset)
  offset += 4
  keyBlob.copy(payload, offset)
  offset += keyBlob.length
  payload.writeUInt32BE(dataToSign.length, offset)
  offset += 4
  dataToSign.copy(payload, offset)
  offset += dataToSign.length
  payload.writeUInt32BE(0, offset)

  const frame = Buffer.alloc(4 + 1 + payload.length)
  frame.writeUInt32BE(1 + payload.length, 0)
  frame[4] = 13 // SSH2_AGENTC_SIGN_REQUEST
  payload.copy(frame, 5)
  return frame
}

describe("YubiKey Touch Prompt & SSH_AUTH_SOCK / SSH_ASKPASS / Pinentry Bridge", () => {
  it("parses SSH2_AGENTC_SIGN_REQUEST packets and classifies SSH_ASKPASS prompts", () => {
    const packet = buildSshSignRequestPacket("sk-ssh-ed25519@openssh.com")
    const parsed = parseSshAgentSignRequest(packet.subarray(5))
    expect(parsed).toBeDefined()
    expect(parsed?.keyType).toBe("ED25519-SK")
    expect(parsed?.isSecurityKey).toBe(true)
    expect(parsed?.fingerprint).toStartWith("SHA256:")

    const touchAskpass = classifyAskpassPrompt(
      "Confirm user presence for key ED25519-SK SHA256:abc123xyz",
    )
    expect(touchAskpass.kind).toBe("touch")
    expect(touchAskpass.keyType).toBe("ED25519-SK")
    expect(touchAskpass.fingerprint).toBe("SHA256:abc123xyz")

    const pinAskpass = classifyAskpassPrompt(
      "Enter PIN for ED25519-SK key /Users/alice/.ssh/id_ed25519_sk: ",
    )
    expect(pinAskpass.kind).toBe("pin")

    expect(isAppleLaunchdSshAgentSocket("/var/run/com.apple.launchd.MOCK123456/Listeners")).toBe(
      true,
    )
    expect(isAppleLaunchdSshAgentSocket("/Users/alice/.gnupg/S.gpg-agent.ssh")).toBe(false)

    const makeEntry = (keyType: string, comment: string) => {
      const kt = Buffer.from(keyType, "utf8")
      const blob = Buffer.alloc(4 + kt.length + 8)
      blob.writeUInt32BE(kt.length, 0)
      kt.copy(blob, 4)
      const cm = Buffer.from(comment, "utf8")
      const entry = Buffer.alloc(4 + blob.length + 4 + cm.length)
      entry.writeUInt32BE(blob.length, 0)
      blob.copy(entry, 4)
      entry.writeUInt32BE(cm.length, 4 + blob.length)
      cm.copy(entry, 8 + blob.length)
      return entry
    }
    const e1 = makeEntry("sk-ssh-ed25519@openssh.com", "yubikey")
    const e2 = makeEntry("ssh-ed25519", "standard")
    const payload = Buffer.alloc(4 + e1.length + e2.length)
    payload.writeUInt32BE(2, 0)
    e1.copy(payload, 4)
    e2.copy(payload, 4 + e1.length)

    const filteredFrame = filterSshAgentIdentitiesAnswer(
      payload,
      (kt) => !kt.toLowerCase().startsWith("sk-"),
    )
    expect(filteredFrame).toBeDefined()
    expect(filteredFrame![4]).toBe(12)
    expect(filteredFrame!.readUInt32BE(5)).toBe(1)
  })

  it("opens Touch YubiKey modal on SSH_AUTH_SOCK sign request (git pull) and auto-closes on hardware touch", async () => {
    const baseTmp = existsSync("/tmp") ? "/tmp" : os.tmpdir()
    const tmpDir = mkdtempSync(path.join(baseTmp, "oc-ssh-test-"))
    const upstreamSock = path.join(tmpDir, "upstream.sock")

    const upstreamServer = net.createServer((sock) => {
      sock.on("data", () => {
        setTimeout(() => {
          if (!sock.destroyed) {
            sock.write(Buffer.from([0, 0, 0, 5, 14, 0, 0, 0, 0]))
          }
        }, 120)
      })
    })
    await new Promise<void>((resolve) => upstreamServer.listen(upstreamSock, () => resolve()))

    const requested: RequestSummary[] = []
    const resolved: ResolvedEvent[] = []
    const coordinator = new PinentryCoordinator({
      onRequested(summary) {
        requested.push(summary)
      },
      onResolved(event) {
        resolved.push(event)
      },
    })

    const bridge = new PinentryBridge({
      coordinator,
      socketDir: tmpDir,
      securityKeyDebounceMs: 15,
    })

    try {
      const env: Record<string, string | undefined> = {
        SSH_AUTH_SOCK: upstreamSock,
      }
      await bridge.prepareShellEnv(env, "git pull --rebase")
      expect(env.SSH_AUTH_SOCK).toBeDefined()
      expect(env.SSH_AUTH_SOCK).not.toBe(upstreamSock)

      const responseBytes = await new Promise<Buffer>((resolve, reject) => {
        const client = net.createConnection({ path: env.SSH_AUTH_SOCK! })
        client.once("connect", () => {
          client.write(buildSshSignRequestPacket("sk-ssh-ed25519@openssh.com"))
        })
        client.once("data", (data) => {
          client.end()
          resolve(typeof data === "string" ? Buffer.from(data) : data)
        })
        client.once("error", reject)
      })

      expect(responseBytes[4]).toBe(14)
      expect(requested.length).toBe(1)
      expect(requested[0]?.kind).toBe("touch")
      expect(requested[0]?.keyType).toBe("ED25519-SK")
      expect(requested[0]?.command).toBe("git pull --rebase")
      expect(resolved).toEqual([{ requestID: requested[0]!.requestID, outcome: "confirmed" }])
      expect(coordinator.listPending()).toEqual([])
    } finally {
      coordinator.close()
      await bridge.close()
      await new Promise<void>((resolve) => upstreamServer.close(() => resolve()))
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it("cancels pending Touch modal when upstream ssh-agent returns SSH_AGENT_FAILURE", async () => {
    const baseTmp = existsSync("/tmp") ? "/tmp" : os.tmpdir()
    const tmpDir = mkdtempSync(path.join(baseTmp, "oc-ssh-fail-"))
    const upstreamSock = path.join(tmpDir, "upstream.sock")

    const upstreamServer = net.createServer((sock) => {
      sock.on("data", () => {
        setTimeout(() => {
          if (!sock.destroyed) {
            sock.write(Buffer.from([0, 0, 0, 1, 5]))
          }
        }, 80)
      })
    })
    await new Promise<void>((resolve) => upstreamServer.listen(upstreamSock, () => resolve()))

    const requested: RequestSummary[] = []
    const resolved: ResolvedEvent[] = []
    const coordinator = new PinentryCoordinator({
      onRequested(summary) {
        requested.push(summary)
      },
      onResolved(event) {
        resolved.push(event)
      },
    })

    const bridge = new PinentryBridge({
      coordinator,
      socketDir: tmpDir,
      securityKeyDebounceMs: 10,
    })

    try {
      const proxySock = await bridge.ensureSshAgentProxy(upstreamSock, "git pull")
      const responseBytes = await new Promise<Buffer>((resolve, reject) => {
        const client = net.createConnection({ path: proxySock })
        client.once("connect", () => {
          client.write(buildSshSignRequestPacket("sk-ssh-ed25519@openssh.com"))
        })
        client.once("data", (data) => {
          client.end()
          resolve(typeof data === "string" ? Buffer.from(data) : data)
        })
        client.once("error", reject)
      })

      expect(responseBytes[4]).toBe(5)
      expect(requested.length).toBe(1)
      expect(resolved).toEqual([{ requestID: requested[0]!.requestID, outcome: "cancelled" }])
    } finally {
      coordinator.close()
      await bridge.close()
      await new Promise<void>((resolve) => upstreamServer.close(() => resolve()))
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it("aborts SSH_AUTH_SOCK sign request with SSH_AGENT_FAILURE when user cancels Touch Modal in TUI", async () => {
    const baseTmp = existsSync("/tmp") ? "/tmp" : os.tmpdir()
    const tmpDir = mkdtempSync(path.join(baseTmp, "oc-ssh-cancel-"))
    const upstreamSock = path.join(tmpDir, "upstream.sock")

    const upstreamServer = net.createServer(() => {})
    await new Promise<void>((resolve) => upstreamServer.listen(upstreamSock, () => resolve()))

    const coordinator = new PinentryCoordinator({
      onRequested(summary) {
        setTimeout(() => {
          coordinator.cancel(summary.requestID)
        }, 20)
      },
    })

    const bridge = new PinentryBridge({
      coordinator,
      socketDir: tmpDir,
      securityKeyDebounceMs: 10,
    })

    try {
      const proxySock = await bridge.ensureSshAgentProxy(upstreamSock, "git pull")
      const responseBytes = await new Promise<Buffer>((resolve, reject) => {
        const client = net.createConnection({ path: proxySock })
        client.once("connect", () => {
          client.write(buildSshSignRequestPacket("sk-ssh-ed25519@openssh.com"))
        })
        client.once("data", (data) => {
          client.end()
          resolve(typeof data === "string" ? Buffer.from(data) : data)
        })
        client.once("error", reject)
      })

      expect(responseBytes[4]).toBe(5)
    } finally {
      coordinator.close()
      await bridge.close()
      await new Promise<void>((resolve) => upstreamServer.close(() => resolve()))
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it("rejects unauthenticated IPC clients and handles bin/oc-yubikey in SSH_ASKPASS + GnuPG Assuan modes", async () => {
    const baseTmp = existsSync("/tmp") ? "/tmp" : os.tmpdir()
    const tmpDir = mkdtempSync(path.join(baseTmp, "oc-cli-test-"))
    const requested: RequestSummary[] = []
    const resolved: ResolvedEvent[] = []

    const coordinator = new PinentryCoordinator({
      onRequested(summary) {
        requested.push(summary)
        if (summary.kind === "pin") {
          setTimeout(() => {
            coordinator.submit(summary.requestID, "424242")
          }, 20)
        }
      },
      onResolved(event) {
        resolved.push(event)
      },
    })

    const bridge = new PinentryBridge({
      coordinator,
      socketDir: tmpDir,
    })
    await bridge.start()

    const cliPath = resolvePinentryCliPath()

    try {
      // 0. Verify unauthenticated IPC request is rejected without prompting TUI
      const unauthReply = await new Promise<string>((resolve, reject) => {
        const sock = net.createConnection({ path: bridge.socketPath })
        let buf = ""
        sock.once("connect", () => {
          sock.write(`${JSON.stringify({ type: "pin", token: "wrong-token" })}\n`)
        })
        sock.on("data", (chunk) => {
          buf += chunk.toString("utf8")
        })
        sock.once("close", () => resolve(buf.trim()))
        sock.once("error", reject)
      })
      expect(JSON.parse(unauthReply)).toEqual({ ok: false, cancelled: true })
      expect(requested.length).toBe(0)

      // 1. Test SSH_ASKPASS touch mode: ssh spawns oc-yubikey and kills it with SIGTERM once YubiKey is touched
      const askpassChild = spawn(
        cliPath,
        ["Confirm user presence for key ED25519-SK SHA256:testFpr123"],
        {
          env: {
            ...process.env,
            OC_YUBIKEY_SOCK: bridge.socketPath,
            OC_YUBIKEY_TOKEN: bridge.token,
            OC_YUBIKEY_COMMAND: "git fetch origin",
          },
          stdio: ["ignore", "pipe", "pipe"],
        },
      )

      await new Promise<void>((resolve) => {
        const check = setInterval(() => {
          if (requested.length >= 1) {
            clearInterval(check)
            resolve()
          }
        }, 10)
      })

      expect(requested[0]?.kind).toBe("touch")
      expect(requested[0]?.keyType).toBe("ED25519-SK")
      expect(requested[0]?.fingerprint).toBe("SHA256:testFpr123")
      expect(requested[0]?.command).toBe("git fetch origin")

      askpassChild.kill("SIGTERM")
      await new Promise<void>((resolve) => askpassChild.once("close", () => resolve()))

      await new Promise((r) => setTimeout(r, 30))
      expect(resolved[0]).toEqual({
        requestID: requested[0]!.requestID,
        outcome: "confirmed",
      })

      // 2. Test GnuPG Assuan pinentry mode (SETDESC + GETPIN + BYE)
      const assuanOut = await new Promise<string>((resolve) => {
        const child = spawn(cliPath, [], {
          env: {
            ...process.env,
            OC_YUBIKEY_SOCK: bridge.socketPath,
            OC_YUBIKEY_TOKEN: bridge.token,
            OC_YUBIKEY_COMMAND: "git commit -S",
          },
          stdio: ["pipe", "pipe", "pipe"],
        })
        let stdout = ""
        let sentCommands = false
        child.stdout.on("data", (chunk: Buffer | string) => {
          stdout += typeof chunk === "string" ? chunk : chunk.toString("utf8")
          if (!sentCommands && stdout.includes("OK Pleased to meet you")) {
            sentCommands = true
            child.stdin.write(
              "SETTITLE Unlock YubiKey\nSETDESC Enter OpenPGP PIN\nSETPROMPT PIN:\nGETPIN\n",
            )
          }
          if (stdout.includes("D 424242\nOK")) {
            child.stdin.write("BYE\n")
          }
        })
        child.once("close", () => resolve(stdout))
      })

      expect(assuanOut).toContain("D 424242\nOK")
      expect(requested[1]?.kind).toBe("pin")
      expect(requested[1]?.command).toBe("git commit -S")
    } finally {
      coordinator.close()
      await bridge.close()
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it("discovers SSH security key files safely and falls back to coordinator when none exist", async () => {
    const baseTmp = existsSync("/tmp") ? "/tmp" : os.tmpdir()
    const tmpDir = mkdtempSync(path.join(baseTmp, "oc-sk-test-"))
    const coordinator = new PinentryCoordinator({
      onRequested(summary) {
        if (summary.kind === "touch") {
          setTimeout(() => coordinator.confirmTouch(summary.requestID), 10)
        }
      },
    })
    const bridge = new PinentryBridge({ coordinator, socketDir: tmpDir })

    try {
      expect(findSshSecurityKeyFile(tmpDir)).toBeUndefined()
      const fallbackRes = await bridge.verifyHardwareTouch(
        { description: "Synthetic touch test" },
        { sshDir: tmpDir },
      )
      expect(fallbackRes).toEqual({ cancelled: false, confirmed: true })

      const syntheticSk = path.join(tmpDir, "id_ed25519_sk")
      writeFileSync(syntheticSk, "SYNTHETIC_SK_KEY", { mode: 0o600 })
      expect(findSshSecurityKeyFile(tmpDir)).toBe(syntheticSk)
    } finally {
      coordinator.close()
      await bridge.close()
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })
})
