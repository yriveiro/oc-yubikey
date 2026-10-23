import { describe, expect, it } from "bun:test"
import { spawn } from "node:child_process"
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs"
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
  resolveGpgWrapperPath,
  resolvePinentryCliPath,
} from "../src/bridge.ts"
import { PinentryCoordinator, type PromptOutputByKind } from "../src/coordinator.ts"
import { isMatchingLocation, resolveIpcTarget, sanitizeDisplayText } from "../src/protocol.ts"
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
  findOpenPgpSignatureKeygrip,
  formatCardStatusReport,
  inspectGpgConfiguration,
  lockYubiKey,
  parseCardStatusOutput,
  parseGpgConfig,
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
  inquireCommand?: "PKSIGN" | "CHECKPIN"
  currentInquirePin: string
  readonly aid: string
  readonly sigKeygrip: string | null
  readonly expectedPin: string
  readonly receivedInquireData: string[]
  pinCachedInAgent: boolean
}

function handleMockInquireLine(
  line: string,
  state: MockAssuanConnectionState,
  socket: net.Socket,
): void {
  if (line.startsWith("D ")) {
    state.currentInquirePin += assuanPercentDecode(line.slice(2))
    return
  }
  if (line === "END") {
    const cmd = state.inquireCommand
    state.awaitingInquire = false
    state.inquireCommand = undefined
    state.receivedInquireData.push(state.currentInquirePin)
    const ok = state.currentInquirePin === state.expectedPin
    state.currentInquirePin = ""
    if (ok) {
      if (cmd === "PKSIGN") state.pinCachedInAgent = true
      socket.write(cmd === "PKSIGN" ? "D (7:sig-val)\nOK\n" : "OK\n")
    } else {
      socket.write("ERR 100663404 Bad PIN <SCD>\n")
    }
    return
  }
  if (line === "CAN") {
    state.awaitingInquire = false
    state.inquireCommand = undefined
    state.currentInquirePin = ""
    socket.write("ERR 83886179 Operation cancelled <Pinentry>\n")
  }
}

function handleMockCommandLine(
  line: string,
  state: MockAssuanConnectionState,
  socket: net.Socket,
): void {
  if (line === "SCD SERIALNO") {
    socket.write(`S SERIALNO ${state.aid} 0\nOK\n`)
    return
  }
  if (line === "KEYINFO --list") {
    const cachedFlag = state.pinCachedInAgent ? "1" : "-"
    const keyinfoLine = state.sigKeygrip
      ? `S KEYINFO ${state.sigKeygrip} T ${state.aid} OPENPGP.1 ${cachedFlag} - - - A\n`
      : ""
    socket.write(`${keyinfoLine}OK\n`)
    return
  }
  if (line === "SCD RESET" || line === "RELOADAGENT") {
    state.pinCachedInAgent = false
    socket.write("OK\n")
    return
  }
  if (line === "PKSIGN" && state.pinCachedInAgent) {
    socket.write("D (7:sig-val)\nOK\n")
    return
  }
  if (line === "PKSIGN" || line.startsWith("SCD CHECKPIN ")) {
    state.awaitingInquire = true
    state.inquireCommand = line === "PKSIGN" ? "PKSIGN" : "CHECKPIN"
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
  sigKeygrip?: string | null
  onCommand?: (cmd: string) => void
}) {
  const tmpDir = mkdtempSync(path.join(os.tmpdir(), "oc-mock-gpg-agent-"))
  const socketPath = path.join(tmpDir, "S.gpg-agent")
  const receivedCommands: string[] = []
  const state: MockAssuanConnectionState = {
    awaitingInquire: false,
    currentInquirePin: "",
    aid: options.aid ?? "D2760001240103040006123456780000",
    sigKeygrip:
      options.sigKeygrip === undefined
        ? "111122223333444455556666777788889999AAAA"
        : options.sigKeygrip,
    expectedPin: options.expectedPin ?? "123456",
    receivedInquireData: [],
    pinCachedInAgent: false,
  }

  const server = net.createServer((socket) => {
    socket.write("OK Pleased to meet you, mock gpg-agent\n")
    let buffer = ""
    socket.on("data", (chunk: Buffer | string) => {
      buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8")
      let idx = buffer.indexOf("\n")
      while (idx !== -1) {
        const line = buffer.slice(0, idx).replace(/\r$/, "")
        buffer = buffer.slice(idx + 1)
        idx = buffer.indexOf("\n")
        if (state.awaitingInquire) {
          handleMockInquireLine(line, state, socket)
          continue
        }
        receivedCommands.push(line)
        options.onCommand?.(line)
        handleMockCommandLine(line, state, socket)
      }
    })
  })

  return {
    socketPath,
    receivedCommands,
    receivedInquireData: state.receivedInquireData,
    isPinCached: () => state.pinCachedInAgent,
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

  it("warms gpg-agent signing cache via KEYINFO --list -> SIGKEY -> SETHASH 10 -> PKSIGN", async () => {
    const mockAgent = startMockGpgAgent({ expectedPin: "654321%!" })
    await mockAgent.listen()

    try {
      const res = await verifyYubiKeyPinLoopback("654321%!", {
        socketPath: mockAgent.socketPath,
      })

      expect(res.ok).toBe(true)
      expect(res.aid).toBe("D2760001240103040006123456780000")
      expect(mockAgent.isPinCached()).toBe(true)
      expect(mockAgent.receivedCommands).toEqual([
        "OPTION pinentry-mode=loopback",
        "SCD SERIALNO",
        "KEYINFO --list",
        "SIGKEY 111122223333444455556666777788889999AAAA",
        `SETHASH 10 ${"0".repeat(128)}`,
        "PKSIGN",
        "BYE",
      ])
      expect(mockAgent.receivedInquireData).toEqual(["654321%!"])
    } finally {
      await mockAgent.close()
    }
  })

  it("falls back to SCD CHECKPIN when KEYINFO --list has no OPENPGP.1 signature keygrip and matches masked AIDs", async () => {
    const mockAgent = startMockGpgAgent({
      expectedPin: "654321%!",
      sigKeygrip: null,
    })
    await mockAgent.listen()

    try {
      const res = await verifyYubiKeyPinLoopback("654321%!", {
        socketPath: mockAgent.socketPath,
      })

      expect(res.ok).toBe(true)
      expect(mockAgent.receivedCommands).toEqual([
        "OPTION pinentry-mode=loopback",
        "SCD SERIALNO",
        "KEYINFO --list",
        "SCD CHECKPIN D2760001240103040006123456780000",
        "BYE",
      ])

      const matched = findOpenPgpSignatureKeygrip(
        [
          "KEYINFO AAAABBBBCCCCDDDDEEEEFFFF0000111122223333 T D2760001240100000006876543210000 OPENPGP.1 - - - - -",
          "KEYINFO 111122223333444455556666777788889999AAAA T D2760001240100000006123456780000 OPENPGP.1 - - - - A",
        ],
        "D2760001240103040006123456780000",
      )
      expect(matched).toBe("111122223333444455556666777788889999AAAA")
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
          pinPolicy: "once",
          pinRetries: { user: currentRetries, reset: 3, admin: 3 },
          keys: { signature: "111122223333444455556666777788889999AAAA" },
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
          pinPolicy: "once",
          pinRetries: { user: currentRetries, reset: 3, admin: 3 },
          keys: { signature: "111122223333444455556666777788889999AAAA" },
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

  it("refuses to prompt or call SCD CHECKPIN when the card has no OpenPGP keys (factory state)", async () => {
    const mockAgent = startMockGpgAgent({ expectedPin: "123456" })
    await mockAgent.listen()

    const requested: RequestSummary[] = []
    const coordinator = new PinentryCoordinator({
      requestTimeoutMs: 50,
      agentSocketPath: mockAgent.socketPath,
      async getCardStatus(): Promise<YubiKeyCardStatus> {
        return {
          connected: true,
          reader: "Yubico YubiKey OTP FIDO CCID",
          serial: "12345678",
          applicationID: "D2760001240103040006123456780000",
          model: "Yubico",
          version: "3.4",
          signatureCount: 0,
          pinPolicy: "once",
          pinRetries: { user: 2, reset: 0, admin: 3 },
          uif: { sign: "off", decrypt: "off", auth: "off" },
        }
      },
      onRequested(summary) {
        requested.push(summary)
      },
    })

    try {
      const unlockRes = await coordinator.unlock({
        reason: "Sign git commit",
        allowRetry: true,
      })

      expect(unlockRes.ok).toBe(false)
      expect(unlockRes.message).toContain("no keys")
      expect(unlockRes.message).toContain("123456")
      expect(requested).toEqual([])
      expect(mockAgent.receivedCommands).toEqual([])
    } finally {
      coordinator.close()
      await mockAgent.close()
    }
  })

  it("refuses to prompt when a personalized card has no OpenPGP keys loaded", async () => {
    const mockAgent = startMockGpgAgent({ expectedPin: "888888" })
    await mockAgent.listen()

    const requested: RequestSummary[] = []
    const coordinator = new PinentryCoordinator({
      requestTimeoutMs: 50,
      agentSocketPath: mockAgent.socketPath,
      async getCardStatus(): Promise<YubiKeyCardStatus> {
        return {
          connected: true,
          serial: "12345678",
          applicationID: "D2760001240103040006123456780000",
          holder: "Jane Doe",
          pinPolicy: "once",
          pinRetries: { user: 3, reset: 3, admin: 3 },
        }
      },
      onRequested(summary) {
        requested.push(summary)
      },
    })

    try {
      const unlockRes = await coordinator.unlock({
        reason: "Sign git commit",
        allowRetry: true,
      })

      expect(unlockRes.ok).toBe(false)
      expect(unlockRes.message).toBe(
        "YubiKey OpenPGP card has no keys loaded. Generate or import OpenPGP keys before unlocking.",
      )
      expect(requested).toEqual([])
      expect(mockAgent.receivedCommands).toEqual([])
    } finally {
      coordinator.close()
      await mockAgent.close()
    }
  })

  it("does not retry after a bad PIN when card retry counters cannot be read or when card is unpersonalized", async () => {
    const mockAgent = startMockGpgAgent({ expectedPin: "123456" })
    await mockAgent.listen()

    const requested: RequestSummary[] = []
    let callCount = 0

    const coordinator = new PinentryCoordinator({
      agentSocketPath: mockAgent.socketPath,
      async getCardStatus(): Promise<YubiKeyCardStatus> {
        callCount += 1
        return {
          connected: true,
          serial: "12345678",
          applicationID: "D2760001240103040006123456780000",
          holder: "Jane Doe",
          pinRetries: callCount === 1 ? { user: 3, reset: 3, admin: 3 } : undefined,
          keys: { signature: "111122223333444455556666777788889999AAAA" },
        }
      },
      onRequested(summary) {
        requested.push(summary)
        setTimeout(() => {
          coordinator.submit(summary.requestID, "wrong-pin")
        }, 10)
      },
    })

    try {
      const unlockRes = await coordinator.unlock({ allowRetry: true })
      expect(unlockRes.ok).toBe(false)
      expect(requested.length).toBe(1)

      const unpersonalizedRequested: RequestSummary[] = []
      const unpersonalizedCoordinator = new PinentryCoordinator({
        agentSocketPath: mockAgent.socketPath,
        async getCardStatus(): Promise<YubiKeyCardStatus> {
          return {
            connected: true,
            serial: "12345678",
            applicationID: "D2760001240103040006123456780000",
            pinPolicy: "once",
            pinRetries: { user: 2, reset: 0, admin: 3 },
            keys: { signature: "111122223333444455556666777788889999AAAA" },
          }
        },
        onRequested(summary) {
          unpersonalizedRequested.push(summary)
          setTimeout(() => {
            unpersonalizedCoordinator.submit(summary.requestID, "wrong-pin")
          }, 10)
        },
      })

      try {
        const unpersRes = await unpersonalizedCoordinator.unlock({
          reason: "Sign git commit",
          allowRetry: true,
        })
        expect(unpersRes.ok).toBe(false)
        expect(unpersonalizedRequested.length).toBe(1)
        expect(unpersonalizedRequested[0]?.description).toBe(
          "Sign git commit — applet not personalized (default PIN: 123456)",
        )
        expect(unpersonalizedRequested[0]?.pinPolicy).toBe("once")
      } finally {
        unpersonalizedCoordinator.close()
      }
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
  it("parses human-readable and colon-delimited gpg --card-status output to identical YubiKeyCardStatus", () => {
    const humanPersonalized = `
Reader ...........: Yubico YubiKey OTP FIDO CCID
Application ID ...: D2760001240103040006123456780000
Application type .: OpenPGP
Version ..........: 3.4
Manufacturer .....: Yubico
Serial number ....: 12345678
Name of cardholder: Jane Doe
Signature PIN ....: forced
PIN retry counter : 3 0 3
Signature counter : 128
UIF setting ......: Sign=on Decrypt=off Auth=on
Signature key ....: 1111 2222 3333 4444 5555  6666 7777 8888 9999 AAAA
`
    const colonPersonalized = `
Reader:Yubico YubiKey OTP FIDO CCID:AID:D2760001240103040006123456780000:openpgp-card:
version:0304:
vendor:0006:Yubico:
serial:12345678:
name:Jane:Doe:
lang::
sex:u:
url::
login::
forcepin:1:::
keyattr:1:1:2048:
keyattr:2:1:2048:
keyattr:3:1:2048:
maxpinlen:127:127:127:
pinretry:3:0:3:
sigcount:128:::
kdf:off:
uif:1:0:1:
cafpr::::
fpr:111122223333444455556666777788889999AAAA:::
fprtime:1700000000:0:0:
grp:0000000000000000000000000000000000000000:0000000000000000000000000000000000000000:0000000000000000000000000000000000000000:
`
    const expectedPersonalized: YubiKeyCardStatus = {
      connected: true,
      reader: "Yubico YubiKey OTP FIDO CCID",
      applicationID: "D2760001240103040006123456780000",
      serial: "12345678",
      model: "Yubico",
      version: "3.4",
      holder: "Jane Doe",
      pinPolicy: "always",
      pinRetries: { user: 3, reset: 0, admin: 3 },
      signatureCount: 128,
      uif: { sign: "on", decrypt: "off", auth: "on" },
      keys: {
        signature: "111122223333444455556666777788889999AAAA",
      },
    }

    expect(parseCardStatusOutput(humanPersonalized)).toEqual(expectedPersonalized)
    expect(parseCardStatusOutput(colonPersonalized)).toEqual(expectedPersonalized)

    const humanFactory = `
Reader ...........: Yubico YubiKey OTP FIDO CCID
Application ID ...: D2760001240103040006123456780000
Application type .: OpenPGP
Version ..........: 3.4
Manufacturer .....: Yubico
Serial number ....: 12345678
Name of cardholder: [not set]
Language prefs ...: [not set]
Salutation .......: 
URL of public key : [not set]
Login data .......: [not set]
Signature PIN ....: not forced
Key attributes ...: rsa2048 rsa2048 rsa2048
Max. PIN lengths .: 127 127 127
PIN retry counter : 2 0 3
Signature counter : 0
KDF setting ......: off
UIF setting ......: Sign=off Decrypt=off Auth=off
Signature key ....: [none]
Encryption key....: [none]
Authentication key: [none]
General key info..: [none]
`
    const colonFactory = `
Reader:Yubico YubiKey OTP FIDO CCID:AID:D2760001240103040006123456780000:openpgp-card:
version:0304:
vendor:0006:Yubico:
serial:12345678:
name:::
lang::
sex:u:
url::
login::
forcepin:0:::
keyattr:1:1:2048:
keyattr:2:1:2048:
keyattr:3:1:2048:
maxpinlen:127:127:127:
pinretry:2:0:3:
sigcount:0:::
kdf:off:
uif:0:0:0:
cafpr::::
fpr::::
fprtime:0:0:0:
grp:0000000000000000000000000000000000000000:0000000000000000000000000000000000000000:0000000000000000000000000000000000000000:
`
    const expectedFactory: YubiKeyCardStatus = {
      connected: true,
      reader: "Yubico YubiKey OTP FIDO CCID",
      applicationID: "D2760001240103040006123456780000",
      serial: "12345678",
      model: "Yubico",
      version: "3.4",
      pinPolicy: "once",
      pinRetries: { user: 2, reset: 0, admin: 3 },
      signatureCount: 0,
      uif: { sign: "off", decrypt: "off", auth: "off" },
    }

    expect(parseCardStatusOutput(humanFactory)).toEqual(expectedFactory)
    expect(parseCardStatusOutput(colonFactory)).toEqual(expectedFactory)
    expect(formatCardStatusReport(true, expectedFactory)).toContain(
      "Signature PIN Policy: once (not forced)",
    )
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
            PINENTRY_USER_DATA: undefined,
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
            PINENTRY_USER_DATA: undefined,
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

  it("enriches IPC PIN requests with card status via PinentryBridge.getCardStatus and fails fast when user PIN is blocked", async () => {
    const baseTmp = existsSync("/tmp") ? "/tmp" : os.tmpdir()
    const tmpDir = mkdtempSync(path.join(baseTmp, "oc-bridge-card-"))
    const requested: RequestSummary[] = []
    let userRetries = 2

    const coordinator = new PinentryCoordinator({
      onRequested(summary) {
        requested.push(summary)
        if (summary.kind === "pin") {
          setTimeout(() => {
            coordinator.submit(summary.requestID, "424242")
          }, 15)
        }
      },
    })

    const bridge = new PinentryBridge({
      coordinator,
      socketDir: tmpDir,
      async getCardStatus(): Promise<YubiKeyCardStatus> {
        return {
          connected: true,
          serial: "12345678",
          holder: "Jane Doe",
          pinPolicy: "once",
          pinRetries: { user: userRetries, reset: 3, admin: 3 },
          keys: { signature: "111122223333444455556666777788889999AAAA" },
        }
      },
    })
    await bridge.start()

    try {
      const sendPinIpc = () =>
        new Promise<{ ok: boolean; cancelled: boolean; pin?: string }>((resolve, reject) => {
          const sock = net.createConnection({ path: bridge.socketPath })
          let buf = ""
          sock.once("connect", () => {
            sock.write(
              `${JSON.stringify({ type: "pin", token: bridge.token, description: "Please enter PIN" })}\n`,
            )
          })
          sock.on("data", (chunk) => {
            buf += chunk.toString("utf8")
          })
          sock.once("close", () => resolve(JSON.parse(buf.trim())))
          sock.once("error", reject)
        })

      const firstReply = await sendPinIpc()
      expect(firstReply).toEqual({ ok: true, cancelled: false, pin: "424242" })
      expect(requested.length).toBe(1)
      expect(requested[0]?.serial).toBe("12345678")
      expect(requested[0]?.holder).toBe("Jane Doe")
      expect(requested[0]?.pinPolicy).toBe("once")
      expect(requested[0]?.retriesLeft).toBe(2)

      userRetries = 0
      const blockedReply = await sendPinIpc()
      expect(blockedReply).toEqual({ ok: false, cancelled: true })
      expect(requested.length).toBe(1)
    } finally {
      coordinator.close()
      await bridge.close()
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })
})

describe("Pinentry shim target resolution", () => {
  async function startSocket(dir: string, name: string): Promise<{ path: string; close: () => Promise<void> }> {
    const socketPath = path.join(dir, name)
    const server = net.createServer()
    await new Promise<void>((resolve) => server.listen(socketPath, () => resolve()))
    chmodSync(socketPath, 0o600)
    return {
      path: socketPath,
      close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    }
  }

  it("routes the prompt to the instance that owns the command, not the one the agent inherited", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "oc-target-test-"))
    const inherited = await startSocket(tmpDir, "inherited.sock")
    const owner = await startSocket(tmpDir, "owner.sock")

    try {
      const target = resolveIpcTarget(
        {
          PINENTRY_USER_DATA: JSON.stringify({
            sock: owner.path,
            token: "owner-token",
            cmd: "git commit -S",
          }),
          OC_YUBIKEY_SOCK: inherited.path,
          OC_YUBIKEY_TOKEN: "inherited-token",
        },
        path.join(tmpDir, "active.json"),
      )

      expect(target.socketPath).toBe(owner.path)
      expect(target.token).toBe("owner-token")
      expect(target.command).toBe("git commit -S")
    } finally {
      await inherited.close()
      await owner.close()
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it("keeps the socket and the token of one instance together", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "oc-target-test-"))
    const owner = await startSocket(tmpDir, "owner.sock")

    try {
      const target = resolveIpcTarget(
        {
          PINENTRY_USER_DATA: JSON.stringify({ sock: owner.path }),
          OC_YUBIKEY_TOKEN: "inherited-token",
        },
        path.join(tmpDir, "active.json"),
      )

      expect(target.socketPath).toBeUndefined()
      expect(target.token).toBeUndefined()
    } finally {
      await owner.close()
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it("falls back to the pointer of the running instance when the agent passed no user data", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "oc-target-test-"))
    const owner = await startSocket(tmpDir, "owner.sock")
    const pointerPath = path.join(tmpDir, "active.json")
    writeFileSync(
      pointerPath,
      JSON.stringify({ socketPath: owner.path, token: "pointer-token" }),
      { mode: 0o600 },
    )
    chmodSync(pointerPath, 0o600)

    try {
      const target = resolveIpcTarget({}, pointerPath)

      expect(target.socketPath).toBe(owner.path)
      expect(target.token).toBe("pointer-token")
    } finally {
      await owner.close()
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it("drops a socket that is gone instead of prompting the wrong instance", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "oc-target-test-"))
    const gone = path.join(tmpDir, "gone.sock")

    try {
      const target = resolveIpcTarget(
        { OC_YUBIKEY_SOCK: gone, OC_YUBIKEY_TOKEN: "inherited-token" },
        path.join(tmpDir, "active.json"),
      )

      expect(target.socketPath).toBeUndefined()
      expect(target.token).toBeUndefined()
    } finally {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })
})

describe("GnuPG configuration and shell environment", () => {
  it("sets GPG_TTY to /dev/null in shell environments and keeps a newer instance's active.json when an older instance closes", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "oc-gpg-env-test-"))
    const coordinator = new PinentryCoordinator()
    const olderBridge = new PinentryBridge({ coordinator, socketDir: tmpDir })
    const newerBridge = new PinentryBridge({ coordinator, socketDir: tmpDir })

    try {
      await olderBridge.start()
      await newerBridge.start()

      const env: Record<string, string | undefined> = { GPG_TTY: "/dev/ttys001" }
      await newerBridge.prepareShellEnv(env, "git commit -S")
      expect(env.GPG_TTY).toBe("/dev/null")

      await olderBridge.close()
      const pointer = JSON.parse(readFileSync(path.join(tmpDir, "active.json"), "utf8")) as {
        socketPath: string
      }
      expect(pointer.socketPath).toBe(newerBridge.socketPath)
    } finally {
      coordinator.close()
      await olderBridge.close()
      await newerBridge.close()
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it("reports conflicting gpg.conf and gpg-agent.conf settings", () => {
    const parsed = parseGpgConfig(
      "use-agent\npinentry-mode loopback\n",
      "default-cache-ttl 28800\nno-allow-loopback-pinentry\n",
    )
    expect(parsed.pinentryMode).toBe("loopback")
    expect(parsed.allowLoopbackPinentry).toBe(false)
    expect(parsed.warnings).toEqual([
      "gpg.conf sets 'pinentry-mode loopback', which forces gpg to prompt on a terminal instead of delegating PIN and touch prompts to gpg-agent's pinentry-program.",
      "gpg-agent.conf sets 'no-allow-loopback-pinentry', which prevents yubikey_unlock from verifying PINs via Assuan loopback.",
    ])

    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "oc-gnupg-conf-"))
    try {
      writeFileSync(path.join(tmpDir, "gpg.conf"), "pinentry-mode loopback\n")
      writeFileSync(
        path.join(tmpDir, "gpg-agent.conf"),
        `pinentry-program ${path.join(tmpDir, "missing-pinentry")}\n`,
      )
      const inspected = inspectGpgConfiguration({ gnupgHomeDir: tmpDir })
      const report = formatCardStatusReport(true, { connected: false }, inspected)
      expect(report).toContain("GPG Pinentry Mode: loopback")
      expect(report).toContain(
        `Warning: gpg-agent.conf pinentry-program does not exist: ${path.join(tmpDir, "missing-pinentry")}`,
      )
    } finally {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it("injects bin/oc-yubikey-gpg via GIT_CONFIG_* idempotently and intercepts loopback PIN inquiries during git commit -S", async () => {
    const baseTmp = existsSync("/tmp") ? "/tmp" : os.tmpdir()
    const tmpDir = mkdtempSync(path.join(baseTmp, "oc-gpg-wrapper-"))
    const mockGpg = path.join(tmpDir, "mock-gpg")
    writeFileSync(
      mockGpg,
      `#!/bin/sh
cat >/dev/null
echo "[GNUPG:] USERID_HINT 777788889999AAAA Jane Doe <jane@example.com>" >&2
echo "[GNUPG:] NEED_PASSPHRASE_PIN 0 0 0" >&2
echo "[GNUPG:] INQUIRE_MAXLEN 100" >&2
echo "[GNUPG:] GET_HIDDEN passphrase.enter" >&2
IFS= read -r pin <&3
if [ "$pin" != "246810" ]; then
  echo "[GNUPG:] BAD_PASSPHRASE" >&2
  exit 2
fi
echo "[GNUPG:] GOT_IT" >&2
sleep 0.08
echo "[GNUPG:] SIG_CREATED D 22 10 00 1700000000 111122223333444455556666777788889999AAAA" >&2
cat <<'EOF'
-----BEGIN PGP SIGNATURE-----

iHUEABYKAB0WIQQRVkaqpdaQy202rLj2Vl8yobe2lGQUCZ32p0gAKCRCVl8yobe2l
GTestSignatureDataHere==
=1234
-----END PGP SIGNATURE-----
EOF
`,
      { mode: 0o755 },
    )
    chmodSync(mockGpg, 0o755)

    const requested: RequestSummary[] = []
    const resolved: ResolvedEvent[] = []
    const coordinator = new PinentryCoordinator({
      onRequested(summary) {
        requested.push(summary)
        if (summary.kind === "pin") {
          setTimeout(() => {
            coordinator.submit(summary.requestID, "246810")
          }, 15)
        }
      },
      onResolved(event) {
        resolved.push(event)
      },
    })
    const bridge = new PinentryBridge({ coordinator, socketDir: tmpDir })
    await bridge.start()

    try {
      const env: Record<string, string | undefined> = {
        ...process.env,
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "user.signingkey",
        GIT_CONFIG_VALUE_0: "111122223333444455556666777788889999AAAA",
        OC_YUBIKEY_GPG_BIN: mockGpg,
        OC_YUBIKEY_GPG_TOUCH_DELAY_MS: "20",
      }
      await bridge.prepareShellEnv(env, "git commit -S -m test")
      await bridge.prepareShellEnv(env, "git commit -S -m test")

      expect(env.GIT_CONFIG_COUNT).toBe("2")
      expect(env.GIT_CONFIG_KEY_0).toBe("user.signingkey")
      expect(env.GIT_CONFIG_KEY_1).toBe("gpg.program")
      expect(env.GIT_CONFIG_VALUE_1).toBe(resolveGpgWrapperPath())

      const runGit = (args: string[]) =>
        new Promise<{ code: number; stdout: string }>((resolve) => {
          const child = spawn("git", ["-C", tmpDir, ...args], {
            env,
            stdio: ["ignore", "pipe", "pipe"],
          })
          let stdout = ""
          child.stdout.on("data", (c) => {
            stdout += String(c)
          })
          child.on("close", (code) => resolve({ code: code ?? 1, stdout }))
        })

      await runGit(["init"])
      await runGit(["config", "user.name", "Jane Doe"])
      await runGit(["config", "user.email", "jane@example.com"])

      const commitRes = await runGit(["commit", "--allow-empty", "-S", "-m", "signed commit"])
      expect(commitRes.code).toBe(0)
      expect(requested.length).toBe(2)
      expect(requested[0]?.kind).toBe("pin")
      expect(requested[0]?.description).toContain("Jane Doe <jane@example.com>")
      expect(requested[0]?.command).toBe("git commit -S -m test")
      expect(requested[1]?.kind).toBe("touch")
      expect(requested[1]?.description).toContain("Jane Doe <jane@example.com>")
      expect(resolved[1]).toEqual({
        requestID: requested[1]!.requestID,
        outcome: "confirmed",
      })

      const catRes = await runGit(["cat-file", "-p", "HEAD"])
      expect(catRes.stdout).toContain("-----BEGIN PGP SIGNATURE-----")
    } finally {
      coordinator.close()
      await bridge.close()
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it("propagates oc-yubikey env vars to process.env for non-shell plugin spawns and restores them on close", async () => {
    const baseTmp = existsSync("/tmp") ? "/tmp" : os.tmpdir()
    const tmpDir = mkdtempSync(path.join(baseTmp, "oc-proc-env-"))
    const savedEnv = {
      OC_YUBIKEY_SOCK: process.env.OC_YUBIKEY_SOCK,
      OC_YUBIKEY_TOKEN: process.env.OC_YUBIKEY_TOKEN,
      PINENTRY_USER_DATA: process.env.PINENTRY_USER_DATA,
      SSH_ASKPASS: process.env.SSH_ASKPASS,
      GIT_CONFIG_COUNT: process.env.GIT_CONFIG_COUNT,
      GIT_CONFIG_KEY_0: process.env.GIT_CONFIG_KEY_0,
      GIT_CONFIG_VALUE_0: process.env.GIT_CONFIG_VALUE_0,
    }

    delete process.env.OC_YUBIKEY_SOCK
    delete process.env.OC_YUBIKEY_TOKEN
    delete process.env.PINENTRY_USER_DATA
    delete process.env.SSH_ASKPASS
    delete process.env.GIT_CONFIG_COUNT
    delete process.env.GIT_CONFIG_KEY_0
    delete process.env.GIT_CONFIG_VALUE_0

    const ownerRequested: RequestSummary[] = []
    const otherRequested: RequestSummary[] = []
    const ownerCoordinator = new PinentryCoordinator({
      onRequested(summary) {
        ownerRequested.push(summary)
        setTimeout(() => ownerCoordinator.confirmTouch(summary.requestID), 15)
      },
    })
    const otherCoordinator = new PinentryCoordinator({
      onRequested(summary) {
        otherRequested.push(summary)
      },
    })

    const ownerBridge = new PinentryBridge({ coordinator: ownerCoordinator, socketDir: tmpDir })
    const otherBridge = new PinentryBridge({ coordinator: otherCoordinator, socketDir: tmpDir })

    try {
      await ownerBridge.start()
      await ownerBridge.prepareShellEnv(process.env)
      await otherBridge.start()

      expect(process.env.OC_YUBIKEY_SOCK).toBe(ownerBridge.socketPath)
      expect(process.env.SSH_ASKPASS).toBe(resolvePinentryCliPath())
      expect(process.env.GIT_CONFIG_KEY_0).toBe("gpg.program")
      expect(process.env.GIT_CONFIG_VALUE_0).toBe(resolveGpgWrapperPath())

      const askpassExitCode = await new Promise<number>((resolve) => {
        const child = spawn(
          process.env.SSH_ASKPASS!,
          ["Confirm user presence for key ED25519-SK SHA256:nonShellSpawn"],
          { stdio: ["ignore", "pipe", "pipe"] },
        )
        child.on("close", (code) => resolve(code ?? 1))
      })

      expect(askpassExitCode).toBe(0)
      expect(ownerRequested.length).toBe(1)
      expect(ownerRequested[0]?.fingerprint).toBe("SHA256:nonShellSpawn")
      expect(otherRequested.length).toBe(0)

      await ownerBridge.close()
      expect(process.env.OC_YUBIKEY_SOCK).toBeUndefined()
      expect(process.env.SSH_ASKPASS).toBeUndefined()
      expect(process.env.GIT_CONFIG_COUNT).toBeUndefined()
    } finally {
      ownerCoordinator.close()
      otherCoordinator.close()
      await ownerBridge.close()
      await otherBridge.close()
      for (const [k, v] of Object.entries(savedEnv)) {
        if (v === undefined) delete process.env[k]
        else process.env[k] = v
      }
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it("propagates SSH_ASKPASS to Bun.spawn calls that omit env and scopes prompts to the requesting worktree location", async () => {
    const baseTmp = existsSync("/tmp") ? "/tmp" : os.tmpdir()
    const tmpDir = mkdtempSync(path.join(baseTmp, "oc-bun-spawn-"))
    const worktreeA = path.join(tmpDir, "wt-a")
    const worktreeB = path.join(tmpDir, "wt-b")
    const upstreamSock = path.join(tmpDir, "upstream-ssh.sock")
    mkdirSync(worktreeA, { recursive: true })
    mkdirSync(worktreeB, { recursive: true })

    expect(isMatchingLocation({ directory: worktreeA }, { directory: worktreeA })).toBe(true)
    expect(isMatchingLocation({ directory: worktreeA }, { directory: worktreeB })).toBe(false)
    expect(isMatchingLocation(undefined, { directory: worktreeA })).toBe(false)
    expect(
      isMatchingLocation(
        { directory: worktreeA, workspaceID: "ws-1" },
        { directory: worktreeA, workspaceID: "ws-2" },
      ),
    ).toBe(false)

    const upstreamServer = net.createServer(() => {})
    await new Promise<void>((resolve) => upstreamServer.listen(upstreamSock, () => resolve()))
    chmodSync(upstreamSock, 0o600)

    const savedEnv = {
      OC_YUBIKEY_SOCK: process.env.OC_YUBIKEY_SOCK,
      OC_YUBIKEY_TOKEN: process.env.OC_YUBIKEY_TOKEN,
      OC_YUBIKEY_COMMAND: process.env.OC_YUBIKEY_COMMAND,
      PINENTRY_USER_DATA: process.env.PINENTRY_USER_DATA,
      SSH_ASKPASS: process.env.SSH_ASKPASS,
      SSH_ASKPASS_REQUIRE: process.env.SSH_ASKPASS_REQUIRE,
      DISPLAY: process.env.DISPLAY,
      GPG_TTY: process.env.GPG_TTY,
      SSH_AUTH_SOCK: process.env.SSH_AUTH_SOCK,
      GIT_CONFIG_COUNT: process.env.GIT_CONFIG_COUNT,
      GIT_CONFIG_KEY_0: process.env.GIT_CONFIG_KEY_0,
      GIT_CONFIG_VALUE_0: process.env.GIT_CONFIG_VALUE_0,
    }

    delete process.env.OC_YUBIKEY_SOCK
    delete process.env.OC_YUBIKEY_TOKEN
    delete process.env.OC_YUBIKEY_COMMAND
    delete process.env.PINENTRY_USER_DATA
    delete process.env.SSH_ASKPASS
    delete process.env.SSH_ASKPASS_REQUIRE
    delete process.env.DISPLAY
    process.env.GPG_TTY = "/dev/ttys009"
    process.env.SSH_AUTH_SOCK = upstreamSock
    delete process.env.GIT_CONFIG_COUNT
    delete process.env.GIT_CONFIG_KEY_0
    delete process.env.GIT_CONFIG_VALUE_0

    const requestedA: RequestSummary[] = []
    const requestedB: RequestSummary[] = []
    const coordinatorA = new PinentryCoordinator({
      onRequested(summary) {
        requestedA.push(summary)
        setTimeout(() => coordinatorA.confirmTouch(summary.requestID), 15)
      },
    })
    const coordinatorB = new PinentryCoordinator({
      onRequested(summary) {
        requestedB.push(summary)
        setTimeout(() => coordinatorB.confirmTouch(summary.requestID), 15)
      },
    })

    const bridgeA = new PinentryBridge({
      coordinator: coordinatorA,
      socketDir: tmpDir,
      directory: worktreeA,
    })
    await bridgeA.start()
    await bridgeA.prepareShellEnv(process.env)

    const bridgeB = new PinentryBridge({
      coordinator: coordinatorB,
      socketDir: tmpDir,
      directory: worktreeB,
    })
    await bridgeB.start()
    await bridgeB.prepareShellEnv(process.env)

    try {
      const proc = Bun.spawn(
        [
          "sh",
          "-c",
          'exec "$SSH_ASKPASS" "Confirm user presence for key ED25519-SK SHA256:bunSpawnPush"',
        ],
        { cwd: worktreeA, stdout: "pipe", stderr: "pipe" },
      )
      const exitCode = await proc.exited

      expect(exitCode).toBe(0)
      expect(requestedA.length).toBe(1)
      expect(requestedA[0]?.kind).toBe("touch")
      expect(requestedA[0]?.keyType).toBe("ED25519-SK")
      expect(requestedA[0]?.fingerprint).toBe("SHA256:bunSpawnPush")
      expect(requestedB.length).toBe(0)

      const syncRes = Bun.spawnSync(
        ["sh", "-c", 'printf "%s|%s" "$OC_YUBIKEY_SOCK" "$SSH_AUTH_SOCK"'],
        { cwd: worktreeA },
      )
      const [syncIpcSock, syncSshSock] = (syncRes.stdout?.toString("utf8") ?? "").split("|")
      expect(syncIpcSock).toBe(bridgeA.socketPath)
      expect(syncSshSock).toContain("ssh-")
      expect(syncSshSock).not.toBe(upstreamSock)

      await bridgeA.close()
      expect(process.env.OC_YUBIKEY_SOCK).toBe(bridgeB.socketPath)
      expect(process.env.SSH_AUTH_SOCK).toContain("ssh-")
      expect(process.env.SSH_AUTH_SOCK).not.toBe(upstreamSock)

      await bridgeB.close()
      expect(process.env.OC_YUBIKEY_SOCK).toBeUndefined()
      expect(process.env.SSH_ASKPASS).toBeUndefined()
      expect(process.env.GPG_TTY).toBe("/dev/ttys009")
      expect(process.env.SSH_AUTH_SOCK).toBe(upstreamSock)
    } finally {
      coordinatorA.close()
      coordinatorB.close()
      await bridgeA.close()
      await bridgeB.close()
      await new Promise<void>((resolve) => upstreamServer.close(() => resolve()))
      for (const [k, v] of Object.entries(savedEnv)) {
        if (v === undefined) delete process.env[k]
        else process.env[k] = v
      }
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it("multiplexes SSH connections via GIT_SSH_COMMAND and preserves active session routing across background location boots", async () => {
    const baseTmp = existsSync("/tmp") ? "/tmp" : os.tmpdir()
    const tmpDir = mkdtempSync(path.join(baseTmp, "oc-ssh-mux-"))
    const repoWorktrees = path.join(tmpDir, "repo-worktrees")
    const worktreeA = path.join(repoWorktrees, "wt-a")
    const worktreeSibling = path.join(repoWorktrees, "wt-sibling")
    const symlinkToWorktreeA = path.join(tmpDir, "wt-a-link")
    const idleBackgroundDir = path.join(tmpDir, "idle-bg")
    mkdirSync(worktreeA, { recursive: true })
    mkdirSync(worktreeSibling, { recursive: true })
    mkdirSync(idleBackgroundDir, { recursive: true })
    symlinkSync(worktreeA, symlinkToWorktreeA)

    const mockSsh = path.join(tmpDir, "mock-ssh.sh")
    writeFileSync(
      mockSsh,
      `#!/bin/sh
control_master=""
control_persist=""
control_path=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o)
      shift
      case "$1" in
        ControlMaster=*) control_master="\${1#ControlMaster=}" ;;
        ControlPersist=*) control_persist="\${1#ControlPersist=}" ;;
        ControlPath=*) control_path="\${1#ControlPath=}" ;;
      esac
      ;;
    -oControlMaster=*) control_master="\${1#-oControlMaster=}" ;;
    -oControlPersist=*) control_persist="\${1#-oControlPersist=}" ;;
    -oControlPath=*) control_path="\${1#-oControlPath=}" ;;
  esac
  shift
done

if [ "$control_master" != "auto" ] || [ -z "$control_persist" ] || [ -z "$control_path" ]; then
  echo "missing ControlMaster options: master=$control_master persist=$control_persist path=$control_path" >&2
  exit 2
fi

mux_file=$(printf '%s' "$control_path" | sed 's/%C/testmuxhash/g')
if [ ! -e "$mux_file" ]; then
  if [ -z "$SSH_ASKPASS" ]; then
    echo "missing SSH_ASKPASS" >&2
    exit 3
  fi
  "$SSH_ASKPASS" "Confirm user presence for key ED25519-SK SHA256:muxHardwareKey" || exit 4
  : > "$mux_file"
fi
echo "ssh-mux-ok"
exit 0
`,
      { mode: 0o755 },
    )
    chmodSync(mockSsh, 0o755)

    const savedEnv = {
      OC_YUBIKEY_SOCK: process.env.OC_YUBIKEY_SOCK,
      OC_YUBIKEY_TOKEN: process.env.OC_YUBIKEY_TOKEN,
      OC_YUBIKEY_COMMAND: process.env.OC_YUBIKEY_COMMAND,
      OC_YUBIKEY_SSH_BIN: process.env.OC_YUBIKEY_SSH_BIN,
      PINENTRY_USER_DATA: process.env.PINENTRY_USER_DATA,
      SSH_ASKPASS: process.env.SSH_ASKPASS,
      SSH_ASKPASS_REQUIRE: process.env.SSH_ASKPASS_REQUIRE,
      DISPLAY: process.env.DISPLAY,
      GIT_SSH_COMMAND: process.env.GIT_SSH_COMMAND,
      GPG_TTY: process.env.GPG_TTY,
      GIT_CONFIG_COUNT: process.env.GIT_CONFIG_COUNT,
      GIT_CONFIG_KEY_0: process.env.GIT_CONFIG_KEY_0,
      GIT_CONFIG_VALUE_0: process.env.GIT_CONFIG_VALUE_0,
    }

    delete process.env.OC_YUBIKEY_SOCK
    delete process.env.OC_YUBIKEY_TOKEN
    delete process.env.OC_YUBIKEY_COMMAND
    process.env.OC_YUBIKEY_SSH_BIN = mockSsh
    delete process.env.PINENTRY_USER_DATA
    delete process.env.SSH_ASKPASS
    delete process.env.SSH_ASKPASS_REQUIRE
    delete process.env.DISPLAY
    delete process.env.GIT_SSH_COMMAND
    delete process.env.GIT_CONFIG_COUNT
    delete process.env.GIT_CONFIG_KEY_0
    delete process.env.GIT_CONFIG_VALUE_0

    const requestedA: RequestSummary[] = []
    const requestedB: RequestSummary[] = []
    const coordinatorA = new PinentryCoordinator({
      onRequested(summary) {
        requestedA.push(summary)
        setTimeout(() => coordinatorA.confirmTouch(summary.requestID), 15)
      },
    })
    const coordinatorB = new PinentryCoordinator({
      onRequested(summary) {
        requestedB.push(summary)
        setTimeout(() => coordinatorB.confirmTouch(summary.requestID), 15)
      },
    })

    const bridgeA = new PinentryBridge({
      coordinator: coordinatorA,
      socketDir: tmpDir,
      directory: worktreeA,
    })
    await bridgeA.start()
    await bridgeA.prepareShellEnv(process.env)

    const shellInvocationEnv: Record<string, string | undefined> = { ...process.env }
    await bridgeA.prepareShellEnv(shellInvocationEnv, "git fetch origin")

    const bridgeB = new PinentryBridge({
      coordinator: coordinatorB,
      socketDir: tmpDir,
      directory: idleBackgroundDir,
    })
    await bridgeB.start()
    await bridgeB.prepareShellEnv(process.env)

    try {
      expect(shellInvocationEnv.GIT_SSH_COMMAND?.endsWith("oc-yubikey-ssh")).toBe(true)
      expect(isMatchingLocation({ directory: worktreeA }, { directory: symlinkToWorktreeA })).toBe(true)

      const runViaGitSsh = async (
        cwd: string | undefined,
        withCustomEnv: boolean,
      ): Promise<{ code: number; stdout: string; stderr: string }> => {
        const proc = Bun.spawn(
          ["sh", "-c", 'exec "$GIT_SSH_COMMAND" autodoc@autodoc.ghe.com "git-upload-pack repo.git"'],
          {
            ...(cwd ? { cwd } : {}),
            ...(withCustomEnv ? { env: { ...process.env, GH_HOST: "autodoc.ghe.com" } } : {}),
            stdout: "pipe",
            stderr: "pipe",
          },
        )
        const [stdout, stderr, code] = await Promise.all([
          new Response(proc.stdout).text(),
          new Response(proc.stderr).text(),
          proc.exited,
        ])
        return { code, stdout: stdout.trim(), stderr: stderr.trim() }
      }

      const firstRun = await runViaGitSsh(worktreeA, true)
      expect(firstRun.code).toBe(0)
      expect(firstRun.stdout).toBe("ssh-mux-ok")
      expect(requestedA.length).toBe(1)
      expect(requestedA[0]?.fingerprint).toBe("SHA256:muxHardwareKey")
      expect(requestedB.length).toBe(0)

      const secondRun = await runViaGitSsh(worktreeSibling, false)
      expect(secondRun.code).toBe(0)
      expect(secondRun.stdout).toBe("ssh-mux-ok")
      expect(requestedA.length).toBe(1)
      expect(requestedB.length).toBe(0)

      const noCwdAskpass = Bun.spawn(
        ["sh", "-c", 'exec "$SSH_ASKPASS" "Confirm user presence for key ED25519-SK SHA256:noCwdTouch"'],
        { stdout: "pipe", stderr: "pipe" },
      )
      expect(await noCwdAskpass.exited).toBe(0)
      expect(requestedA.length).toBe(2)
      expect(requestedA[1]?.fingerprint).toBe("SHA256:noCwdTouch")
      expect(requestedB.length).toBe(0)
    } finally {
      coordinatorA.close()
      coordinatorB.close()
      await bridgeA.close()
      await bridgeB.close()
      for (const [k, v] of Object.entries(savedEnv)) {
        if (v === undefined) delete process.env[k]
        else process.env[k] = v
      }
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it("skips redundant PIN prompts in coordinator.unlock when gpg-agent already has the OpenPGP PIN cached", async () => {
    const mockAgent = startMockGpgAgent({ expectedPin: "888888" })
    await mockAgent.listen()

    const requested: RequestSummary[] = []
    const coordinator = new PinentryCoordinator({
      agentSocketPath: mockAgent.socketPath,
      async getCardStatus(): Promise<YubiKeyCardStatus> {
        return {
          connected: true,
          serial: "23400176",
          applicationID: "D2760001240100000006234001760000",
          holder: "Yago Riveiro",
          pinPolicy: "once",
          pinRetries: { user: 3, reset: 0, admin: 3 },
          uif: { sign: "off", decrypt: "off", auth: "off" },
          keys: { signature: "111122223333444455556666777788889999AAAA" },
        }
      },
      onRequested(summary) {
        requested.push(summary)
        setTimeout(() => {
          coordinator.submit(summary.requestID, "888888")
        }, 10)
      },
    })

    try {
      const firstUnlock = await coordinator.unlock({
        reason: "Sign first commit",
        allowRetry: true,
      })
      expect(firstUnlock.ok).toBe(true)
      expect(requested.length).toBe(1)
      expect(mockAgent.isPinCached()).toBe(true)

      const secondUnlock = await coordinator.unlock({
        reason: "Sign amended commit",
        allowRetry: true,
      })
      expect(secondUnlock.ok).toBe(true)
      expect(requested.length).toBe(1)
    } finally {
      coordinator.close()
      await mockAgent.close()
    }
  })
})
