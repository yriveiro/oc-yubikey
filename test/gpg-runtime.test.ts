import { describe, expect, it } from "bun:test"
import { spawn } from "node:child_process"
import {
  chmodSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs"
import net from "node:net"
import os from "node:os"
import path from "node:path"
import { resolvePinentryCliPath } from "../src/bridge.ts"
import { PinentryCoordinator } from "../src/coordinator.ts"
import { GpgRuntime, classifyClientAssuanLine } from "../src/gpg-runtime.ts"
import {
  assertMaxSocketPathLength,
  assertSafeConfigFilePath,
  createSecureRuntimeRoot,
  sanitizeDisplayText,
} from "../src/protocol.ts"
import type { RequestSummary, ResolvedEvent } from "../src/rpc.ts"
import { GpgAgentAssuanClient, execCommand } from "../src/yubikey.ts"

function throwExpectedError(fn: () => unknown): string {
  try {
    fn()
    return "DID_NOT_THROW"
  } catch (err) {
    return err instanceof Error ? err.message : String(err)
  }
}

describe("GpgRuntime boundary validation and Assuan allowlist", () => {
  it("permits safe signing and card-read Assuan verbs while blocking passphrase harvesting and agent mutations", () => {
    expect(classifyClientAssuanLine("RESET")).toEqual({ action: "forward", line: "RESET" })
    expect(classifyClientAssuanLine("KEYINFO --list")).toEqual({
      action: "forward",
      line: "KEYINFO --list",
    })
    expect(classifyClientAssuanLine("SCD SERIALNO")).toEqual({
      action: "forward",
      line: "SCD SERIALNO",
    })
    expect(classifyClientAssuanLine("SCD GETATTR UIF-1")).toEqual({
      action: "forward",
      line: "SCD GETATTR UIF-1",
    })
    expect(classifyClientAssuanLine("OPTION ttytype=xterm-256color")).toEqual({
      action: "forward",
      line: "OPTION ttytype=xterm-256color",
    })
    expect(classifyClientAssuanLine("OPTION pinentry-mode=ask")).toEqual({
      action: "forward",
      line: "OPTION pinentry-mode=ask",
    })
    expect(classifyClientAssuanLine("PKSIGN --hash=sha512")).toEqual({
      action: "forward",
      line: "PKSIGN --hash=sha512",
      cryptoVerb: "PKSIGN",
    })
    expect(classifyClientAssuanLine("PKDECRYPT")).toEqual({
      action: "forward",
      line: "PKDECRYPT",
      cryptoVerb: "PKDECRYPT",
    })
    expect(classifyClientAssuanLine("PKAUTH")).toEqual({
      action: "forward",
      line: "PKAUTH",
      cryptoVerb: "PKAUTH",
    })

    expect(classifyClientAssuanLine("OPTION putenv=PINENTRY_USER_DATA=spoofed")).toEqual({
      action: "reply-ok",
    })
    expect(classifyClientAssuanLine("OPTION pinentry-user-data=spoofed")).toEqual({
      action: "reply-ok",
    })

    expect(classifyClientAssuanLine("OPTION pinentry-mode=loopback")).toEqual({ action: "forbid" })
    expect(classifyClientAssuanLine("GET_PASSPHRASE --data key X X X")).toEqual({
      action: "forbid",
    })
    expect(classifyClientAssuanLine("RELOADAGENT")).toEqual({ action: "forbid" })
    expect(classifyClientAssuanLine("KILLAGENT")).toEqual({ action: "forbid" })
    expect(classifyClientAssuanLine("PRESET_PASSPHRASE ABCD -1 3132")).toEqual({
      action: "forbid",
    })
    expect(classifyClientAssuanLine("SCD APDU 00A40400")).toEqual({ action: "forbid" })
    expect(classifyClientAssuanLine("SCD RESET")).toEqual({ action: "forbid" })
    expect(classifyClientAssuanLine("SCD CHECKPIN D27600012401")).toEqual({ action: "forbid" })
    expect(classifyClientAssuanLine("RESET\nRELOADAGENT")).toEqual({ action: "forbid" })
  })

  it("allocates 0700 unpredictable runtime roots, enforces 103-byte socket caps, strips directional Unicode, and ignores untrusted PATH in bin/oc-yubikey", async () => {
    const root = createSecureRuntimeRoot()
    try {
      expect(lstatSync(root).mode & 0o777).toBe(0o700)
      const exact103 = `/${"a".repeat(102)}`
      expect(assertMaxSocketPathLength(exact103)).toBe(exact103)
      expect(throwExpectedError(() => assertMaxSocketPathLength(`/${"a".repeat(103)}`))).toContain(
        "exceeds 103 bytes",
      )
      expect(
        throwExpectedError(() => assertSafeConfigFilePath("/tmp/bad\npinentry-program /x", "cfg")),
      ).toContain("Unsafe cfg path")
      expect(sanitizeDisplayText("Sign\u200e\u200f\u061c\r\nKey\u202e\ufeff")).toBe("Sign Key")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }

    const poisonDir = mkdtempSync(path.join(os.tmpdir(), "ocyk-poison-path-"))
    const markerFile = path.join(poisonDir, "hijacked.txt")
    const fakeBun = path.join(poisonDir, "bun")
    writeFileSync(
      fakeBun,
      `#!/bin/sh\necho hijacked > "${markerFile}"\nexit 99\n`,
      { mode: 0o755 },
    )
    chmodSync(fakeBun, 0o755)

    try {
      const greeting = await new Promise<string>((resolve) => {
        const child = spawn(resolvePinentryCliPath(), [], {
          env: {
            HOME: os.homedir(),
            PATH: poisonDir,
          },
          stdio: ["pipe", "pipe", "pipe"],
        })
        let out = ""
        child.stdout.on("data", (chunk: Buffer | string) => {
          out += String(chunk)
          if (out.includes("OK")) child.stdin.write("BYE\n")
        })
        child.on("close", () => resolve(out))
      })

      expect(greeting).toContain("OK Pleased to meet you")
      expect(existsSync(markerFile)).toBe(false)
    } finally {
      rmSync(poisonDir, { recursive: true, force: true })
    }
  })

  it("imports public keys without touching source GNUPGHOME, signs headlessly via dedicated gpg-agent, and forbids privileged Assuan commands on the session socket", async () => {
    const sourceHome = mkdtempSync("/tmp/ocyk-src-")
    chmodSync(sourceHome, 0o700)
    writeFileSync(path.join(sourceHome, "gpg.conf"), "no-tty\npinentry-mode loopback\n", {
      mode: 0o600,
    })
    writeFileSync(path.join(sourceHome, "gpg-agent.conf"), "allow-loopback-pinentry\n", {
      mode: 0o600,
    })

    const cleanSourceEnv = {
      HOME: os.homedir(),
      PATH: "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
      GNUPGHOME: sourceHome,
    }

    await execCommand(
      "gpg",
      [
        "--batch",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "secret-pin-77",
        "--quick-generate-key",
        "Runtime Signer <signer@example.com>",
        "ed25519",
        "sign",
        "never",
      ],
      { env: cleanSourceEnv },
    )

    const cardSnapshot = {
      connected: true,
      serial: "87654321",
      holder: "Runtime Signer",
      pinPolicy: "once" as const,
      pinRetries: { user: 3, reset: 3, admin: 3 },
      keys: { signature: "111122223333444455556666777788889999AAAA" },
    }

    const requested: RequestSummary[] = []
    const coordinator = new PinentryCoordinator({
      getCardStatus: () => Promise.resolve(cardSnapshot),
      onRequested(summary) {
        requested.push(summary)
        if (summary.kind === "pin") {
          setTimeout(() => coordinator.submit(summary.requestID, "secret-pin-77"), 15)
        }
      },
    })

    const runtime = new GpgRuntime({
      coordinator,
      sourceGnupgHome: sourceHome,
      systemScdaemonSock: path.join(sourceHome, "nonexistent.scdaemon"),
      getCardStatus: () => Promise.resolve(cardSnapshot),
    })

    try {
      const session = await runtime.ensureSessionClient("ses_sign_1", "git commit -S -m feat")
      expect(lstatSync(path.join(session.gnupgHome, "gpg.conf")).mode & 0o777).toBe(0o400)

      cpSyncKeyFile(sourceHome, runtime.agentHome)
      await runtime.syncPublicKeyring()

      const signRes = await execCommand(
        "gpg",
        ["--batch", "--armor", "--detach-sign"],
        {
          env: {
            HOME: os.homedir(),
            PATH: "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
            GNUPGHOME: session.gnupgHome,
          },
          input: "signed commit tree payload\n",
        },
      )

      expect(signRes.code).toBe(0)
      expect(signRes.stdout).toContain("-----BEGIN PGP SIGNATURE-----")
      expect(requested.length).toBe(1)
      expect(requested[0]?.kind).toBe("pin")
      expect(requested[0]?.command).toBe("git commit -S -m feat")
      expect(requested[0]?.serial).toBe("87654321")

      const ref = runtime.registerInvocation({ sessionID: "ses_sign_1", command: "git tag -s" })
      expect(runtime.lookupInvocation(ref)).toEqual({
        sessionID: "ses_sign_1",
        command: "git tag -s",
      })

      const client = await GpgAgentAssuanClient.connect(session.socketPath)
      try {
        const reloadRes = await client.command("RELOADAGENT")
        expect(reloadRes.ok).toBe(false)
        expect(reloadRes.errorCode).toBe(67109115)

        const getPassRes = await client.command("GET_PASSPHRASE --data k X X X")
        expect(getPassRes.ok).toBe(false)
        expect(getPassRes.errorCode).toBe(67109115)

        const loopbackRes = await client.command("OPTION pinentry-mode=loopback")
        expect(loopbackRes.ok).toBe(false)
        expect(loopbackRes.errorCode).toBe(67109115)

        const scdApduRes = await client.command("SCD APDU 00A40400")
        expect(scdApduRes.ok).toBe(false)
        expect(scdApduRes.errorCode).toBe(67109115)
      } finally {
        await client.close()
      }
      const agentDirect = await GpgAgentAssuanClient.connect(runtime.agentSocketPath)
      try {
        const seeded = await agentDirect.command("GET_PASSPHRASE --data lock-probe X Prompt Desc")
        expect(seeded.ok).toBe(true)
        expect(seeded.dataLines).toEqual(["secret-pin-77"])

        const beforeLock = await agentDirect.command(
          "GET_PASSPHRASE --data --no-ask lock-probe X Prompt Desc",
        )
        expect(beforeLock.ok).toBe(true)
        expect(beforeLock.dataLines).toEqual(["secret-pin-77"])
      } finally {
        await agentDirect.close()
      }

      const lockRes = await runtime.lock()
      expect(lockRes.ok).toBe(true)
      expect(runtime.isLocked).toBe(true)

      const agentAfterLock = await GpgAgentAssuanClient.connect(runtime.agentSocketPath)
      try {
        const afterLock = await agentAfterLock.command(
          "GET_PASSPHRASE --data --no-ask lock-probe X Prompt Desc",
        )
        expect(afterLock.ok).toBe(false)
      } finally {
        await agentAfterLock.close()
      }
    } finally {
      coordinator.close()
      await runtime.stop()
      await execCommand("gpgconf", ["--kill", "all"], { env: cleanSourceEnv })
      expect(existsSync(runtime.runtimeRoot)).toBe(false)
      rmSync(sourceHome, { recursive: true, force: true })
    }
  })

  it("relays S.scdaemon commands while blocking RESET/KILLSCDAEMON, opens TouchModal on UIF=on PKSIGN with Esc abort, and locks only the dedicated agent", async () => {
    const mockDir = mkdtempSync("/tmp/ocyk-scd-")
    chmodSync(mockDir, 0o700)
    const mockScdSock = path.join(mockDir, "S.scdaemon")
    const receivedBySystemScd: string[] = []
    let holdSignReply = false
    let releaseSignReply: (() => void) | undefined

    const mockScdServer = net.createServer((sock) => {
      sock.write("OK GNU Privacy Guard's Smartcard server ready\n")
      let buf = ""
      sock.on("data", (chunk: Buffer | string) => {
        buf += String(chunk)
        let idx = buf.indexOf("\n")
        while (idx !== -1) {
          const line = buf.slice(0, idx).replace(/\r$/, "").trim()
          buf = buf.slice(idx + 1)
          idx = buf.indexOf("\n")
          if (!line) continue
          receivedBySystemScd.push(line)
          if (line === "GETATTR UIF-1") {
            sock.write("S UIF-1 1\nOK\n")
          } else if (line.startsWith("PKSIGN")) {
            if (holdSignReply) {
              releaseSignReply = () => {
                if (!sock.destroyed) sock.write("D (7:sig-val)\nOK\n")
              }
            } else {
              sock.write("D (7:sig-val)\nOK\n")
            }
          } else if (line === "BYE") {
            sock.end("OK closing\n")
          } else {
            sock.write("OK\n")
          }
        }
      })
    })
    await new Promise<void>((resolve) => mockScdServer.listen(mockScdSock, () => resolve()))
    chmodSync(mockScdSock, 0o600)

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

    const runtime = new GpgRuntime({
      coordinator,
      sourceGnupgHome: mockDir,
      systemScdaemonSock: mockScdSock,
    })

    try {
      await runtime.start()
      expect(runtime.isLocked).toBe(false)
      runtime.registerInvocation({ sessionID: "ses_uif", command: "git tag -s v1.0.0" })

      const scdClient = await GpgAgentAssuanClient.connect(runtime.scdProxySocketPath)
      try {
        expect((await scdClient.command("OPTION event-signal=31")).ok).toBe(true)
        const sockNameRes = await scdClient.command("GETINFO socket_name")
        expect(sockNameRes.ok).toBe(true)
        expect(sockNameRes.dataLines[0]).toBe(runtime.scdProxySocketPath)

        const resetsBefore = runtime.blockedScdaemonResets
        expect((await scdClient.command("RESET")).ok).toBe(true)
        expect((await scdClient.command("RESTART")).ok).toBe(true)
        expect((await scdClient.command("KILLSCDAEMON")).ok).toBe(true)
        expect(runtime.blockedScdaemonResets - resetsBefore).toBe(3)
        expect(receivedBySystemScd.some((cmd) => /^(RESET|RESTART|KILLSCDAEMON)$/i.test(cmd))).toBe(
          false,
        )

        expect((await scdClient.command("GETATTR UIF-1")).ok).toBe(true)
        holdSignReply = true
        const signPromise = scdClient.command("PKSIGN --hash=sha512 OPENPGP.1")

        await waitUntil(() => requested.length === 1)
        expect(requested[0]?.kind).toBe("touch")
        expect(requested[0]?.command).toBe("git tag -s v1.0.0")

        releaseSignReply?.()
        const signRes = await signPromise
        expect(signRes.ok).toBe(true)
        expect(resolved[0]).toEqual({ requestID: requested[0]!.requestID, outcome: "confirmed" })
      } finally {
        await scdClient.close()
      }

      const scdCancelClient = await GpgAgentAssuanClient.connect(runtime.scdProxySocketPath)
      try {
        holdSignReply = true
        const cancelSignPromise = scdCancelClient.command("PKSIGN --hash=sha512 OPENPGP.1")
        await waitUntil(() => requested.length === 2)
        coordinator.cancel(requested[1]!.requestID, "user-pressed-escape")
        const cancelledRes = await cancelSignPromise
        expect(cancelledRes.ok).toBe(false)
        expect(cancelledRes.errorCode).toBe(83886179)
      } finally {
        scdCancelClient.destroy()
      }

      const lockRes = await runtime.lock()
      expect(lockRes.ok).toBe(true)
      expect(runtime.isLocked).toBe(true)
      expect(receivedBySystemScd.some((cmd) => /RESET|RESTART|KILL/i.test(cmd))).toBe(false)
    } finally {
      coordinator.close()
      await runtime.stop()
      await new Promise<void>((resolve) => mockScdServer.close(() => resolve()))
      rmSync(mockDir, { recursive: true, force: true })
    }
  })
})

function cpSyncKeyFile(sourceHome: string, agentHome: string): void {
  const srcKeys = path.join(sourceHome, "private-keys-v1.d")
  const dstKeys = path.join(agentHome, "private-keys-v1.d")
  mkdirSync(dstKeys, { recursive: true, mode: 0o700 })
  cpSync(srcKeys, dstKeys, { recursive: true, force: true })
}

async function waitUntil(predicate: () => boolean, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error("Timed out waiting for condition")
    await new Promise((r) => setTimeout(r, 10))
  }
}
