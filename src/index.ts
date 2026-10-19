import {
  Plugin,
  type RpcHandlers,
  type ToolEditor,
} from "@opencode/plugin"
import {
  type AskpassClassification,
  PinentryBridge,
  type PinentryBridgeOptions,
  type SshFingerprint,
  type SshKeyType,
  classifyAskpassPrompt,
  filterSshAgentIdentitiesAnswer,
  findSshSecurityKeyFile,
  formatFriendlySshKeyType,
  isAppleAgentSocket,
  isAppleLaunchdSshAgentSocket,
  parseSshAgentSignRequest,
  resolvePinentryCliPath,
} from "./bridge.ts"
import {
  PinentryCoordinator,
  type PinentryCoordinatorOptions,
  type PromptInputByKind,
  type PromptOutputByKind,
} from "./coordinator.ts"
import { sanitizeDisplayText } from "./protocol.ts"
import {
  Pinentry,
  type RequestKind,
  type RequestSummary,
  type ResolutionOutcome,
  type ResolvedEvent,
  type YubiKeyCardStatus,
} from "./rpc.ts"
import { checkGpgAgentReady, getYubiKeyCardStatus, lockYubiKey } from "./yubikey.ts"

export {
  type AskpassClassification,
  PinentryBridge,
  type PinentryBridgeOptions,
  PinentryCoordinator,
  type PinentryCoordinatorOptions,
  type PromptInputByKind,
  type PromptOutputByKind,
  type RequestKind,
  type RequestSummary,
  type ResolutionOutcome,
  type ResolvedEvent,
  type SshFingerprint,
  type SshKeyType,
  classifyAskpassPrompt,
  filterSshAgentIdentitiesAnswer,
  findSshSecurityKeyFile,
  formatFriendlySshKeyType,
  isAppleAgentSocket,
  isAppleLaunchdSshAgentSocket,
  parseSshAgentSignRequest,
  resolvePinentryCliPath,
  sanitizeDisplayText,
}

export function formatCardStatusReport(
  gpgAgentReady: boolean,
  card: YubiKeyCardStatus,
): string {
  if (!card.connected) {
    return `gpg-agent ready: ${gpgAgentReady ? "yes" : "no"}\nYubiKey OpenPGP card: not connected`
  }

  const retries = card.pinRetries
    ? `[${card.pinRetries.user} ${card.pinRetries.reset} ${card.pinRetries.admin}] (user=${card.pinRetries.user}, reset=${card.pinRetries.reset}, admin=${card.pinRetries.admin})`
    : "unknown"

  const uifText = card.uif
    ? `Sign=${card.uif.sign} Decrypt=${card.uif.decrypt} Auth=${card.uif.auth}`
    : "unknown"

  return [
    "YubiKey OpenPGP Card: connected",
    `Reader: ${card.reader ?? "unknown"}`,
    `Serial: ${card.serial ?? "unknown"}`,
    `Application ID: ${card.applicationID ?? "unknown"}`,
    `Holder: ${card.holder ?? "not set"}`,
    `Signature Counter: ${card.signatureCount ?? 0}`,
    `PIN Retry Counters: ${retries}`,
    `Touch Policy (UIF): ${uifText}`,
    `gpg-agent Ready: ${gpgAgentReady ? "yes" : "no"}`,
  ].join("\n")
}

const EMPTY_OBJECT_SCHEMA = {
  type: "object",
  properties: {},
  required: [],
  additionalProperties: false,
} as const

const UNLOCK_INPUT_SCHEMA = {
  type: "object",
  properties: {
    reason: {
      type: "string",
      description: "Optional reason displayed in the TUI modal (e.g. 'Sign git commit')",
    },
  },
  required: [],
  additionalProperties: false,
} as const

function registerStatusAndLockTools(
  editor: ToolEditor,
  agentSocketPath: string | undefined,
): void {
  editor.add({
    name: "yubikey_status",
    options: { codemode: false },
    description:
      "Check connected YubiKey OpenPGP smartcard status (serial, holder, signature counter, PIN retry counters, UIF touch policy) and gpg-agent readiness.",
    input: EMPTY_OBJECT_SCHEMA,
    execute: async (_input, context) => {
      await context.progress({ status: "Checking YubiKey and gpg-agent status" })
      const [gpgAgentReady, card] = await Promise.all([
        checkGpgAgentReady({ socketPath: agentSocketPath, signal: context.signal }),
        getYubiKeyCardStatus({ signal: context.signal }),
      ])
      return { content: formatCardStatusReport(gpgAgentReady, card), metadata: { gpgAgentReady, card } }
    },
  })
  editor.add({
    name: "yubikey_lock",
    options: { codemode: false },
    description:
      "Clear cached YubiKey OpenPGP PIN in scdaemon and reload gpg-agent (SCD RESET + RELOADAGENT).",
    input: EMPTY_OBJECT_SCHEMA,
    execute: async (_input, context) => {
      await context.progress({ status: "Locking YubiKey and clearing gpg-agent cache" })
      const result = await lockYubiKey({ socketPath: agentSocketPath, signal: context.signal })
      return { content: result.message, metadata: result }
    },
  })
}

function registerInteractiveYubiKeyTools(
  editor: ToolEditor,
  coordinator: PinentryCoordinator,
  bridge: PinentryBridge,
): void {
  editor.add({
    name: "yubikey_unlock",
    options: { codemode: false },
    description:
      "Prompt the user in the OpenCode TUI modal for their YubiKey OpenPGP PIN and verify/cache it directly in gpg-agent via Assuan loopback (SCD CHECKPIN). Use this before running signed git commits or tags. The PIN is never exposed to the model.",
    input: UNLOCK_INPUT_SCHEMA,
    execute: async (rawInput, context) => {
      const input = (rawInput ?? {}) as { reason?: string }
      await context.progress({ status: "Waiting for YubiKey PIN entry in OpenCode TUI" })
      const res = await coordinator.unlock({ reason: input.reason, allowRetry: true }, { signal: context.signal })
      return { content: res.message, metadata: { ok: res.ok, card: res.card } }
    },
  })
  editor.add({
    name: "yubikey_touch",
    options: { codemode: false },
    description:
      "Prompt the user in the OpenCode TUI modal to physically touch their YubiKey and verify hardware user presence.",
    input: UNLOCK_INPUT_SCHEMA,
    execute: async (rawInput, context) => {
      const input = (rawInput ?? {}) as { reason?: string }
      await context.progress({ status: "Waiting for physical YubiKey touch in OpenCode TUI" })
      const res = await bridge.verifyHardwareTouch({ description: input.reason }, { signal: context.signal })
      const ok = res.confirmed && !res.cancelled
      const msg = ok ? "Physical user presence verified on YubiKey." : "YubiKey touch confirmation was cancelled."
      return { content: msg, metadata: { ok, ...res } }
    },
  })
}

function registerYubiKeyTools(
  editor: ToolEditor,
  coordinator: PinentryCoordinator,
  bridge: PinentryBridge,
  agentSocketPath: string | undefined,
): void {
  registerStatusAndLockTools(editor, agentSocketPath)
  registerInteractiveYubiKeyTools(editor, coordinator, bridge)
}

function createPinentryRpcHandlers(
  coordinator: PinentryCoordinator,
  bridge: PinentryBridge,
  agentSocketPath: string | undefined,
  allowRawPinRpc: boolean,
): RpcHandlers<typeof Pinentry> {
  return {
    unlock: (input, callCtx) => coordinator.unlock(input, { signal: callCtx.signal }),
    promptPin: async (input, callCtx) => {
      if (!allowRawPinRpc) {
        return { cancelled: true, cancelReason: "disabled-by-policy" }
      }
      return coordinator.requestPin(input, { signal: callCtx.signal })
    },
    promptTouch: (input, callCtx) => bridge.verifyHardwareTouch(input, { signal: callCtx.signal }),
    submit: async (input) => ({ ok: coordinator.submit(input.requestID, input.pin) }),
    confirmTouch: async (input) => ({ ok: coordinator.confirmTouch(input.requestID) }),
    cancel: async (input) => ({ ok: coordinator.cancel(input.requestID, input.reason) }),
    status: async (_input, callCtx) => {
      const [gpgAgentReady, card] = await Promise.all([
        checkGpgAgentReady({ socketPath: agentSocketPath, signal: callCtx.signal }),
        getYubiKeyCardStatus({ signal: callCtx.signal }),
      ])
      return {
        pending: coordinator.listPending(),
        gpgAgentReady,
        card,
      }
    },
    lock: (_input, callCtx) =>
      lockYubiKey({ socketPath: agentSocketPath, signal: callCtx.signal }),
  }
}

export default Plugin.define({
  id: "oc-yubikey",
  async setup(ctx) {
    let emitRequested: ((summary: RequestSummary) => Promise<void>) | undefined
    let emitResolved: ((event: ResolvedEvent) => Promise<void>) | undefined

    const agentSocketPath =
      typeof ctx.options?.agentSocketPath === "string" ? ctx.options.agentSocketPath : undefined
    const allowRawPinRpc = ctx.options?.allowRawPinRpc === true

    const coordinator = new PinentryCoordinator({
      agentSocketPath,
      onRequested: (summary) => emitRequested?.(summary),
      onResolved: (event) => emitResolved?.(event),
    })

    const bridge = new PinentryBridge({ coordinator })
    await bridge.start()

    const rpcRegistration = await ctx.rpc.register(
      Pinentry,
      createPinentryRpcHandlers(coordinator, bridge, agentSocketPath, allowRawPinRpc),
    )

    emitRequested = (summary) => rpcRegistration.events.emit("prompt", summary)
    emitResolved = (event) => rpcRegistration.events.emit("settled", event)

    const shellHookRegistration = await ctx.shell.hook("create.before", async (invocation) => {
      await bridge.prepareShellEnv(invocation.env, invocation.command)
    })

    const toolRegistration = await ctx.tool.transform((editor) => {
      registerYubiKeyTools(editor, coordinator, bridge, agentSocketPath)
    })

    return async () => {
      coordinator.close()
      await bridge.close()
      await shellHookRegistration.dispose()
      await toolRegistration.dispose()
      await rpcRegistration.dispose()
    }
  },
})

export { Pinentry } from "./rpc.ts"
export * from "./yubikey.ts"
