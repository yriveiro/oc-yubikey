import { randomUUID } from "node:crypto"
import { sanitizeDisplayText } from "./protocol.ts"
import type {
  PromptPinInput,
  PromptPinOutput,
  PromptTouchInput,
  PromptTouchOutput,
  RequestKind,
  RequestSummary,
  ResolutionOutcome,
  ResolvedEvent,
  UnlockInput,
  UnlockOutput,
  YubiKeyCardStatus,
} from "./rpc.ts"
import {
  type VerifyPinResult,
  getYubiKeyCardStatus,
  verifyYubiKeyPinLoopback,
} from "./yubikey.ts"

export type PromptInputByKind = {
  readonly pin: PromptPinInput
  readonly touch: PromptTouchInput
}

export type PromptOutputByKind = {
  readonly pin: PromptPinOutput
  readonly touch: PromptTouchOutput
}

type PendingRequest<K extends RequestKind = RequestKind> = {
  readonly [P in K]: {
    readonly kind: P
    readonly summary: RequestSummary & { readonly kind: P }
    readonly resolve: (result: PromptOutputByKind[P]) => void
    readonly timer: ReturnType<typeof setTimeout>
    readonly cleanupSignal?: () => void
  }
}[K]

export interface RequestExecutionOptions {
  readonly requestID?: string
  readonly signal?: AbortSignal
  readonly timeoutMs?: number
}

export interface PinentryCoordinatorOptions {
  readonly requestTimeoutMs?: number
  readonly agentSocketPath?: string
  readonly onRequested?: (summary: RequestSummary) => void | Promise<void>
  readonly onResolved?: (event: ResolvedEvent) => void | Promise<void>
  readonly getCardStatus?: (options?: { signal?: AbortSignal }) => Promise<YubiKeyCardStatus>
}

const DEFAULT_META_BY_KIND: Readonly<
  Record<RequestKind, { readonly title: string; readonly prompt: string }>
> = {
  pin: { title: "YubiKey PIN Entry", prompt: "PIN:" },
  touch: { title: "Touch Your YubiKey", prompt: "Touch YubiKey" },
}

function buildSanitizedSummary<const K extends RequestKind>(
  kind: K,
  requestID: string,
  input: PromptPinInput & PromptTouchInput,
): RequestSummary & { readonly kind: K } {
  const defaults = DEFAULT_META_BY_KIND[kind]
  const optionalStrings: ReadonlyArray<readonly [keyof RequestSummary, string | undefined, number]> =
    [
      ["description", input.description, 240],
      ["error", input.error, 240],
      ["serial", input.serial, 64],
      ["holder", input.holder, 120],
      ["keyType", input.keyType, 48],
      ["fingerprint", input.fingerprint, 96],
      ["command", input.command, 120],
    ]

  const extra: Record<string, unknown> = {}
  for (const [key, rawVal, maxLen] of optionalStrings) {
    const clean = sanitizeDisplayText(rawVal, maxLen)
    if (clean !== undefined) {
      extra[key] = clean
    }
  }
  if (input.retriesLeft !== undefined) {
    extra.retriesLeft = input.retriesLeft
  }

  return {
    requestID,
    kind,
    title: sanitizeDisplayText(input.title, 80) || defaults.title,
    prompt: sanitizeDisplayText(input.prompt, 40) || defaults.prompt,
    ...extra,
  }
}

function formatUnlockReason(card: YubiKeyCardStatus, reason?: string): string {
  if (reason) return reason
  if (card.connected) {
    return `Unlock YubiKey OpenPGP card${card.serial ? ` (${card.serial})` : ""}`
  }
  return "Enter your YubiKey OpenPGP PIN to unlock gpg-agent"
}

function canRetryAfterFailure(
  verifyRes: VerifyPinResult,
  allowRetry: boolean,
  attempt: number,
  maxAttempts: number,
  updatedRetries: number | undefined,
): boolean {
  if (!verifyRes.badPin || !allowRetry || attempt >= maxAttempts) {
    return false
  }
  return updatedRetries === undefined || updatedRetries > 1
}

export class PinentryCoordinator {
  private readonly pending = new Map<string, PendingRequest>()
  private readonly requestTimeoutMs: number
  private readonly agentSocketPath?: string
  private readonly callbacks: PinentryCoordinatorOptions

  constructor(options: PinentryCoordinatorOptions = {}) {
    this.requestTimeoutMs = options.requestTimeoutMs ?? 180_000
    this.agentSocketPath = options.agentSocketPath
    this.callbacks = options
  }

  listPending(): RequestSummary[] {
    return [...this.pending.values()].map((entry) => entry.summary)
  }

  private enqueuePending<const K extends RequestKind>(
    kind: K,
    input: PromptInputByKind[K],
    onAbortedResult: () => PromptOutputByKind[K],
    options: RequestExecutionOptions = {},
  ): Promise<PromptOutputByKind[K]> {
    if (options.signal?.aborted) {
      return Promise.resolve(onAbortedResult())
    }

    const requestID = options.requestID ?? randomUUID()
    const summary = buildSanitizedSummary(kind, requestID, input)

    return new Promise<PromptOutputByKind[K]>((resolve) => {
      const timer = setTimeout(() => {
        this.cancel(requestID, "timeout")
      }, options.timeoutMs ?? this.requestTimeoutMs)

      let cleanupSignal: (() => void) | undefined
      if (options.signal) {
        const onAbort = () => {
          this.cancel(requestID, "aborted")
        }
        options.signal.addEventListener("abort", onAbort, { once: true })
        cleanupSignal = () => options.signal?.removeEventListener("abort", onAbort)
      }

      const pendingEntry: PendingRequest<K> = {
        kind,
        summary,
        resolve,
        timer,
        cleanupSignal,
      }
      this.pending.set(requestID, pendingEntry as PendingRequest)

      void Promise.resolve(this.callbacks.onRequested?.(summary)).catch(() => {})
    })
  }

  requestPin(
    input: PromptPinInput,
    options: RequestExecutionOptions = {},
  ): Promise<PromptPinOutput> {
    return this.enqueuePending(
      "pin",
      input,
      () => ({ cancelled: true, cancelReason: "aborted" }),
      options,
    )
  }

  requestTouch(
    input: PromptTouchInput = {},
    options: RequestExecutionOptions = {},
  ): Promise<PromptTouchOutput> {
    return this.enqueuePending(
      "touch",
      input,
      () => ({ cancelled: true, confirmed: false }),
      options,
    )
  }

  private settlePending(
    requestID: string,
    outcome: ResolutionOutcome,
    applyResolution: (entry: PendingRequest) => boolean,
  ): boolean {
    const entry = this.pending.get(requestID)
    if (!entry || !applyResolution(entry)) return false
    this.pending.delete(requestID)
    clearTimeout(entry.timer)
    entry.cleanupSignal?.()
    void Promise.resolve(this.callbacks.onResolved?.({ requestID, outcome })).catch(() => {})
    return true
  }

  submit(requestID: string, pin: string): boolean {
    const entry = this.pending.get(requestID)
    if (entry?.kind === "touch") {
      return this.confirmTouch(requestID)
    }
    if (typeof pin !== "string" || pin.length === 0 || pin.length > 256 || /[\r\n\0]/.test(pin)) {
      return false
    }
    return this.settlePending(requestID, "submitted", (item) => {
      if (item.kind !== "pin") return false
      item.resolve({ cancelled: false, pin })
      return true
    })
  }

  confirmTouch(requestID: string): boolean {
    return this.settlePending(requestID, "confirmed", (item) => {
      if (item.kind !== "touch") return false
      item.resolve({ cancelled: false, confirmed: true })
      return true
    })
  }

  cancel(requestID: string, reason?: string): boolean {
    return this.settlePending(requestID, "cancelled", (item) => {
      if (item.kind === "pin") {
        item.resolve({
          cancelled: true,
          ...(reason !== undefined ? { cancelReason: reason } : {}),
        })
      } else {
        item.resolve({ cancelled: true, confirmed: false })
      }
      return true
    })
  }

  private async promptAndVerifyPin(
    card: YubiKeyCardStatus,
    reason: string | undefined,
    effectiveError: string | undefined,
    signal: AbortSignal | undefined,
  ): Promise<{ cancelled: boolean; verifyRes?: VerifyPinResult }> {
    const promptResult = await this.requestPin(
      {
        title: "YubiKey PIN Entry",
        description: formatUnlockReason(card, reason),
        prompt: "PIN:",
        error: effectiveError,
        serial: card.serial,
        holder: card.holder,
        retriesLeft: card.pinRetries?.user,
      },
      { signal },
    )

    if (promptResult.cancelled || !promptResult.pin) {
      return { cancelled: true }
    }

    const verifyRes = await verifyYubiKeyPinLoopback(promptResult.pin, {
      socketPath: this.agentSocketPath,
      aid: card.applicationID,
      signal,
    })
    return { cancelled: false, verifyRes }
  }

  async unlock(
    input: UnlockInput = {},
    options: { signal?: AbortSignal } = {},
  ): Promise<UnlockOutput> {
    const readCard = this.callbacks.getCardStatus ?? getYubiKeyCardStatus
    let card = await readCard({ signal: options.signal })

    const allowRetry = input.allowRetry ?? true
    const maxAttempts = allowRetry ? 3 : 1
    let lastError: string | undefined

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const retriesLeft = card.pinRetries?.user
      if (retriesLeft !== undefined && retriesLeft <= 0) {
        return {
          ok: false,
          message:
            "YubiKey OpenPGP user PIN is blocked (0 retries remaining). Use Admin PIN / Reset Code.",
          card,
        }
      }

      const effectiveError =
        retriesLeft === 1 && !lastError
          ? "Warning: Only 1 PIN attempt remaining before YubiKey PIN is blocked!"
          : lastError

      const step = await this.promptAndVerifyPin(card, input.reason, effectiveError, options.signal)
      if (step.cancelled || !step.verifyRes) {
        return { ok: false, message: "YubiKey PIN entry was cancelled.", card }
      }

      card = await readCard({ signal: options.signal })
      if (step.verifyRes.ok) {
        return {
          ok: true,
          message: `YubiKey${card.serial ? ` (${card.serial})` : ""} unlocked and PIN cached in gpg-agent.`,
          card,
        }
      }

      const updatedRetries = card.pinRetries?.user
      if (!canRetryAfterFailure(step.verifyRes, allowRetry, attempt, maxAttempts, updatedRetries)) {
        return { ok: false, message: step.verifyRes.message, card }
      }

      const baseErr = step.verifyRes.error ?? "Bad PIN"
      lastError =
        updatedRetries !== undefined ? `${baseErr} (${updatedRetries} tries remaining)` : baseErr
    }

    return {
      ok: false,
      message: lastError ? `YubiKey unlock failed: ${lastError}` : "YubiKey unlock failed.",
      card,
    }
  }

  close(): void {
    for (const [requestID] of this.pending) {
      this.cancel(requestID, "coordinator-closed")
    }
  }
}
