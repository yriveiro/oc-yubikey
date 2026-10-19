import { Rpc } from "@opencode/plugin/rpc"

interface StandardSchemaV1<Input = unknown, Output = Input> {
  readonly "~standard": {
    readonly version: 1
    readonly vendor: string
    readonly validate: (value: unknown) => { readonly value: Output } | { readonly issues: ReadonlyArray<{ readonly message: string }> }
    readonly types?: {
      readonly input: Input
      readonly output: Output
    }
  }
}

export type RequestKind = "pin" | "touch"

export type ResolutionOutcome = "submitted" | "confirmed" | "cancelled"

export interface YubiKeyUifStatus {
  readonly sign: string
  readonly decrypt: string
  readonly auth: string
}

export interface YubiKeyCardStatus {
  readonly connected: boolean
  readonly reader?: string
  readonly serial?: string
  readonly applicationID?: string
  readonly model?: string
  readonly version?: string
  readonly holder?: string
  readonly signatureCount?: number
  readonly pinRetries?: {
    readonly user: number
    readonly reset: number
    readonly admin: number
  }
  readonly uif?: YubiKeyUifStatus
  readonly keys?: {
    readonly signature?: string
    readonly encryption?: string
    readonly authentication?: string
  }
}

export interface RequestSummary extends Readonly<Record<string, unknown>> {
  readonly requestID: string
  readonly kind?: RequestKind
  readonly title: string
  readonly description?: string
  readonly prompt: string
  readonly error?: string
  readonly serial?: string
  readonly holder?: string
  readonly retriesLeft?: number
  readonly keyType?: string
  readonly fingerprint?: string
  readonly command?: string
}

export interface UnlockInput {
  readonly reason?: string
  readonly allowRetry?: boolean
}

export interface UnlockOutput {
  readonly ok: boolean
  readonly message: string
  readonly card: YubiKeyCardStatus
}

export interface PromptPinInput {
  readonly title?: string
  readonly description?: string
  readonly prompt?: string
  readonly error?: string
  readonly serial?: string
  readonly holder?: string
  readonly retriesLeft?: number
  readonly command?: string
}

export interface PromptPinOutput {
  readonly cancelled: boolean
  readonly cancelReason?: string
  readonly pin?: string
}

export interface PromptTouchInput {
  readonly title?: string
  readonly description?: string
  readonly prompt?: string
  readonly serial?: string
  readonly holder?: string
  readonly keyType?: string
  readonly fingerprint?: string
  readonly command?: string
}

export interface PromptTouchOutput {
  readonly cancelled: boolean
  readonly confirmed: boolean
}

export interface SubmitInput {
  readonly requestID: string
  readonly pin: string
}

export interface ConfirmTouchInput {
  readonly requestID: string
}

export interface CancelInput {
  readonly requestID: string
  readonly reason?: string
}

export type EmptyInput = Readonly<Record<string, never>>

export interface OkOutput {
  readonly ok: boolean
}

export interface StatusOutput {
  readonly pending: ReadonlyArray<RequestSummary>
  readonly gpgAgentReady: boolean
  readonly card: YubiKeyCardStatus
}

export interface LockOutput {
  readonly ok: boolean
  readonly message: string
}

export interface ResolvedEvent extends Readonly<Record<string, unknown>> {
  readonly requestID: string
  readonly outcome: ResolutionOutcome
}

function stripUndefined<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item) => stripUndefined(item)) as unknown as T
  }
  if (typeof value === "object" && value !== null) {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value)) {
      if (v !== undefined) {
        out[k] = stripUndefined(v)
      }
    }
    return out as T
  }
  return value
}

function standardSchema<T>(parse: (value: unknown) => T): StandardSchemaV1<T, T> {
  return {
    "~standard": {
      version: 1,
      vendor: "oc-yubikey",
      validate(value: unknown) {
        try {
          return { value: stripUndefined(parse(value)) }
        } catch (error) {
          return {
            issues: [
              {
                message: error instanceof Error ? error.message : String(error),
              },
            ],
          }
        }
      },
    },
  }
}

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`Expected object for ${label}`)
  }
  return value as Record<string, unknown>
}

function asString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new Error(`Expected string for ${field}`)
  }
  return value
}

function asOptionalString(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null) return undefined
  return asString(value, field)
}

function asOptionalNumber(value: unknown, field: string): number | undefined {
  if (value === undefined || value === null) return undefined
  if (typeof value !== "number" || Number.isNaN(value)) {
    throw new Error(`Expected number for ${field}`)
  }
  return value
}

function asBoolean(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") {
    throw new Error(`Expected boolean for ${field}`)
  }
  return value
}

function parseCardStatus(value: unknown): YubiKeyCardStatus {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return { connected: false }
  }
  const obj = value as Record<string, unknown>
  return {
    connected: Boolean(obj.connected),
    reader: asOptionalString(obj.reader, "card.reader"),
    serial: asOptionalString(obj.serial, "card.serial"),
    applicationID: asOptionalString(obj.applicationID, "card.applicationID"),
    model: asOptionalString(obj.model, "card.model"),
    version: asOptionalString(obj.version, "card.version"),
    holder: asOptionalString(obj.holder, "card.holder"),
    signatureCount: asOptionalNumber(obj.signatureCount, "card.signatureCount"),
    pinRetries:
      typeof obj.pinRetries === "object" && obj.pinRetries !== null
        ? {
            user:
              asOptionalNumber((obj.pinRetries as Record<string, unknown>).user, "pinRetries.user") ??
              0,
            reset:
              asOptionalNumber(
                (obj.pinRetries as Record<string, unknown>).reset,
                "pinRetries.reset",
              ) ?? 0,
            admin:
              asOptionalNumber(
                (obj.pinRetries as Record<string, unknown>).admin,
                "pinRetries.admin",
              ) ?? 0,
          }
        : undefined,
    uif:
      typeof obj.uif === "object" && obj.uif !== null
        ? {
            sign: asOptionalString((obj.uif as Record<string, unknown>).sign, "uif.sign") ?? "off",
            decrypt: asOptionalString((obj.uif as Record<string, unknown>).decrypt, "uif.decrypt") ?? "off",
            auth: asOptionalString((obj.uif as Record<string, unknown>).auth, "uif.auth") ?? "off",
          }
        : undefined,
    keys:
      typeof obj.keys === "object" && obj.keys !== null
        ? {
            signature: asOptionalString((obj.keys as Record<string, unknown>).signature, "keys.signature"),
            encryption: asOptionalString((obj.keys as Record<string, unknown>).encryption, "keys.encryption"),
            authentication: asOptionalString(
              (obj.keys as Record<string, unknown>).authentication,
              "keys.authentication",
            ),
          }
        : undefined,
  }
}

function parseRequestSummary(value: unknown): RequestSummary {
  const obj = asObject(value, "RequestSummary")
  const rawKind = asOptionalString(obj.kind, "kind")
  const kind: RequestKind | undefined =
    rawKind === "touch" ? "touch" : rawKind === "pin" ? "pin" : undefined
  return {
    requestID: asString(obj.requestID, "requestID"),
    ...(kind !== undefined ? { kind } : {}),
    title: asString(obj.title, "title"),
    description: asOptionalString(obj.description, "description"),
    prompt: asString(obj.prompt, "prompt"),
    error: asOptionalString(obj.error, "error"),
    serial: asOptionalString(obj.serial, "serial"),
    holder: asOptionalString(obj.holder, "holder"),
    retriesLeft: asOptionalNumber(obj.retriesLeft, "retriesLeft"),
    keyType: asOptionalString(obj.keyType, "keyType"),
    fingerprint: asOptionalString(obj.fingerprint, "fingerprint"),
    command: asOptionalString(obj.command, "command"),
  }
}

export const Pinentry = Rpc.define({
  id: "oc-yubikey",
  methods: {
    unlock: {
      input: standardSchema<UnlockInput>((val) => {
        if (val === undefined || val === null) return {}
        const obj = asObject(val, "unlock.input")
        return {
          reason: asOptionalString(obj.reason, "reason"),
          allowRetry: typeof obj.allowRetry === "boolean" ? obj.allowRetry : undefined,
        }
      }),
      output: standardSchema<UnlockOutput>((val) => {
        const obj = asObject(val, "unlock.output")
        return {
          ok: asBoolean(obj.ok, "ok"),
          message: asString(obj.message, "message"),
          card: parseCardStatus(obj.card),
        }
      }),
    },
    promptPin: {
      input: standardSchema<PromptPinInput>((val) => {
        if (val === undefined || val === null) return {}
        const obj = asObject(val, "promptPin.input")
        return {
          title: asOptionalString(obj.title, "title"),
          description: asOptionalString(obj.description, "description"),
          prompt: asOptionalString(obj.prompt, "prompt"),
          error: asOptionalString(obj.error, "error"),
          serial: asOptionalString(obj.serial, "serial"),
          holder: asOptionalString(obj.holder, "holder"),
          retriesLeft: asOptionalNumber(obj.retriesLeft, "retriesLeft"),
          command: asOptionalString(obj.command, "command"),
        }
      }),
      output: standardSchema<PromptPinOutput>((val) => {
        const obj = asObject(val, "promptPin.output")
        return {
          cancelled: asBoolean(obj.cancelled, "cancelled"),
          cancelReason: asOptionalString(obj.cancelReason, "cancelReason"),
          pin: asOptionalString(obj.pin, "pin"),
        }
      }),
    },
    promptTouch: {
      input: standardSchema<PromptTouchInput>((val) => {
        if (val === undefined || val === null) return {}
        const obj = asObject(val, "promptTouch.input")
        return {
          title: asOptionalString(obj.title, "title"),
          description: asOptionalString(obj.description, "description"),
          prompt: asOptionalString(obj.prompt, "prompt"),
          serial: asOptionalString(obj.serial, "serial"),
          holder: asOptionalString(obj.holder, "holder"),
          keyType: asOptionalString(obj.keyType, "keyType"),
          fingerprint: asOptionalString(obj.fingerprint, "fingerprint"),
          command: asOptionalString(obj.command, "command"),
        }
      }),
      output: standardSchema<PromptTouchOutput>((val) => {
        const obj = asObject(val, "promptTouch.output")
        return {
          cancelled: asBoolean(obj.cancelled, "cancelled"),
          confirmed: asBoolean(obj.confirmed, "confirmed"),
        }
      }),
    },
    submit: {
      input: standardSchema<SubmitInput>((val) => {
        const obj = asObject(val, "submit.input")
        const pin = asString(obj.pin, "pin")
        if (pin.length > 256 || /[\r\n\0]/.test(pin)) {
          throw new Error("Invalid PIN format")
        }
        return {
          requestID: asString(obj.requestID, "requestID"),
          pin,
        }
      }),
      output: standardSchema<OkOutput>((val) => {
        const obj = asObject(val, "submit.output")
        return { ok: asBoolean(obj.ok, "ok") }
      }),
    },
    confirmTouch: {
      input: standardSchema<ConfirmTouchInput>((val) => {
        const obj = asObject(val, "confirmTouch.input")
        return {
          requestID: asString(obj.requestID, "requestID"),
        }
      }),
      output: standardSchema<OkOutput>((val) => {
        const obj = asObject(val, "confirmTouch.output")
        return { ok: asBoolean(obj.ok, "ok") }
      }),
    },
    cancel: {
      input: standardSchema<CancelInput>((val) => {
        const obj = asObject(val, "cancel.input")
        return {
          requestID: asString(obj.requestID, "requestID"),
          reason: asOptionalString(obj.reason, "reason"),
        }
      }),
      output: standardSchema<OkOutput>((val) => {
        const obj = asObject(val, "cancel.output")
        return { ok: asBoolean(obj.ok, "ok") }
      }),
    },
    status: {
      input: standardSchema<EmptyInput>((val) => {
        if (val === undefined || val === null) return {}
        asObject(val, "status.input")
        return {}
      }),
      output: standardSchema<StatusOutput>((val) => {
        const obj = asObject(val, "status.output")
        const pendingRaw = Array.isArray(obj.pending) ? obj.pending : []
        return {
          pending: pendingRaw.map(parseRequestSummary),
          gpgAgentReady: asBoolean(obj.gpgAgentReady, "gpgAgentReady"),
          card: parseCardStatus(obj.card),
        }
      }),
    },
    lock: {
      input: standardSchema<EmptyInput>((val) => {
        if (val === undefined || val === null) return {}
        asObject(val, "lock.input")
        return {}
      }),
      output: standardSchema<LockOutput>((val) => {
        const obj = asObject(val, "lock.output")
        return {
          ok: asBoolean(obj.ok, "ok"),
          message: asString(obj.message, "message"),
        }
      }),
    },
  },
  events: {
    prompt: {
      schema: standardSchema<RequestSummary>(parseRequestSummary),
    },
    settled: {
      schema: standardSchema<ResolvedEvent>((val) => {
        const obj = asObject(val, "settled")
        const outcome = asString(obj.outcome, "outcome")
        if (outcome !== "submitted" && outcome !== "confirmed" && outcome !== "cancelled") {
          throw new Error(`Invalid outcome: ${outcome}`)
        }
        return {
          requestID: asString(obj.requestID, "requestID"),
          outcome,
        }
      }),
    },
  },
})
