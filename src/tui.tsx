import { Plugin } from "@opencode/plugin/tui"
import type { Context, KeymapCommand, LocationRef, RpcClient, ThemeSurface } from "@opencode/plugin/tui/context"
import { type KeyEvent, TextAttributes } from "@opentui/core"
import {
  type JSX,
  createComponent,
  createElement,
  createTextNode,
  effect,
  insert,
  insertNode,
  memo,
  setProp,
} from "@opentui/solid"
import { createSignal, onCleanup, onMount } from "solid-js"
import { Pinentry, type RequestSummary } from "./rpc.ts"

const MAX_TUI_PIN_LENGTH = 128

function applyProp(el: JSX.Element, key: string, value: unknown): void {
  if (value === undefined) return
  if (typeof value === "function" && !key.startsWith("on")) {
    const compute = value as () => unknown
    effect((prev) => setProp(el, key, compute(), prev))
    return
  }
  setProp(el, key, value)
}

function appendChild(el: JSX.Element, child: unknown, multi: boolean): void {
  if (child === null || child === undefined || typeof child === "boolean") return
  if (typeof child === "string" || typeof child === "number") {
    insertNode(el, createTextNode(String(child)))
  } else if (typeof child === "function") {
    insert(el, child, multi ? null : undefined)
  } else {
    insertNode(el, child as JSX.Element)
  }
}

function h<K extends keyof JSX.IntrinsicElements>(
  tag: K,
  props?: JSX.IntrinsicElements[K] | null,
  ...children: unknown[]
): JSX.Element {
  const el = createElement(tag)
  if (props) {
    for (const [key, value] of Object.entries(props)) {
      applyProp(el, key, value)
    }
  }
  const multi = children.length > 1
  for (const child of children) {
    appendChild(el, child, multi)
  }
  return el
}

function show(when: () => unknown, render: () => JSX.Element): JSX.Element {
  const cond = memo(() => Boolean(when()), true)
  return (() => (cond() ? render() : null)) as unknown as JSX.Element
}

function renderLabeledValue(theme: ThemeSurface, label: string, value: () => string): JSX.Element {
  return h(
    "text",
    { fg: theme.text.muted },
    `${label}: `,
    h("span", { style: { fg: theme.text.base } }, value),
  )
}

function renderCardMetaRow(theme: ThemeSurface, request: RequestSummary): JSX.Element {
  return h(
    "box",
    { flexDirection: "row", gap: 2 },
    show(
      () => request.serial,
      () => renderLabeledValue(theme, "Serial", () => request.serial ?? ""),
    ),
    show(
      () => request.holder,
      () => renderLabeledValue(theme, "Holder", () => request.holder ?? ""),
    ),
    show(
      () => request.pinPolicy,
      () => renderLabeledValue(theme, "PIN Policy", () => request.pinPolicy ?? ""),
    ),
    show(
      () => request.retriesLeft !== undefined,
      () =>
        h(
          "text",
          { fg: theme.text.muted },
          "Retries: ",
          h(
            "span",
            {
              style: () => ({
                fg:
                  (request.retriesLeft ?? 3) <= 1
                    ? theme.text.feedback.error.base
                    : theme.text.base,
              }),
            },
            () => String(request.retriesLeft ?? ""),
          ),
        ),
    ),
  )
}

interface PinentryModalProps {
  readonly context: Context
  readonly request: RequestSummary
  readonly onSubmitPin: (pin: string) => Promise<void>
  readonly onCancel: (reason: string) => Promise<void>
}

function PinentryModal(props: PinentryModalProps) {
  const theme = props.context.theme.surface("dialog")

  const [pin, setPin] = createSignal("")
  const [reveal, setReveal] = createSignal(false)
  const [submitting, setSubmitting] = createSignal(false)

  const handleSubmit = async () => {
    if (submitting()) return
    setSubmitting(true)
    try {
      const value = pin()
      setPin("")
      await props.onSubmitPin(value)
    } finally {
      setSubmitting(false)
    }
  }

  const handleCancel = async (reason: string) => {
    if (submitting()) return
    setSubmitting(true)
    setPin("")
    try {
      await props.onCancel(reason)
    } finally {
      setSubmitting(false)
    }
  }

  props.context.keymap.layer(() => ({
    mode: "modal",
    priority: 10,
    commands: [
      {
        bind: "escape",
        title: "Cancel YubiKey PIN",
        group: "Dialog",
        run: () => {
          void handleCancel("user-pressed-escape")
        },
      },
    ],
  }))

  const onKeyPress = (event: KeyEvent) => {
    if (submitting()) {
      event.preventDefault()
      return
    }
    if (event.name === "escape") {
      event.preventDefault()
      void handleCancel("user-pressed-escape")
      return
    }
    if (event.name === "return" || event.name === "enter") {
      event.preventDefault()
      void handleSubmit()
      return
    }
    if (
      event.name === "tab" ||
      (event.ctrl && event.name === "r") ||
      (event.meta && event.name === "r")
    ) {
      event.preventDefault()
      setReveal((prev) => !prev)
      return
    }
    if ((event.ctrl && event.name === "u") || (event.ctrl && event.name === "w")) {
      event.preventDefault()
      setPin("")
      return
    }
    if (event.name === "backspace" || event.name === "delete") {
      event.preventDefault()
      setPin((prev) => prev.slice(0, -1))
      return
    }
    if (!event.ctrl && !event.meta && event.sequence && event.sequence.length === 1) {
      const code = event.sequence.charCodeAt(0)
      if (code >= 0x20 && code !== 0x7f) {
        event.preventDefault()
        setPin((prev) => (prev.length < MAX_TUI_PIN_LENGTH ? prev + event.sequence : prev))
      }
    }
  }

  onMount(() => {
    props.context.renderer.keyInput.on("keypress", onKeyPress)
  })

  onCleanup(() => {
    setPin("")
    props.context.renderer.keyInput.off("keypress", onKeyPress)
  })

  const maskedDisplay = () => {
    const current = pin()
    if (!current) return ""
    return reveal() ? current : "•".repeat(current.length)
  }

  const hasCardMeta = () =>
    [
      props.request.serial,
      props.request.holder,
      props.request.pinPolicy,
      props.request.retriesLeft,
    ].some((value) => value !== undefined && value !== "")

  return h(
    "box",
    { paddingLeft: 2, paddingRight: 2, paddingBottom: 1, gap: 1, flexDirection: "column" },
    h(
      "box",
      { flexDirection: "row", justifyContent: "space-between" },
      h("text", { attributes: TextAttributes.BOLD, fg: theme.text.base }, () => `🔑 ${props.request.title || "YubiKey PIN Entry"}`),
      h("text", { fg: theme.text.muted, onMouseUp: () => void handleCancel("user-clicked-esc") }, "esc"),
    ),
    show(() => props.request.description, () => h("text", { fg: theme.text.muted, wrapMode: "word" }, () => props.request.description ?? "")),
    show(() => hasCardMeta(), () => renderCardMetaRow(theme, props.request)),
    show(
      () => props.request.error,
      () =>
        h(
          "box",
          { paddingLeft: 1, paddingRight: 1, backgroundColor: theme.background.feedback.error.base },
          h("text", { attributes: TextAttributes.BOLD, fg: theme.text.feedback.error.base, wrapMode: "word" }, () => `⚠ ${props.request.error ?? ""}`),
        ),
    ),
    h(
      "box",
      { flexDirection: "column", gap: 1 },
      h(
        "box",
        { flexDirection: "row", justifyContent: "space-between" },
        h("text", { attributes: TextAttributes.BOLD, fg: theme.text.base }, () => props.request.prompt || "PIN:"),
        h("text", { fg: theme.text.muted }, () => `${pin().length > 0 ? `${pin().length} chars ` : ""}${reveal() ? "(visible)" : "(masked)"}`),
      ),
      h(
        "box",
        { paddingLeft: 1, paddingRight: 1, backgroundColor: theme.background.raised.base, flexDirection: "row" },
        h(
          "text",
          { fg: () => (pin().length > 0 ? theme.text.base : theme.text.muted) },
          () => (pin().length > 0 ? `${maskedDisplay()}█` : "█ Enter YubiKey PIN…"),
        ),
      ),
      h(
        "box",
        { flexDirection: "row", gap: 2, paddingTop: 1 },
        h("text", { fg: theme.text.base, onMouseUp: () => void handleSubmit() }, "enter ", h("span", { style: { fg: theme.text.muted } }, "unlock")),
        h("text", { fg: theme.text.base, onMouseUp: () => setReveal((prev) => !prev) }, "tab/ctrl+r ", h("span", { style: { fg: theme.text.muted } }, () => (reveal() ? "hide" : "show"))),
        h("text", { fg: theme.text.base, onMouseUp: () => setPin("") }, "ctrl+u ", h("span", { style: { fg: theme.text.muted } }, "clear")),
        h("text", { fg: theme.text.base, onMouseUp: () => void handleCancel("user-clicked-cancel") }, "esc ", h("span", { style: { fg: theme.text.muted } }, "cancel")),
      ),
    ),
  )
}

interface TouchModalProps {
  readonly context: Context
  readonly request: RequestSummary
  readonly onConfirm: () => Promise<void>
  readonly onCancel: (reason: string) => Promise<void>
}

function TouchModal(props: TouchModalProps) {
  const theme = props.context.theme.surface("dialog")
  const [pulse, setPulse] = createSignal(true)
  const [closing, setClosing] = createSignal(false)

  const handleCancel = async (reason: string) => {
    if (closing()) return
    setClosing(true)
    try {
      await props.onCancel(reason)
    } finally {
      setClosing(false)
    }
  }

  const handleConfirm = async () => {
    if (closing()) return
    setClosing(true)
    try {
      await props.onConfirm()
    } finally {
      setClosing(false)
    }
  }

  props.context.keymap.layer(() => ({
    mode: "modal",
    priority: 10,
    commands: [
      {
        bind: "escape",
        title: "Cancel YubiKey Touch",
        group: "Dialog",
        run: () => {
          void handleCancel("user-pressed-escape")
        },
      },
    ],
  }))

  const onKeyPress = (event: KeyEvent) => {
    if (closing()) {
      event.preventDefault()
      return
    }
    if (event.name === "escape") {
      event.preventDefault()
      void handleCancel("user-pressed-escape")
      return
    }
  }

  onMount(() => {
    const timer = setInterval(() => {
      setPulse((prev) => !prev)
    }, 550)
    props.context.renderer.keyInput.on("keypress", onKeyPress)
    onCleanup(() => {
      clearInterval(timer)
      props.context.renderer.keyInput.off("keypress", onKeyPress)
    })
  })

  const hasMeta = () =>
    Boolean(
      props.request.command ||
        props.request.keyType ||
        props.request.fingerprint ||
        props.request.serial ||
        props.request.holder,
    )

  return h(
    "box",
    { paddingLeft: 2, paddingRight: 2, paddingBottom: 1, gap: 1, flexDirection: "column" },
    h(
      "box",
      { flexDirection: "row", justifyContent: "space-between" },
      h("text", { attributes: TextAttributes.BOLD, fg: theme.text.base }, () => `👆 ${props.request.title || "Touch Your YubiKey"}`),
      h("text", { fg: theme.text.muted, onMouseUp: () => void handleCancel("user-clicked-esc") }, "esc"),
    ),
    show(() => props.request.description, () => h("text", { fg: theme.text.muted, wrapMode: "word" }, () => props.request.description ?? "")),
    h(
      "box",
      { paddingLeft: 1, paddingRight: 1, paddingTop: 1, paddingBottom: 1, backgroundColor: theme.background.raised.base, flexDirection: "row", justifyContent: "space-between" },
      h("text", { attributes: TextAttributes.BOLD, fg: theme.text.feedback.warning.base }, () => `${pulse() ? "◉" : "◎"} Waiting for physical touch on your YubiKey…`),
    ),
    show(
      () => hasMeta(),
      () =>
        h(
          "box",
          { flexDirection: "column", gap: 0 },
          show(() => props.request.command, () => renderLabeledValue(theme, "Command", () => props.request.command ?? "")),
          show(
            () => Boolean(props.request.keyType || props.request.fingerprint),
            () => renderLabeledValue(theme, "Key", () => [props.request.keyType, props.request.fingerprint].filter(Boolean).join(" ")),
          ),
          show(
            () => Boolean(props.request.serial || props.request.holder),
            () =>
              h(
                "box",
                { flexDirection: "row", gap: 2 },
                show(() => props.request.serial, () => renderLabeledValue(theme, "Serial", () => props.request.serial ?? "")),
                show(() => props.request.holder, () => renderLabeledValue(theme, "Holder", () => props.request.holder ?? "")),
              ),
          ),
        ),
    ),
    h(
      "box",
      { flexDirection: "row", justifyContent: "space-between", paddingTop: 1 },
      h("text", { fg: theme.text.muted }, "Automatically closes when you touch the YubiKey"),
      h(
        "box",
        { flexDirection: "row", gap: 2 },
        h("text", { fg: theme.text.base, onMouseUp: () => void handleConfirm() }, h("span", { style: { fg: theme.text.muted } }, "dismiss")),
        h("text", { fg: theme.text.base, onMouseUp: () => void handleCancel("user-clicked-cancel") }, "esc ", h("span", { style: { fg: theme.text.muted } }, "cancel")),
      ),
    ),
  )
}

type QueuedRequest = RequestSummary & {
  readonly location?: LocationRef
}

type PinentryRpcClient = RpcClient<typeof Pinentry>

function formatError(error: unknown): string {
  if (error instanceof Error) return error.message
  if (
    typeof error === "object" &&
    error !== null &&
    "message" in error &&
    typeof error.message === "string"
  ) {
    return error.message
  }
  return String(error)
}

function formatNotificationMessage(req: QueuedRequest): string {
  if (req.kind === "touch") {
    return [
      req.description || "Touch your YubiKey to confirm presence",
      req.keyType ? `[${req.keyType}]` : "",
    ]
      .filter(Boolean)
      .join(" ")
  }
  if (req.error) {
    return `${req.error} — ${req.description || "Re-enter YubiKey PIN"}`
  }
  return req.description || req.prompt || "Enter your YubiKey PIN in OpenCode"
}

function renderRequestModal(
  context: Context,
  rpc: PinentryRpcClient,
  next: QueuedRequest,
  targetLocation: () => LocationRef,
  settleDialogLocally: (requestID: string) => void,
) {
  const handleCancel = async (reason: string) => {
    settleDialogLocally(next.requestID)
    await rpc.cancel({ requestID: next.requestID, reason }, { location: targetLocation() }).catch(() => {})
  }

  if (next.kind === "touch") {
    return createComponent(TouchModal, {
      context,
      request: next,
      onConfirm: async () => {
        settleDialogLocally(next.requestID)
        await rpc
          .confirmTouch({ requestID: next.requestID }, { location: targetLocation() })
          .catch(() => {})
      },
      onCancel: handleCancel,
    })
  }

  return createComponent(PinentryModal, {
    context,
    request: next,
    onSubmitPin: async (pin) => {
      settleDialogLocally(next.requestID)
      await rpc.submit({ requestID: next.requestID, pin }, { location: targetLocation() }).catch((err) => {
        context.ui.toast.show({
          title: "YubiKey PIN Error",
          message: formatError(err),
          variant: "error",
        })
      })
    },
    onCancel: handleCancel,
  })
}

interface TuiCommandActions {
  readonly status: () => Promise<void>
  readonly unlock: (reason?: string) => Promise<void>
  readonly lock: () => Promise<void>
  readonly touch: (reason?: string) => Promise<void>
}

function showStatusToast(
  context: Context,
  status: { readonly gpgAgentReady: boolean; readonly card: RequestSummary & { readonly connected?: boolean; readonly pinRetries?: { readonly user: number; readonly reset: number; readonly admin: number }; readonly signatureCount?: number; readonly uif?: { readonly sign: string; readonly decrypt: string; readonly auth: string } } },
): void {
  const card = status.card
  if (!card.connected) {
    context.ui.toast.show({
      title: "YubiKey Status",
      message: `No YubiKey detected (gpg-agent: ${status.gpgAgentReady ? "ready" : "offline"})`,
      variant: "warning",
    })
    return
  }
  const retries = card.pinRetries
    ? `[${card.pinRetries.user}/${card.pinRetries.reset}/${card.pinRetries.admin}]`
    : "n/a"
  const pinPolicy = card.pinPolicy ? ` | PIN: ${card.pinPolicy}` : ""
  const uif = card.uif ? ` | Touch: S=${card.uif.sign}/D=${card.uif.decrypt}/A=${card.uif.auth}` : ""
  context.ui.toast.show({
    title: `🔑 YubiKey ${card.serial ?? "Connected"}`,
    message: `Holder: ${card.holder || "unset"} | Sigs: ${card.signatureCount ?? 0}${pinPolicy} | Retries: ${retries}${uif}`,
    variant: "info",
    duration: 5000,
  })
}

function showResultToast(
  context: Context,
  res: { readonly ok: boolean; readonly message: string },
  okTitle: string,
  okVariant: "success" | "info",
  failTitle: string,
  failVariant: "warning" | "error",
): void {
  context.ui.toast.show({
    title: res.ok ? okTitle : failTitle,
    message: res.message,
    variant: res.ok ? okVariant : failVariant,
    duration: 4000,
  })
}

async function runTouchCommand(
  context: Context,
  rpc: PinentryRpcClient,
  location: LocationRef,
  reason?: string,
): Promise<void> {
  const input = { title: "Touch Your YubiKey", ...(reason ? { description: reason } : {}), prompt: "Touch YubiKey" }
  const res = await rpc.promptTouch(input, { location })
  const ok = res.confirmed && !res.cancelled
  const message = ok
    ? "Physical user presence verified on your YubiKey."
    : "YubiKey touch confirmation was cancelled."
  showResultToast(context, { ok, message }, "👆 YubiKey Touch Confirmed", "success", "YubiKey Touch Cancelled", "warning")
}

function createTuiCommandActions(
  context: Context,
  rpc: PinentryRpcClient,
  getLocation: () => LocationRef,
): TuiCommandActions {
  const runSafely = async (errorTitle: string, fn: () => Promise<void>) => {
    try {
      await fn()
    } catch (error) {
      context.ui.toast.show({ title: errorTitle, message: formatError(error), variant: "error" })
    }
  }

  return {
    status: () =>
      runSafely("YubiKey Status Error", async () => {
        const res = await rpc.status({}, { location: getLocation() })
        showStatusToast(context, res as unknown as Parameters<typeof showStatusToast>[1])
      }),
    unlock: (reason?: string) =>
      runSafely("YubiKey Unlock Error", async () => {
        const res = await rpc.unlock({ ...(reason ? { reason } : {}), allowRetry: true }, { location: getLocation() })
        showResultToast(context, res, "🔑 YubiKey Unlocked", "success", "YubiKey Unlock Failed", "warning")
      }),
    lock: () =>
      runSafely("YubiKey Lock Error", async () => {
        const res = await rpc.lock({}, { location: getLocation() })
        showResultToast(context, res, "🔒 YubiKey Locked", "info", "YubiKey Lock Failed", "error")
      }),
    touch: (reason?: string) =>
      runSafely("YubiKey Touch Prompt Error", () => runTouchCommand(context, rpc, getLocation(), reason)),
  }
}

async function dispatchSlashInput(actions: TuiCommandActions, rawInput?: string): Promise<void> {
  const trimmed = (rawInput ?? "").trim()
  const sub = trimmed.toLowerCase()
  if (sub === "lock" || sub === "reset") {
    await actions.lock()
    return
  }
  if (sub === "status" || sub === "info") {
    await actions.status()
    return
  }
  if (sub === "touch" || sub.startsWith("touch ")) {
    await actions.touch(trimmed.replace(/^touch\s*/i, "").trim() || undefined)
    return
  }
  const reason =
    sub === "" || sub === "unlock"
      ? undefined
      : trimmed.replace(/^unlock\s+/i, "").trim() || undefined
  await actions.unlock(reason)
}

function buildKeymapCommands(actions: TuiCommandActions): readonly KeymapCommand[] {
  return [
    {
      id: "oc-yubikey.yubikey",
      title: "YubiKey: Unlock, Lock, Touch, or Status",
      description:
        "Unlock YubiKey PIN, lock cached PIN, test touch prompt, or check OpenPGP card status",
      group: "YubiKey",
      palette: true,
      slash: { name: "yubikey", aliases: ["pinentry", "yk"], arguments: true },
      run: (rawInput) => dispatchSlashInput(actions, rawInput),
    },
    {
      id: "oc-yubikey.unlock",
      title: "YubiKey: Unlock PIN",
      group: "YubiKey",
      palette: true,
      run: () => actions.unlock(),
    },
    {
      id: "oc-yubikey.touch",
      title: "YubiKey: Touch Prompt",
      group: "YubiKey",
      palette: true,
      run: () => actions.touch(),
    },
    {
      id: "oc-yubikey.lock",
      title: "YubiKey: Lock",
      group: "YubiKey",
      palette: true,
      run: () => actions.lock(),
    },
    {
      id: "oc-yubikey.status",
      title: "YubiKey: Card Status",
      group: "YubiKey",
      palette: true,
      run: () => actions.status(),
    },
  ]
}

export default Plugin.define({
  id: "oc-yubikey.tui",
  setup(context) {
    const rpc = context.client.rpc(Pinentry)
    const getLocation = () => context.location ?? context.data.location.default()

    const [genStore, updateGenStore] = context.storage.memory<{ generation: number }>("lifecycle", {
      initial: { generation: 0 },
    })
    let myGeneration = 0
    updateGenStore((draft) => {
      draft.generation += 1
      myGeneration = draft.generation
    })
    const isCurrentGen = () => genStore.generation === myGeneration

    const [pendingQueue, setPendingQueue] = createSignal<QueuedRequest[]>([])
    const [activeDialogRequestID, setActiveDialogRequestID] = createSignal<string | undefined>(
      undefined,
    )

    const settleDialogLocally = (requestID: string): void => {
      setActiveDialogRequestID(undefined)
      setPendingQueue((prev) => prev.filter((item) => item.requestID !== requestID))
      context.ui.dialog.clear()
    }

    const openNextModal = () => {
      if (!isCurrentGen()) return
      const next = pendingQueue()[0]
      if (!next) {
        if (activeDialogRequestID() !== undefined) {
          setActiveDialogRequestID(undefined)
          context.ui.dialog.clear()
        }
        return
      }
      if (activeDialogRequestID() === next.requestID) return

      setActiveDialogRequestID(next.requestID)
      const targetLocation = () => next.location ?? getLocation()

      context.ui.dialog.show(
        () => renderRequestModal(context, rpc, next, targetLocation, settleDialogLocally),
        () => {
          if (activeDialogRequestID() === next.requestID) {
            setActiveDialogRequestID(undefined)
            setPendingQueue((prev) => prev.filter((item) => item.requestID !== next.requestID))
            void rpc
              .cancel(
                { requestID: next.requestID, reason: "dialog-closed" },
                { location: targetLocation() },
              )
              .catch(() => {})
          }
        },
      )
      context.ui.dialog.set({ size: "medium", centered: true })
    }

    const handleRequested = (req: QueuedRequest) => {
      if (!isCurrentGen()) return
      let added = false
      setPendingQueue((prev) => {
        if (prev.some((item) => item.requestID === req.requestID)) return prev
        added = true
        return [...prev, req]
      })
      if (!added) return

      const isTouch = req.kind === "touch"
      void context.attention
        .notify({
          title: req.title || (isTouch ? "👆 Touch Your YubiKey" : "YubiKey PIN Required"),
          message: formatNotificationMessage(req),
          notification: { when: "blurred" },
          sound: { name: "permission", volume: 0.8, when: "always" },
        })
        .catch(() => {})

      openNextModal()
    }

    const handleResolved = (requestID: string) => {
      if (!isCurrentGen()) return
      let removed = false
      setPendingQueue((prev) => {
        if (!prev.some((item) => item.requestID === requestID)) return prev
        removed = true
        return prev.filter((item) => item.requestID !== requestID)
      })
      const wasActive = activeDialogRequestID() === requestID
      if (wasActive) {
        setActiveDialogRequestID(undefined)
        context.ui.dialog.clear()
      }
      if (removed || wasActive) {
        openNextModal()
      }
    }

    const unsubPrompt = rpc.events.on("prompt", (event) => {
      handleRequested({ ...event.data, location: event.location })
    })

    const unsubSettled = rpc.events.on("settled", (event) => {
      handleResolved(event.data.requestID)
    })

    const stopDataListen = context.data.listen(({ details }) => {
      if (!isCurrentGen()) return
      if (details.type === "rpc.oc-yubikey.prompt") {
        const data = details.data as RequestSummary
        handleRequested({ ...data, location: details.location ?? getLocation() })
      } else if (details.type === "rpc.oc-yubikey.settled") {
        const data = details.data as { requestID: string }
        handleResolved(data.requestID)
      }
    })

    void rpc
      .status({}, { location: getLocation() })
      .then((status) => {
        if (isCurrentGen() && status.pending.length > 0) {
          const loc = getLocation()
          setPendingQueue(status.pending.map((item) => ({ ...item, location: loc })))
          openNextModal()
        }
      })
      .catch(() => {})

    const commands = buildKeymapCommands(createTuiCommandActions(context, rpc, getLocation))
    context.keymap.layer(() => ({
      mode: "global",
      commands,
    }))

    const disposeFooterSlot = context.ui.slot({
      append: "prompt.footer.status",
      render: () =>
        show(
          () => pendingQueue().length > 0,
          () =>
            h(
              "text",
              { fg: context.theme.text.feedback.warning.base, onMouseUp: () => openNextModal() },
              () => (pendingQueue()[0]?.kind === "touch" ? "👆 Touch YubiKey required" : "🔑 YubiKey PIN required"),
            ),
        ),
    })

    return () => {
      unsubPrompt()
      unsubSettled()
      stopDataListen()
      disposeFooterSlot()
    }
  },
})
