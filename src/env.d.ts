interface Buffer extends Uint8Array {
  writeUInt32BE(value: number, offset?: number): number
  readUInt32BE(offset?: number): number
  subarray(start?: number, end?: number): Buffer
  copy(target: Uint8Array, targetStart?: number, sourceStart?: number, sourceEnd?: number): number
  toString(encoding?: "utf8" | "hex" | "base64" | "ascii"): string
}

declare var Buffer: {
  alloc(size: number, fill?: number): Buffer
  from(data: string, encoding?: "utf8" | "hex" | "base64" | "ascii"): Buffer
  from(data: ArrayLike<number> | ArrayBufferView): Buffer
  concat(list: readonly Uint8Array[], totalLength?: number): Buffer
  isBuffer(obj: unknown): obj is Buffer
}

declare namespace NodeJS {
  interface ProcessEnv {
    [key: string]: string | undefined
  }
  interface WritableStream {
    write(chunk: string | Uint8Array): boolean
  }
  interface ReadableStream {
    on(event: "data", listener: (chunk: Buffer | string) => void): this
    on(event: "end" | "error", listener: () => void): this
  }
  interface Timeout {
    unref?(): this
  }
}

interface Timer {
  unref?(): this
}

declare var process: {
  readonly pid: number
  readonly argv: string[]
  readonly env: NodeJS.ProcessEnv
  readonly stdout: NodeJS.WritableStream
  readonly stderr: NodeJS.WritableStream
  readonly stdin: NodeJS.ReadableStream
  getuid?(): number
  exit(code?: number): never
  on(event: "SIGTERM" | "SIGINT" | "SIGHUP", listener: () => void): void
}

interface BunSpawnOptions {
  readonly cmd?: readonly string[]
  readonly cwd?: string | URL
  readonly env?: Record<string, string | undefined>
  readonly stdin?: "ignore" | "pipe" | "inherit" | null
  readonly stdout?: "ignore" | "pipe" | "inherit" | null
  readonly stderr?: "ignore" | "pipe" | "inherit" | null
  readonly [key: string]: unknown
}

interface BunSubprocess {
  readonly pid: number
  readonly exited: Promise<number>
  readonly stdout?: ReadableStream<Uint8Array> | null
  readonly stderr?: ReadableStream<Uint8Array> | null
  kill(signal?: number | string): void
}

interface BunSyncSubprocess {
  readonly exitCode: number
  readonly stdout?: Buffer
  readonly stderr?: Buffer
}

declare var Bun: {
  spawn(cmd: readonly string[], options?: BunSpawnOptions): BunSubprocess
  spawn(options: BunSpawnOptions & { readonly cmd: readonly string[] }): BunSubprocess
  spawnSync(cmd: readonly string[], options?: BunSpawnOptions): BunSyncSubprocess
  spawnSync(options: BunSpawnOptions & { readonly cmd: readonly string[] }): BunSyncSubprocess
}

declare module "node:crypto" {
  export interface Hash {
    update(data: string | Uint8Array): this
    digest(encoding: "hex" | "base64"): string
  }
  export function createHash(algorithm: "sha256" | "sha512"): Hash
  export function randomBytes(size: number): Buffer
  export function randomUUID(): `${string}-${string}-${string}-${string}-${string}`
  export function timingSafeEqual(a: ArrayBufferView, b: ArrayBufferView): boolean
}

declare module "node:fs" {
  export interface Stats {
    readonly uid: number
    readonly mode: number
    isFile(): boolean
    isDirectory(): boolean
    isSocket(): boolean
    isSymbolicLink(): boolean
  }
  export function chmodSync(path: string, mode: number): void
  export function existsSync(path: string): boolean
  export function lstatSync(path: string): Stats
  export function mkdirSync(
    path: string,
    options?: { recursive?: boolean; mode?: number },
  ): string | undefined
  export function mkdtempSync(prefix: string): string
  export interface Dirent {
    readonly name: string
    isDirectory(): boolean
    isFile(): boolean
  }
  export function readdirSync(path: string): string[]
  export function readdirSync(path: string, options: { withFileTypes: true }): Dirent[]
  export function readFileSync(path: string, encoding: "utf8"): string
  export function realpathSync(path: string): string
  export function renameSync(oldPath: string, newPath: string): void
  export function rmSync(path: string, options?: { recursive?: boolean; force?: boolean }): void
  export function symlinkSync(target: string, path: string): void
  export function writeFileSync(
    path: string,
    data: string | Uint8Array,
    options?: { mode?: number; flag?: string },
  ): void
}

declare module "node:net" {
  export interface Socket {
    readonly destroyed: boolean
    write(data: string | Uint8Array): boolean
    end(data?: string | Uint8Array): this
    destroy(error?: Error): this
    on(event: "data", listener: (chunk: Buffer) => void): this
    on(event: "error", listener: (err: Error) => void): this
    on(event: "close", listener: () => void): this
    once(event: "data", listener: (chunk: Buffer) => void): this
    once(event: "connect", listener: () => void): this
    once(event: "error", listener: (err: Error) => void): this
    once(event: "close", listener: () => void): this
  }
  export interface Server {
    listen(path: string, listeningListener?: () => void): this
    close(callback?: (err?: Error) => void): this
    once(event: "error", listener: (err: Error) => void): this
  }
  export function createConnection(options: { path: string }): Socket
  export function createServer(connectionListener?: (socket: Socket) => void): Server
  namespace netDefault {
    export type { Socket, Server }
    export { createConnection, createServer }
  }
  export default netDefault
}

declare module "node:os" {
  export function homedir(): string
  export function tmpdir(): string
  const osDefault: {
    homedir: typeof homedir
    tmpdir: typeof tmpdir
  }
  export default osDefault
}

declare module "node:path" {
  export function join(...paths: string[]): string
  export function resolve(...paths: string[]): string
  export function dirname(p: string): string
  export function basename(p: string): string
  export function relative(from: string, to: string): string
  export function isAbsolute(p: string): boolean
  const pathDefault: {
    join: typeof join
    resolve: typeof resolve
    dirname: typeof dirname
    basename: typeof basename
    relative: typeof relative
    isAbsolute: typeof isAbsolute
  }
  export default pathDefault
}

declare module "node:url" {
  export function fileURLToPath(url: string | URL): string
}

declare module "node:child_process" {
  import type { ReadableStream, WritableStream } from "node:stream"
  export interface ChildProcess {
    readonly stdin: WritableStream & { end(): void }
    readonly stdout: ReadableStream
    readonly stderr: ReadableStream
    readonly stdio: readonly (ReadableStream | WritableStream | null | undefined)[]
    kill(signal?: string): boolean
    on(event: "error", listener: (err: Error) => void): this
    on(event: "close" | "exit", listener: (code: number | null) => void): this
    once(event: "error", listener: (err: Error) => void): this
    once(event: "close" | "exit", listener: (code: number | null) => void): this
  }
  export function spawn(
    command: string,
    args: readonly string[],
    options?: {
      env?: Record<string, string | undefined>
      stdio?: "inherit" | readonly ("ignore" | "pipe" | "inherit")[]
    },
  ): ChildProcess
}

declare module "node:stream" {
  export interface ReadableStream {
    on(event: "data", listener: (chunk: Buffer | string) => void): this
  }
  export interface WritableStream {
    write(chunk: string | Uint8Array): boolean
    end(): void
  }
}

declare module "@opencode/plugin/rpc" {
  export interface StandardSchemaV1<Input = unknown, Output = Input> {
    readonly "~standard": {
      readonly version: 1
      readonly vendor: string
      readonly validate: (
        value: unknown,
      ) =>
        | { readonly value: Output }
        | { readonly issues: ReadonlyArray<{ readonly message: string }> }
      readonly types?: {
        readonly input: Input
        readonly output: Output
      }
    }
  }

  export type InferInput<S> = S extends StandardSchemaV1<infer I, unknown> ? I : unknown
  export type InferOutput<S> = S extends StandardSchemaV1<unknown, infer O> ? O : unknown

  export interface MethodDefinition<I = unknown, O = unknown> {
    readonly input: StandardSchemaV1<I, I>
    readonly output: StandardSchemaV1<O, O>
  }

  export interface EventDefinition<T = unknown> {
    readonly schema: StandardSchemaV1<T, T>
  }

  export interface RpcDefinition<
    Id extends string = string,
    Methods extends Readonly<Record<string, MethodDefinition<any, any>>> = Readonly<
      Record<string, MethodDefinition<any, any>>
    >,
    Events extends Readonly<Record<string, EventDefinition<any>>> = Readonly<
      Record<string, EventDefinition<any>>
    >,
  > {
    readonly id: Id
    readonly methods: Methods
    readonly events: Events
  }

  export namespace Rpc {
    export function define<
      const Id extends string,
      const Methods extends Readonly<Record<string, MethodDefinition<any, any>>>,
      const Events extends Readonly<Record<string, EventDefinition<any>>>,
    >(definition: {
      readonly id: Id
      readonly methods: Methods
      readonly events: Events
    }): RpcDefinition<Id, Methods, Events>
  }
}

declare module "@opencode/plugin" {
  import type { InferInput, InferOutput, RpcDefinition } from "@opencode/plugin/rpc"

  export interface DisposableRegistration {
    dispose(): Promise<void>
  }

  export interface RpcHandlerContext {
    readonly signal: AbortSignal
  }

  export type RpcHandlers<D extends RpcDefinition> = {
    readonly [K in keyof D["methods"]]: (
      input: InferInput<D["methods"][K]["input"]>,
      ctx: RpcHandlerContext,
    ) => Promise<InferOutput<D["methods"][K]["output"]>>
  }

  export interface RpcRegistration<D extends RpcDefinition> extends DisposableRegistration {
    readonly events: {
      emit<E extends keyof D["events"] & string>(
        name: E,
        payload: InferOutput<D["events"][E]["schema"]>,
      ): Promise<void>
    }
  }

  export interface ShellInvocation {
    readonly command?: string
    readonly env: Record<string, string | undefined>
  }

  export interface ToolContext {
    readonly signal: AbortSignal
    progress(info: { status: string }): Promise<void>
  }

  export interface ToolDefinition {
    readonly name: string
    readonly options?: { readonly codemode?: boolean }
    readonly description: string
    readonly input: Record<string, unknown>
    execute(
      input: unknown,
      context: ToolContext,
    ): Promise<{ content: string; metadata?: Record<string, unknown> }>
  }

  export interface ToolEditor {
    add(tool: ToolDefinition): void
  }

  export interface ServerPluginContext {
    readonly location?: {
      readonly directory?: string
      readonly workspaceID?: string
    }
    readonly options?: Readonly<Record<string, unknown>>
    readonly rpc: {
      register<D extends RpcDefinition>(
        contract: D,
        handlers: RpcHandlers<D>,
      ): Promise<RpcRegistration<D>>
    }
    readonly shell: {
      hook(
        event: "create.before",
        handler: (invocation: ShellInvocation) => Promise<void> | void,
      ): Promise<DisposableRegistration>
    }
    readonly tool: {
      transform(fn: (editor: ToolEditor) => void): Promise<DisposableRegistration>
    }
  }

  export interface ServerPluginDefinition {
    readonly id: string
    setup(ctx: ServerPluginContext): Promise<(() => Promise<void> | void) | void>
  }

  export namespace Plugin {
    export function define(plugin: ServerPluginDefinition): ServerPluginDefinition
  }
}

declare module "@opencode/plugin/tui/context" {
  import type { InferInput, InferOutput, RpcDefinition } from "@opencode/plugin/rpc"
  import type { KeyEvent } from "@opentui/core"
  import type { JSX } from "@opentui/solid"

  export interface LocationRef {
    readonly directory: string
    readonly workspaceID?: string
  }

  export type RpcClient<D extends RpcDefinition> = {
    readonly [K in keyof D["methods"]]: (
      input: InferInput<D["methods"][K]["input"]>,
      options?: { readonly location?: LocationRef },
    ) => Promise<InferOutput<D["methods"][K]["output"]>>
  } & {
    readonly events: {
      on<E extends keyof D["events"] & string>(
        name: E,
        handler: (event: {
          readonly data: InferOutput<D["events"][E]["schema"]>
          readonly location: LocationRef
        }) => void,
      ): () => void
    }
  }

  export interface ThemeSurface {
    readonly text: {
      readonly base: string
      readonly muted: string
      readonly feedback: {
        readonly error: { readonly base: string }
        readonly warning: { readonly base: string }
      }
    }
    readonly background: {
      readonly raised: { readonly base: string }
      readonly feedback: {
        readonly error: { readonly base: string }
      }
    }
  }

  export interface KeymapCommand {
    readonly id?: string
    readonly title?: string
    readonly description?: string
    readonly group?: string
    readonly bind?: false | string
    readonly palette?: true
    readonly slash?: {
      readonly name: string
      readonly aliases?: string[]
      readonly arguments?: true
    }
    readonly run: (input?: string, event?: KeyEvent) => void | false | Promise<void>
  }

  export interface KeymapLayer {
    readonly mode?: string
    readonly priority?: number
    readonly commands?: readonly KeymapCommand[]
  }

  export interface Context {
    readonly location: LocationRef | undefined
    readonly client: {
      rpc<D extends RpcDefinition>(contract: D): RpcClient<D>
    }
    readonly data: {
      readonly location: {
        default(): LocationRef
      }
      readonly session?: {
        get(sessionID: string): { readonly location?: LocationRef } | undefined
      }
      listen(
        handler: (event: {
          readonly details: {
            readonly type: string
            readonly data: unknown
            readonly location?: LocationRef
          }
        }) => void,
      ): () => void
    }
    readonly storage: {
      memory<Value extends object>(
        key: string,
        options: { readonly initial: Value },
      ): readonly [Value, (mutation: (draft: Value) => void) => void]
    }
    readonly theme: {
      readonly text: ThemeSurface["text"]
      surface(name: "dialog"): ThemeSurface
    }
    readonly renderer: {
      readonly keyInput: {
        on(event: "keypress", handler: (event: KeyEvent) => void): void
        off(event: "keypress", handler: (event: KeyEvent) => void): void
      }
    }
    readonly attention: {
      notify(options: {
        readonly title?: string
        readonly message: string
        readonly notification?: boolean | { readonly when?: "always" | "focused" | "blurred" }
        readonly sound?:
          | boolean
          | {
              readonly name?:
                | "default"
                | "question"
                | "permission"
                | "error"
                | "done"
                | "subagent_done"
              readonly volume?: number
              readonly when?: "always" | "focused" | "blurred"
            }
      }): Promise<unknown>
    }
    readonly keymap: {
      layer(factory: () => KeymapLayer): void
    }
    readonly ui: {
      readonly router?: {
        current(): { readonly type: string; readonly sessionID?: string }
      }
      readonly dialog: {
        show(render: () => JSX.Element, onClose?: () => void): void
        set(options: { readonly size?: "medium" | "large" | "xlarge"; readonly centered?: boolean }): void
        clear(): void
      }
      readonly toast: {
        show(options: {
          readonly title?: string
          readonly message: string
          readonly variant?: "info" | "success" | "warning" | "error"
          readonly duration?: number
        }): void
      }
      slot(claim: {
        readonly append: "prompt.footer.status" | "app"
        readonly render: () => JSX.Element
      }): () => void
    }
  }
}

declare module "@opencode/plugin/tui" {
  import type { Context } from "@opencode/plugin/tui/context"

  export interface TuiPluginDefinition {
    readonly id: string
    setup(context: Context): (() => void) | void
  }

  export namespace Plugin {
    export function define(plugin: TuiPluginDefinition): TuiPluginDefinition
  }
}

declare module "@opentui/core" {
  export enum TextAttributes {
    NONE = 0,
    BOLD = 1,
  }
  export interface KeyEvent {
    readonly name: string
    readonly sequence?: string
    readonly ctrl?: boolean
    readonly meta?: boolean
    readonly shift?: boolean
    preventDefault(): void
  }
}

declare module "@opentui/solid" {
  export namespace JSX {
    export type Element =
      | { readonly __jsxElement?: true }
      | string
      | number
      | boolean
      | null
      | undefined
    export interface ElementChildrenAttribute {
      children: {}
    }
    export interface IntrinsicElements {
      box: {
        readonly paddingLeft?: number
        readonly paddingRight?: number
        readonly paddingTop?: number
        readonly paddingBottom?: number
        readonly gap?: number
        readonly flexDirection?: "row" | "column"
        readonly justifyContent?: "space-between" | "flex-start" | "center"
        readonly backgroundColor?: string
        readonly children?: unknown
      }
      text: {
        readonly attributes?: number
        readonly fg?: string | (() => string)
        readonly wrapMode?: "word" | "char" | "none"
        readonly onMouseUp?: () => void
        readonly children?: unknown
      }
      span: {
        readonly style?: { readonly fg?: string } | (() => { readonly fg?: string })
        readonly children?: unknown
      }
    }
  }

  export function createElement(tag: keyof JSX.IntrinsicElements): JSX.Element
  export function createTextNode(value: string): JSX.Element
  export function insertNode(parent: JSX.Element, node: JSX.Element, anchor?: JSX.Element): void
  export function insert(
    parent: JSX.Element,
    accessor: unknown,
    marker?: JSX.Element | null,
    initial?: unknown,
  ): JSX.Element
  export function setProp<T>(node: JSX.Element, name: string, value: T, prev?: T): T
  export function effect<T>(fn: (prev?: T) => T, init?: T): void
  export function memo<T>(fn: () => T, equal?: boolean): () => T
  export function createComponent<P>(Comp: (props: P) => JSX.Element, props: P): JSX.Element
}

declare module "@opentui/solid/jsx-runtime" {
  import type { JSX as SolidJSX } from "@opentui/solid"
  export namespace JSX {
    export type Element = SolidJSX.Element
    export type ElementChildrenAttribute = SolidJSX.ElementChildrenAttribute
    export type IntrinsicElements = SolidJSX.IntrinsicElements
  }
}

declare module "solid-js" {
  import type { JSX } from "@opentui/solid"

  export type Accessor<T> = () => T
  export type Setter<T> = (value: T | ((prev: T) => T)) => T

  export function createSignal<T>(initialValue: T): [Accessor<T>, Setter<T>]
  export function onMount(fn: () => void): void
  export function onCleanup(fn: () => void): void
  export function Show<T>(props: {
    readonly when: T | undefined | null | false
    readonly children: JSX.Element | ((item: Accessor<NonNullable<T>>) => JSX.Element)
  }): JSX.Element
}

declare module "bun:test" {
  export interface AsymmetricMatchers {
    toBe(expected: unknown): void
    toEqual(expected: unknown): void
    toContain(expected: unknown): void
    toMatch(expected: RegExp | string): void
    toStartWith(expected: string): void
    toBeUndefined(): void
    toBeDefined(): void
    toBeGreaterThan(expected: number): void
    toBeLessThanOrEqual(expected: number): void
  }
  export interface ExpectMatchers extends AsymmetricMatchers {
    readonly not: AsymmetricMatchers
  }
  export function describe(name: string, fn: () => void): void
  export function it(name: string, fn: () => Promise<void> | void): void
  export function test(name: string, fn: () => Promise<void> | void): void
  export function expect(actual: unknown): ExpectMatchers
  export function afterEach(fn: () => Promise<void> | void): void
  export function beforeEach(fn: () => Promise<void> | void): void
}
