# `oc-yubikey` — YubiKey PIN & Touch Prompts for OpenCode V2

`oc-yubikey` is an OpenCode V2 plugin (`@opencode/plugin` + `@opencode/plugin/tui`) for macOS that brings native **YubiKey PIN entry** and **physical touch confirmation** into the OpenCode TUI—with audio notifications, automatic dismissal on hardware touch, and zero-exposure in-process Assuan PIN verification.

```bash
# Quick check inside any OpenCode session:
/yubikey status
```

---

## Table of Contents

- [Level 1 — Overview & Quick Start](#level-1--overview--quick-start)
- [Level 2 — Daily Usage](#level-2--daily-usage)
- [Level 3 — System Architecture](#level-3--system-architecture)
- [Level 4 — Security Model & Hardening](#level-4--security-model--hardening)
- [Level 5 — Configuration, Troubleshooting & Development](#level-5--configuration-troubleshooting--development)

---

## Level 1 — Overview & Quick Start

Hardware-backed YubiKey commands (`git pull`, `git push`, `ssh`, `git commit -S`, `git tag -s`) use FIDO2 (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`) or OpenPGP keys. Each command blocks on a PIN or a physical touch on the YubiKey contact sensor. Without a TUI prompt, terminal sessions appear frozen or pop up external GUI windows behind the terminal.

`oc-yubikey` solves both problems directly inside OpenCode:

- **👆 Touch Your YubiKey Modal (`TouchModal`)**: Opens automatically with an audio chime when an SSH or OpenPGP operation awaits physical touch, displays the active command and key fingerprint, and **dismisses itself the instant you touch the YubiKey** (or aborts immediately if you press `Esc`).
- **🔑 YubiKey PIN Modal (`PinentryModal`)**: Masked PIN input with retry counter warnings, card serial/holder metadata, and in-process `gpg-agent` Assuan loopback verification (`PKSIGN` / `SCD CHECKPIN`) so your PIN never touches disk, shell history, or model context.

### Quick Start (2 Steps)

1. **Register the plugin in `~/.config/opencode/opencode.jsonc`:**

   ```jsonc
   {
     "$schema": "https://opencode.ai/config.json",
     "plugins": ["github:<owner>/oc-yubikey"]
   }
   ```

   Replace `<owner>` with the GitHub account that hosts the plugin. A local checkout path (for example `"/path/to/oc-yubikey"`) also works during development.

2. **Verify inside OpenCode:**
   Run `/yubikey status` in the TUI prompt or ask the agent to run `yubikey_status`. `oc-yubikey` injects `bin/oc-yubikey-gpg` as `gpg.program` and `bin/oc-yubikey` as `SSH_ASKPASS`. You do not need to edit `~/.gnupg/gpg.conf` or `~/.gnupg/gpg-agent.conf`.

---

## Level 2 — Daily Usage

### Automatic Touch & PIN Triggers

When `oc-yubikey` starts in `setup()`, it applies `prepareShellEnv(process.env)` and registers a `shell.hook("create.before")` hook. Both OpenCode shell commands and child processes spawned by other plugins inherit the authenticated IPC channel, `bin/oc-yubikey-gpg` wrapper, and transparent `SSH_AUTH_SOCK` proxy:

| Operation | Trigger | TUI Modal | Resolution |
| :--- | :--- | :--- | :--- |
| `git pull`, `git fetch`, `git push`, `ssh` (FIDO2 `-sk` or OpenPGP SSH key) | `SSH2_AGENTC_SIGN_REQUEST` or `SSH_ASKPASS` | `TouchModal` / `PinentryModal` | Auto-closes on physical YubiKey touch (`SIGN_RESPONSE` / `SIGTERM`) or aborts on `Esc` |
| `git commit -S`, `git tag -s`, `gpg --sign` | `bin/oc-yubikey-gpg` loopback `GET_HIDDEN` or `gpg-agent` Assuan `CONFIRM` / `GETPIN` | `TouchModal` / `PinentryModal` | Auto-closes on physical touch or submits PIN over local IPC |
| `/yubikey unlock` or `yubikey_unlock` tool | Direct Assuan loopback (`PKSIGN` / `SCD CHECKPIN`) | `PinentryModal` | Verifies and caches OpenPGP PIN in `gpg-agent` |

### TUI Slash Commands & Command Palette

| Command | Aliases | Description |
| :--- | :--- | :--- |
| `/yubikey` or `/yubikey unlock [reason]` | `/pinentry`, `/yk` | Open the PIN modal and unlock the YubiKey OpenPGP card in `gpg-agent` |
| `/yubikey touch [reason]` | `/yk touch` | Trigger a real FIDO2 hardware touch challenge (`ssh-keygen -Y sign`), play sound notification, and auto-dismiss on physical YubiKey touch |
| `/yubikey status` | `/yk info` | Show a toast with card serial, holder, signature counter, PIN policy, PIN retries, and UIF touch policy |
| `/yubikey lock` | `/yk reset` | Clear the cached PIN (`SCD RESET` + `RELOADAGENT`) |

### OpenPGP Card States & PIN Behavior

An OpenPGP smartcard always defines a user PIN (`PW1`) and a retry counter in DO `0xC4`. The plugin reads the card before prompting for three states:

| User Scenario | Hardware Card State | Observable Signals | Plugin Behavior |
| :--- | :--- | :--- | :--- |
| PIN is blocked | `PW1` error counter is `0` | `pinRetries.user === 0` | Refuses to prompt and reports that the user PIN is blocked |
| Applet never personalized | Factory state (`PW1` = `123456`, empty reset code) | `pinRetries.reset === 0`, no `holder`, no `keys` | Refuses `unlock()` without prompting and disables retries |
| Card has no OpenPGP keys | Applet initialized without keys | `keys === undefined` | Refuses `unlock()` before opening `PinentryModal` |

### Modal Keyboard Shortcuts

| Key | `PinentryModal` Action | `TouchModal` Action |
| :--- | :--- | :--- |
| `Enter` | Submit PIN to `gpg-agent` / `SSH_ASKPASS` | — |
| `Tab` / `Ctrl+R` / `Alt+R` | Toggle masked (`••••••`) vs. visible PIN | — |
| `Ctrl+U` / `Ctrl+W` | Clear current PIN buffer | — |
| `Backspace` / `Delete` | Remove last character | — |
| `Esc` | Cancel PIN entry | Abort waiting SSH/GPG operation immediately (`SSH_AGENT_FAILURE`) |

### Agent Tools

All four tools are registered with `options: { codemode: false }` so the LLM must invoke them as explicit top-level tool calls:

- **`yubikey_status`**: Inspects `gpg-agent` readiness and `gpg --card-status` metadata (reader, serial, Application ID, holder, signature count, signature PIN policy `once` / `always`, PIN retry counters `[user reset admin]`, and UIF touch policy).
- **`yubikey_unlock`**: Opens the TUI `PinentryModal` and verifies and caches the user's PIN directly in `gpg-agent` (`OPTION pinentry-mode=loopback` → `SCD SERIALNO` → `KEYINFO --list` → `SIGKEY <sigKeygrip>` → `SETHASH 10 <zero-hash>` → `PKSIGN`, with fallback to `SCD CHECKPIN <aid>`). The PIN is never returned to the LLM.
- **`yubikey_touch`**: Triggers a hardware FIDO2 user-presence challenge (`ssh-keygen -Y sign` against `~/.ssh/id_*_sk`), opens `TouchModal` in the TUI, and resolves automatically when the user physically touches the YubiKey.
- **`yubikey_lock`**: Clears cached PIN state in `scdaemon` and reloads `gpg-agent` (`SCD RESET` + `RELOADAGENT`).

---

## Level 3 — System Architecture

### Component Topology

```mermaid
flowchart TB
  subgraph TUI["OpenCode TUI Process (src/tui.tsx)"]
    ModalPin["PinentryModal\n(Masked PIN Input)"]
    ModalTouch["TouchModal\n(Pulsing Touch Prompt)"]
    Attention["context.attention.notify\n(Audio & Desktop Alert)"]
  end

  subgraph Server["OpenCode Server Process (src/index.ts)"]
    Coord["PinentryCoordinator\n(src/coordinator.ts)"]
    Bridge["PinentryBridge\n(src/bridge.ts)"]
    Assuan["GpgAgentAssuanClient\n(src/yubikey.ts)"]
  end

  subgraph Runtime["Shell & External Daemons"]
    ShellCmd["git pull / git push / git commit -S"]
    CliShim["bin/oc-yubikey\n(src/cli.ts)"]
    SshAgent["Upstream ssh-agent\nor gpg-agent.ssh"]
    GpgAgent["gpg-agent + scdaemon\n(YubiKey Hardware)"]
  end

  TUI <-->|"Typed RPC (src/rpc.ts)\nprompt / settled / submit / cancel"| Coord
  Coord <--> Bridge
  Coord -->|"Assuan Loopback\nPKSIGN / SCD CHECKPIN"| Assuan
  Assuan <-->|"~/.gnupg/S.gpg-agent"| GpgAgent

  Bridge -.->|"shell.hook('create.before')\nSSH_AUTH_SOCK + SSH_ASKPASS + OC_YUBIKEY_TOKEN"| ShellCmd
  ShellCmd -->|"SSH2_AGENTC_SIGN_REQUEST (13)"| Bridge
  Bridge <-->|"Proxied SSH Agent Frames"| SshAgent
  ShellCmd -->|"SSH_ASKPASS"| CliShim
  GpgAgent -->|"Assuan CONFIRM / GETPIN"| CliShim
  CliShim <-->|"Authenticated Unix IPC\n(256-bit token, 0600)"| Bridge
```

### Flow 1: SSH Security Key & Hardware Agent Touch (`SSH_AUTH_SOCK` Proxy)

```mermaid
sequenceDiagram
  autonumber
  participant Git as git pull / ssh
  participant Proxy as PinentryBridge (SSH Proxy)
  participant Agent as Upstream ssh-agent / gpg-agent.ssh
  participant Coord as PinentryCoordinator
  participant TUI as OpenCode TUI (TouchModal)

  Git->>Proxy: SSH2_AGENTC_SIGN_REQUEST (msg 13)
  Proxy->>Agent: Forward SIGN_REQUEST
  Note over Proxy: Parse keyType (ED25519-SK) & SHA256 fingerprint<br/>Start debounce timer (40ms SK / 150ms Agent)
  Proxy->>Coord: requestTouch({ keyType, fingerprint, command })
  Coord->>TUI: RPC event "prompt" (kind: "touch")
  Note over TUI: Play sound & display TouchModal
  alt User touches YubiKey hardware
    Agent-->>Proxy: SSH2_AGENT_SIGN_RESPONSE (msg 14)
    Proxy-->>Git: Forward SIGN_RESPONSE
    Proxy->>Coord: confirmTouch(requestID)
    Coord->>TUI: RPC event "settled" (outcome: "confirmed")
    Note over TUI: TouchModal auto-closes
  else User presses Esc in TUI
    TUI->>Coord: RPC cancel(requestID, "user-pressed-escape")
    Coord-->>Proxy: Resolution { cancelled: true }
    Proxy-->>Git: Synthetic SSH_AGENT_FAILURE (msg 5)
    Proxy->>Agent: Destroy upstream socket
  end
```

### Flow 2: `SSH_ASKPASS` & GnuPG Assuan `pinentry` Shim (`bin/oc-yubikey`)

```mermaid
sequenceDiagram
  autonumber
  participant Caller as ssh-sk-helper or gpg-agent
  participant Shim as bin/oc-yubikey (src/cli.ts)
  participant Bridge as PinentryBridge (IPC Server)
  participant Coord as PinentryCoordinator
  participant TUI as OpenCode TUI

  Caller->>Shim: Spawn (SSH_ASKPASS arg or Assuan stdin)
  Shim->>Bridge: Connect /tmp/oc-yk-<uid>/ipc-<id>.sock + 256-bit token
  Bridge->>Bridge: Verify timingSafeEqual(token)
  Bridge->>Coord: requestTouch() or requestPin()
  Coord->>TUI: RPC event "prompt"
  alt Touch confirmed via SIGTERM / Assuan BYE
    Caller->>Shim: SIGTERM or Assuan "BYE"
    Shim->>Bridge: Socket EOF
    Bridge->>Coord: confirmTouch(requestID)
    Coord->>TUI: RPC event "settled" (auto-dismiss)
  else PIN submitted in TUI
    TUI->>Coord: RPC submit(requestID, pin)
    Coord-->>Bridge: { cancelled: false, pin }
    Bridge-->>Shim: { ok: true, pin }
    Shim-->>Caller: stdout PIN or Assuan "D <percent-encoded-pin>\nOK"
  end
```

The shim talks to the instance that owns the running command. `gpg-agent` passes that
instance as `PINENTRY_USER_DATA` to the pinentry program it launches, and the shim
prefers it over the `OC_YUBIKEY_*` variables, which the agent inherited from the shell
that started it and which can name an instance that is gone. `prepareShellEnv()` also sets
`GPG_TTY=/dev/null` so a non-interactive OpenCode shell never directs `gpg` or
`pinentry-curses` to open the terminal owned by the OpenCode TUI.

### Flow 3: Direct Assuan Loopback Unlock (`yubikey_unlock`)

```mermaid
sequenceDiagram
  autonumber
  participant User as User / Agent
  participant Coord as PinentryCoordinator
  participant TUI as OpenCode TUI (PinentryModal)
  participant Assuan as GpgAgentAssuanClient
  participant GPG as gpg-agent / scdaemon

  User->>Coord: unlock({ reason, allowRetry: true })
  Coord->>GPG: gpg --card-status (read serial, holder, pinRetries)
  Coord->>TUI: RPC event "prompt" (kind: "pin", retriesLeft)
  TUI->>Coord: RPC submit(requestID, pin)
  Coord->>Assuan: verifyYubiKeyPinLoopback(pin)
  Assuan->>GPG: OPTION pinentry-mode=loopback
  GPG-->>Assuan: OK
  Assuan->>GPG: SCD SERIALNO
  GPG-->>Assuan: S SERIALNO D2760001240103040006123456780000
  Assuan->>GPG: KEYINFO --list
  GPG-->>Assuan: S KEYINFO <sigKeygrip> T <aid> OPENPGP.1 - - - - A
  Assuan->>GPG: SIGKEY <sigKeygrip> + SETHASH 10 <64-byte-zero-hex> + PKSIGN
  GPG-->>Assuan: INQUIRE PASSPHRASE
  Assuan->>GPG: D <percent-encoded-pin> + END
  GPG-->>Assuan: D (7:sig-val...) + OK
  Assuan-->>Coord: { ok: true }
```

### Coordinator Request State Machine

```mermaid
stateDiagram-v2
  [*] --> Pending: requestPin() / requestTouch()
  Pending --> Submitted: submit(requestID, pin)\n[kind == "pin"]
  Pending --> Confirmed: confirmTouch(requestID)\n[kind == "touch" or IPC EOF]
  Pending --> Cancelled: cancel(requestID, reason)\n[Esc / dialog-closed / SSH_AGENT_FAILURE / AbortSignal / 180s timeout]
  Submitted --> [*]
  Confirmed --> [*]
  Cancelled --> [*]
```

---

## Level 4 — Security Model & Hardening

`oc-yubikey` enforces defense-in-depth across every IPC boundary, socket, and TUI surface:

| Control | Implementation |
| :--- | :--- |
| **Zero Model Exposure** | `yubikey_unlock` verifies and caches the PIN inside the server process via Assuan loopback (`PKSIGN` / `SCD CHECKPIN`) and returns only `{ ok, message, card }`. The raw `promptPin` RPC is disabled by default unless `allowRawPinRpc: true` is explicitly configured. |
| **Per-Instance 256-bit IPC Token Auth** | `PinentryBridge` generates a 32-byte cryptographic token (`randomBytes(32).toString("hex")`) per instance and verifies every IPC connection using `crypto.timingSafeEqual`. Unauthenticated local sockets are rejected before reaching `PinentryCoordinator`. |
| **Socket & Directory Ownership Verification** | `/tmp/oc-yk-<uid>` (`0700`), `ipc-<id>.sock` (`0600`), `active.json` (`0600`), and upstream `gpg-agent` / `SSH_AUTH_SOCK` paths are verified via `lstatSync` to reject symlinks, non-sockets, foreign UIDs, and group/world permissions (`mode & 0o077`). |
| **Atomic Pointer Updates** | `active.json` is written via an exclusive temporary file (`flag: "wx"`, `mode: 0o600`) and atomically renamed into place, then removed on `bridge.close()`. |
| **PIN Retry Lockout Guard** | `PinentryCoordinator.unlock()` refuses to prompt when the card has no OpenPGP keys or when `pinRetries.user <= 0`, and stops automatic retries when `pinRetries.user <= 1`, when retry counters are unreadable, or when the applet is unpersonalized. |
| **Assuan & Display Sanitization** | Assuan commands reject `\r`, `\n`, and `\0`, validate `aid`/`keygrip` against `/^[0-9A-Fa-f]{16,64}$/`, zero temporary `Buffer` instances (`pinBuf.fill(0)`), and strip ANSI/OSC control characters and Unicode bidirectional overrides (`sanitizeDisplayText`) before rendering in the TUI. |
| **Trusted Executable Resolution** | Child processes (`gpg`, `gpgconf`, `gpg-connect-agent`, fallback `pinentry-mac`) are resolved against root/user-owned non-world-writable system directories (`/opt/homebrew/bin`, `/usr/local/MacGPG2/bin`, `/usr/local/bin`, `/usr/bin`, `/bin`) with recursion guards (`OC_YUBIKEY_FALLBACK_ACTIVE=1`). |
| **Bounded Buffers & Queues** | Enforces strict caps on IPC payloads (`64 KB`), SSH agent frames (`256 KB`), Assuan lines (`16 KB`–`64 KB`), child stdout/stderr (`256 KB`), and TUI PIN input (`128` characters). |

---

## Level 5 — Configuration, Troubleshooting & Development

### Plugin Options (`opencode.jsonc`)

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [
    [
      "/path/to/oc-yubikey",
      {
        // Optional explicit gpg-agent Assuan socket path:
        "agentSocketPath": "/Users/alice/.gnupg/S.gpg-agent",
        // Optional (default: false): allow raw promptPin RPC calls:
        "allowRawPinRpc": false
      }
    ]
  ]
}
```

### Environment Variables

| Variable | Role |
| :--- | :--- |
| `OC_GPG_AGENT_SOCK` | Overrides `gpgconf --list-dirs agent-socket` for Assuan connections |
| `OC_FALLBACK_PINENTRY` | Explicit path to a fallback GUI pinentry binary when running outside OpenCode |
| `OC_YUBIKEY_SOCK` | Injected automatically by `PinentryBridge.prepareShellEnv()` |
| `OC_YUBIKEY_TOKEN` | Per-instance 256-bit hex authentication token injected into shell subcommands |
| `OC_YUBIKEY_COMMAND` | Summarized shell command displayed in `TouchModal` / `PinentryModal` |
| `PINENTRY_USER_DATA` | Same socket, token and command as JSON; `gpg-agent` hands it to the pinentry program it launches, and it names the instance that owns the running command |

`bin/oc-yubikey` resolves the instance to talk to from `PINENTRY_USER_DATA` first, then
`OC_YUBIKEY_SOCK` / `OC_YUBIKEY_TOKEN`, then the `active.json` pointer of the running
instance. `gpg-agent` inherits the environment of the shell that started it, so its copy
of `OC_YUBIKEY_SOCK` can name an instance that is gone. The `PINENTRY_USER_DATA` it
passes to the pinentry program names the instance of the command that is running now.

### macOS Apple `launchd` `ssh-agent` vs. Homebrew OpenSSH (`-sk` Keys)

macOS's built-in `/usr/bin/ssh-agent` (`com.apple.launchd.*/Listeners`) ships `/usr/libexec/ssh-sk-helper` compiled **without** `libfido2` (`internal security key support not enabled`). Loading an `sk-ssh-ed25519@openssh.com` or `sk-ecdsa-*` key into Apple's agent without `SSH_SK_PROVIDER` breaks agent signing. That failure also stops Homebrew OpenSSH (`/opt/homebrew/bin/ssh`) from using the local `~/.ssh/id_*_sk` file.

`PinentryBridge` detects when it proxies an Apple `launchd` `ssh-agent` socket without `SSH_SK_PROVIDER` and filters `sk-*` identities out of `SSH2_AGENT_IDENTITIES_ANSWER` (message `12`). Homebrew OpenSSH then uses `~/.ssh/id_*_sk` with Homebrew's `ssh-sk-helper` and `bin/oc-yubikey` (`SSH_ASKPASS=force`), which opens `TouchModal` until you touch the YubiKey.

### Troubleshooting

- **`gpg-agent rejected loopback pinentry mode`**: Remove `no-allow-loopback-pinentry` (or add `allow-loopback-pinentry`) in `~/.gnupg/gpg-agent.conf` and run `gpg-connect-agent reloadagent /bye`.
- **`git commit -S` fails or does not open the PIN modal**: Run `yubikey_status` to inspect your GnuPG configuration. Ensure `~/.gnupg/gpg.conf` does not set `pinentry-mode loopback` (which bypasses `pinentry-program`), and set `pinentry-program /path/to/oc-yubikey/bin/oc-yubikey` in `~/.gnupg/gpg-agent.conf` followed by `gpg-connect-agent reloadagent /bye`.
- **Touch modal does not appear during `gpg --sign` outside OpenCode's shell**: Ensure `pinentry-program /path/to/oc-yubikey/bin/oc-yubikey` is set in `~/.gnupg/gpg-agent.conf` and reload `gpg-agent`.
- **YubiKey not detected (`connected: false`)**: Verify `gpg --card-status` succeeds in your terminal and that no other process holds an exclusive PC/SC lock on the smartcard reader.
- **TUI toast `Plugin failed: github:<owner>/oc-yubikey`**: Refresh the installed copy from the `/plugins` dialog, or remove `~/.cache/opencode/npm/git-oc-yubikey-*` so OpenCode reinstalls the latest commit. `src/tui.tsx` uses `@opentui/solid`'s reconciler primitives (`createElement`, `createTextNode`, `insertNode`, `insert`, `setProp`, `effect`, `createComponent`) directly rather than raw JSX syntax so it loads cleanly from `~/.cache/opencode/npm/.../node_modules` where OpenTUI's Babel Solid transform does not run.

### Development & Verification

This repository uses **TypeScript 6.0+** (`verbatimModuleSyntax`, `noImplicitOverride`, `allowImportingTsExtensions`, compile-time `Expect<Equal<...>>` checks). It runs natively on **Bun** and **Node 24+**.

```bash
# Type-check with TypeScript 6.0+
bun run typecheck

# Run unit, integration, and security tests
bun test
```
