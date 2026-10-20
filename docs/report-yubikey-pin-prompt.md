# Report — `oc-yubikey` asks for a PIN on a YubiKey that has no PIN defined

| | |
| --- | --- |
| Date | 2026-10-20 |
| Repo | `oc-yubikey` @ `0d450e9` |
| Card measured | Yubico YubiKey, serial `12345678`, OpenPGP applet 3.4, AID `D2760001240103040006123456780000` |
| Tooling | `/opt/homebrew/bin/gpg`, `gpg-connect-agent`, GnuPG `master` sources, OpenPGP card spec v2.0.1, `yubikey-manager` `main` sources |

The card serial and the AID in this report are placeholders. They do not identify a physical device.

---

## 1. Summary

Three independent defects combine to produce the reported symptom.

1. **Every PIN prompt in the plugin is unconditional.** None of the three paths that can raise a PIN modal
   consults the card before asking. The pinentry shim, the SSH askpass path, and the plugin-initiated
   `unlock()` all ask for a PIN without ever asking the card whether a PIN is needed.

2. **The plugin throws away the card's PIN state.** `parseCardStatusOutput()` drops `Signature PIN ....: not forced`
   and `forcepin:0`, and the `--with-colons` fallback drops the PIN retry counters as well. The plugin already
   runs `gpg --card-status`. It just does not read the answer out of it.

3. **There is no "PIN not defined" state in the OpenPGP card standard**, so the symptom cannot be fixed by
   looking for a flag that says "no PIN". The card always has a user PIN (PW1) with an error counter.
   What the user calls "a YubiKey without a PIN defined" is one of three real card states, and the plugin
   detects only one of them.

The highest-value fix is small: parse the PIN policy the card already reports, and stop the plugin-initiated
`unlock()` from prompting on a card that has nothing to unlock.

---

## 2. Where the PIN prompt is raised

There are three paths. All three end in `PinentryCoordinator.requestPin()` (`src/coordinator.ts:177`), which
emits the `prompt` RPC event and renders `PinentryModal` (`src/tui.tsx:116`).

### 2.1 gpg-agent → pinentry shim → bridge → coordinator → modal

```
gpg-agent  --Assuan GETPIN-->  bin/oc-yubikey
                                  src/cli.ts:251  handleAssuanGetPin()
                                  src/cli.ts:257  IPC { type: "pin" }
                                  src/bridge.ts:405  dispatchIpcRequest()
                                  src/bridge.ts:436  coordinator.requestPin()
                                  src/coordinator.ts:177  enqueuePending("pin")
                                  -> RPC event "prompt" -> PinentryModal
```

`handleAssuanGetPin()` is a relay. It forwards the Assuan `GETPIN` request over the authenticated IPC socket
and returns whatever PIN comes back. **The shim has no card visibility and performs no card lookup.**

### 2.2 `SSH_ASKPASS` → shim → coordinator → modal

```
ssh  --SSH_ASKPASS "…">  bin/oc-yubikey
                            src/cli.ts:94  runAskpassMode()
                            src/protocol.ts:116  classifyAskpassPrompt()
                            -> IPC { type: "pin" } -> same path as 2.1
```

The only input is the prompt string. `classifyAskpassPrompt()` decides "pin vs touch" by regular expression
(`PIN_PROMPT_RE`, `src/protocol.ts:87`). A prompt containing `enter passphrase`, `passphrase for`, `pin for`,
or `password` becomes a PIN prompt, whatever the card is doing.

### 2.3 Plugin-initiated `unlock()` → coordinator → modal → `SCD CHECKPIN`

```
yubikey_unlock tool (src/index.ts:150)  /  RPC "unlock"
    -> src/coordinator.ts:283  PinentryCoordinator.unlock()
    -> src/coordinator.ts:310  promptAndVerifyPin()   <-- prompts, unconditionally
    -> src/coordinator.ts:275  verifyYubiKeyPinLoopback(pin)
    -> src/yubikey.ts:516      gpg-agent "SCD CHECKPIN <aid>"
```

This path is the plugin's own, and it is the one that prompts **without any external caller having asked for a
PIN**. `unlock()` reads the card first (`src/coordinator.ts:288`) and then checks exactly one thing about it
before prompting — whether the user PIN counter is already exhausted (`src/coordinator.ts:295`). Everything else
about the card is ignored.

---

## 3. Why the plugin cannot tell that the card needs no PIN

### 3.1 Nothing reads a PIN-state signal

`grep -rni "signature pin|forcepin" src/ test/` → no matches.
`grep -rn "not defined|no pin|pin.?defined" src/` → no matches.

The plugin has no notion of the card's PIN state beyond the three retry counters.

### 3.2 The card-status parser discards the fields that matter

`parseCardStatusOutput()` (`src/yubikey.ts:785`) drives off two handler tables,
`HUMAN_CARD_FIELD_HANDLERS` (`src/yubikey.ts:704`) and `COLON_CARD_FIELD_HANDLERS` (`src/yubikey.ts:746`).
Neither contains an entry for the PIN policy.

Measured against the real `gpg --card-status` output of the attached card:

```
Reader ...........: Yubico YubiKey OTP FIDO CCID
Signature PIN ....: not forced          <-- dropped
Max. PIN lengths .: 127 127 127         <-- dropped
PIN retry counter : 2 0 3               <-- kept
Signature key ....: [none]
General key info..: [none]
```

```json
// parseCardStatusOutput(gpg --card-status), actual output
{
  "connected": true,
  "reader": "Yubico YubiKey OTP FIDO CCID",
  "serial": "12345678",
  "applicationID": "D2760001240103040006123456780000",
  "model": "Yubico",
  "version": "3.4",
  "signatureCount": 0,
  "pinRetries": { "user": 2, "reset": 0, "admin": 3 },
  "uif": { "sign": "off", "decrypt": "off", "auth": "off" }
}
```

`Signature PIN ....: not forced` is present in the raw output and absent from the parse result.

### 3.3 The bridge that receives the request never looks at the card

`PinentryBridgeOptions.getCardStatus` (`src/bridge.ts:231`) is declared and never read. `PinentryBridge` is
the component that receives the `type: "pin"` IPC request (`src/bridge.ts:405`) and it is the natural place to
gate the prompt on card state, but it has no card reader wired in.

### 3.4 GnuPG has no "PIN defined" concept either

Searching GnuPG `master` for the concept turns up nothing:

```
grep -rn "not defined|no PIN|PIN is not set|not_set" scd/*.c g10/card-util.c   # no matches
```

GnuPG's entire model of the card's PIN is the 7-byte `PW Status Bytes` DO (`0xC4`), per the OpenPGP card
specification v2.0.1:

```
PW Status Bytes (7 bytes, binary)
1st byte: 00 = PW1 (no. 81) only valid for one PSO:CDS command
          01 = PW1 valid for several PSO:CDS commands
2nd byte: max. length of PW1 (user)
3rd byte: max. length of Resetting Code (RC) for PW1
4th byte: max. length of PW3 (admin)
Byte 5, 6, 7: Error counter of PW1, RC and PW3.
            If 00, then the corresponding PW/RC is blocked.
            Incorrect usage decrements the counter, correct verification sets it to 03.
```

So the card always has a PW1, and the card always reports an error counter for it. **There is no bit anywhere
that says "no PIN has been defined".** GnuPG, `ykman`, and the OpenPGP card spec all agree on this: `ykman`'s
`get_openpgp_info()` reports PIN tries remaining, reset-code tries remaining, admin-PIN tries remaining, and
the signature PIN policy — and nothing else.

---

## 4. What the card actually reports, measured live

### 4.1 Via `gpg --card-status`

```
Application ID ...: D2760001240103040006123456780000
Application type .: OpenPGP
Version ..........: 3.4
Name of cardholder: [not set]
Signature PIN ....: not forced
Max. PIN lengths .: 127 127 127
PIN retry counter : 2 0 3
Signature counter : 0
KDF setting ......: off
UIF setting ......: Sign=off Decrypt=off Auth=off
Signature key ....: [none]
Encryption key....: [none]
Authentication key: [none]
General key info..: [none]
```

### 4.2 Via gpg-agent Assuan

```
$ gpg-connect-agent 'SCD GETATTR CHV-STATUS' /bye
S CHV-STATUS +1+127+127+127+2+0+3          # '+' is the Assuan escape for a space
$ gpg-connect-agent 'SCD GETATTR EXTCAP' /bye
S EXTCAP gc=1+ki=1+fc=1+pd=1+mcl3=2048+aac=1+sm=0+si=5+dec=0+bt=1+kdf=1
```

`SCD GETATTR <name>` is the same command `gpg` itself uses (`g10/call-agent.c:1236`), over the same socket the
plugin already speaks to. `CHV-STATUS` decodes as the 7 bytes of DO `0xC4`:

| Byte | Value | Meaning (DO `0xC4`) | Plugin uses it? |
| --- | --- | --- | --- |
| 1 | `1` | PW1 valid for several signatures ("not forced") | **no** |
| 2 | `127` | max length PW1 | no |
| 3 | `127` | max length RC | no |
| 4 | `127` | max length PW3 | no |
| 5 | `2` | PW1 error counter | yes |
| 6 | `0` | RC error counter — **RC blocked or never set** | yes, but not interpreted |
| 7 | `3` | PW3 error counter | yes |

`si=5` is the life-cycle status indicator from the Historical bytes DO (`0x5F52`), per the spec:
`00` = no life-cycle management, `03` = initialisation state, `05` = operational state (activated).
This card is operational.

### 4.3 Why GnuPG asks for a PIN in the first place

`scd/app-openpgp.c`, `do_sign()`:

```c
  /* Check CHV if needed.  */
  if (!app->did_chv1 || app->force_chv1)
    {
      rc = verify_a_chv (app, ctrl, 1, sigcount, 1);
      ...
```

`force_chv1` comes from byte 1 of DO `0xC4` (`app->force_chv1 = (buflen && *buffer == 0)`), i.e. it is `true`
only for policy `00`. `verify_a_chv()` ends in `askpin (ctrl, prompt, &pin)`, which is scdaemon asking
gpg-agent for the PIN, which is gpg-agent asking the pinentry program — which is `bin/oc-yubikey`.

**The consequence for this plugin is structural:** the pinentry shim is the last link in the chain. It cannot
stop gpg-agent from asking. It can only answer. Any "do not ask" decision has to be made either in
gpg-agent/scdaemon (not this plugin's code) or by the plugin answering the request itself without a modal.

---

## 5. Defects

### D1 — `unlock()` prompts on a card with nothing to unlock, and a wrong PIN burns a hardware retry

`src/coordinator.ts:283-339`. The card is read at `src/coordinator.ts:288` and only the "counter exhausted"
case is handled (`src/coordinator.ts:295`). On the measured card:

- `General key info..: [none]`, `Signature key ....: [none]` → the applet holds no OpenPGP keys, so there is
  no key to unlock and `SCD CHECKPIN` can never succeed.
- `pinRetries.user` is 2 → two hardware attempts are available.

The user is asked for a PIN anyway, and `verifyYubiKeyPinLoopback()` sends it to the card with `SCD CHECKPIN`
(`src/yubikey.ts:516`). A wrong PIN decrements the hardware counter. `canRetryAfterFailure()`
(`src/coordinator.ts:108`) re-prompts only while the counter is still above 1, so on this card the first wrong
answer spends one of the two remaining attempts and the plugin then stops. On a card whose counter read 3, the
plugin would spend two before stopping.

**This is the sharpest form of the reported symptom**: the plugin asks for a PIN that cannot exist and cannot
succeed, and the price of the wrong answer is a hardware retry.

### D2 — The PIN policy the card already reports is discarded

`src/yubikey.ts:704-744`. See §3.2. The information needed to tell "this card demands a PIN for every
signature" from "this card only needs it once" is in the `gpg --card-status` output the plugin already runs,
and is thrown away.

### D3 — The `--with-colons` fallback silently loses the PIN counters

`getYubiKeyCardStatus()` (`src/yubikey.ts:842`) falls back to `gpg --with-colons --card-status` when the
human-readable form yields `connected: false`. Measured against the real colon output:

```
Reader:Yubico YubiKey OTP FIDO CCID:AID:D2760001240103040006123456780000:openpgp-card:
forcepin:0:::
maxpinlen:127:127:127:
pinretry:2:0:3:
```

```json
// parseCardStatusOutput(gpg --with-colons --card-status), actual output
{
  "connected": true,
  "reader": "Yubico YubiKey OTP FIDO CCID:AID:D2760001240103040006123456780000:openpgp-card:",
  "version": "0304:"
}
```

Three separate problems, all from the same root cause — the human-form regex
`/^([A-Za-z ]+?)\s*\.*:\s*(.+)$/` (`src/yubikey.ts:796`) is tried **before** the colon-form branch
(`src/yubikey.ts:805`), so it claims the colon lines first:

- `pinretry:2:0:3:` → key `pinretry`, value `2:0:3:` → no handler → **`pinRetries` lost entirely**.
- `forcepin:0:::` → key `forcepin` → no handler → **PIN policy lost**.
- `Reader:…` → key `Reader`, value `Yubico YubiKey OTP FIDO CCID:AID:D2760001240103040006123456780000:openpgp-card:`
  → the reader field swallows the whole line.

The first one has a safety consequence. The README advertises a "PIN Retry Lockout Guard" that prevents
"accidental depletion of the final hardware attempt". On the colon path `pinRetries` is `undefined`, so the
guard at `src/coordinator.ts:295` never trips, and `canRetryAfterFailure()` returns `true` for
`updatedRetries === undefined` (`src/coordinator.ts:118`). **The guard is inert on exactly the path where the
card-status read was already degraded.**

### D4 — The bridge has an unwired card reader

`src/bridge.ts:231` declares `getCardStatus` and never uses it. The component that receives the PIN request
cannot consult the card, so §2.1's relay cannot be gated.

---

## 6. What "no PIN defined" can actually mean

Because the card always has a PW1 (§3.4), the phrase maps onto three distinct hardware states. The plugin
detects one of the three.

| User's phrase | Actual card state | Observable today | Detected by plugin? |
| --- | --- | --- | --- |
| "PIN is blocked / lost" | PW1 error counter = `0` | `pinRetries.user === 0` | **yes** — `src/coordinator.ts:295` |
| "I never set a PIN on this key" | applet still in its factory state: RC empty (counter `0`), no cardholder name, no keys, PW1 still the Yubico default | `pinRetries.reset === 0`, `holder` absent, `keys` absent | **no** |
| "I reset the key with `ykman openpgp reset`" | back to factory defaults: PW1 = `123456`, admin = `12345678` | same shape as the row above | **no** |

Yubico documents the factory defaults for the OpenPGP applet: user PIN `123456`, admin PIN `12345678`. The
OpenPGP card spec adds that "by default DO 'RC' is empty and the related error counter is zero, so it cannot be
used", and that a correct verification resets a counter to `03`. So a reset-code counter of `0` means the
applet was never personalised — the strongest proxy available, though not a proof, since three wrong reset-code
attempts would produce the same reading.

---

## 7. Recommended fix

Ordered by value per unit of effort.

### F1 — Read the PIN policy out of the card status (fixes D2)

Add `pinPolicy?: "always" | "once"` to `YubiKeyCardStatus` (`src/rpc.ts:25`).

- Human form: add a handler for key `signature pin`. Map `"forced"` to `"always"` and `"not forced"` to `"once"`.
- Colon form: add a handler for tag `forcepin`. Map `1` to `"always"` and `0` to `"once"`.

`forcepin` is `!info.chv1_cached` in GnuPG (`g10/cardctl.c:513`) and `chv1_cached` is byte 1 of DO `0xC4`
(`g10/call-agent.c:590`), so `forcepin:0` means "the PIN is valid for several signatures" — the card does not
demand it per operation.

Surface it in `formatCardStatusReport()` (`src/index.ts:63`) and in the TUI status toast, so the user can see
the card's PIN posture without running `gpg --card-status` by hand.

### F2 — Gate `unlock()` on card state (fixes D1)

Before the first prompt in `unlock()` (`src/coordinator.ts:294`), refuse to prompt and return an explanatory
message when the card cannot be unlocked:

- no OpenPGP keys on the card (`card.keys === undefined`, which the parser already yields for
  `General key info..: [none]`) → "this card has no OpenPGP keys; set one up before unlocking";
- `pinRetries.reset === 0` together with no keys and no holder → "this applet was never personalised; its
  PIN is the Yubico default `123456`", and **do not retry** (`allowRetry` forced to `false`), so no hardware
  attempt is spent on a guess.

`card.keys === undefined` is already reliable: `parseCardStatusOutput()` filters out the literal `[none]`
(`src/yubikey.ts:800`), so a card with no keys yields no `keys` field.

### F3 — Fix the colon-form parser (fixes D3)

Two changes in `parseCardStatusOutput()`:

- Try the colon branch **before** the human-form regex when the line looks like a colon record, or make the
  human regex refuse a value that still contains `:`. Either way `Reader:…:AID:…` must not be swallowed whole.
- Handle `pinretry` from the colon fields (`cols[1]`, `cols[2]`, `cols[3]`) and `forcepin` from `cols[1]`.

Add a regression test that feeds both real output shapes through `parseCardStatusOutput()` and asserts the
same `YubiKeyCardStatus` from both.

### F4 — Make the pinentry shim card-aware (fixes the §2.1 relay)

The shim already has the card status through the plugin's process, but the plugin's card status is in the
OpenCode server process, not in the shim. Two ways to close the gap:

- **Wire `getCardStatus` into `PinentryBridge`** (`src/bridge.ts:231`) and have `dispatchIpcRequest()`
  (`src/bridge.ts:405`) attach the card's serial, holder, PIN policy, and remaining retries to the pin request
  it forwards. The TUI modal then shows *why* it is asking, instead of a bare `PIN:` prompt.
- **Have the shim query gpg-agent directly.** `SCD GETATTR CHV-STATUS` over the agent socket gives the policy
  and the counters in one round trip, using the same Assuan client the plugin already has
  (`src/yubikey.ts:185`).

Note the limit: the shim cannot prevent gpg-agent from asking. It can make the prompt informative, and it can
fail fast with a clear message when the card cannot accept a PIN at all.

### F5 — Document the semantics in the README

The README's Level 2 table lists what triggers each modal but says nothing about the card states that make a
PIN prompt futile. Add the three rows of §6.

---

## 8. How to verify

Reproduce the parser and detection behaviour without touching the card's PIN counter:

```bash
gpg --card-status
gpg --with-colons --card-status
gpg-connect-agent 'SCD GETATTR CHV-STATUS' /bye
gpg-connect-agent 'SCD GETATTR EXTCAP' /bye
```

`SCD GETATTR` is read-only. Do **not** use `SCD CHECKPIN` as a probe — it consumes a hardware attempt.

Existing test surface: `test/pinentry.test.ts` already stubs `getCardStatus` for the coordinator
(`test/pinentry.test.ts:226`, `test/pinentry.test.ts:282`), so F1 and F2 are testable with the existing mock
card-status pattern.

---

## 9. Limits of this report

- The measurements come from one attached YubiKey in the state described in §4. The "applet never
  personalised" reading of "no PIN defined" is inferred from that card's shape (RC counter `0`, no keys, no
  cardholder, life-cycle status `05`) plus Yubico's documented factory defaults. It was not reproduced on a
  second card in a different state.
- The exact hardware behaviour of a factory-state applet when GnuPG issues a `VERIFY` (accepted, rejected, or
  rejected-without-decrement) was not measured, because measuring it costs a hardware attempt. The retry-counter
  arithmetic in §6 therefore assumes the spec's "incorrect usage decrements the counter".
- Bit 2 (`0x04`) of the life-cycle status indicator is set on the measured card (`si=5`). The OpenPGP card spec
  v2.0.1 defines only the whole-byte values `00`, `03`, `05`, and GnuPG's `parse_login_data`
  (`scd/app-openpgp.c`) documents the equivalent card-side flags only in the login-data `F=` field, whose bit 0
  is "CHV1 and CHV2 are not synchronized" and whose bit 1 is "CHV2 has been set to the default PIN of
  123456". The meaning of bit 2 of the status indicator byte itself was not established here, and nothing in
  this report depends on it.
