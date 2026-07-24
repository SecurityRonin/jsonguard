# 3. Secure-by-default API: decode-first `GuardInput`, lossy-carrying return types

Date: 2026-07-24
Status: Accepted

## Context

The fleet's mandatory design axiom is Secure by Design / Secure by Default
(`~/src/ronin-issen/CLAUDE.md` inherits it from `CLAUDE.core.md`): the
zero-knowledge path must be the safe one, the type system enforces correctness,
and return types carry security-relevant state so a caller cannot forget to check
it. A sanitizer library is exactly where this matters — the whole point is that a
developer who reads nothing and calls the first function ends up safe.

Two concrete footguns motivated the design:

1. **Byte input decoded naively.** If a sanitizer accepted `&[u8]` and escaped at
   the byte level *before* UTF-8 decoding, a multibyte character whose trailing
   byte is `0x5C` (`\`) or `0x22` (`"`) — common in Big5 / GBK / EUC-KR — would be
   mis-escaped. `guard_input.rs`'s test documents the canonical case: Big5 `許` =
   `0xB3 0x5C`, where naive byte escaping would treat `0x5C` as a backslash.
2. **A caller forgetting a "decode first" step.** Any API of the form "call
   `decode()` then `sanitize()`" leaves the unsafe ordering reachable.

## Decision

1. **A sealed `GuardInput` trait is the single input abstraction.** Every
   sanitizer and the inspector accept `impl GuardInput`, implemented for `&str`,
   `&[u8]`, `&[u8; N]`, and `&String` (sealed via `mod private::Sealed` so no
   downstream type can add an unsafe impl). Evidence: `src/guard_input.rs`.
2. **Decode-first is mandatory and invisible.** `GuardInput::as_utf8_lossy()`
   runs `String::from_utf8_lossy` before any inspection or escaping, so byte input
   is always valid UTF-8 by the time a sanitizer sees it. There is no caller-facing
   decode step to forget. Evidence: `guard_input.rs` impls; every sanitizer in
   `text.rs` opens with `let (text, lossy) = input.as_utf8_lossy();`.
3. **Return types structurally carry the `lossy` bit.** `Guarded { value: String,
   lossy: bool }` and `DecodedStr { text: String, lossy: bool }` embed whether the
   decode replaced undecodable bytes with U+FFFD. The caller cannot receive a
   silently-lossy result without the flag being present in the return value.
   `Guarded`/`DecodedStr` also `impl Display` (emitting `value`/`text`) so they
   drop into format strings, while `lossy` remains available for a fidelity check.
   Evidence: `src/types.rs`.

## Consequences

- The zero-config path is safe: `csv_field(user_bytes)` compiles and does the
  right thing for both `&str` and `&[u8]`, with the CJKV byte-collision hazard
  handled by construction.
- A consumer that cares about data fidelity (reject vs. accept a mangled record)
  reads `guarded.lossy` — a structural field, not a side-channel warning it must
  remember to consult.
- The sealed trait means the safe-input set is closed and auditable; adding a new
  accepted input type is a deliberate change in `guard_input.rs`, not something a
  downstream crate can do implicitly.
- Trade-off: `&str` and `&String` inputs report `lossy = false` unconditionally
  (they are already valid UTF-8), so the flag is only informative for byte input —
  accepted, since that is precisely where undecodable data can appear.
