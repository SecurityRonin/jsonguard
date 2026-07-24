# 6. `JsonSafe<'a>` serde wrapper — a type, not a function the caller must remember

Date: 2026-07-24
Status: Accepted

## Context

Consumers that emit JSON via `serde_json` (the common case in the fleet — memf uses
jsonguard for safe CLI output) do not call `jsonl_safe` by hand; they serialize
structs. `serde_json` escapes C0 control characters (`< 0x20`) losslessly as
`\u00XX`, but it passes the bidirectional overrides, the C1 controls (U+0080–U+009F),
and DEL (U+007F) through **literally**. So an attacker-controlled string emitted via
`serde_json::json!` or `#[derive(Serialize)]` can still carry a terminal-spoofing
bidi override into the JSON output, even though the surrounding sanitizers exist —
because the serde path bypasses them.

Per the Secure-by-Default axiom, the fix must be structural: "call `sanitize()`
first" is a footgun, and the safe path must be the one a competent developer reaches
for without reading the docs.

## Decision

Provide **`JsonSafe<'a>(pub &'a str)`**, a newtype that implements `Serialize`
(behind `feature = "serde"`). Wrapping a string in `JsonSafe` and serializing it
neutralizes exactly the codepoints `serde_json` renders literally-but-unsafely
(DEL, C1, and the bidi overrides) by replacing them with U+FFFD; C0 controls are
**left untouched** because `serde_json` already escapes them losslessly, so
re-handling them would be redundant. A fast path serializes the borrow with no
allocation when the string contains nothing unsafe.

The gap is closed by the *type*: a field typed `JsonSafe<'_>` cannot be serialized
unsafely, whereas a bare `&str` field silently could.

Evidence: `src/serde_safe.rs` (module doc comment stating the exact gap;
`is_json_display_unsafe` codepoint set; the no-alloc fast path); git RED/GREEN pair
`b049563` / `4f6866c` ("JsonSafe neutralizes bidi/C1/DEL in serde JSON output").

## Consequences

- serde-emitting consumers get structural safety by changing a field type, not by
  remembering a call — the serde path is brought up to the same guarantee as the
  hand-called sanitizers.
- The narrow scope (only DEL/C1/bidi, deferring C0 to serde) avoids double-escaping
  and keeps the output identical to plain serde for clean strings, which is what the
  no-alloc fast path preserves.
- The feature is opt-in (`feature = "serde"`, see ADR 2), so non-serde consumers
  carry no `serde` dependency.
- Replacement-with-U+FFFD (rather than stripping) keeps byte/character positions
  stable and makes the neutralization visible in the output for an examiner.
