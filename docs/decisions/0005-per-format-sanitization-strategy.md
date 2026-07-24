# 5. Per-format sanitization and escaping strategy

Date: 2026-07-24
Status: Accepted

## Context

"Safe output" is not one operation — each target sink has its own encoding rules
and its own attack surface. A single generic escaper would either under-protect one
format or corrupt another. The crate has to make an explicit, per-format neutralization
choice for each sink, and those choices are load-bearing: they define exactly what the
library guarantees against which attack class (README "Attack Coverage" table).

The threat classes are documented in the README and validated against real corpora
(`docs/validation.md`): CSV/TSV formula injection, RFC 4180 quote handling, TSV column
shift via embedded TAB, JSON string-escape injection, CJKV byte-collision with `\`/`"`,
bidi overrides, C0/C1/DEL control characters, and null bytes.

## Decision

Neutralize per format, with the choices fixed in `src/text.rs`:

1. **CSV (`csv_field`)** — prefix a field beginning with `= + - @` with an
   apostrophe (`'`) so a spreadsheet treats it as text, not a formula (the OWASP
   CSV-injection mitigation); then apply RFC 4180 quoting — wrap in `"…"` and
   double any internal `"` — when the field contains a quote, comma, or newline.
   `\n`/`\r` are deliberately **preserved** because they are what triggers RFC 4180
   quoting; all other unsafe chars are stripped.
2. **TSV (`tsv_safe`)** — replace TAB/CR/LF with a space (they break the
   tab-delimited column boundary), strip bidi and control characters, and apply the
   same formula-prefix escape.
3. **JSONL (`jsonl_safe`)** — emit a complete, quoted JSON string value with
   backslash/quote/control-character escaping, so an embedded `"` or newline cannot
   break out of the string and inject a key.
4. **Display (`display_safe`, `cap_display`)** — strip C0 (U+0000–U+001F), DEL
   (U+007F), C1 (U+0080–U+009F), and the bidirectional overrides
   (U+200E/200F, U+202A–202E, U+2066–2069, U+061C); `cap_display` truncates on a
   **character** boundary with a `…` sentinel, never mid-code-point, and strips
   before counting.

The unsafe-codepoint sets are defined once each in `text.rs`
(`is_display_unsafe`, `is_bidi`) and reused, rather than re-listed per function.

Evidence: `src/text.rs` (`csv_field`, `tsv_safe`, `jsonl_safe`, `display_safe`,
`cap_display`, `is_display_unsafe`, `is_bidi`); README "Attack Coverage";
`docs/validation.md`.

## Consequences

- Each function's guarantee is explicit and testable against the corpora in
  `docs/validation.md` (Unicode UCD bidi sequences, OWASP formula payloads, Markus
  Kuhn's UTF-8 stress test, CJKV hazards).
- The apostrophe-prefix mitigation is visible in the output (a leading `'`), which
  is the accepted, standard CSV-injection defense; consumers that need the raw value
  back use `inspect()` to detect rather than `csv_field()` to transform.
- Preserving `\n`/`\r` in CSV (to drive quoting) while replacing them in TSV (to
  protect columns) is an intentional per-format divergence, not an inconsistency —
  the two formats have opposite requirements for embedded newlines.
- Because the codepoint predicates are centralized, adding a newly-recognized bidi
  or control codepoint is a one-line change that propagates to every sanitizer and
  the inspector at once.
