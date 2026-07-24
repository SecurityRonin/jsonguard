# jsonguard — Purpose & Scope

> **Tier: library.** jsonguard is a cross-cutting utility leaf that other crates
> *link*, not a product an examiner runs. Per the fleet PRD & ADR standard
> (`ronin-issen/CLAUDE.md`, ADR-0003), a library's intent doc is a concise
> Purpose & Scope, not a full product-requirements document. The load-bearing
> design decisions live in [`docs/decisions/`](decisions/).

## What it is

jsonguard is a `no_std`-first Rust library for **input inspection and output
sanitization** of untrusted strings and bytes destined for structured text sinks:
JSON / JSONL, CSV, TSV, and terminal/UI display. It guards both ends of a data
pipeline — inspecting what is accepted at ingestion, and neutralizing what is
emitted — against formula injection, bidirectional-override spoofing,
control-character and null-byte attacks, JSON string-escape injection, and CJKV
byte-collision encoding hazards.

In the fleet architecture it is a **KNOWLEDGE-layer utility leaf**: it decodes no
evidence container, navigates no address space, and emits no
`forensicnomicon::report::Finding`. It is the shared safe-output primitive the fleet
reaches for when writing untrusted data to a machine or human sink (for example,
memf uses it for safe CLI output).

## Who links it

- Fleet crates that render untrusted artifact content to CSV/TSV/JSONL exports or to
  a terminal, and must not let attacker-controlled bytes break the format or spoof
  the display.
- Fleet crates that emit JSON via `serde_json` and need bidi/C1/DEL neutralized
  structurally (via the `JsonSafe<'_>` wrapper).
- Outside consumers wanting a small, dependency-light, secure-by-default sanitizer;
  the low MSRV floor (Rust 1.75) and `no_std` + `alloc` support keep it linkable in
  constrained contexts.

## What it does

- **Sanitize for emission** — `csv_field` (OWASP formula-injection prefix + RFC 4180
  quoting), `tsv_safe` (column-shift and control neutralization), `jsonl_safe`
  (complete escaped JSON string value), `display_safe` / `cap_display`
  (control/bidi stripping, char-safe truncation). Each returns a `Guarded` carrying
  the transformed value and a `lossy` flag.
- **Inspect at ingestion** — `inspect()` passively scans input and returns
  `Findings`: a full per-`Violation` list (kind + byte offset + offending char) plus
  format-specific safety queries (`is_csv_safe`, `is_tsv_safe`, `is_jsonl_safe`,
  `is_display_safe`) and generic ones (`has_formula`, `has_bidi`, `has_controls`,
  `has_invalid_utf8`, `is_clean`). Nothing is modified.
- **Serialize safely** — `JsonSafe<'a>` (feature `serde`) closes the gap where
  `serde_json` passes bidi/C1/DEL through literally.
- **Decode safely** — every function accepts `&str` **or** `&[u8]` through the sealed
  `GuardInput` trait, decoding bytes via UTF-8-lossy *before* inspection or escaping,
  so CJKV byte collisions (e.g. Big5 `許` = `0xB3 0x5C`) are handled by construction.

## Scope

- Input inspection and output sanitization for JSON/JSONL, CSV, TSV, and display
  contexts.
- Secure-by-default API: the zero-config path is the safe path; byte input is
  decoded first, and return types structurally carry the `lossy` bit.
- `no_std` support via the `alloc` feature; optional `std`, `serde`, and advisory
  features (`nosql`, `binary`).
- Validated against real-world attack corpora (Unicode UCD bidi sequences, OWASP
  formula payloads, Markus Kuhn's UTF-8 stress test, CJKV hazards) — see
  [`docs/validation.md`](validation.md).

## Non-goals

- **Not a forensic format reader or analyzer.** No container decoding, no filesystem
  or memory navigation, no anomaly findings. It is exempt from the fleet
  reader/analyzer (`core/` + `forensic/`) split (ADR 1).
- **Not a JSON/CSV parser.** It sanitizes and inspects; it does not deserialize
  structured documents. `serde_json` (a dev-dependency) is used only to validate the
  `JsonSafe` output, not as a parsing surface.
- **Not a schema validator or business-rule engine.** It neutralizes encoding-level
  and display-level attacks, not semantic policy.
- **Does not round-trip.** Sanitizers are intentionally lossy transformations for a
  target sink; a consumer needing the raw value back uses `inspect()` to detect
  rather than a sanitizer to transform.
- **No binary / CLI / GUI.** There is no runnable surface; the crate is linked, not
  run.

## Validation approach

Correctness is proven against **independent, third-party attack corpora** rather than
only self-authored fixtures: the Unicode Consortium's bidi test sequences (UCD
17.0.0), OWASP CSV-injection payloads, Markus Kuhn's UTF-8 decoder stress test, and
CJKV encoding hazards including the Big5 `0xB3 0x5C` collision and surrogate/overlong
byte sequences. Sources, hashes, and reproduction steps are documented in
[`docs/validation.md`](validation.md); the corpora and their consuming tests live in
`tests/` (`real_world_samples.rs`, `tests/corpus/`).
