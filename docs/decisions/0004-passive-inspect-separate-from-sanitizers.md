# 4. Passive `inspect()` / `Findings` kept separate from the transforming sanitizers

Date: 2026-07-24
Status: Accepted

## Context

The original 0.1 crate covered only the *emission* end: sanitizers
(`csv_field`, `tsv_safe`, `jsonl_safe`, `display_safe`, `cap_display`) that
transform a string into output safe for a target sink. But untrusted data is also
dangerous at the *ingestion* end, where a consumer wants to know what it is
accepting before it stores or routes it — and may prefer to **reject** a record
rather than silently rewrite it (an audit boundary, an API gate).

Rewriting and inspecting are different operations with different contracts:
sanitizing mutates and is lossy by design; inspecting must be non-destructive and
report exactly what it found and where. The design plan
(`docs/plans/2026-05-21-input-inspection-design.md`) settled on a passive scanner
that leaves the existing sanitizers unchanged.

## Decision

Add a **passive `inspect()`** function returning a **`Findings`** report, kept
architecturally separate from the sanitizers:

- `inspect(impl GuardInput) -> Findings` scans input and modifies nothing.
- `Findings { violations: Vec<Violation>, lossy: bool }` carries the full
  per-violation list; each `Violation { kind: ViolationKind, byte_offset,
  char: Option<char> }` pins the offending byte position and character.
- `ViolationKind` enumerates `FormulaInjection`, `BidiOverride`, `ControlChar`,
  `InvalidUtf8` — the classes the sanitizers neutralize, surfaced for detection.
- `Findings` exposes format-specific safety queries (`is_csv_safe`, `is_tsv_safe`,
  `is_jsonl_safe`, `is_display_safe`) and generic ones (`has_formula`, `has_bidi`,
  `has_controls`, `has_invalid_utf8`, `is_clean`) so a caller can branch:
  accept-clean, sanitize, or reject.

Evidence: `src/inspect.rs`, `src/types.rs`; git `56e857b` ("adds inspect() input
inspection API"), the RED/GREEN commit pairs `1b8a0dc`/`791a4d0`,
`289b19e`/`efbae93`, `1d906cb`/`10eeea3`, `0ad22ee`/`6250103`.

## Consequences

- Ingestion-time rejection and emission-time sanitization are both first-class and
  composable: a gate can `inspect()` and reject, or fall through to a sanitizer.
- The sanitizers are unchanged and independently usable — a consumer that only
  emits never pays for the inspector, and vice versa (both live behind `alloc`).
- Because `byte_offset` reports the position in the original input, a `Violation`
  can be shown against the raw bytes for an audit log — consistent with the fleet's
  "show the offending value and its location" robustness discipline.
- Surfacing an unrecognized/dangerous datum with its offset and char (rather than a
  bare boolean) follows the fleet rule that a rejection must name what was found and
  where, not just that something was wrong.
