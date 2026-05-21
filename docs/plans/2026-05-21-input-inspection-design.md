# jsonguard input inspection — design

**Date:** 2026-05-21
**Status:** Approved, ready for implementation plan

---

## Summary

Add passive, non-destructive input inspection to jsonguard. A single `inspect()` function scans input for dangerous patterns and returns a `Findings` struct. `Findings` carries the full violation list and exposes format-specific safety queries as methods. The existing output sanitizers (`csv_field`, `tsv_safe`, `jsonl_safe`, `display_safe`) are unchanged.

---

## Types

### `ViolationKind`

```rust
pub enum ViolationKind {
    FormulaInjection,  // = + - @ at char index 0
    BidiOverride,      // any bidi control codepoint
    ControlChar,       // C0 (U+0000–U+001F), DEL (U+007F), C1 (U+0080–U+009F)
    InvalidUtf8,       // invalid byte sequence in &[u8] input
}
```

### `Violation`

```rust
pub struct Violation {
    pub kind:        ViolationKind,
    pub byte_offset: usize,        // byte position in the original input
    pub char:        Option<char>, // None for InvalidUtf8
}
```

`ControlChar` covers null bytes; callers filter on `violation.char == Some('\0')` if they need them distinguished. `byte_offset` on `InvalidUtf8` points to the start of the invalid byte run.

### `Findings`

```rust
pub struct Findings {
    pub violations: Vec<Violation>,
    pub lossy:      bool, // true when &[u8] input had undecodable bytes
}
```

#### Generic methods

```rust
impl Findings {
    pub fn is_clean(&self) -> bool
    pub fn has_formula(&self) -> bool
    pub fn has_bidi(&self) -> bool
    pub fn has_controls(&self) -> bool
    pub fn has_invalid_utf8(&self) -> bool
}
```

#### Format-specific safety checks

Each answers: "would the corresponding sanitizer change this input?"

```rust
    pub fn is_csv_safe(&self) -> bool
    // false if: FormulaInjection, BidiOverride, ControlChar except \n and \r, InvalidUtf8
    // \n and \r are preserved by csv_field (quoted), so not flagged

    pub fn is_tsv_safe(&self) -> bool
    // false if: FormulaInjection, BidiOverride, ANY ControlChar (incl \t \n \r), InvalidUtf8
    // TSV has no quoting — all structural chars are destructive

    pub fn is_jsonl_safe(&self) -> bool
    // false if: BidiOverride, ControlChar, InvalidUtf8
    // FormulaInjection NOT flagged — = has no meaning in JSON string values

    pub fn is_display_safe(&self) -> bool
    // false if: BidiOverride, ControlChar, InvalidUtf8
    // FormulaInjection NOT flagged — = is benign in display/log contexts
```

---

## Public API

```rust
pub fn inspect<I: GuardInput>(input: I) -> Findings
```

One function. All format-specific querying happens on `Findings`. Accepts both `&str` and `&[u8]` via the existing sealed `GuardInput` trait.

### Usage examples

```rust
// Reject at an API boundary
let f = inspect(user_input);
if !f.is_csv_safe() {
    return Err("input contains unsafe characters");
}

// Audit log with full detail
let f = inspect(raw_bytes);
for v in &f.violations {
    log::warn!("violation {:?} at byte {}", v.kind, v.byte_offset);
}

// Branch: sanitize or reject
let f = inspect(user_input);
if f.is_clean() {
    Ok(csv_field(user_input))
} else if f.is_csv_safe() {
    Ok(csv_field(user_input)) // sanitizer will handle it
} else {
    Err("rejected: contains characters unsafe for CSV")
}
```

---

## Module layout

```
src/
  lib.rs         ← re-exports inspect, Findings, Violation, ViolationKind
  guard_input.rs ← unchanged
  types.rs       ← add Findings, Violation, ViolationKind
  text.rs        ← unchanged (output sanitizers)
  inspect.rs     ← new: inspect() function only
```

---

## Constraints

- `no_std` + `alloc` (same as the rest of the crate)
- Zero new production dependencies
- Sealed `GuardInput` trait — no new impls needed
- MSRV: Rust 1.75
- Strict TDD: RED commit (failing tests) before GREEN commit (implementation), per project CLAUDE.md
