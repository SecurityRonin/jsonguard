# Input Inspection Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task.

**Goal:** Add passive, non-destructive input inspection to jsonguard — a single `inspect()` function that scans any `GuardInput` for dangerous patterns and returns a `Findings` struct with full violation details and format-specific safety queries.

**Architecture:** `ViolationKind`, `Violation`, and `Findings` are added to `src/types.rs` alongside the existing `Guarded`/`DecodedStr`. `GuardInput` gains a `raw_bytes()` method (needed to find invalid UTF-8 byte positions without false-positives). A new `src/inspect.rs` contains the single public `inspect()` function. All existing output sanitizers are unchanged.

**Tech Stack:** Rust 1.75, `no_std` + `alloc` feature (default enabled), `cargo test` for unit tests. Zero new dependencies.

---

## Before You Start

### TDD mandate (non-negotiable)

Per project CLAUDE.md:
- **Two commits per task**: one RED (failing tests only), one GREEN (implementation).
- Run tests after RED to confirm they fail. Run again after GREEN to confirm they pass.
- If a test passes immediately before implementation, the test is wrong — fix it.

### Crate constraints

- Every new type and function must be behind `#[cfg(feature = "alloc")]`.
- Test modules must start with `use std::prelude::v1::*;` (the crate is `no_std`; tests link std implicitly via the test harness).
- No new production dependencies.

### Byte offset semantics (document this in code)

`Violation::byte_offset` has two coordinate spaces depending on kind:
- **`InvalidUtf8`**: offset in the *original* `&[u8]` input (from raw byte scan).
- **All other kinds**: offset in the *decoded* UTF-8 string (from char iteration).

For `&str` input there are never `InvalidUtf8` violations (Rust guarantees valid UTF-8), so both spaces are identical. For `&[u8]` input without invalid sequences (`lossy == false`), both spaces are also identical. The mismatch only occurs for `&[u8]` with invalid sequences, which is documented in the public API.

---

## Module layout after all tasks

```
src/
  lib.rs         ← re-exports inspect, Findings, Violation, ViolationKind
  guard_input.rs ← add raw_bytes() to GuardInput trait + all impls
  types.rs       ← add ViolationKind, Violation, Findings (with methods)
  text.rs        ← unchanged
  inspect.rs     ← new: inspect() function only
```

---

## Task 1: Core types — `ViolationKind`, `Violation`, `Findings`

**Files:**
- Modify: `src/types.rs`

### Step 1: Write failing tests (RED)

Add to the existing `#[cfg(test)] mod tests` block in `src/types.rs`:

```rust
    // ViolationKind, Violation, Findings — compile-time structure tests
    #[test]
    fn violation_kind_variants_exist() {
        let _ = ViolationKind::FormulaInjection;
        let _ = ViolationKind::BidiOverride;
        let _ = ViolationKind::ControlChar;
        let _ = ViolationKind::InvalidUtf8;
    }

    #[test]
    fn violation_fields_accessible() {
        let v = Violation {
            kind: ViolationKind::ControlChar,
            byte_offset: 3,
            char: Some('\x01'),
        };
        assert_eq!(v.byte_offset, 3);
        assert_eq!(v.char, Some('\x01'));
    }

    #[test]
    fn violation_char_none_for_invalid_utf8() {
        let v = Violation {
            kind: ViolationKind::InvalidUtf8,
            byte_offset: 0,
            char: None,
        };
        assert!(v.char.is_none());
    }

    #[test]
    fn findings_fields_accessible() {
        let f = Findings { violations: Vec::new(), lossy: false };
        assert!(f.violations.is_empty());
        assert!(!f.lossy);
    }

    #[test]
    fn findings_lossy_flag() {
        let f = Findings { violations: Vec::new(), lossy: true };
        assert!(f.lossy);
    }
```

### Step 2: Run tests — confirm RED

```bash
cd ~/src/jsonguard && cargo test 2>&1
```

Expected: compile error — `ViolationKind`, `Violation`, `Findings` not defined.

### Step 3: Commit RED

```bash
git add src/types.rs
git commit -m "test(inspect): RED — ViolationKind, Violation, Findings type tests"
```

### Step 4: Implement (GREEN)

Add before the existing `#[cfg(test)]` block in `src/types.rs`:

```rust
#[cfg(feature = "alloc")]
#[derive(Debug, PartialEq)]
pub enum ViolationKind {
    FormulaInjection,
    BidiOverride,
    ControlChar,
    InvalidUtf8,
}

#[cfg(feature = "alloc")]
#[derive(Debug, PartialEq)]
pub struct Violation {
    pub kind:        ViolationKind,
    pub byte_offset: usize,
    pub char:        Option<char>,
}

#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct Findings {
    pub violations: alloc::vec::Vec<Violation>,
    pub lossy:      bool,
}
```

### Step 5: Run tests — confirm GREEN

```bash
cd ~/src/jsonguard && cargo test 2>&1
```

Expected: all tests pass.

### Step 6: Commit GREEN

```bash
git add src/types.rs
git commit -m "feat(inspect): GREEN — ViolationKind, Violation, Findings types"
```

---

## Task 2: Generic `Findings` methods

**Files:**
- Modify: `src/types.rs`

### Step 1: Write failing tests (RED)

Add to the test module in `src/types.rs` (after the Task 1 tests):

```rust
    // Helper used across Tasks 2 and 3
    fn v(kind: ViolationKind, byte_offset: usize, ch: Option<char>) -> Violation {
        Violation { kind, byte_offset, char: ch }
    }

    fn findings(vs: Vec<Violation>) -> Findings {
        Findings { violations: vs, lossy: false }
    }

    // Generic method tests
    #[test]
    fn is_clean_empty() {
        assert!(findings(vec![]).is_clean());
    }

    #[test]
    fn is_clean_false_when_violation_present() {
        assert!(!findings(vec![v(ViolationKind::ControlChar, 0, Some('\0'))]).is_clean());
    }

    #[test]
    fn has_formula_true() {
        assert!(findings(vec![v(ViolationKind::FormulaInjection, 0, Some('='))]).has_formula());
    }

    #[test]
    fn has_formula_false() {
        assert!(!findings(vec![v(ViolationKind::ControlChar, 0, Some('\0'))]).has_formula());
    }

    #[test]
    fn has_bidi_true() {
        assert!(findings(vec![v(ViolationKind::BidiOverride, 5, Some('\u{202E}'))]).has_bidi());
    }

    #[test]
    fn has_bidi_false() {
        assert!(!findings(vec![]).has_bidi());
    }

    #[test]
    fn has_controls_true() {
        assert!(findings(vec![v(ViolationKind::ControlChar, 0, Some('\x01'))]).has_controls());
    }

    #[test]
    fn has_controls_false() {
        assert!(!findings(vec![v(ViolationKind::FormulaInjection, 0, Some('='))]).has_controls());
    }

    #[test]
    fn has_invalid_utf8_true() {
        assert!(findings(vec![v(ViolationKind::InvalidUtf8, 0, None)]).has_invalid_utf8());
    }

    #[test]
    fn has_invalid_utf8_false() {
        assert!(!findings(vec![]).has_invalid_utf8());
    }
```

### Step 2: Run tests — confirm RED

```bash
cd ~/src/jsonguard && cargo test 2>&1
```

Expected: compile error — `is_clean`, `has_formula`, etc. not defined.

### Step 3: Commit RED

```bash
git add src/types.rs
git commit -m "test(inspect): RED — generic Findings method tests"
```

### Step 4: Implement (GREEN)

Add to `src/types.rs` immediately after the `Findings` struct definition:

```rust
#[cfg(feature = "alloc")]
impl Findings {
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }

    pub fn has_formula(&self) -> bool {
        self.violations.iter().any(|v| matches!(v.kind, ViolationKind::FormulaInjection))
    }

    pub fn has_bidi(&self) -> bool {
        self.violations.iter().any(|v| matches!(v.kind, ViolationKind::BidiOverride))
    }

    pub fn has_controls(&self) -> bool {
        self.violations.iter().any(|v| matches!(v.kind, ViolationKind::ControlChar))
    }

    pub fn has_invalid_utf8(&self) -> bool {
        self.violations.iter().any(|v| matches!(v.kind, ViolationKind::InvalidUtf8))
    }
}
```

### Step 5: Run tests — confirm GREEN

```bash
cd ~/src/jsonguard && cargo test 2>&1
```

Expected: all tests pass.

### Step 6: Commit GREEN

```bash
git add src/types.rs
git commit -m "feat(inspect): GREEN — generic Findings methods"
```

---

## Task 3: Format-specific `Findings` methods

**Files:**
- Modify: `src/types.rs`

### Semantics reference

| Method | Formula | Bidi | Control \n \r | Control other | InvalidUtf8 |
|---|:-:|:-:|:-:|:-:|:-:|
| `is_csv_safe` | ✗ | ✗ | ✓ (allowed) | ✗ | ✗ |
| `is_tsv_safe` | ✗ | ✗ | ✗ | ✗ | ✗ |
| `is_jsonl_safe` | ✓ (irrelevant) | ✗ | ✗ | ✗ | ✗ |
| `is_display_safe` | ✓ (irrelevant) | ✗ | ✗ | ✗ | ✗ |

(`✗` = this violation makes the method return `false`; `✓` = this violation is ignored.)

### Step 1: Write failing tests (RED)

Add to the test module in `src/types.rs`:

```rust
    // is_csv_safe
    #[test]
    fn csv_safe_clean_input() {
        assert!(findings(vec![]).is_csv_safe());
    }

    #[test]
    fn csv_safe_false_for_formula() {
        assert!(!findings(vec![v(ViolationKind::FormulaInjection, 0, Some('='))]).is_csv_safe());
    }

    #[test]
    fn csv_safe_false_for_bidi() {
        assert!(!findings(vec![v(ViolationKind::BidiOverride, 3, Some('\u{202E}'))]).is_csv_safe());
    }

    #[test]
    fn csv_safe_false_for_null_control() {
        assert!(!findings(vec![v(ViolationKind::ControlChar, 0, Some('\0'))]).is_csv_safe());
    }

    #[test]
    fn csv_safe_true_for_newline_control() {
        // csv_field quotes fields with \n — it doesn't strip them
        assert!(findings(vec![v(ViolationKind::ControlChar, 5, Some('\n'))]).is_csv_safe());
    }

    #[test]
    fn csv_safe_true_for_cr_control() {
        assert!(findings(vec![v(ViolationKind::ControlChar, 5, Some('\r'))]).is_csv_safe());
    }

    #[test]
    fn csv_safe_false_for_invalid_utf8() {
        assert!(!findings(vec![v(ViolationKind::InvalidUtf8, 0, None)]).is_csv_safe());
    }

    // is_tsv_safe
    #[test]
    fn tsv_safe_clean_input() {
        assert!(findings(vec![]).is_tsv_safe());
    }

    #[test]
    fn tsv_safe_false_for_formula() {
        assert!(!findings(vec![v(ViolationKind::FormulaInjection, 0, Some('+'))]).is_tsv_safe());
    }

    #[test]
    fn tsv_safe_false_for_newline() {
        // TSV has no quoting — \n breaks row structure
        assert!(!findings(vec![v(ViolationKind::ControlChar, 5, Some('\n'))]).is_tsv_safe());
    }

    #[test]
    fn tsv_safe_false_for_tab() {
        assert!(!findings(vec![v(ViolationKind::ControlChar, 3, Some('\t'))]).is_tsv_safe());
    }

    #[test]
    fn tsv_safe_false_for_cr() {
        assert!(!findings(vec![v(ViolationKind::ControlChar, 3, Some('\r'))]).is_tsv_safe());
    }

    #[test]
    fn tsv_safe_false_for_bidi() {
        assert!(!findings(vec![v(ViolationKind::BidiOverride, 0, Some('\u{200E}'))]).is_tsv_safe());
    }

    // is_jsonl_safe
    #[test]
    fn jsonl_safe_clean_input() {
        assert!(findings(vec![]).is_jsonl_safe());
    }

    #[test]
    fn jsonl_safe_true_for_formula() {
        // '=' has no meaning in a JSON string value
        assert!(findings(vec![v(ViolationKind::FormulaInjection, 0, Some('='))]).is_jsonl_safe());
    }

    #[test]
    fn jsonl_safe_false_for_bidi() {
        assert!(!findings(vec![v(ViolationKind::BidiOverride, 5, Some('\u{202E}'))]).is_jsonl_safe());
    }

    #[test]
    fn jsonl_safe_false_for_control() {
        assert!(!findings(vec![v(ViolationKind::ControlChar, 0, Some('\n'))]).is_jsonl_safe());
    }

    #[test]
    fn jsonl_safe_false_for_invalid_utf8() {
        assert!(!findings(vec![v(ViolationKind::InvalidUtf8, 0, None)]).is_jsonl_safe());
    }

    // is_display_safe
    #[test]
    fn display_safe_clean_input() {
        assert!(findings(vec![]).is_display_safe());
    }

    #[test]
    fn display_safe_true_for_formula() {
        assert!(findings(vec![v(ViolationKind::FormulaInjection, 0, Some('@'))]).is_display_safe());
    }

    #[test]
    fn display_safe_false_for_bidi() {
        assert!(!findings(vec![v(ViolationKind::BidiOverride, 0, Some('\u{061C}'))]).is_display_safe());
    }

    #[test]
    fn display_safe_false_for_control() {
        assert!(!findings(vec![v(ViolationKind::ControlChar, 0, Some('\x7F'))]).is_display_safe());
    }

    #[test]
    fn display_safe_false_for_invalid_utf8() {
        assert!(!findings(vec![v(ViolationKind::InvalidUtf8, 0, None)]).is_display_safe());
    }
```

### Step 2: Run tests — confirm RED

```bash
cd ~/src/jsonguard && cargo test 2>&1
```

Expected: compile error — `is_csv_safe`, `is_tsv_safe`, `is_jsonl_safe`, `is_display_safe` not defined.

### Step 3: Commit RED

```bash
git add src/types.rs
git commit -m "test(inspect): RED — format-specific Findings method tests"
```

### Step 4: Implement (GREEN)

Add to the `impl Findings` block in `src/types.rs` (after `has_invalid_utf8`):

```rust
    pub fn is_csv_safe(&self) -> bool {
        !self.violations.iter().any(|v| match &v.kind {
            ViolationKind::FormulaInjection => true,
            ViolationKind::BidiOverride     => true,
            ViolationKind::InvalidUtf8      => true,
            ViolationKind::ControlChar      => !matches!(v.char, Some('\n') | Some('\r')),
        })
    }

    pub fn is_tsv_safe(&self) -> bool {
        self.is_clean()
    }

    pub fn is_jsonl_safe(&self) -> bool {
        !self.violations.iter().any(|v| matches!(
            v.kind,
            ViolationKind::BidiOverride | ViolationKind::ControlChar | ViolationKind::InvalidUtf8
        ))
    }

    pub fn is_display_safe(&self) -> bool {
        self.is_jsonl_safe()
    }
```

Note: `is_tsv_safe` returns `!self.is_clean()` negated — i.e., any violation at all makes TSV unsafe, because TSV rejects every dangerous pattern including `\n`, `\r`, `\t`. `is_display_safe` and `is_jsonl_safe` share the same predicate (both ignore formula injection).

### Step 5: Run tests — confirm GREEN

```bash
cd ~/src/jsonguard && cargo test 2>&1
```

Expected: all tests pass.

### Step 6: Commit GREEN

```bash
git add src/types.rs
git commit -m "feat(inspect): GREEN — format-specific Findings methods"
```

---

## Task 4: `GuardInput::raw_bytes` + `inspect()` function

**Files:**
- Modify: `src/guard_input.rs` (add `raw_bytes()` to trait and all impls)
- Create: `src/inspect.rs`
- Modify: `src/lib.rs` (declare module, add re-exports)

### Why `raw_bytes()`?

`inspect()` needs to find the byte offsets of invalid UTF-8 sequences in `&[u8]` input. After `as_utf8_lossy()` those positions are lost (invalid bytes become U+FFFD). Scanning the raw bytes with `core::str::from_utf8` lets us find exact offsets without false-positives.

### Step 1: Write failing tests (RED)

Create `src/inspect.rs` with tests only (no implementation):

```rust
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use crate::types::ViolationKind;

// Implementation goes here after RED commit

#[cfg(test)]
mod tests {
    use std::prelude::v1::*;
    use super::*;
    use crate::types::ViolationKind;

    #[test]
    fn inspect_clean_str() {
        let f = inspect("hello world");
        assert!(f.is_clean());
        assert!(!f.lossy);
    }

    #[test]
    fn inspect_clean_bytes() {
        let f = inspect(b"hello".as_ref());
        assert!(f.is_clean());
        assert!(!f.lossy);
    }

    #[test]
    fn inspect_detects_formula_equals() {
        let f = inspect("=SUM(A1)");
        assert!(f.has_formula());
        let v = f.violations.iter().find(|v| matches!(v.kind, ViolationKind::FormulaInjection)).unwrap();
        assert_eq!(v.byte_offset, 0);
        assert_eq!(v.char, Some('='));
    }

    #[test]
    fn inspect_detects_formula_plus() {
        assert!(inspect("+cmd").has_formula());
    }

    #[test]
    fn inspect_detects_formula_minus() {
        assert!(inspect("-cmd").has_formula());
    }

    #[test]
    fn inspect_detects_formula_at() {
        assert!(inspect("@SUM").has_formula());
    }

    #[test]
    fn inspect_no_formula_mid_string() {
        assert!(!inspect("value=something").has_formula());
    }

    #[test]
    fn inspect_detects_bidi_rlo() {
        let f = inspect("hello\u{202E}world");
        assert!(f.has_bidi());
        let v = f.violations.iter().find(|v| matches!(v.kind, ViolationKind::BidiOverride)).unwrap();
        assert_eq!(v.byte_offset, 5); // "hello" is 5 bytes
        assert_eq!(v.char, Some('\u{202E}'));
    }

    #[test]
    fn inspect_detects_bidi_lrm() {
        assert!(inspect("x\u{200E}y").has_bidi());
    }

    #[test]
    fn inspect_detects_bidi_arabic_letter_mark() {
        assert!(inspect("x\u{061C}y").has_bidi());
    }

    #[test]
    fn inspect_detects_null_byte() {
        let f = inspect("a\x00b");
        assert!(f.has_controls());
        let v = f.violations.iter().find(|v| matches!(v.kind, ViolationKind::ControlChar)).unwrap();
        assert_eq!(v.byte_offset, 1);
        assert_eq!(v.char, Some('\0'));
    }

    #[test]
    fn inspect_detects_c0_control() {
        let f = inspect("a\x01b");
        assert!(f.has_controls());
        let v = f.violations.iter().find(|v| matches!(v.kind, ViolationKind::ControlChar)).unwrap();
        assert_eq!(v.byte_offset, 1);
    }

    #[test]
    fn inspect_detects_del() {
        assert!(inspect("a\x7Fb").has_controls());
    }

    #[test]
    fn inspect_detects_c1_control() {
        // U+0085 NEXT LINE
        assert!(inspect("a\u{0085}b").has_controls());
    }

    #[test]
    fn inspect_detects_newline_as_control() {
        let f = inspect("line1\nline2");
        assert!(f.has_controls());
        let v = f.violations.iter().find(|v| matches!(v.kind, ViolationKind::ControlChar)).unwrap();
        assert_eq!(v.char, Some('\n'));
    }

    #[test]
    fn inspect_detects_tab_as_control() {
        assert!(inspect("a\tb").has_controls());
    }

    #[test]
    fn inspect_bytes_invalid_utf8_lossy() {
        let f = inspect(b"\xFF\xFE hello".as_ref());
        assert!(f.has_invalid_utf8());
        assert!(f.lossy);
        let v = f.violations.iter().find(|v| matches!(v.kind, ViolationKind::InvalidUtf8)).unwrap();
        assert_eq!(v.byte_offset, 0);
        assert!(v.char.is_none());
    }

    #[test]
    fn inspect_bytes_multiple_invalid_sequences() {
        // Two separate invalid sequences
        let f = inspect(b"\xFF hello \xFE".as_ref());
        let invalid: Vec<_> = f.violations.iter()
            .filter(|v| matches!(v.kind, ViolationKind::InvalidUtf8))
            .collect();
        assert_eq!(invalid.len(), 2);
        assert_eq!(invalid[0].byte_offset, 0);
        assert_eq!(invalid[1].byte_offset, 7); // " hello " is 7 bytes after \xFF
    }

    #[test]
    fn inspect_str_no_invalid_utf8() {
        // &str is always valid UTF-8 — never reported as InvalidUtf8
        let f = inspect("hello \u{FFFD} world"); // legitimate U+FFFD in str
        assert!(!f.has_invalid_utf8());
    }

    #[test]
    fn inspect_multiple_violations() {
        let f = inspect("=test\u{202E}\x01");
        assert!(f.has_formula());
        assert!(f.has_bidi());
        assert!(f.has_controls());
    }

    #[test]
    fn inspect_violations_sorted_by_byte_offset() {
        let f = inspect("=hello\u{202E}");
        // formula at 0, bidi at 6 ("=hello" is 6 bytes)
        let offsets: Vec<usize> = f.violations.iter().map(|v| v.byte_offset).collect();
        let mut sorted = offsets.clone();
        sorted.sort();
        assert_eq!(offsets, sorted);
    }

    #[test]
    fn inspect_csv_integration_safe() {
        assert!(inspect("hello world").is_csv_safe());
        assert!(inspect("line1\nline2").is_csv_safe()); // \n allowed in quoted CSV
    }

    #[test]
    fn inspect_csv_integration_unsafe() {
        assert!(!inspect("=SUM(A1)").is_csv_safe());
        assert!(!inspect("hello\u{202E}").is_csv_safe());
        assert!(!inspect("a\x01b").is_csv_safe());
    }

    #[test]
    fn inspect_tsv_vs_csv_newline() {
        // \n is CSV-safe but not TSV-safe
        let f = inspect("line1\nline2");
        assert!(f.is_csv_safe());
        assert!(!f.is_tsv_safe());
    }

    #[test]
    fn inspect_jsonl_formula_ignored() {
        assert!(inspect("=value").is_jsonl_safe());
        assert!(!inspect("=value\u{202E}").is_jsonl_safe());
    }

    #[test]
    fn inspect_display_formula_ignored() {
        assert!(inspect("=value").is_display_safe());
        assert!(!inspect("=value\x01").is_display_safe());
    }

    #[test]
    fn inspect_unicode_text_clean() {
        let f = inspect("許功蓋 Ünïcödé");
        assert!(f.is_clean());
        assert!(!f.lossy);
    }

    #[test]
    fn inspect_bytes_big5_invalid_utf8() {
        // Big5 許 = \xB3\x5C — invalid UTF-8
        let f = inspect(b"\xB3\x5C".as_ref());
        assert!(f.has_invalid_utf8());
        assert!(f.lossy);
    }
}
```

Declare the module and add re-exports in `src/lib.rs`. Add after the existing `mod text;` line:

```rust
#[cfg(feature = "alloc")]
mod inspect;

#[cfg(feature = "alloc")]
pub use inspect::inspect;
#[cfg(feature = "alloc")]
pub use types::{Findings, Violation, ViolationKind};
```

### Step 2: Run tests — confirm RED

```bash
cd ~/src/jsonguard && cargo test 2>&1
```

Expected: compile error — `inspect` function not defined, `raw_bytes` not in `GuardInput`.

### Step 3: Commit RED

```bash
git add src/inspect.rs src/lib.rs
git commit -m "test(inspect): RED — inspect() function tests"
```

### Step 4: Implement (GREEN)

**4a. Add `raw_bytes()` to `src/guard_input.rs`**

Update the trait definition:

```rust
#[cfg(feature = "alloc")]
pub trait GuardInput: private::Sealed {
    fn as_utf8_lossy(&self) -> (String, bool);
    fn raw_bytes(&self) -> Option<&[u8]>;
}
```

Add `raw_bytes` to each impl:

```rust
#[cfg(feature = "alloc")]
impl GuardInput for &str {
    fn as_utf8_lossy(&self) -> (String, bool) {
        (String::from(*self), false)
    }
    fn raw_bytes(&self) -> Option<&[u8]> { None }
}

#[cfg(feature = "alloc")]
impl GuardInput for &[u8] {
    fn as_utf8_lossy(&self) -> (String, bool) {
        use alloc::borrow::Cow;
        let cow = String::from_utf8_lossy(self);
        let lossy = matches!(cow, Cow::Owned(_));
        (cow.into_owned(), lossy)
    }
    fn raw_bytes(&self) -> Option<&[u8]> { Some(self) }
}

#[cfg(feature = "alloc")]
impl GuardInput for &alloc::string::String {
    fn as_utf8_lossy(&self) -> (String, bool) {
        ((*self).clone(), false)
    }
    fn raw_bytes(&self) -> Option<&[u8]> { None }
}

#[cfg(feature = "alloc")]
impl<const N: usize> GuardInput for &[u8; N] {
    fn as_utf8_lossy(&self) -> (String, bool) {
        use alloc::borrow::Cow;
        let cow = String::from_utf8_lossy(*self);
        let lossy = matches!(cow, Cow::Owned(_));
        (cow.into_owned(), lossy)
    }
    fn raw_bytes(&self) -> Option<&[u8]> { Some(*self) }
}
```

**4b. Create `src/inspect.rs`**

```rust
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use crate::guard_input::GuardInput;
#[cfg(feature = "alloc")]
use crate::types::{Findings, Violation, ViolationKind};

fn is_bidi(c: char) -> bool {
    matches!(c,
        '\u{200E}' | '\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}'
        | '\u{061C}'
    )
}

fn is_control_char(c: char) -> bool {
    matches!(c,
        '\u{0000}'..='\u{001F}'
        | '\u{007F}'
        | '\u{0080}'..='\u{009F}'
    )
}

#[cfg(feature = "alloc")]
pub fn inspect<I: GuardInput>(input: I) -> Findings {
    let raw = input.raw_bytes();
    let (text, lossy) = input.as_utf8_lossy();
    let mut violations: Vec<Violation> = Vec::new();

    // Detect invalid UTF-8 sequences with exact byte offsets from original bytes.
    // Only possible for &[u8] input — raw_bytes() returns None for &str.
    if let Some(bytes) = raw {
        let mut i = 0;
        while i < bytes.len() {
            match core::str::from_utf8(&bytes[i..]) {
                Ok(_) => break,
                Err(e) => {
                    violations.push(Violation {
                        kind: ViolationKind::InvalidUtf8,
                        byte_offset: i + e.valid_up_to(),
                        char: None,
                    });
                    i += e.valid_up_to();
                    i += e.error_len().unwrap_or(bytes.len() - i);
                }
            }
        }
    }

    // Scan decoded text for FormulaInjection, BidiOverride, ControlChar.
    // byte_offset here is in the decoded string's coordinate space.
    let mut byte_offset: usize = 0;
    let mut first_char = true;

    for ch in text.chars() {
        if first_char {
            first_char = false;
            if matches!(ch, '=' | '+' | '-' | '@') {
                violations.push(Violation {
                    kind: ViolationKind::FormulaInjection,
                    byte_offset,
                    char: Some(ch),
                });
            }
        }

        if is_bidi(ch) {
            violations.push(Violation {
                kind: ViolationKind::BidiOverride,
                byte_offset,
                char: Some(ch),
            });
        } else if is_control_char(ch) {
            violations.push(Violation {
                kind: ViolationKind::ControlChar,
                byte_offset,
                char: Some(ch),
            });
        }

        byte_offset += ch.len_utf8();
    }

    violations.sort_by_key(|v| v.byte_offset);
    Findings { violations, lossy }
}

#[cfg(test)]
mod tests {
    // ... (tests written in the RED step above)
}
```

**4c. Final `src/lib.rs` state**

```rust
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(test)]
extern crate std;

mod guard_input;
mod types;
mod text;
#[cfg(feature = "alloc")]
mod inspect;

#[cfg(feature = "alloc")]
pub use guard_input::GuardInput;
#[cfg(feature = "alloc")]
pub use types::{DecodedStr, Guarded, Findings, Violation, ViolationKind};
#[cfg(feature = "alloc")]
pub use text::{
    bytes_to_utf8_lossy_safe,
    cap_display,
    csv_field,
    display_safe,
    jsonl_safe,
    tsv_safe,
};
#[cfg(feature = "alloc")]
pub use inspect::inspect;
```

### Step 5: Run tests — confirm GREEN

```bash
cd ~/src/jsonguard && cargo test 2>&1
```

Expected: all tests pass (69 existing + new inspect tests).

### Step 6: Run clippy and no_std checks

```bash
cd ~/src/jsonguard && cargo clippy -- -D warnings 2>&1
cargo build --no-default-features 2>&1
cargo build --no-default-features --features alloc 2>&1
```

All should succeed (warnings only on `--no-default-features` for dead code — expected).

### Step 7: Commit GREEN

```bash
git add src/guard_input.rs src/inspect.rs src/lib.rs
git commit -m "feat(inspect): GREEN — GuardInput::raw_bytes, inspect(), lib re-exports"
```

---

## Final: Run full suite + push

```bash
cd ~/src/jsonguard && cargo test && cargo clippy -- -D warnings 2>&1
git push
```

---

## Expected commit log (most recent first)

```
feat(inspect): GREEN — GuardInput::raw_bytes, inspect(), lib re-exports
test(inspect): RED — inspect() function tests
feat(inspect): GREEN — format-specific Findings methods
test(inspect): RED — format-specific Findings method tests
feat(inspect): GREEN — generic Findings methods
test(inspect): RED — generic Findings method tests
feat(inspect): GREEN — ViolationKind, Violation, Findings types
test(inspect): RED — ViolationKind, Violation, Findings type tests
```
