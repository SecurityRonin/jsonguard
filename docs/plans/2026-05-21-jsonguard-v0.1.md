# jsonguard v0.1 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task.

**Goal:** Implement `jsonguard` — a Rust library for secure output sanitization of JSON/JSONL, CSV, and TSV — covering formula injection, bidi-override, control-character, and CJKV encoding attacks with a secure-by-default API.

**Architecture:** A sealed `GuardInput` trait accepts both `&str` and `&[u8]`, making UTF-8 decode mandatory and invisible. All sanitizers return `Guarded { value: String, lossy: bool }`. Six public functions: `bytes_to_utf8_lossy_safe`, `display_safe`, `cap_display`, `tsv_safe`, `csv_field`, `jsonl_safe`.

**Tech Stack:** Rust 1.75, `no_std` + `alloc` feature (default enabled), `proptest` for property tests, `cargo test` for unit tests.

---

## Before You Start

### Repository state

The repo at `~/src/jsonguard` already has:
- `Cargo.toml` — `name = "jsonguard"`, `default = ["alloc"]`, `dev-dependencies = { proptest = "1" }`
- `src/lib.rs` — cargo template boilerplate (rewrite it)
- `src/binary/`, `src/nosql/`, `src/text/` — empty directories (remove them)
- `LICENSE`, `README.md` — already written, do not touch

Remove the empty directories:
```bash
rmdir src/binary src/nosql src/text
```

### TDD mandate (non-negotiable)

Per project CLAUDE.md:
- **Two commits per task**: one RED (failing tests only), one GREEN (implementation that passes).
- Run tests after the RED commit to confirm they fail. Run again after GREEN to confirm they pass.
- If a test passes immediately after writing it (before implementation), the test is wrong — fix it.

### Git signing

Commits use gitsign. If the credential cache is not running, start it before making any commits:
```bash
gitsign credential-cache start
export GITSIGN_CREDENTIAL_CACHE="$HOME/Library/Caches/sigstore/gitsign/cache.sock"
```

---

## Why This Design (Read Before Implementing)

### Secure by default — the core axiom

Every sanitizer accepts `GuardInput`, not `&str`. This means callers can pass `&[u8]` directly and the UTF-8 decode happens automatically inside the sanitizer. There is no "call decode() first" doc comment footgun.

**The CJKV 0x5C problem:** Big5-encoded text can have bytes like `許` = `0xB3 0x5C`. The second byte `0x5C` is ASCII `\`. If you pass raw Big5 bytes to a JSON string escaper that operates on bytes, `0x5C` triggers JSON escape processing and corrupts the output. The fix is to decode to UTF-8 first — then `許` becomes the Unicode codepoint U+8A31, which has no `\` in its UTF-8 encoding. `GuardInput` enforces this decode-first invariant structurally: the byte path calls `String::from_utf8_lossy` before any sanitizer sees the bytes.

Same issue exists for GBK, EUC-KR, and other DBCS encodings. After UTF-8 decode, none of these encoding collisions exist.

### The sealed trait

`GuardInput` is a sealed trait (cannot be implemented externally). This is intentional — we can only guarantee the decode invariant holds for `&str` (already UTF-8) and `&[u8]` (UTF-8 lossy decode). If third-party code could implement `GuardInput` for their own type, they could bypass the decode step.

Sealed trait pattern in Rust:
```rust
mod private {
    pub trait Sealed {}
}
pub trait GuardInput: private::Sealed { ... }
// impls are in this crate only
impl private::Sealed for &str {}
impl private::Sealed for &[u8] {}
```

### `lossy: bool` on the return type

When `&[u8]` input contains invalid UTF-8, `String::from_utf8_lossy` inserts U+FFFD replacement characters. The `lossy` flag signals this happened. Callers who need to log a warning, reject the record, or audit the input have the information they need. Callers who don't care just use `{}` formatting.

`lossy` propagates through all sanitizers: if the decode was lossy, the sanitizer's `Guarded` has `lossy = true` even if the sanitizer itself didn't change any characters.

---

## Module layout

After removing the empty dirs, the final layout is:

```
src/
  lib.rs           <- crate root, re-exports public API
  guard_input.rs   <- GuardInput sealed trait + impls for &str and &[u8]
  types.rs         <- Guarded and DecodedStr structs
  text.rs          <- all sanitizer functions
```

---

## Task 1: Core types — `GuardInput`, `Guarded`, `DecodedStr`

**Files:**
- Create: `src/guard_input.rs`
- Create: `src/types.rs`
- Modify: `src/lib.rs`

### Step 1: Write the failing tests (RED)

Create `src/guard_input.rs` with tests only — no implementation:

```rust
// tests only, no impl yet
#[cfg(test)]
mod tests {
    // These tests will fail to compile until the trait and impls exist.
    // That IS the expected RED failure.
    use super::*;

    #[test]
    fn str_input_not_lossy() {
        let (text, lossy) = "hello".as_utf8_lossy();
        assert_eq!(text, "hello");
        assert!(!lossy);
    }

    #[test]
    fn bytes_valid_utf8_not_lossy() {
        let (text, lossy) = b"hello".as_utf8_lossy();
        assert_eq!(text, "hello");
        assert!(!lossy);
    }

    #[test]
    fn bytes_invalid_utf8_is_lossy() {
        let (text, lossy) = b"\xFF\xFE".as_utf8_lossy();
        assert!(text.contains('\u{FFFD}'));
        assert!(lossy);
    }

    #[test]
    fn bytes_big5_0x5c_second_byte() {
        // 許 in Big5 = 0xB3 0x5C. The 0x5C byte is backslash in ASCII.
        // After UTF-8 lossy decode, it becomes replacement chars (Big5 is not valid UTF-8).
        // The point: 0x5C does NOT survive as a raw backslash byte.
        let (text, lossy) = b"\xB3\x5C".as_utf8_lossy();
        assert!(lossy); // Big5 bytes are not valid UTF-8
        // No raw 0x5C byte remains as '\' in the decoded string
        assert!(!text.contains('\\'));
    }
}
```

Create `src/types.rs` with tests only:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guarded_display_emits_value() {
        let g = Guarded { value: "hello".to_string(), lossy: false };
        assert_eq!(g.to_string(), "hello");
    }

    #[test]
    fn guarded_lossy_flag_accessible() {
        let g = Guarded { value: "x".to_string(), lossy: true };
        assert!(g.lossy);
    }

    #[test]
    fn decoded_str_display_emits_text() {
        let d = DecodedStr { text: "world".to_string(), lossy: false };
        assert_eq!(d.to_string(), "world");
    }
}
```

Modify `src/lib.rs` to declare the modules (compilation will fail — that's RED):

```rust
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod guard_input;
mod types;
```

### Step 2: Run tests — confirm RED

```bash
cd ~/src/jsonguard && cargo test 2>&1
```

Expected: compile error — `GuardInput` trait and `as_utf8_lossy` method don't exist yet, `Guarded`/`DecodedStr` structs don't exist.

### Step 3: Commit RED

```bash
git add src/lib.rs src/guard_input.rs src/types.rs
git commit -m "test(core): RED — GuardInput trait and Guarded/DecodedStr type tests"
```

### Step 4: Implement (GREEN)

Fill in `src/guard_input.rs`:

```rust
#[cfg(feature = "alloc")]
use alloc::string::String;

mod private {
    pub trait Sealed {}
    impl Sealed for &str {}
    impl<'a> Sealed for &'a [u8] {}
}

pub trait GuardInput: private::Sealed {
    fn as_utf8_lossy(&self) -> (String, bool);
}

#[cfg(feature = "alloc")]
impl GuardInput for &str {
    fn as_utf8_lossy(&self) -> (String, bool) {
        ((*self).to_owned(), false)
    }
}

#[cfg(feature = "alloc")]
impl GuardInput for &[u8] {
    fn as_utf8_lossy(&self) -> (String, bool) {
        use alloc::borrow::Cow;
        let cow = String::from_utf8_lossy(self);
        let lossy = matches!(cow, Cow::Owned(_));
        (cow.into_owned(), lossy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str_input_not_lossy() {
        let (text, lossy) = "hello".as_utf8_lossy();
        assert_eq!(text, "hello");
        assert!(!lossy);
    }

    #[test]
    fn bytes_valid_utf8_not_lossy() {
        let (text, lossy) = b"hello".as_utf8_lossy();
        assert_eq!(text, "hello");
        assert!(!lossy);
    }

    #[test]
    fn bytes_invalid_utf8_is_lossy() {
        let (text, lossy) = b"\xFF\xFE".as_utf8_lossy();
        assert!(text.contains('\u{FFFD}'));
        assert!(lossy);
    }

    #[test]
    fn bytes_big5_0x5c_second_byte() {
        let (text, lossy) = b"\xB3\x5C".as_utf8_lossy();
        assert!(lossy);
        assert!(!text.contains('\\'));
    }
}
```

Fill in `src/types.rs`:

```rust
#[cfg(feature = "alloc")]
use alloc::string::String;

#[cfg(feature = "alloc")]
pub struct Guarded {
    pub value: String,
    pub lossy: bool,
}

#[cfg(feature = "alloc")]
impl core::fmt::Display for Guarded {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.value)
    }
}

#[cfg(feature = "alloc")]
pub struct DecodedStr {
    pub text: String,
    pub lossy: bool,
}

#[cfg(feature = "alloc")]
impl core::fmt::Display for DecodedStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guarded_display_emits_value() {
        let g = Guarded { value: "hello".to_string(), lossy: false };
        assert_eq!(g.to_string(), "hello");
    }

    #[test]
    fn guarded_lossy_flag_accessible() {
        let g = Guarded { value: "x".to_string(), lossy: true };
        assert!(g.lossy);
    }

    #[test]
    fn decoded_str_display_emits_text() {
        let d = DecodedStr { text: "world".to_string(), lossy: false };
        assert_eq!(d.to_string(), "world");
    }
}
```

Update `src/lib.rs` to re-export:

```rust
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod guard_input;
mod types;

pub use guard_input::GuardInput;
#[cfg(feature = "alloc")]
pub use types::{DecodedStr, Guarded};
```

### Step 5: Run tests — confirm GREEN

```bash
cd ~/src/jsonguard && cargo test 2>&1
```

Expected: all tests pass.

### Step 6: Commit GREEN

```bash
git add src/lib.rs src/guard_input.rs src/types.rs
git commit -m "feat(core): GREEN — GuardInput sealed trait, Guarded, DecodedStr"
```

---

## Task 2: `bytes_to_utf8_lossy_safe`

This is the explicit decode function — for callers who want to decode bytes and inspect the result before sanitizing, rather than having it happen inside a sanitizer.

**Files:**
- Create: `src/text.rs`
- Modify: `src/lib.rs`

### Step 1: Write failing tests (RED)

Create `src/text.rs`:

```rust
#[cfg(feature = "alloc")]
use alloc::string::String;
use crate::types::DecodedStr;

// Implementation goes here after RED commit

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_valid_utf8_not_lossy() {
        let d = bytes_to_utf8_lossy_safe(b"hello");
        assert_eq!(d.text, "hello");
        assert!(!d.lossy);
    }

    #[test]
    fn decode_invalid_utf8_lossy() {
        let d = bytes_to_utf8_lossy_safe(b"\xFF\x80");
        assert!(d.lossy);
        assert!(d.text.contains('\u{FFFD}'));
    }

    #[test]
    fn decode_empty_bytes() {
        let d = bytes_to_utf8_lossy_safe(b"");
        assert_eq!(d.text, "");
        assert!(!d.lossy);
    }

    #[test]
    fn decode_valid_unicode() {
        // 許 in UTF-8 is 0xE8 0xA8 0xB1 (not 0xB3 0x5C Big5)
        let d = bytes_to_utf8_lossy_safe("許功蓋".as_bytes());
        assert_eq!(d.text, "許功蓋");
        assert!(!d.lossy);
    }

    #[test]
    fn decode_big5_bytes_are_lossy() {
        // Big5 encoded 許 = 0xB3 0x5C — not valid UTF-8
        let d = bytes_to_utf8_lossy_safe(b"\xB3\x5C\xA6\x5C");
        assert!(d.lossy);
    }

    #[test]
    fn decode_display_works() {
        let d = bytes_to_utf8_lossy_safe(b"hello");
        assert_eq!(d.to_string(), "hello");
    }
}
```

Declare the module in `src/lib.rs`:

```rust
mod text;
pub use text::bytes_to_utf8_lossy_safe;
```

### Step 2: Run tests — confirm RED

```bash
cd ~/src/jsonguard && cargo test text::tests 2>&1
```

Expected: compile error — `bytes_to_utf8_lossy_safe` not found.

### Step 3: Commit RED

```bash
git add src/text.rs src/lib.rs
git commit -m "test(text): RED — bytes_to_utf8_lossy_safe tests"
```

### Step 4: Implement (GREEN)

Add to `src/text.rs` (before the test module):

```rust
#[cfg(feature = "alloc")]
pub fn bytes_to_utf8_lossy_safe(bytes: &[u8]) -> DecodedStr {
    use alloc::borrow::Cow;
    let cow = String::from_utf8_lossy(bytes);
    let lossy = matches!(cow, Cow::Owned(_));
    DecodedStr {
        text: cow.into_owned(),
        lossy,
    }
}
```

### Step 5: Run tests — confirm GREEN

```bash
cd ~/src/jsonguard && cargo test text::tests::decode 2>&1
```

Expected: 6 tests pass.

### Step 6: Commit GREEN

```bash
git add src/text.rs src/lib.rs
git commit -m "feat(text): GREEN — bytes_to_utf8_lossy_safe"
```

---

## Task 3: `display_safe` and `cap_display`

These sanitize text for general display — strip control characters and bidi override characters. Safe for logging, UI output, terminal display.

**Files:**
- Modify: `src/text.rs`
- Modify: `src/lib.rs`

### Bidi control characters to strip

The following Unicode codepoints are stripped by `display_safe` and `cap_display`:

| Codepoint(s) | Name |
|---|---|
| U+0000-U+001F | C0 control characters |
| U+007F | DELETE |
| U+0080-U+009F | C1 control characters |
| U+200E | LEFT-TO-RIGHT MARK |
| U+200F | RIGHT-TO-LEFT MARK |
| U+202A-U+202E | LRE, RLE, PDF, LRO, RLO |
| U+2066-U+2069 | LRI, RLI, FSI, PDI |
| U+061C | ARABIC LETTER MARK |

Define this predicate internally (not public):
```rust
fn is_display_unsafe(c: char) -> bool {
    matches!(c,
        '\u{0000}'..='\u{001F}'
        | '\u{007F}'
        | '\u{0080}'..='\u{009F}'
        | '\u{200E}' | '\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}'
        | '\u{061C}'
    )
}
```

### Step 1: Write failing tests (RED)

Add to `src/text.rs` test module:

```rust
    // display_safe tests
    #[test]
    fn display_safe_passthrough_normal_text() {
        let g = display_safe("hello world");
        assert_eq!(g.to_string(), "hello world");
        assert!(!g.lossy);
    }

    #[test]
    fn display_safe_strips_null_byte() {
        let g = display_safe("hel\x00lo");
        assert_eq!(g.to_string(), "hello");
    }

    #[test]
    fn display_safe_strips_c0_controls() {
        let g = display_safe("a\x01b\x1Fc");
        assert_eq!(g.to_string(), "abc");
    }

    #[test]
    fn display_safe_strips_bidi_rlo() {
        // U+202E is RIGHT-TO-LEFT OVERRIDE
        let g = display_safe("hello\u{202E}world");
        assert_eq!(g.to_string(), "helloworld");
    }

    #[test]
    fn display_safe_strips_c1_controls() {
        // U+0085 is NEXT LINE (a C1 control)
        let g = display_safe("a\u{0085}b");
        assert_eq!(g.to_string(), "ab");
    }

    #[test]
    fn display_safe_preserves_unicode_text() {
        let g = display_safe("許功蓋 Ünïcödé");
        assert_eq!(g.to_string(), "許功蓋 Ünïcödé");
    }

    #[test]
    fn display_safe_bytes_input_invalid_utf8_lossy() {
        let g = display_safe(b"\xFF\xFE hello".as_ref());
        assert!(g.lossy);
        assert!(g.to_string().contains("hello"));
    }

    // cap_display tests
    #[test]
    fn cap_display_passthrough_short_text() {
        let g = cap_display("hi", 10);
        assert_eq!(g.to_string(), "hi");
    }

    #[test]
    fn cap_display_truncates_at_char_boundary() {
        // "hello world" is 11 chars; cap at 5 = "hello..."
        let g = cap_display("hello world", 5);
        assert_eq!(g.to_string(), "hello\u{2026}");
    }

    #[test]
    fn cap_display_strips_unsafe_before_counting() {
        // Bidi char is stripped; the 3-char limit counts safe chars only
        let g = cap_display("ab\u{202E}cd", 3);
        assert_eq!(g.to_string(), "abc\u{2026}");
    }

    #[test]
    fn cap_display_exact_length_no_ellipsis() {
        let g = cap_display("hello", 5);
        assert_eq!(g.to_string(), "hello");
    }

    #[test]
    fn cap_display_zero_limit() {
        let g = cap_display("hello", 0);
        assert_eq!(g.to_string(), "\u{2026}");
    }
```

### Step 2: Run tests — confirm RED

```bash
cd ~/src/jsonguard && cargo test 2>&1
```

Expected: compile error — `display_safe` and `cap_display` not defined.

### Step 3: Commit RED

```bash
git add src/text.rs
git commit -m "test(text): RED — display_safe and cap_display tests"
```

### Step 4: Implement (GREEN)

Add to `src/text.rs`:

```rust
fn is_display_unsafe(c: char) -> bool {
    matches!(c,
        '\u{0000}'..='\u{001F}'
        | '\u{007F}'
        | '\u{0080}'..='\u{009F}'
        | '\u{200E}' | '\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}'
        | '\u{061C}'
    )
}

#[cfg(feature = "alloc")]
pub fn display_safe<I: crate::guard_input::GuardInput>(input: I) -> crate::types::Guarded {
    let (text, lossy) = input.as_utf8_lossy();
    let value: String = text.chars().filter(|&c| !is_display_unsafe(c)).collect();
    crate::types::Guarded { value, lossy }
}

#[cfg(feature = "alloc")]
pub fn cap_display<I: crate::guard_input::GuardInput>(
    input: I,
    max_chars: usize,
) -> crate::types::Guarded {
    let (text, lossy) = input.as_utf8_lossy();
    let safe: String = text.chars().filter(|&c| !is_display_unsafe(c)).collect();
    let value = if safe.chars().count() > max_chars {
        let truncated: String = safe.chars().take(max_chars).collect();
        alloc::format!("{}\u{2026}", truncated)
    } else {
        safe
    };
    crate::types::Guarded { value, lossy }
}
```

Update `src/lib.rs` re-exports:

```rust
pub use text::{bytes_to_utf8_lossy_safe, cap_display, display_safe};
```

### Step 5: Run tests — confirm GREEN

```bash
cd ~/src/jsonguard && cargo test 2>&1
```

Expected: all tests pass.

### Step 6: Commit GREEN

```bash
git add src/text.rs src/lib.rs
git commit -m "feat(text): GREEN — display_safe and cap_display"
```

---

## Task 4: `tsv_safe`

TSV (Tab-Separated Values) has no quoting mechanism. Any TAB in a field value shifts subsequent columns. Any CR or LF starts a new row. Formula injection applies to fields that begin with `= + - @`.

**Sanitization rules for `tsv_safe`:**
1. Replace TAB (`\t`, U+0009) with space
2. Replace LF (`\n`, U+000A) with space
3. Replace CR (`\r`, U+000D) with space
4. Strip all other C0 controls (U+0000-U+0008, U+000B, U+000C, U+000E-U+001F)
5. Strip DEL (U+007F)
6. Strip C1 controls (U+0080-U+009F)
7. Strip bidi control characters (same set as `is_display_unsafe`)
8. If the cleaned field starts with `=`, `+`, `-`, or `@`, prepend `'` (formula injection guard)

Note: Steps 1-3 replace structural chars with space rather than stripping them, to preserve word boundaries.

**Files:**
- Modify: `src/text.rs`
- Modify: `src/lib.rs`

### Step 1: Write failing tests (RED)

Add to `src/text.rs` test module:

```rust
    // tsv_safe tests
    #[test]
    fn tsv_safe_passthrough_normal() {
        let g = tsv_safe("hello world");
        assert_eq!(g.to_string(), "hello world");
        assert!(!g.lossy);
    }

    #[test]
    fn tsv_safe_replaces_tab_with_space() {
        let g = tsv_safe("col1\tcol2");
        assert_eq!(g.to_string(), "col1 col2");
    }

    #[test]
    fn tsv_safe_replaces_lf_with_space() {
        let g = tsv_safe("line1\nline2");
        assert_eq!(g.to_string(), "line1 line2");
    }

    #[test]
    fn tsv_safe_replaces_crlf_with_spaces() {
        let g = tsv_safe("row1\r\nrow2");
        assert_eq!(g.to_string(), "row1  row2"); // CR and LF each become space
    }

    #[test]
    fn tsv_safe_formula_injection_equals() {
        let g = tsv_safe("=SUM(A1:A10)");
        assert_eq!(g.to_string(), "'=SUM(A1:A10)");
    }

    #[test]
    fn tsv_safe_formula_injection_plus() {
        let g = tsv_safe("+1234");
        assert_eq!(g.to_string(), "'+1234");
    }

    #[test]
    fn tsv_safe_formula_injection_minus() {
        let g = tsv_safe("-1234");
        assert_eq!(g.to_string(), "'-1234");
    }

    #[test]
    fn tsv_safe_formula_injection_at() {
        let g = tsv_safe("@SUM");
        assert_eq!(g.to_string(), "'@SUM");
    }

    #[test]
    fn tsv_safe_no_formula_guard_midstring() {
        // A formula char NOT at the start is fine
        let g = tsv_safe("value=something");
        assert_eq!(g.to_string(), "value=something");
    }

    #[test]
    fn tsv_safe_strips_bidi_override() {
        let g = tsv_safe("hello\u{202E}world");
        assert_eq!(g.to_string(), "helloworld");
    }

    #[test]
    fn tsv_safe_strips_c0_nontab() {
        // \x01 is a C0 control (not tab/LF/CR) — should be stripped
        let g = tsv_safe("a\x01b");
        assert_eq!(g.to_string(), "ab");
    }

    #[test]
    fn tsv_safe_bytes_input() {
        let g = tsv_safe(b"=SUM\tval".as_ref());
        assert_eq!(g.to_string(), "'=SUM val");
        assert!(!g.lossy);
    }

    #[test]
    fn tsv_safe_bytes_invalid_utf8_lossy_with_formula_guard() {
        let g = tsv_safe(b"=\xFF".as_ref());
        assert!(g.to_string().starts_with("'="));
        assert!(g.lossy);
    }

    #[test]
    fn tsv_safe_unicode_preserved() {
        let g = tsv_safe("許功蓋");
        assert_eq!(g.to_string(), "許功蓋");
        assert!(!g.lossy);
    }
```

### Step 2: Run tests — confirm RED

```bash
cd ~/src/jsonguard && cargo test 'text::tests::tsv_safe' 2>&1
```

Expected: compile error — `tsv_safe` not defined.

### Step 3: Commit RED

```bash
git add src/text.rs
git commit -m "test(text): RED — tsv_safe tests"
```

### Step 4: Implement (GREEN)

Add to `src/text.rs`:

```rust
#[cfg(feature = "alloc")]
pub fn tsv_safe<I: crate::guard_input::GuardInput>(input: I) -> crate::types::Guarded {
    let (text, lossy) = input.as_utf8_lossy();

    let cleaned: String = text.chars().filter_map(|c| match c {
        '\t' | '\n' | '\r' => Some(' '),
        c if is_display_unsafe(c) => None,
        c => Some(c),
    }).collect();

    let value = match cleaned.chars().next() {
        Some('=' | '+' | '-' | '@') => alloc::format!("'{}", cleaned),
        _ => cleaned,
    };

    crate::types::Guarded { value, lossy }
}
```

Update `src/lib.rs` re-exports:

```rust
pub use text::{bytes_to_utf8_lossy_safe, cap_display, display_safe, tsv_safe};
```

### Step 5: Run tests — confirm GREEN

```bash
cd ~/src/jsonguard && cargo test 2>&1
```

Expected: all tests pass.

### Step 6: Commit GREEN

```bash
git add src/text.rs src/lib.rs
git commit -m "feat(text): GREEN — tsv_safe"
```

---

## Task 5: `csv_field`

CSV (RFC 4180) uses comma as delimiter, double-quote for quoting, and CRLF for row boundaries.

**RFC 4180 quoting rules:**
- A field containing `,`, `"`, `\n`, or `\r` MUST be wrapped in double quotes
- A `"` inside a quoted field is escaped by doubling it: `"` -> `""`
- A field with no special characters can be output bare

**Additional guards (beyond RFC 4180):**
- Formula injection: if the decoded field (after bidi/control stripping) starts with `=`, `+`, `-`, or `@`, prepend `'`
- Bidi controls: strip before processing
- C0/C1 controls (except `\n` and `\r` which trigger quoting): strip
- The `'` formula guard is applied before RFC 4180 quoting

**Output examples:**

| Input | Output |
|---|---|
| `hello` | `hello` |
| `hello, world` | `"hello, world"` |
| `say "hi"` | `"say ""hi"""` |
| `=SUM(A1)` | `'=SUM(A1)` |
| `=SUM(A1), ok` | `"'=SUM(A1), ok"` |
| `line1\nline2` | `"line1\nline2"` (quoted, LF preserved) |

Note: Unlike TSV, CSV preserves newlines in fields by quoting them. The newline is NOT replaced with space.

**Files:**
- Modify: `src/text.rs`
- Modify: `src/lib.rs`

### Step 1: Write failing tests (RED)

Add to `src/text.rs` test module:

```rust
    // csv_field tests
    #[test]
    fn csv_field_passthrough_simple() {
        let g = csv_field("hello");
        assert_eq!(g.to_string(), "hello");
        assert!(!g.lossy);
    }

    #[test]
    fn csv_field_quotes_comma() {
        let g = csv_field("hello, world");
        assert_eq!(g.to_string(), r#""hello, world""#);
    }

    #[test]
    fn csv_field_doubles_internal_quotes() {
        let g = csv_field(r#"say "hi""#);
        assert_eq!(g.to_string(), r#""say ""hi"""#);
    }

    #[test]
    fn csv_field_quotes_newline() {
        let g = csv_field("line1\nline2");
        assert_eq!(g.to_string(), "\"line1\nline2\"");
    }

    #[test]
    fn csv_field_quotes_cr() {
        let g = csv_field("line1\rline2");
        assert_eq!(g.to_string(), "\"line1\rline2\"");
    }

    #[test]
    fn csv_field_formula_injection_bare() {
        // No comma — no quoting; just prefix '
        let g = csv_field("=SUM(A1:A10)");
        assert_eq!(g.to_string(), "'=SUM(A1:A10)");
    }

    #[test]
    fn csv_field_formula_injection_with_comma() {
        // Has comma — must be quoted; formula guard inside quotes
        let g = csv_field("=SUM(A1), total");
        assert_eq!(g.to_string(), r#""'=SUM(A1), total""#);
    }

    #[test]
    fn csv_field_formula_plus() {
        let g = csv_field("+1");
        assert_eq!(g.to_string(), "'+1");
    }

    #[test]
    fn csv_field_formula_minus() {
        let g = csv_field("-1");
        assert_eq!(g.to_string(), "'-1");
    }

    #[test]
    fn csv_field_formula_at() {
        let g = csv_field("@user");
        assert_eq!(g.to_string(), "'@user");
    }

    #[test]
    fn csv_field_strips_bidi() {
        let g = csv_field("hello\u{202E}world");
        assert_eq!(g.to_string(), "helloworld");
    }

    #[test]
    fn csv_field_strips_c0_not_newline() {
        // \x01 stripped; \n triggers quoting
        let g = csv_field("a\x01b\nc");
        assert_eq!(g.to_string(), "\"ab\nc\"");
    }

    #[test]
    fn csv_field_obrien() {
        // Single quote in field — no special treatment
        let g = csv_field("O'Brien");
        assert_eq!(g.to_string(), "O'Brien");
    }

    #[test]
    fn csv_field_obrien_with_comma() {
        let g = csv_field("O'Brien, Jr.");
        assert_eq!(g.to_string(), r#""O'Brien, Jr.""#);
    }

    #[test]
    fn csv_field_unicode_preserved() {
        let g = csv_field("許功蓋");
        assert_eq!(g.to_string(), "許功蓋");
        assert!(!g.lossy);
    }

    #[test]
    fn csv_field_bytes_invalid_utf8_lossy() {
        let g = csv_field(b"\xFF\xFE hello".as_ref());
        assert!(g.lossy);
    }

    #[test]
    fn csv_field_empty_string() {
        let g = csv_field("");
        assert_eq!(g.to_string(), "");
    }
```

### Step 2: Run tests — confirm RED

```bash
cd ~/src/jsonguard && cargo test 'text::tests::csv_field' 2>&1
```

Expected: compile error — `csv_field` not defined.

### Step 3: Commit RED

```bash
git add src/text.rs
git commit -m "test(text): RED — csv_field tests"
```

### Step 4: Implement (GREEN)

Add to `src/text.rs`:

```rust
fn needs_csv_quoting(s: &str) -> bool {
    s.chars().any(|c| matches!(c, ',' | '"' | '\n' | '\r'))
}

#[cfg(feature = "alloc")]
pub fn csv_field<I: crate::guard_input::GuardInput>(input: I) -> crate::types::Guarded {
    let (text, lossy) = input.as_utf8_lossy();

    // Strip bidi and C0/C1 controls; PRESERVE \n and \r (they trigger RFC 4180 quoting)
    let cleaned: String = text.chars().filter(|&c| {
        if matches!(c, '\n' | '\r') {
            return true;
        }
        !is_display_unsafe(c)
    }).collect();

    // Apply formula injection guard before quoting decision
    let guarded = match cleaned.chars().next() {
        Some('=' | '+' | '-' | '@') => alloc::format!("'{}", cleaned),
        _ => cleaned,
    };

    // Apply RFC 4180 quoting if needed
    let value = if needs_csv_quoting(&guarded) {
        let escaped = guarded.replace('"', "\"\"");
        alloc::format!("\"{}\"", escaped)
    } else {
        guarded
    };

    crate::types::Guarded { value, lossy }
}
```

Update `src/lib.rs` re-exports:

```rust
pub use text::{bytes_to_utf8_lossy_safe, cap_display, csv_field, display_safe, tsv_safe};
```

### Step 5: Run tests — confirm GREEN

```bash
cd ~/src/jsonguard && cargo test 2>&1
```

Expected: all tests pass.

### Step 6: Commit GREEN

```bash
git add src/text.rs src/lib.rs
git commit -m "feat(text): GREEN — csv_field"
```

---

## Task 6: `jsonl_safe`

JSON Lines (JSONL) format: one JSON value per line. `jsonl_safe` produces a valid JSON string value (with surrounding `"`) from arbitrary input.

**JSON string escaping (RFC 8259):**

| Character | Escape |
|---|---|
| `"` (U+0022) | `\"` |
| `\` (U+005C) | `\\` |
| U+0008 (BS) | `\b` |
| U+0009 (HT) | `\t` |
| U+000A (LF) | `\n` |
| U+000C (FF) | `\f` |
| U+000D (CR) | `\r` |
| U+0000-U+0007, U+000B, U+000E-U+001F | `\uXXXX` |
| U+007F-U+009F (DEL + C1 controls) | `\uXXXX` |
| Bidi controls | `\uXXXX` (preserve value, escape for display safety) |

Note: Unlike `display_safe`/`tsv_safe`, `jsonl_safe` does NOT strip bidi characters — it escapes them as `\uXXXX`. This preserves the data while making the bytes safe in the JSON wire format.

**Output:** `"<escaped_value>"` — the surrounding double quotes are included. This is a complete JSON string literal, ready to be written to a JSONL stream.

**Files:**
- Modify: `src/text.rs`
- Modify: `src/lib.rs`

### Step 1: Write failing tests (RED)

Add to `src/text.rs` test module:

```rust
    // jsonl_safe tests
    #[test]
    fn jsonl_safe_wraps_in_quotes() {
        let g = jsonl_safe("hello");
        assert_eq!(g.to_string(), r#""hello""#);
        assert!(!g.lossy);
    }

    #[test]
    fn jsonl_safe_escapes_backslash() {
        let g = jsonl_safe(r#"C:\Users\foo"#);
        assert_eq!(g.to_string(), r#""C:\\Users\\foo""#);
    }

    #[test]
    fn jsonl_safe_escapes_double_quote() {
        let g = jsonl_safe(r#"say "hi""#);
        assert_eq!(g.to_string(), r#""say \"hi\"""#);
    }

    #[test]
    fn jsonl_safe_escapes_newline() {
        let g = jsonl_safe("line1\nline2");
        assert_eq!(g.to_string(), r#""line1\nline2""#);
    }

    #[test]
    fn jsonl_safe_escapes_tab() {
        let g = jsonl_safe("col1\tcol2");
        assert_eq!(g.to_string(), r#""col1\tcol2""#);
    }

    #[test]
    fn jsonl_safe_escapes_cr() {
        let g = jsonl_safe("row\r");
        assert_eq!(g.to_string(), r#""row\r""#);
    }

    #[test]
    fn jsonl_safe_escapes_c0_control_as_unicode() {
        // U+0001 -> 
        let g = jsonl_safe("\x01");
        assert_eq!(g.to_string(), "\"\\u0001\"");
    }

    #[test]
    fn jsonl_safe_escapes_del_as_unicode() {
        // U+007F DELETE
        let g = jsonl_safe("\x7F");
        assert_eq!(g.to_string(), "\"\\u007f\"");
    }

    #[test]
    fn jsonl_safe_escapes_c1_control_as_unicode() {
        // U+0085 NEXT LINE
        let g = jsonl_safe("\u{0085}");
        assert_eq!(g.to_string(), "\"\\u0085\"");
    }

    #[test]
    fn jsonl_safe_escapes_bidi_rlo_as_unicode() {
        // U+202E RIGHT-TO-LEFT OVERRIDE — escaped as ‮, NOT stripped
        let g = jsonl_safe("hello\u{202E}world");
        assert_eq!(g.to_string(), "\"hello\\u202eworld\"");
    }

    #[test]
    fn jsonl_safe_preserves_unicode_text() {
        let g = jsonl_safe("許功蓋");
        assert_eq!(g.to_string(), r#""許功蓋""#);
        assert!(!g.lossy);
    }

    #[test]
    fn jsonl_safe_bytes_big5_becomes_replacement_chars() {
        // Big5 bytes decoded lossy BEFORE JSON escaping.
        // 0x5C byte does NOT survive as a raw backslash.
        let g = jsonl_safe(b"\xB3\x5C".as_ref());
        assert!(g.lossy);
        let s = g.to_string();
        assert!(s.starts_with('"') && s.ends_with('"'),
            "output must be a valid JSON string literal");
        // Validate no bare backslash (every \ must start a valid escape sequence)
        let inner = &s[1..s.len()-1];
        let mut chars = inner.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                let next = chars.next().expect("backslash must be followed by escape char");
                assert!(
                    matches!(next, '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't' | 'u'),
                    "invalid escape sequence \\{}", next
                );
            }
        }
    }

    #[test]
    fn jsonl_safe_empty_string() {
        let g = jsonl_safe("");
        assert_eq!(g.to_string(), r#""""#);
    }
```

### Step 2: Run tests — confirm RED

```bash
cd ~/src/jsonguard && cargo test 'text::tests::jsonl_safe' 2>&1
```

Expected: compile error — `jsonl_safe` not defined.

### Step 3: Commit RED

```bash
git add src/text.rs
git commit -m "test(text): RED — jsonl_safe tests"
```

### Step 4: Implement (GREEN)

Add to `src/text.rs`:

```rust
fn is_bidi(c: char) -> bool {
    matches!(c,
        '\u{200E}' | '\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}'
        | '\u{061C}'
    )
}

#[cfg(feature = "alloc")]
pub fn jsonl_safe<I: crate::guard_input::GuardInput>(input: I) -> crate::types::Guarded {
    let (text, lossy) = input.as_utf8_lossy();
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');

    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x08' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\x0C' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            // C0 controls (excluding the named ones above)
            '\u{0000}'..='\u{0007}'
            | '\u{000B}'
            | '\u{000E}'..='\u{001F}' => {
                let code = c as u32;
                out.push_str(&alloc::format!("\\u{:04x}", code));
            }
            // DEL + C1 controls
            '\u{007F}'..='\u{009F}' => {
                let code = c as u32;
                out.push_str(&alloc::format!("\\u{:04x}", code));
            }
            // Bidi controls — \uXXXX escape (not stripped)
            c if is_bidi(c) => {
                let code = c as u32;
                out.push_str(&alloc::format!("\\u{:04x}", code));
            }
            c => out.push(c),
        }
    }

    out.push('"');
    crate::types::Guarded { value: out, lossy }
}
```

Update `src/lib.rs` re-exports:

```rust
pub use text::{bytes_to_utf8_lossy_safe, cap_display, csv_field, display_safe, jsonl_safe, tsv_safe};
```

### Step 5: Run tests — confirm GREEN

```bash
cd ~/src/jsonguard && cargo test 2>&1
```

Expected: all tests pass.

### Step 6: Commit GREEN

```bash
git add src/text.rs src/lib.rs
git commit -m "feat(text): GREEN — jsonl_safe"
```

---

## Final: Full test suite + clippy

### Run everything

```bash
cd ~/src/jsonguard && cargo test && cargo clippy -- -D warnings 2>&1
```

Expected: all tests pass, no clippy warnings.

### Final `src/lib.rs` state

```rust
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod guard_input;
mod types;
mod text;

pub use guard_input::GuardInput;
#[cfg(feature = "alloc")]
pub use types::{DecodedStr, Guarded};
#[cfg(feature = "alloc")]
pub use text::{
    bytes_to_utf8_lossy_safe,
    cap_display,
    csv_field,
    display_safe,
    jsonl_safe,
    tsv_safe,
};
```

### Verify no_std compatibility

```bash
cd ~/src/jsonguard && cargo build --no-default-features 2>&1
# Expected: compiles (no functions available, but crate compiles)

cargo build --no-default-features --features alloc 2>&1
# Expected: compiles with all functions available
```

---

## Edge cases to validate manually after tests pass

1. `csv_field("=cmd|'/C calc'!A0")` — Excel DDE injection — must start with `'`
2. `jsonl_safe("\u{202E}TXET")` — must contain `\\u202e` not raw bidi char
3. `tsv_safe("\t\t\t")` — must be `"   "` (three spaces)
4. `csv_field("\"")` — single `"` — must be `"\"\""` (RFC 4180 doubled, wrapped)
5. `cap_display("\u{202E}hello", 3)` — bidi stripped first, then `"hel\u{2026}"`
6. `bytes_to_utf8_lossy_safe(b"\xED\xA0\x80")` — U+D800 surrogate, invalid UTF-8 — must be lossy

---

## Expected commit log (most recent first)

```
feat(text): GREEN — jsonl_safe
test(text): RED — jsonl_safe tests
feat(text): GREEN — csv_field
test(text): RED — csv_field tests
feat(text): GREEN — tsv_safe
test(text): RED — tsv_safe tests
feat(text): GREEN — display_safe and cap_display
test(text): RED — display_safe and cap_display tests
feat(text): GREEN — bytes_to_utf8_lossy_safe
test(text): RED — bytes_to_utf8_lossy_safe tests
feat(core): GREEN — GuardInput sealed trait, Guarded, DecodedStr
test(core): RED — GuardInput trait and Guarded/DecodedStr type tests
```
