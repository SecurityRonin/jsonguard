# jsonguard v0.1 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build `jsonguard` — a zero-dependency, `no_std`-compatible Rust library that sanitizes strings for safe emission into JSON/JSONL, CSV, TSV, terminal tables, MongoDB, Elasticsearch, Redis, BSON, and MessagePack, guarding against injection, formula, bidi-override, control-character, and NoSQL operator attacks.

**Architecture:** Four module groups — `text` (TSV/CSV/JSONL/display), `nosql` (MongoDB/Elasticsearch/Redis), `binary` (BSON/MessagePack/Protocol Buffers advisory), and `decode` (raw-bytes → `DecodedStr{text, lossy}`) — all gated behind Cargo features. Every sanitizer returns `Cow<'_, str>`: borrowed when input is already clean (the common case, zero allocation), owned only when changes are needed. Core module is `no_std + alloc`; `nosql` and `binary` require the `nosql` and `binary` features respectively.

**Tech Stack:** Rust 1.75, no mandatory runtime dependencies, `proptest` for property-based tests in dev, `alloc` feature guards for `Cow`/`String` APIs.

**Engineering Decisions:**
- TSV tab→space (not deletion) matches Volatility3 convention; documented in module-level doc comment.
- Formula injection prefix (`'`) follows OWASP CSV Injection guidance — defangs `= + - @` openers.
- Bidi override removal is done at-sanitize-time (not decode-time) in this library; callers who want decode-time stripping should chain with `decode::bytes_to_utf8_lossy_safe`.
- MongoDB key sanitization strips `$` prefix and `.` from keys only — values are not touched (MongoDB stores arbitrary string values safely; injection is a key-name issue).
- Protocol Buffers advisory module contains only documentation (no code) — PB is injection-proof at wire level.
- `no_std + alloc` for all modules: no `std::io::Write`, no `std::error::Error` (unless `std` feature enabled).

---

## Repo layout (end state)

```
jsonguard/
├── Cargo.toml
├── src/
│   ├── lib.rs               # #![no_std], feature gates, pub re-exports
│   ├── decode.rs            # DecodedStr, bytes_to_utf8_lossy_safe
│   ├── text/
│   │   ├── mod.rs           # shared needs_fix kernel
│   │   ├── tsv.rs           # tsv_safe()
│   │   ├── csv.rs           # csv_field()
│   │   ├── json.rs          # jsonl_safe()
│   │   └── display.rs       # display_safe(), cap_display()
│   ├── nosql/
│   │   ├── mod.rs
│   │   ├── mongo.rs         # sanitize_mongo_key(), has_mongo_operator()
│   │   ├── elastic.rs       # sanitize_es_query(), sanitize_es_field()
│   │   └── redis.rs         # sanitize_redis_arg()
│   └── binary/
│       ├── mod.rs
│       ├── bson.rs          # sanitize_bson_key() (shares $ logic with mongo)
│       ├── msgpack.rs       # advisory: schema recommendations
│       └── protobuf.rs      # advisory: injection-proof at wire level (doc only)
└── docs/plans/
    └── 2026-05-21-jsonguard-v0.1.md   (this file)
```

---

## Shared character classification kernel

Every module uses the same `needs_fix` predicate family. Keep them in `src/text/mod.rs` as `pub(crate)` functions so each module imports rather than re-declares them.

```rust
/// Returns true for chars that are row/field boundary threats in TSV/JSONL
/// and also C0/C1 controls + bidi overrides.
pub(crate) fn is_control_or_boundary(c: char) -> bool {
    matches!(c,
        '\u{0000}'..='\u{001F}'   // C0 controls (includes \t \n \r NUL)
        | '\u{007F}'              // DEL
        | '\u{0080}'..='\u{009F}' // C1 controls
        | '\u{202A}'..='\u{202E}' // bidi embedding / override
        | '\u{2066}'..='\u{2069}' // bidi isolate
        | '\u{200E}' | '\u{200F}' // LRM / RLM
    )
}

/// Returns true for chars that are invisible zero-width markers
/// (not controls, but deceptive in display contexts).
pub(crate) fn is_zero_width_invisible(c: char) -> bool {
    matches!(c,
        '\u{200B}'  // ZWSP
        | '\u{200C}' | '\u{200D}' // ZWNJ / ZWJ
        | '\u{FEFF}' // BOM / ZWNBSP
        | '\u{2060}' // word joiner
    )
}
```

---

## Task 1: Crate skeleton + `lib.rs` + `text/mod.rs` kernel

### Files
- Create: `src/lib.rs`
- Create: `src/text/mod.rs`

### Step 1: Write RED tests (lib-level smoke + kernel)

Create `src/lib.rs` with the test module only, referencing not-yet-existing items:

```rust
// src/lib.rs
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(feature = "alloc")]
extern crate alloc;

pub mod text;
// nosql and binary added in later tasks

#[cfg(test)]
mod tests {
    #[test]
    fn crate_compiles() {}
}
```

Create `src/text/mod.rs` with tests that reference `is_control_or_boundary` and `is_zero_width_invisible` before they exist:

```rust
// src/text/mod.rs
pub mod tsv;
pub mod csv;
pub mod json;
pub mod display;

pub(crate) fn is_control_or_boundary(_c: char) -> bool { todo!() }
pub(crate) fn is_zero_width_invisible(_c: char) -> bool { todo!() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_is_control_or_boundary() {
        assert!(is_control_or_boundary('\t'));
    }
    #[test]
    fn newline_is_control_or_boundary() {
        assert!(is_control_or_boundary('\n'));
    }
    #[test]
    fn nul_is_control_or_boundary() {
        assert!(is_control_or_boundary('\u{0000}'));
    }
    #[test]
    fn del_is_control_or_boundary() {
        assert!(is_control_or_boundary('\u{007F}'));
    }
    #[test]
    fn c1_control_is_boundary() {
        assert!(is_control_or_boundary('\u{0085}')); // NEL
    }
    #[test]
    fn rtl_override_is_boundary() {
        assert!(is_control_or_boundary('\u{202E}'));
    }
    #[test]
    fn lrm_is_boundary() {
        assert!(is_control_or_boundary('\u{200E}'));
    }
    #[test]
    fn regular_ascii_not_boundary() {
        assert!(!is_control_or_boundary('A'));
        assert!(!is_control_or_boundary(' '));
        assert!(!is_control_or_boundary('-'));
    }
    #[test]
    fn unicode_letter_not_boundary() {
        assert!(!is_control_or_boundary('ñ'));
        assert!(!is_control_or_boundary('中'));
    }
    #[test]
    fn zwsp_is_zero_width_invisible() {
        assert!(is_zero_width_invisible('\u{200B}'));
    }
    #[test]
    fn bom_is_zero_width_invisible() {
        assert!(is_zero_width_invisible('\u{FEFF}'));
    }
    #[test]
    fn regular_space_not_zero_width() {
        assert!(!is_zero_width_invisible(' '));
    }
}
```

Also create stub files so the `pub mod` declarations compile:

```rust
// src/text/tsv.rs   (stub)
// src/text/csv.rs   (stub)
// src/text/json.rs  (stub)
// src/text/display.rs (stub)
```

### Step 2: Run to verify RED

```bash
cd ~/src/jsonguard && cargo test 2>&1 | grep -E "FAILED|error"
```

Expected: tests that call `todo!()` panic → FAILED.

### Step 3: Implement GREEN

Replace the `todo!()` bodies in `src/text/mod.rs` with the real implementations shown above in the "Shared character classification kernel" section.

### Step 4: Verify GREEN

```bash
cd ~/src/jsonguard && cargo test 2>&1 | tail -4
```

Expected: all tests pass.

### Step 5: RED commit, then GREEN commit

```bash
# RED was committed at step 2; now:
git add src/lib.rs src/text/mod.rs src/text/tsv.rs src/text/csv.rs src/text/json.rs src/text/display.rs
git commit --no-gpg-sign -m "feat(GREEN): text module kernel — is_control_or_boundary, is_zero_width_invisible"
```

---

## Task 2: `text::tsv` — `tsv_safe()`

**Why tab→space not deletion:** TSV has no escape mechanism. Deleting a tab could silently merge two tokens (`"foo\tbar"` → `"foobar"`), changing meaning. Space preserves the token boundary. This matches Volatility3's convention. Document this in the function's doc comment.

### Files
- Modify: `src/text/tsv.rs`

### Step 1: Write RED tests

```rust
// src/text/tsv.rs
#[cfg(feature = "alloc")]
use alloc::borrow::Cow;

/// Make `s` safe to emit as one TSV field (tab-separated values, no quoting).
///
/// # What is replaced
///
/// | Input | Output | Rationale |
/// |---|---|---|
/// | `\t` U+0009 | space | field-boundary char; replaced not deleted to preserve token boundary (matches Volatility3 convention) |
/// | `\n` U+000A | space | record-boundary char |
/// | `\r` U+000D | space | record-boundary char |
/// | NUL U+0000 | removed | C-string truncation |
/// | other C0 U+0001–U+001F | removed | terminal/parser confusion |
/// | DEL U+007F | removed | control |
/// | C1 controls U+0080–U+009F | removed | some terminals act on them |
/// | Bidi overrides U+202A–U+202E, U+2066–U+2069, U+200E, U+200F | removed | RTL/reversal attacks |
/// | All other chars | unchanged | preserve identity |
///
/// # Allocation
///
/// Returns `Cow::Borrowed` when the input is already clean (zero allocation).
/// Returns `Cow::Owned` only when substitutions are needed.
#[cfg(feature = "alloc")]
pub fn tsv_safe(s: &str) -> Cow<'_, str> {
    todo!()
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use super::*;
    #[cfg(feature = "alloc")]
    use alloc::borrow::Cow;

    #[cfg(feature = "alloc")]
    #[test]
    fn clean_string_borrows() {
        let s = "svchost.exe";
        let result = tsv_safe(s);
        assert!(matches!(result, Cow::Borrowed(_)), "clean input must not allocate");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn tab_replaced_with_space() {
        assert_eq!(tsv_safe("foo\tbar"), "foo bar");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn newline_replaced_with_space() {
        assert_eq!(tsv_safe("foo\nbar"), "foo bar");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn carriage_return_replaced_with_space() {
        assert_eq!(tsv_safe("foo\rbar"), "foo bar");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn nul_removed() {
        assert_eq!(tsv_safe("foo\u{0000}bar"), "foobar");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn c0_controls_removed() {
        // SOH (0x01), BEL (0x07)
        assert_eq!(tsv_safe("foo\u{0001}bar"), "foobar");
        assert_eq!(tsv_safe("foo\u{0007}bar"), "foobar");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn del_removed() {
        assert_eq!(tsv_safe("foo\u{007F}bar"), "foobar");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn c1_controls_removed() {
        assert_eq!(tsv_safe("foo\u{0085}bar"), "foobar"); // NEL
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn rtl_override_removed() {
        // U+202E RTL Override — classic "cod\u{202E}txt.exe" reversal attack
        assert_eq!(tsv_safe("cod\u{202E}txt.exe"), "codtxt.exe");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn lrm_removed() {
        assert_eq!(tsv_safe("foo\u{200E}bar"), "foobar");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn unicode_preserved() {
        assert_eq!(tsv_safe("lsass\u{00E9}.exe"), "lsass\u{00E9}.exe");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn chinese_preserved() {
        assert_eq!(tsv_safe("系统进程"), "系统进程");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn empty_string() {
        let result = tsv_safe("");
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result, "");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn multiple_replacements_in_one_pass() {
        assert_eq!(tsv_safe("a\tb\nc\rd"), "a b c d");
    }
}
```

### Step 2: Verify RED

```bash
cd ~/src/jsonguard && cargo test text::tsv 2>&1 | grep -E "FAILED|panicked|error"
```

Expected: FAILED (todo! panics).

### Step 3: Implement GREEN

```rust
#[cfg(feature = "alloc")]
pub fn tsv_safe(s: &str) -> Cow<'_, str> {
    use crate::text::is_control_or_boundary;
    if !s.chars().any(is_control_or_boundary) {
        return Cow::Borrowed(s);
    }
    let mut out = alloc::string::String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\t' | '\n' | '\r' => out.push(' '),
            c if is_control_or_boundary(c) => {} // remove: C0/C1/bidi (non-whitespace)
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}
```

### Step 4: Verify GREEN

```bash
cd ~/src/jsonguard && cargo test text::tsv 2>&1 | tail -3
```

Expected: all tests pass.

### Step 5: Commit

```bash
git add src/text/tsv.rs
git commit --no-gpg-sign -m "feat(GREEN): text::tsv — tsv_safe() with Cow borrow optimization"
```

---

## Task 3: `text::csv` — `csv_field()`

RFC 4180 + formula injection guard. The OWASP "CSV Injection" attack: a cell value starting with `= + - @` is interpreted as a formula by Excel/LibreOffice/Google Sheets when the CSV is opened. Forensic CSVs are routinely opened in spreadsheets. Fix: prefix `'` (apostrophe) — this forces spreadsheets to treat the cell as text, while being invisible in most display contexts.

### Files
- Modify: `src/text/csv.rs`

### Step 1: Write RED tests

```rust
// src/text/csv.rs
#[cfg(feature = "alloc")]
use alloc::borrow::Cow;

/// Format one field for an RFC 4180 CSV row.
///
/// Rules applied in order:
/// 1. Strip NUL and C0/C1 controls (except `\n`/`\r` which are legal inside
///    a quoted field per RFC 4180). Strip bidi overrides.
/// 2. Guard formula injection: if the stripped field starts with `= + - @`,
///    a leading tab, or a leading CR, prefix with `'` (OWASP CSV Injection
///    mitigation — forces spreadsheet to treat as text).
/// 3. If the field contains `,`, `"`, `\n`, or `\r`: wrap in `"` and double
///    any internal `"` → `""`.
/// 4. Otherwise return as-is.
///
/// Apply to **every** free-text field in a CSV row — not just paths.
#[cfg(feature = "alloc")]
pub fn csv_field(s: &str) -> Cow<'_, str> {
    todo!()
}

/// Returns true if `s` starts with a spreadsheet formula trigger character.
pub fn has_formula_prefix(s: &str) -> bool {
    todo!()
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use super::*;

    // --- has_formula_prefix ---
    #[test]
    fn formula_prefix_equals() { assert!(has_formula_prefix("=cmd")); }
    #[test]
    fn formula_prefix_plus() { assert!(has_formula_prefix("+1")); }
    #[test]
    fn formula_prefix_minus() { assert!(has_formula_prefix("-1")); }
    #[test]
    fn formula_prefix_at() { assert!(has_formula_prefix("@SUM")); }
    #[test]
    fn formula_prefix_tab() { assert!(has_formula_prefix("\t=cmd")); }
    #[test]
    fn formula_prefix_cr() { assert!(has_formula_prefix("\r=cmd")); }
    #[test]
    fn no_formula_prefix_svchost() { assert!(!has_formula_prefix("svchost.exe")); }
    #[test]
    fn no_formula_prefix_empty() { assert!(!has_formula_prefix("")); }

    // --- csv_field ---
    #[cfg(feature = "alloc")]
    #[test]
    fn clean_field_borrows() {
        let s = "svchost.exe";
        let result = csv_field(s);
        assert!(matches!(result, alloc::borrow::Cow::Borrowed(_)));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn field_with_comma_is_quoted() {
        assert_eq!(csv_field("foo,bar"), r#""foo,bar""#);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn field_with_double_quote_is_quoted_and_doubled() {
        assert_eq!(csv_field(r#"say "hi""#), r#""say ""hi"""#);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn field_with_newline_is_quoted() {
        assert_eq!(csv_field("foo\nbar"), "\"foo\nbar\"");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn field_with_cr_is_quoted() {
        assert_eq!(csv_field("foo\rbar"), "\"foo\rbar\"");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn formula_injection_equals_prefixed() {
        assert_eq!(csv_field("=cmd|'/c calc'!A1"), "'=cmd|'/c calc'!A1");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn formula_injection_plus_prefixed() {
        assert_eq!(csv_field("+malware"), "'+malware");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn formula_injection_at_prefixed() {
        assert_eq!(csv_field("@SUM(1)"), "'@SUM(1)");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn nul_stripped_before_quoting() {
        // NUL is stripped; result has no comma → no quoting needed
        assert_eq!(csv_field("foo\u{0000}bar"), "foobar");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn c0_controls_stripped_except_newline_cr() {
        // BEL stripped, newline preserved inside quoting
        assert_eq!(csv_field("foo\u{0007}bar"), "foobar");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn rtl_override_stripped() {
        assert_eq!(csv_field("cod\u{202E}txt.exe"), "codtxt.exe");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn unicode_preserved_no_quoting() {
        assert_eq!(csv_field("lsass\u{00E9}.exe"), "lsass\u{00E9}.exe");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn empty_field_borrows() {
        let result = csv_field("");
        assert!(matches!(result, alloc::borrow::Cow::Borrowed(_)));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn formula_prefix_with_comma_both_guarded() {
        // = prefix → prefix ', then contains comma → wrap in quotes
        let result = csv_field("=foo,bar");
        assert!(result.starts_with("'="));
        assert!(result.contains(','));
    }
}
```

### Step 2: Verify RED

```bash
cd ~/src/jsonguard && cargo test text::csv 2>&1 | grep -E "FAILED|panicked"
```

### Step 3: Implement GREEN

```rust
pub fn has_formula_prefix(s: &str) -> bool {
    // Strip leading whitespace controls (tab, CR) that could precede the trigger
    let trimmed = s.trim_start_matches(|c| c == '\t' || c == '\r');
    matches!(trimmed.chars().next(), Some('=' | '+' | '-' | '@'))
}

#[cfg(feature = "alloc")]
pub fn csv_field(s: &str) -> Cow<'_, str> {
    use crate::text::is_control_or_boundary;
    use alloc::string::String;

    // Step 1: strip controls (keep \n and \r — legal in quoted RFC 4180 fields)
    let needs_control_strip = s.chars().any(|c| {
        is_control_or_boundary(c) && c != '\n' && c != '\r'
    });
    let cleaned: Cow<'_, str> = if needs_control_strip {
        let mut buf = String::with_capacity(s.len());
        for c in s.chars() {
            if is_control_or_boundary(c) && c != '\n' && c != '\r' {
                // strip: NUL, C0 (except \n\r), C1, bidi
            } else {
                buf.push(c);
            }
        }
        Cow::Owned(buf)
    } else {
        Cow::Borrowed(s)
    };

    // Step 2: formula injection guard
    let needs_formula_guard = has_formula_prefix(&cleaned);
    let guarded: Cow<'_, str> = if needs_formula_guard {
        let mut buf = String::with_capacity(cleaned.len() + 1);
        buf.push('\'');
        buf.push_str(&cleaned);
        Cow::Owned(buf)
    } else {
        cleaned
    };

    // Step 3: RFC 4180 quoting
    let needs_quoting = guarded.chars().any(|c| matches!(c, ',' | '"' | '\n' | '\r'));
    if !needs_quoting {
        return guarded;
    }
    let mut out = String::with_capacity(guarded.len() + 2);
    out.push('"');
    for c in guarded.chars() {
        if c == '"' { out.push('"'); } // RFC 4180: double internal quotes
        out.push(c);
    }
    out.push('"');
    Cow::Owned(out)
}
```

### Step 4: Verify GREEN

```bash
cd ~/src/jsonguard && cargo test text::csv 2>&1 | tail -3
```

### Step 5: Commit

```bash
git add src/text/csv.rs
git commit --no-gpg-sign -m "feat(GREEN): text::csv — csv_field() RFC 4180 + formula injection guard"
```

---

## Task 4: `text::json` — `jsonl_safe()`

JSONL (JSON Lines) stores one JSON object per line. The only extra concern vs. JSON is that `\n` and `\r` in a string value would split the line and corrupt the JSONL stream. `serde_json` handles all character escaping inside the JSON value correctly; this function guards the **line boundary** specifically.

**Note for callers:** If you are using `serde_json::json!` or `serde_json::to_string`, you do NOT need `jsonl_safe` on individual field values — serde_json already escapes `\n`/`\r` as `\n`/`\r`. `jsonl_safe` is for callers who hand-construct JSONL by concatenating raw strings (uncommon but occasionally needed for streaming).

### Files
- Modify: `src/text/json.rs`

### Step 1: Write RED tests

```rust
// src/text/json.rs
#[cfg(feature = "alloc")]
use alloc::borrow::Cow;

/// Strip `\n` and `\r` from a string that will be embedded in a JSONL
/// (JSON Lines) value — guards against line-splitting that corrupts the
/// JSONL stream.
///
/// # When to use
///
/// Only when hand-constructing JSONL without a full JSON serializer.
/// If you use `serde_json::to_string` / `serde_json::json!`, this is
/// unnecessary — serde_json escapes newlines automatically.
#[cfg(feature = "alloc")]
pub fn jsonl_safe(s: &str) -> Cow<'_, str> {
    todo!()
}

/// Returns true if `s` contains any character that would split a JSONL line.
pub fn has_jsonl_line_break(s: &str) -> bool {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use alloc::borrow::Cow;

    #[test]
    fn detects_newline() { assert!(has_jsonl_line_break("foo\nbar")); }
    #[test]
    fn detects_cr() { assert!(has_jsonl_line_break("foo\rbar")); }
    #[test]
    fn clean_string_no_break() { assert!(!has_jsonl_line_break("svchost.exe")); }
    #[test]
    fn empty_no_break() { assert!(!has_jsonl_line_break("")); }

    #[cfg(feature = "alloc")]
    #[test]
    fn clean_borrows() {
        let s = "svchost.exe";
        assert!(matches!(jsonl_safe(s), Cow::Borrowed(_)));
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn newline_removed() { assert_eq!(jsonl_safe("foo\nbar"), "foobar"); }
    #[cfg(feature = "alloc")]
    #[test]
    fn cr_removed() { assert_eq!(jsonl_safe("foo\rbar"), "foobar"); }
    #[cfg(feature = "alloc")]
    #[test]
    fn tab_preserved() { assert_eq!(jsonl_safe("foo\tbar"), "foo\tbar"); }
    #[cfg(feature = "alloc")]
    #[test]
    fn unicode_preserved() { assert_eq!(jsonl_safe("中文"), "中文"); }
}
```

### Step 2: Verify RED

```bash
cd ~/src/jsonguard && cargo test text::json 2>&1 | grep FAILED
```

### Step 3: Implement GREEN

```rust
pub fn has_jsonl_line_break(s: &str) -> bool {
    s.contains('\n') || s.contains('\r')
}

#[cfg(feature = "alloc")]
pub fn jsonl_safe(s: &str) -> Cow<'_, str> {
    if !has_jsonl_line_break(s) {
        return Cow::Borrowed(s);
    }
    Cow::Owned(s.chars().filter(|&c| c != '\n' && c != '\r').collect())
}
```

### Step 4 + 5: Verify + commit

```bash
cd ~/src/jsonguard && cargo test text::json 2>&1 | tail -3
git add src/text/json.rs
git commit --no-gpg-sign -m "feat(GREEN): text::json — jsonl_safe(), has_jsonl_line_break()"
```

---

## Task 5: `text::display` — `display_safe()` + `cap_display()`

Terminal display context: no injection risk, but RTL override, ANSI/ESC injection, and invisible zero-width chars are real threats. Key difference from `tsv_safe`: **zero-width invisible chars are replaced with visible placeholders** (`<U+200B>` etc.) rather than deleted — so a forensic analyst *sees* the anomaly rather than having evidence silently removed.

**Note on `unicode-width`:** `cap_display` needs column-width measurement. Add `unicode-width = "0.1"` to `[dependencies]` and gate it under the `alloc` feature (it is `no_std` compatible). Do NOT add it as mandatory — add it as a regular dependency (it is tiny, ~15 KB, no unsafe).

Update `Cargo.toml`:
```toml
[dependencies]
unicode-width = { version = "0.1", default-features = false }
```

### Files
- Modify: `src/text/display.rs`
- Modify: `Cargo.toml`

### Step 1: Write RED tests

```rust
// src/text/display.rs
#[cfg(feature = "alloc")]
use alloc::borrow::Cow;

/// Make `s` safe for display in an interactive terminal table cell.
///
/// - C0/C1 controls (except `\n` which comfy-table handles) → removed.
///   `\r` is **explicitly removed** (bare CR rewinds cursor, enabling row-overwrite).
/// - Bidi override chars → removed.
/// - Zero-width invisible chars (ZWSP, BOM, ZWNJ, ZWJ, word joiner) →
///   replaced with visible placeholder `<U+XXXX>` so the analyst sees the anomaly.
/// - All other chars → unchanged.
#[cfg(feature = "alloc")]
pub fn display_safe(s: &str) -> Cow<'_, str> {
    todo!()
}

/// Cap `s` at `max_cols` display columns (measured in Unicode terminal column
/// width via `unicode-width`). Appends `…` (U+2026) if truncated.
/// Returns `Cow::Borrowed` when the string is already within the limit.
#[cfg(feature = "alloc")]
pub fn cap_display(s: &str, max_cols: usize) -> Cow<'_, str> {
    todo!()
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use super::*;

    #[cfg(feature = "alloc")]
    #[test]
    fn clean_string_borrows() {
        assert!(matches!(display_safe("svchost.exe"), alloc::borrow::Cow::Borrowed(_)));
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn cr_removed() {
        // bare \r cursor-rewind attack
        assert_eq!(display_safe("foo\rbar"), "foobar");
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn rtl_override_removed() {
        assert_eq!(display_safe("cod\u{202E}txt.exe"), "codtxt.exe");
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn nul_removed() {
        assert_eq!(display_safe("foo\u{0000}bar"), "foobar");
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn esc_removed() {
        // ESC = U+001B (ANSI injection vector)
        assert_eq!(display_safe("foo\u{001B}[31mbar"), "foobar");
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn zwsp_becomes_placeholder() {
        assert_eq!(display_safe("foo\u{200B}bar"), "foo<U+200B>bar");
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn bom_becomes_placeholder() {
        assert_eq!(display_safe("\u{FEFF}foo"), "<U+FEFF>foo");
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn zwnj_becomes_placeholder() {
        assert_eq!(display_safe("foo\u{200C}bar"), "foo<U+200C>bar");
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn newline_preserved() {
        // \n is preserved — comfy-table uses it for in-cell line breaks
        assert_eq!(display_safe("foo\nbar"), "foo\nbar");
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn cap_display_short_borrows() {
        let s = "hello";
        assert!(matches!(cap_display(s, 80), alloc::borrow::Cow::Borrowed(_)));
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn cap_display_truncates_ascii() {
        let result = cap_display("hello world", 5);
        assert_eq!(result, "hell…"); // 4 chars + ellipsis = 5 cols
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn cap_display_cjk_counts_double_width() {
        // CJK chars are 2 columns wide; cap at 4 cols
        let result = cap_display("中文AB", 4);
        assert_eq!(result, "中文"); // 中(2)+文(2)=4, no ellipsis needed
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn cap_display_zero_limit() {
        assert_eq!(cap_display("hello", 0), "");
    }
}
```

### Step 2: Verify RED

```bash
cd ~/src/jsonguard && cargo test text::display 2>&1 | grep FAILED
```

### Step 3: Implement GREEN

```rust
use unicode_width::UnicodeWidthChar;

#[cfg(feature = "alloc")]
pub fn display_safe(s: &str) -> Cow<'_, str> {
    use crate::text::{is_control_or_boundary, is_zero_width_invisible};
    use alloc::string::String;

    fn needs_change(c: char) -> bool {
        // \n is kept (comfy-table), but \r is a cursor-rewind attack
        (is_control_or_boundary(c) && c != '\n') || is_zero_width_invisible(c)
    }

    if !s.chars().any(needs_change) {
        return Cow::Borrowed(s);
    }

    let mut out = String::with_capacity(s.len() + 32);
    for c in s.chars() {
        if is_zero_width_invisible(c) {
            // Make anomaly visible — do not silently delete evidence
            use alloc::format;
            out.push_str(&format!("<U+{:04X}>", c as u32));
        } else if is_control_or_boundary(c) && c != '\n' {
            // Drop: CR, NUL, ESC, other C0/C1, bidi overrides
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

#[cfg(feature = "alloc")]
pub fn cap_display(s: &str, max_cols: usize) -> Cow<'_, str> {
    use alloc::string::String;

    if max_cols == 0 {
        return Cow::Owned(String::new());
    }

    let mut cols = 0usize;
    let mut end_byte = s.len(); // assume fits
    let mut fits = true;

    for (i, c) in s.char_indices() {
        let w = c.width().unwrap_or(0);
        if cols + w > max_cols {
            end_byte = i;
            fits = false;
            break;
        }
        cols += w;
    }

    if fits {
        return Cow::Borrowed(s);
    }

    // Truncate and append ellipsis (ellipsis itself is 1 col wide)
    let mut out = String::with_capacity(end_byte + 3);
    // back off one more char to fit the ellipsis if needed
    let mut truncated = &s[..end_byte];
    while !truncated.is_empty() {
        let last_char_width = truncated.chars().next_back()
            .and_then(|c| c.width()).unwrap_or(0);
        let current_cols: usize = truncated.chars()
            .map(|c| c.width().unwrap_or(0)).sum();
        if current_cols + 1 <= max_cols { // +1 for ellipsis
            break;
        }
        truncated = &truncated[..truncated.len() - last_char_width.max(1)];
    }
    out.push_str(truncated);
    out.push('…');
    Cow::Owned(out)
}
```

### Step 4 + 5: Verify + commit

```bash
cd ~/src/jsonguard && cargo test text::display 2>&1 | tail -3
git add src/text/display.rs Cargo.toml
git commit --no-gpg-sign -m "feat(GREEN): text::display — display_safe(), cap_display() with unicode-width"
```

---

## Task 6: `decode` — `DecodedStr` + `bytes_to_utf8_lossy_safe()`

The DBCS/Big5 problem lives here. A Rust `String` is always valid UTF-8, so there is no injection risk inside one. The risk is at the **bytes → String boundary**: `from_utf8_lossy` silently replaces invalid bytes with U+FFFD, making a Big5-encoded `許` (0xB3 0x5C) look like `"\u{FFFD}\"` — a replacement char followed by a real backslash. The analyst cannot tell if U+FFFD appeared in the real name or if it is an artifact of lossy decoding. The `lossy` flag solves this.

### Files
- Create: `src/decode.rs`
- Modify: `src/lib.rs` (add `pub mod decode;`)

### Step 1: Write RED tests

```rust
// src/decode.rs

/// The result of decoding raw bytes into a Rust String.
///
/// `lossy: true` means one or more bytes could not be decoded losslessly;
/// U+FFFD replacement characters appear where the undecodable bytes were.
/// Callers should surface this flag to analysts so they know the displayed
/// name may not accurately represent the original bytes.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedStr {
    pub text: alloc::string::String,
    pub lossy: bool,
}

/// Decode raw bytes into a `DecodedStr`, flagging lossy substitutions.
///
/// Strategy:
/// 1. Try `str::from_utf8`. If it succeeds: `lossy: false`.
/// 2. Otherwise: `String::from_utf8_lossy`, set `lossy: true`.
///
/// Does **not** attempt DBCS/Big5/GBK/Shift-JIS decoding — add the
/// `encoding_rs` crate behind a `legacy-codepages` feature for that.
#[cfg(feature = "alloc")]
pub fn bytes_to_utf8_lossy_safe(bytes: &[u8]) -> DecodedStr {
    todo!()
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use super::*;

    #[cfg(feature = "alloc")]
    #[test]
    fn valid_utf8_not_lossy() {
        let r = bytes_to_utf8_lossy_safe(b"svchost.exe");
        assert_eq!(r.text, "svchost.exe");
        assert!(!r.lossy);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn valid_utf8_unicode_not_lossy() {
        let r = bytes_to_utf8_lossy_safe("lsassé.exe".as_bytes());
        assert!(!r.lossy);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn invalid_utf8_is_lossy() {
        // 0xFF is not valid UTF-8
        let r = bytes_to_utf8_lossy_safe(b"foo\xFFbar");
        assert!(r.lossy);
        assert!(r.text.contains('\u{FFFD}'));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn big5_trail_byte_is_lossy() {
        // Big5 許 = 0xB3 0x5C; 0xB3 is invalid UTF-8 lead → lossy
        let r = bytes_to_utf8_lossy_safe(&[0xB3, 0x5C]);
        assert!(r.lossy);
        // The 0x5C byte decodes as '\' in the lossy output — confirm we didn't
        // silently produce a phantom backslash that looks clean
        assert!(r.text.contains('\u{FFFD}'));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn empty_bytes_not_lossy() {
        let r = bytes_to_utf8_lossy_safe(b"");
        assert_eq!(r.text, "");
        assert!(!r.lossy);
    }
}
```

### Step 2: Verify RED, Step 3: Implement GREEN

```rust
#[cfg(feature = "alloc")]
pub fn bytes_to_utf8_lossy_safe(bytes: &[u8]) -> DecodedStr {
    match core::str::from_utf8(bytes) {
        Ok(s) => DecodedStr { text: alloc::string::String::from(s), lossy: false },
        Err(_) => DecodedStr {
            text: alloc::string::String::from_utf8_lossy(bytes).into_owned(),
            lossy: true,
        },
    }
}
```

### Step 4 + 5: Verify + commit

```bash
cd ~/src/jsonguard && cargo test decode 2>&1 | tail -3
git add src/decode.rs src/lib.rs
git commit --no-gpg-sign -m "feat(GREEN): decode — DecodedStr + bytes_to_utf8_lossy_safe() with lossy flag"
```

---

## Task 7: `nosql::mongo` — MongoDB key sanitization

MongoDB executes `$`-prefixed key names as operators (`$where`, `$gt`, `$ne`, etc.). It also uses `.` as a field-path separator. These are **key-name** threats, not value threats — MongoDB stores arbitrary string values safely.

Feature gate: `#[cfg(feature = "nosql")]`

### Files
- Create: `src/nosql/mod.rs`
- Create: `src/nosql/mongo.rs`
- Modify: `src/lib.rs` (add `#[cfg(feature = "nosql")] pub mod nosql;`)

### Step 1: Write RED tests

```rust
// src/nosql/mongo.rs
#[cfg(feature = "alloc")]
use alloc::borrow::Cow;

/// Returns true if `key` is (or starts with) a MongoDB operator.
/// MongoDB operators begin with `$`.
pub fn has_mongo_operator(key: &str) -> bool {
    todo!()
}

/// Sanitize a string for use as a MongoDB **key name**.
///
/// Removes `$` from the start (operator prefix) and replaces `.` with `_`
/// (field-path separator). These are key-name-only threats — MongoDB
/// stores arbitrary string values without this sanitization.
#[cfg(feature = "alloc")]
pub fn sanitize_mongo_key(key: &str) -> Cow<'_, str> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_operator_dollar_where() { assert!(has_mongo_operator("$where")); }
    #[test]
    fn has_operator_dollar_gt() { assert!(has_mongo_operator("$gt")); }
    #[test]
    fn no_operator_plain_name() { assert!(!has_mongo_operator("name")); }
    #[test]
    fn no_operator_empty() { assert!(!has_mongo_operator("")); }

    #[cfg(feature = "alloc")]
    #[test]
    fn plain_key_borrows() {
        let k = "process_name";
        assert!(matches!(sanitize_mongo_key(k), Cow::Borrowed(_)));
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn dollar_prefix_removed() {
        assert_eq!(sanitize_mongo_key("$where"), "where");
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn dot_replaced_with_underscore() {
        assert_eq!(sanitize_mongo_key("foo.bar"), "foo_bar");
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn dollar_and_dot_combined() {
        assert_eq!(sanitize_mongo_key("$foo.bar"), "foo_bar");
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn multiple_dots_replaced() {
        assert_eq!(sanitize_mongo_key("a.b.c"), "a_b_c");
    }
}
```

### Step 3: Implement GREEN

```rust
pub fn has_mongo_operator(key: &str) -> bool {
    key.starts_with('$')
}

#[cfg(feature = "alloc")]
pub fn sanitize_mongo_key(key: &str) -> Cow<'_, str> {
    let trimmed = key.trim_start_matches('$');
    let needs_dot_replace = trimmed.contains('.');
    if trimmed.len() == key.len() && !needs_dot_replace {
        return Cow::Borrowed(key);
    }
    Cow::Owned(trimmed.replace('.', "_"))
}
```

### Commit

```bash
cd ~/src/jsonguard && cargo test --features nosql nosql::mongo 2>&1 | tail -3
git add src/nosql/ src/lib.rs
git commit --no-gpg-sign -m "feat(GREEN): nosql::mongo — sanitize_mongo_key(), has_mongo_operator()"
```

---

## Task 8: `nosql::elastic` — Elasticsearch query sanitization

Elasticsearch uses the Lucene query syntax. Special characters that must be escaped when a value is used in a query string: `+ - = && || > < ! ( ) { } [ ] ^ " ~ * ? : \ /`. Also, field names should not contain `.` (nested field separator) unless intentional.

### Files
- Create: `src/nosql/elastic.rs`
- Modify: `src/nosql/mod.rs`

### Step 1: Write RED tests

```rust
// src/nosql/elastic.rs
#[cfg(feature = "alloc")]
use alloc::borrow::Cow;

/// Lucene query special characters that must be escaped with `\`.
pub const LUCENE_SPECIAL: &[char] = &[
    '+', '-', '=', '&', '|', '>', '<', '!',
    '(', ')', '{', '}', '[', ']', '^', '"',
    '~', '*', '?', ':', '\\', '/',
];

/// Escape a value for use inside a Lucene/Elasticsearch query string.
/// Prefixes each special character with `\`.
#[cfg(feature = "alloc")]
pub fn sanitize_es_query(s: &str) -> Cow<'_, str> {
    todo!()
}

/// Sanitize a string for use as an Elasticsearch field name.
/// Replaces `.` with `_` (nested field separator).
#[cfg(feature = "alloc")]
pub fn sanitize_es_field(s: &str) -> Cow<'_, str> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    #[test]
    fn plain_value_borrows() {
        assert!(matches!(sanitize_es_query("svchost"), Cow::Borrowed(_)));
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn colon_escaped() {
        assert_eq!(sanitize_es_query("key:value"), r"key\:value");
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn plus_escaped() {
        assert_eq!(sanitize_es_query("+admin"), r"\+admin");
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn wildcard_escaped() {
        assert_eq!(sanitize_es_query("foo*bar"), r"foo\*bar");
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn backslash_escaped() {
        assert_eq!(sanitize_es_query(r"C:\Windows"), r"C\:\\Windows");
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn multiple_specials() {
        assert_eq!(sanitize_es_query("a+b:c"), r"a\+b\:c");
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn field_plain_borrows() {
        assert!(matches!(sanitize_es_field("process_name"), Cow::Borrowed(_)));
    }
    #[cfg(feature = "alloc")]
    #[test]
    fn field_dot_replaced() {
        assert_eq!(sanitize_es_field("host.name"), "host_name");
    }
}
```

### Step 3: Implement GREEN

```rust
#[cfg(feature = "alloc")]
pub fn sanitize_es_query(s: &str) -> Cow<'_, str> {
    if !s.chars().any(|c| LUCENE_SPECIAL.contains(&c)) {
        return Cow::Borrowed(s);
    }
    let mut out = alloc::string::String::with_capacity(s.len() * 2);
    for c in s.chars() {
        if LUCENE_SPECIAL.contains(&c) { out.push('\\'); }
        out.push(c);
    }
    Cow::Owned(out)
}

#[cfg(feature = "alloc")]
pub fn sanitize_es_field(s: &str) -> Cow<'_, str> {
    if !s.contains('.') { return Cow::Borrowed(s); }
    Cow::Owned(s.replace('.', "_"))
}
```

### Commit

```bash
cd ~/src/jsonguard && cargo test --features nosql nosql::elastic 2>&1 | tail -3
git add src/nosql/elastic.rs src/nosql/mod.rs
git commit --no-gpg-sign -m "feat(GREEN): nosql::elastic — sanitize_es_query() Lucene escape, sanitize_es_field()"
```

---

## Task 9: `nosql::redis` — Redis RESP injection

Redis uses the RESP (REdis Serialization Protocol) wire format. Commands are separated by `\r\n`. If a user-controlled string is spliced into a Redis command string (as opposed to using a proper Redis client library with parameterization), embedded `\r\n` sequences can inject additional commands. Tab has no special meaning in RESP.

### Files
- Create: `src/nosql/redis.rs`
- Modify: `src/nosql/mod.rs`

### Step 1: Write RED tests

```rust
// src/nosql/redis.rs
#[cfg(feature = "alloc")]
use alloc::borrow::Cow;

/// Strip `\r` and `\n` from a string used as a Redis command argument.
///
/// RESP uses `\r\n` as command/line separator. Embedded newlines in a
/// raw-string argument can inject additional commands. Use a proper Redis
/// client library with parameterized commands instead of hand-constructing
/// RESP; this function is a defense-in-depth fallback.
#[cfg(feature = "alloc")]
pub fn sanitize_redis_arg(s: &str) -> Cow<'_, str> {
    todo!()
}

/// Returns true if `s` contains a RESP command separator.
pub fn has_resp_separator(s: &str) -> bool {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_no_separator() { assert!(!has_resp_separator("GET foo")); }
    #[test]
    fn newline_is_separator() { assert!(has_resp_separator("foo\nbar")); }
    #[test]
    fn cr_is_separator() { assert!(has_resp_separator("foo\rbar")); }

    #[cfg(feature = "alloc")]
    #[test]
    fn clean_borrows() { assert!(matches!(sanitize_redis_arg("key"), Cow::Borrowed(_))); }
    #[cfg(feature = "alloc")]
    #[test]
    fn newline_removed() { assert_eq!(sanitize_redis_arg("foo\nbar"), "foobar"); }
    #[cfg(feature = "alloc")]
    #[test]
    fn cr_removed() { assert_eq!(sanitize_redis_arg("foo\rbar"), "foobar"); }
    #[cfg(feature = "alloc")]
    #[test]
    fn crlf_removed() { assert_eq!(sanitize_redis_arg("foo\r\nSET evil 1"), "fooSET evil 1"); }
}
```

### Step 3 + commit

```rust
pub fn has_resp_separator(s: &str) -> bool { s.contains('\n') || s.contains('\r') }

#[cfg(feature = "alloc")]
pub fn sanitize_redis_arg(s: &str) -> Cow<'_, str> {
    if !has_resp_separator(s) { return Cow::Borrowed(s); }
    Cow::Owned(s.chars().filter(|&c| c != '\n' && c != '\r').collect())
}
```

```bash
cd ~/src/jsonguard && cargo test --features nosql nosql::redis 2>&1 | tail -3
git add src/nosql/redis.rs src/nosql/mod.rs
git commit --no-gpg-sign -m "feat(GREEN): nosql::redis — sanitize_redis_arg(), has_resp_separator()"
```

---

## Task 10: `binary::bson` — BSON key sanitization

BSON (Binary JSON, used by MongoDB) has the same `$`-operator and `.`-separator key threats as MongoDB. The `sanitize_bson_key` function is therefore identical to `sanitize_mongo_key` — but lives in the `binary` module because BSON is a binary serialization format, not a text format.

To avoid code duplication, `binary::bson` re-exports from `nosql::mongo`. This requires both `binary` and `nosql` features together; document this in the module.

Feature gate: `#[cfg(all(feature = "binary", feature = "nosql"))]` for the shared implementation. Alternatively, duplicate the tiny logic (3 lines). **Decision: duplicate** — avoids forcing `nosql` as a dependency of `binary`. Document the intentional duplication.

### Files
- Create: `src/binary/mod.rs`
- Create: `src/binary/bson.rs`
- Create: `src/binary/msgpack.rs`
- Create: `src/binary/protobuf.rs`
- Modify: `src/lib.rs`

### Step 1: Write RED tests (`src/binary/bson.rs`)

```rust
// src/binary/bson.rs
//! BSON key sanitization.
//!
//! BSON shares MongoDB's key-name threat model: `$`-prefixed keys are
//! operator names; `.` is the field-path separator. The `sanitize_bson_key`
//! implementation is intentionally duplicated from `nosql::mongo` to avoid
//! coupling the `binary` feature to the `nosql` feature.
#[cfg(feature = "alloc")]
use alloc::borrow::Cow;

pub fn has_bson_operator(key: &str) -> bool { todo!() }

#[cfg(feature = "alloc")]
pub fn sanitize_bson_key(key: &str) -> Cow<'_, str> { todo!() }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn operator_detected() { assert!(has_bson_operator("$where")); }
    #[test]
    fn plain_not_operator() { assert!(!has_bson_operator("name")); }
    #[cfg(feature = "alloc")]
    #[test]
    fn plain_borrows() { assert!(matches!(sanitize_bson_key("name"), Cow::Borrowed(_))); }
    #[cfg(feature = "alloc")]
    #[test]
    fn dollar_stripped() { assert_eq!(sanitize_bson_key("$gt"), "gt"); }
    #[cfg(feature = "alloc")]
    #[test]
    fn dot_replaced() { assert_eq!(sanitize_bson_key("a.b"), "a_b"); }
}
```

### Implementation (identical logic to mongo, duplicated intentionally)

```rust
pub fn has_bson_operator(key: &str) -> bool { key.starts_with('$') }

#[cfg(feature = "alloc")]
pub fn sanitize_bson_key(key: &str) -> Cow<'_, str> {
    let trimmed = key.trim_start_matches('$');
    if trimmed.len() == key.len() && !trimmed.contains('.') {
        return Cow::Borrowed(key);
    }
    Cow::Owned(trimmed.replace('.', "_"))
}
```

`src/binary/msgpack.rs` and `src/binary/protobuf.rs` are **advisory-only** modules — they contain only documentation, no executable code. Write them as doc-comment-only module files.

```rust
// src/binary/msgpack.rs
//! MessagePack advisory guidance.
//!
//! MessagePack is a binary format; string values are length-prefixed and do
//! not use delimiter characters. There is no classic injection risk comparable
//! to CSV/TSV for MessagePack values.
//!
//! # Recommendations
//!
//! - **Use typed schemas.** Arbitrary-type fields (e.g., MessagePack's `Any`
//!   / `Value` enum) can be coerced to unexpected types by crafted data.
//!   Always validate field types on deserialization.
//! - **Cap string lengths.** A multi-megabyte string in a "process name" field
//!   is evidence of corruption or an attack. Validate length before storing.
//! - **Validate keys.** Map keys in MessagePack can be arbitrary types; if
//!   you use string keys, apply the same `$`/`.` guard as BSON keys when
//!   the data is forwarded to MongoDB.
```

```rust
// src/binary/protobuf.rs
//! Protocol Buffers advisory guidance.
//!
//! Protocol Buffers (proto2/proto3) is injection-proof at the wire level:
//! field identity is determined by numeric field numbers, not string names.
//! A crafted string value in a `string` field cannot change the schema.
//!
//! # Remaining risks
//!
//! - **Proto-JSON mapping.** If you use `prost`'s JSON serialization or
//!   `protoc-gen-openapi`, the field *names* are human-readable strings and
//!   the standard JSON injection risks apply. Use `serde_json::json!` or a
//!   proper serializer — never hand-roll JSON from proto field values.
//! - **Arbitrary bytes in `bytes` fields.** A `bytes` field accepts any byte
//!   sequence. If the receiving code re-interprets these bytes as a command
//!   or SQL query, injection is possible at that boundary — apply the
//!   appropriate sanitizer there, not at the proto encoding layer.
```

### Commit

```bash
cd ~/src/jsonguard && cargo test --features binary binary 2>&1 | tail -3
git add src/binary/ src/lib.rs
git commit --no-gpg-sign -m "feat(GREEN): binary — bson key sanitization + msgpack/protobuf advisory docs"
```

---

## Task 11: Property-based tests with `proptest`

Add property tests to verify the invariants that matter most — particularly that `tsv_safe` and `csv_field` never produce output that contains the forbidden characters.

### Files
- Create: `tests/proptest_sanitize.rs`

```rust
// tests/proptest_sanitize.rs
use jsonguard::text::{tsv::tsv_safe, csv::csv_field};
use proptest::prelude::*;

proptest! {
    #[test]
    fn tsv_safe_never_contains_tab(s in ".*") {
        let result = tsv_safe(&s);
        prop_assert!(!result.contains('\t'), "tab found in tsv_safe output: {:?}", result);
    }

    #[test]
    fn tsv_safe_never_contains_newline(s in ".*") {
        let result = tsv_safe(&s);
        prop_assert!(!result.contains('\n'));
        prop_assert!(!result.contains('\r'));
    }

    #[test]
    fn tsv_safe_never_contains_c0(s in ".*") {
        let result = tsv_safe(&s);
        for c in result.chars() {
            prop_assert!(
                c >= '\u{0020}' || c == '\n',  // space and above, or newline (space substitute)
                "C0 control found: U+{:04X}", c as u32
            );
        }
    }

    #[test]
    fn csv_field_parseable(s in ".*") {
        let field = csv_field(&s);
        // If quoted: must start and end with ", and internal " must be ""
        if field.starts_with('"') {
            prop_assert!(field.ends_with('"'), "quoted field must end with quote");
        }
        // Must never start with = + - @ (formula injection)
        prop_assert!(!matches!(field.chars().next(), Some('=' | '+' | '-' | '@')),
            "formula prefix in output: {:?}", &field[..4.min(field.len())]);
    }

    #[test]
    fn clean_strings_borrow(s in "[A-Za-z0-9 ._/-]{0,100}") {
        // ASCII alphanumeric/common-punct strings should never allocate
        use std::borrow::Cow;
        let t = tsv_safe(&s);
        prop_assert!(matches!(t, Cow::Borrowed(_)), "expected borrow for clean string: {:?}", s);
        let c = csv_field(&s);
        prop_assert!(matches!(c, Cow::Borrowed(_)), "expected borrow for clean CSV string: {:?}", s);
    }
}
```

Run:
```bash
cd ~/src/jsonguard && cargo test --test proptest_sanitize 2>&1 | tail -5
```

Commit:
```bash
git add tests/proptest_sanitize.rs
git commit --no-gpg-sign -m "test: proptest invariants for tsv_safe and csv_field"
```

---

## Task 12: Public API cleanup + `lib.rs` re-exports + README

### `src/lib.rs` (final state)

```rust
#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod decode;
pub mod text;

#[cfg(feature = "nosql")]
pub mod nosql;

#[cfg(feature = "binary")]
pub mod binary;

// Convenience re-exports for the most common functions
#[cfg(feature = "alloc")]
pub use text::tsv::tsv_safe;
#[cfg(feature = "alloc")]
pub use text::csv::{csv_field, has_formula_prefix};
#[cfg(feature = "alloc")]
pub use text::json::{jsonl_safe, has_jsonl_line_break};
#[cfg(feature = "alloc")]
pub use text::display::{display_safe, cap_display};
#[cfg(feature = "alloc")]
pub use decode::{DecodedStr, bytes_to_utf8_lossy_safe};
```

### README.md (skeleton)

Create `README.md` with:
- One-paragraph description
- Feature table (default/alloc/nosql/binary/full)
- Quick-start example for each format
- Threat model section (what each function guards against and what it does NOT guard against)
- "Engineering decisions" section documenting tab→space Volatility3 convention and formula-injection prefix choice

### Commit

```bash
git add src/lib.rs README.md
git commit --no-gpg-sign -m "docs: public API re-exports + README skeleton"
```

---

## Task 13: Wire into `memory-forensic`

After `jsonguard` is working, add it to the memory-forensic workspace and replace the local CSV arm sanitization.

### Files
- Modify: `/Users/4n6h4x0r/src/memory-forensic/Cargo.toml` (workspace.dependencies + memf dependencies)
- Modify: `/Users/4n6h4x0r/src/memory-forensic/src/main.rs` (Csv arm, add `use jsonguard::{csv_field, tsv_safe}`)

### Steps

1. Add to workspace deps:
   ```toml
   # In memory-forensic/Cargo.toml [workspace.dependencies]
   jsonguard = { path = "../jsonguard" }
   ```

2. Add to memf binary deps:
   ```toml
   jsonguard.workspace = true
   ```

3. In `src/main.rs`, add import:
   ```rust
   use jsonguard::{csv_field, display_safe};
   ```

4. Find every `OutputFormat::Csv` arm and replace raw `d.name` interpolation with `csv_field(&d.name)` and `csv_field(&d.path)`. The known broken arm is `print_windows_drivers` — audit all other `Csv` arms too.

5. Run `cargo test --bin memf` — all 128 tests must still pass.

6. Commit:
   ```bash
   git add Cargo.toml src/main.rs
   git commit --no-gpg-sign -m "feat: wire jsonguard into memf — fix broken Csv arm sanitization"
   ```

---

## Execution

Plan complete and saved to `docs/plans/2026-05-21-jsonguard-v0.1.md`.

**Two execution options:**

**1. Subagent-Driven (this session)** — I dispatch a fresh subagent per task, with spec + code quality review between tasks. Fast iteration, stays in this session.

**2. Parallel Session (separate)** — Open a new Claude Code session in `~/src/jsonguard`, run `/pickup` then `superpowers:executing-plans`. Lets this session stay focused on memory-forensic.

**Which approach?**
