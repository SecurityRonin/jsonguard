# jsonguard

[![Crates.io](https://img.shields.io/crates/v/jsonguard.svg)](https://crates.io/crates/jsonguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/jsonguard/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/jsonguard/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

Input inspection and output sanitization for JSON/JSONL, CSV, and TSV. Guards against formula injection, bidi-override, control-character, and encoding attacks at both ends of the data pipeline — with a secure-by-default API that makes the safe path the only path.

## The Problem

Untrusted data is dangerous at both ends of a pipeline:

**At ingestion** — you need to know what you're accepting before you store it or route it:

| Pattern | Risk |
|---------|------|
| `=HYPERLINK(...)` arriving in a field | Stored formula executes when exported to CSV |
| U+202E in a username | Display name reversed in UI — phishing vector |
| `\xFF\xFE` bytes from an external source | Unvalidated bytes corrupt downstream JSON encoding |

**At emission** — structured formats have strict encoding rules that raw strings violate:

| Attack | Format | Example |
|--------|--------|---------|
| Formula injection | CSV/TSV | `=HYPERLINK("https://evil.example","click me")` |
| JSON string injection | JSONL | `hello"\n,"injected_key":"injected_value` |
| Bidi override | All | U+202E reverses displayed text |
| Control characters | All | TAB/CR/LF breaks field boundaries |
| CJKV encoding hazard | JSONL | Big5 `許` has `0x5C` as second byte — triggers JSON `\` escape |
| Unbalanced quotes | CSV | Raw `"` in a field breaks RFC 4180 parsers |

Most crates address one end or one attack class. `jsonguard` covers both ends, all attack classes, by default.

## Secure by Default

Every function in `jsonguard` accepts `&str` **or** `&[u8]`. Byte input is decoded through a safe UTF-8 lossy path before inspection or sanitization. There is no "call `decode()` first" footgun — the decode step is invisible and mandatory.

```rust
use jsonguard::{csv_field, tsv_safe, jsonl_safe};

// Both compile. Both are safe. The &[u8] path decodes first.
let from_str   = csv_field("O'Brien, \"quoted\"");
let from_bytes = csv_field(b"\xB3\x5C raw bytes from Big5 source");
//                          ^^ 許 in Big5; 0x5C second byte is handled correctly

assert!(!from_str.lossy);   // &str input: always valid UTF-8
assert!(from_bytes.lossy);  // byte input: \xB3 was undecodable, replaced
println!("{}", from_bytes); // still a valid, safe CSV field
```

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `alloc` | ✓ | `Cow<'_, str>` / `String` return types |
| `std` | | `std::error::Error` impl |

## Install

```toml
[dependencies]
jsonguard = "0.2"
```

No-std compatible:

```toml
[dependencies]
jsonguard = { version = "0.2", default-features = false, features = ["alloc"] }
```

## Usage

### CSV

```rust
use jsonguard::csv_field;

// Wraps in quotes and escapes internal quotes per RFC 4180
let field = csv_field("=SUM(A1:A10)");  // formula injection blocked
assert_eq!(field.to_string(), r#"'=SUM(A1:A10)"#);

let field = csv_field("name with \"quotes\"");
assert_eq!(field.to_string(), r#""name with ""quotes"""#);
```

### TSV

```rust
use jsonguard::tsv_safe;

// Tabs, CR, LF replaced; bidi stripped; formula-prefixed fields escaped
let cell = tsv_safe("value\twith\ttabs");
assert_eq!(cell.to_string(), "value with tabs");
```

### JSON Lines

```rust
use jsonguard::jsonl_safe;

// Produces a valid JSON string value (with surrounding quotes)
let val = jsonl_safe("line1\nline2");
assert_eq!(val.to_string(), r#""line1\nline2""#);
```

### Display-safe strings

```rust
use jsonguard::{display_safe, cap_display};

// Strip control chars and bidi overrides for any display context
let s = display_safe("normal \x00 text \u{202E} reversed");
assert_eq!(s.to_string(), "normal  text  reversed");

// Truncate with a safe sentinel, never mid-character
let s = cap_display("hello world", 5);
assert_eq!(s.to_string(), "hello…");
```

### Raw bytes

```rust
use jsonguard::bytes_to_utf8_lossy_safe;

let decoded = bytes_to_utf8_lossy_safe(b"\xFF\xFE valid utf-8 \xC0\x80 not");
assert!(decoded.lossy);  // replacement chars inserted
println!("{}", decoded); // safe for display
```

### The `Guarded` type

Every sanitizer returns `Guarded`:

```rust
pub struct Guarded {
    pub value: String,
    pub lossy: bool,   // true when input had undecodable bytes
}
```

`Guarded` implements `Display` (emits `value`) so it drops straight into format strings. Check `lossy` when you care about data fidelity — e.g., log a warning or reject the record.

### Input inspection

`inspect()` passively scans input and returns a `Findings` report without modifying anything.

```rust
use jsonguard::inspect;

// Reject at an API boundary
let f = inspect(user_input);
if !f.is_csv_safe() {
    return Err("input contains characters unsafe for CSV");
}

// Audit log with per-violation detail
let f = inspect(raw_bytes);
for v in &f.violations {
    eprintln!("violation {:?} at byte {}", v.kind, v.byte_offset);
}

// Branch: sanitize or reject
let f = inspect(user_input);
if f.is_clean() {
    Ok(csv_field(user_input))       // no changes needed
} else if f.is_csv_safe() {
    Ok(csv_field(user_input))       // sanitizer handles it
} else {
    Err("rejected: unsafe characters for CSV")
}
```

`Findings` exposes format-specific safety queries (`is_csv_safe`, `is_tsv_safe`, `is_jsonl_safe`, `is_display_safe`) and generic violation queries (`has_formula`, `has_bidi`, `has_controls`, `has_invalid_utf8`). Each `Violation` carries the `byte_offset` and the offending `char`.

## Attack Coverage

| Attack class | Handled |
|--------------|---------|
| CSV formula injection (`= + - @` prefix) | ✓ `'`-prefix escape |
| RFC 4180 quote handling | ✓ double-quote escape |
| TSV column shift (embedded TAB) | ✓ replace with space |
| JSON string escape (backslash, quote, control chars) | ✓ |
| CJKV Big5/GBK/EUC-KR byte collision with `\` and `"` | ✓ decode-first |
| Bidi override (U+202E, U+200F, U+2069, etc.) | ✓ strip |
| C0/C1 control characters | ✓ strip |
| Null bytes | ✓ strip |
| UTF-8 overlong sequences and surrogates | ✓ lossy decode |

**Validated against real-world attack corpora** — 50 Unicode Consortium bidi sequences (UCD 17.0.0), 7 OWASP formula injection payloads, Markus Kuhn's UTF-8 stress test (22 KB), and CJKV encoding hazards including Big5 `\xB3\x5C` and surrogate/overlong sequences. See [`docs/validation.md`](docs/validation.md) for sources and reproduction steps.

## Acknowledgements

- [OWASP CSV Injection](https://owasp.org/www-community/attacks/CSV_Injection) — formula injection documentation
- [RFC 4180](https://www.ietf.org/rfc/rfc4180.txt) — CSV format specification
- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) — JSON format specification
- [Unicode Bidirectional Algorithm](https://unicode.org/reports/tr9/) — bidi control character reference

---

[Privacy Policy](https://securityronin.com/privacy) · [Terms of Service](https://securityronin.com/terms) · © 2026 Security Ronin Ltd
