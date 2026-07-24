# jsonguard

**Input inspection and output sanitization for JSON/JSONL, CSV, and TSV — one crate for both ends of the data pipeline, with a secure-by-default API that makes the safe path the only path.**

```rust
use jsonguard::{csv_field, tsv_safe, jsonl_safe, inspect};

// Every function accepts &str OR &[u8]; byte input decodes through a safe
// UTF-8 lossy path first, so there is no "call decode() first" footgun.
let field = csv_field("=SUM(A1:A10)");   // formula injection neutralized
let cell  = tsv_safe("value\twith\ttabs"); // embedded tabs replaced

// Passive scan — returns a Findings report without modifying anything.
let f = inspect(user_input);
if !f.is_csv_safe() { /* reject at the boundary */ }
```

**[GitHub Repository →](https://github.com/SecurityRonin/jsonguard)**

---

## What it does

Untrusted data is dangerous at both ends of a pipeline. `jsonguard` covers both, by default:

- **At ingestion** — `inspect()` passively scans input and returns a `Findings` report (per-violation `kind`, `byte_offset`, and offending `char`) so you can accept, sanitize, or reject at an API boundary. Format-specific queries (`is_csv_safe`, `is_tsv_safe`, `is_jsonl_safe`, `is_display_safe`) and generic ones (`has_formula`, `has_bidi`, `has_controls`, `has_invalid_utf8`).
- **At emission** — `csv_field`, `tsv_safe`, `jsonl_safe`, `display_safe`, and `cap_display` produce output that respects each format's encoding rules. Every sanitizer returns a `Guarded { value, lossy }`; `Guarded` implements `Display`, and `lossy` flags input that carried undecodable bytes so a data-fidelity check is structurally present rather than a side-channel warning.

## Attack coverage

CSV formula injection (`= + - @` prefix), RFC 4180 quote handling, TSV column-shift via embedded TAB, JSON string escaping, CJKV Big5/GBK/EUC-KR byte collisions with `\` and `"` (decode-first), bidi overrides (U+202E and friends), C0/C1 control characters, null bytes, and UTF-8 overlong/surrogate sequences.

## Secure by default

Every function accepts `&str` **or** `&[u8]`. Byte input is decoded through a safe UTF-8 lossy path before inspection or sanitization — the decode step is invisible and mandatory, so the zero-knowledge path is the safe one.

## Validation

`jsonguard` is validated against real-world attack corpora — 50 Unicode Consortium bidi sequences (UCD 17.0.0), OWASP formula-injection payloads, Markus Kuhn's UTF-8 stress test, and CJKV encoding hazards. See the [Validation](validation.md) page for sources and reproduction steps.

---

[Validation](validation.md) · [Privacy Policy](privacy.md) · [Terms of Service](terms.md) · [GitHub](https://github.com/SecurityRonin/jsonguard) · © 2026 Security Ronin Ltd.
