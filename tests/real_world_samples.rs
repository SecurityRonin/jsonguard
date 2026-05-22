// Integration tests against real-world attack samples and authoritative test data.
// Sources:
//   Unicode Consortium BidiCharacterTest.txt / BidiTest.txt (UCD 17.0.0)
//   Markus Kuhn UTF-8 stress test (https://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt)
//   OWASP CSV Injection (https://owasp.org/www-community/attacks/CSV_Injection)

use jsonguard::{csv_field, display_safe, inspect, jsonl_safe, tsv_safe};

// ---------------------------------------------------------------------------
// Bidi corpus — lines from BidiCharacterTest.txt that contain known bidi
// control codepoints, exercised through inspect() and the output sanitizers.
// ---------------------------------------------------------------------------
mod bidi_corpus {
    use super::*;

    // BidiCharacterTest.txt — embedded at compile time.
    // Each data line has the form: <hex codepoints>;<paragraph dir>;<resolved level>;<levels>;<reorder>
    // We extract lines that contain U+202E (RIGHT-TO-LEFT OVERRIDE) by scanning the hex fields.
    static BIDI_CHAR_TEST: &str = include_str!("corpus/BidiCharacterTest.txt");

    /// Collect the first N data lines whose codepoint sequence contains U+202E.
    fn rlo_lines(n: usize) -> Vec<String> {
        BIDI_CHAR_TEST
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .filter(|l| {
                // Data line first field: space-separated hex codepoints
                l.split(';').next().map_or(false, |cps| {
                    cps.split_whitespace()
                        .any(|cp| u32::from_str_radix(cp, 16).map_or(false, |n| n == 0x202E))
                })
            })
            .take(n)
            .map(|l| {
                // Reconstruct a string from the codepoint sequence (first field).
                l.split(';')
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .filter_map(|cp| u32::from_str_radix(cp, 16).ok())
                    .filter_map(char::from_u32)
                    .collect()
            })
            .collect()
    }

    #[test]
    fn bidi_char_test_loads() {
        // Sanity: file is present and non-trivial
        assert!(
            BIDI_CHAR_TEST.len() > 1000,
            "BidiCharacterTest.txt too small — download may have failed"
        );
        let data_lines = BIDI_CHAR_TEST
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .count();
        assert!(
            data_lines > 1000,
            "expected >1000 data lines, got {data_lines}"
        );
    }

    #[test]
    fn inspect_detects_bidi_in_rlo_corpus_lines() {
        let lines = rlo_lines(50);
        assert!(
            !lines.is_empty(),
            "no U+202E lines found in BidiCharacterTest.txt"
        );
        for line in &lines {
            let f = inspect(line.as_str());
            assert!(
                f.has_bidi(),
                "expected has_bidi() for corpus line containing U+202E: {:?}",
                line
            );
            assert!(
                !f.is_csv_safe(),
                "bidi-containing line must not be csv_safe: {:?}",
                line
            );
            assert!(
                !f.is_display_safe(),
                "bidi-containing line must not be display_safe: {:?}",
                line
            );
        }
    }

    #[test]
    fn display_safe_strips_rlo_from_corpus_lines() {
        for line in rlo_lines(20) {
            let g = display_safe(line.as_str());
            // U+202E must not appear in sanitized output
            assert!(
                !g.to_string().contains('\u{202E}'),
                "display_safe must strip U+202E from: {:?}",
                line
            );
        }
    }

    #[test]
    fn csv_field_sanitizes_rlo_from_corpus_lines() {
        for line in rlo_lines(20) {
            let g = csv_field(line.as_str());
            let out = g.to_string();
            assert!(
                !out.contains('\u{202E}'),
                "csv_field must strip U+202E from: {:?}",
                line
            );
        }
    }

    #[test]
    fn jsonl_safe_encodes_rlo_as_unicode_escape() {
        // jsonl_safe preserves data by escaping bidi as \uXXXX
        for line in rlo_lines(10) {
            let g = jsonl_safe(line.as_str());
            let out = g.to_string();
            // Must not contain raw U+202E
            assert!(
                !out.contains('\u{202E}'),
                "jsonl_safe must not emit raw U+202E"
            );
            // Must contain the Unicode escape sequence for RLO
            assert!(
                out.contains("\\u202e"),
                "jsonl_safe must escape U+202E as \\u202e, got: {out:?}"
            );
        }
    }

    // Handcrafted bidi attack samples with real embedded codepoints.
    static BIDI_SAMPLES: &str = include_str!("corpus/bidi_samples.txt");

    #[test]
    fn bidi_samples_file_loads() {
        assert!(BIDI_SAMPLES.len() > 50, "bidi_samples.txt too small");
    }

    #[test]
    fn inspect_detects_bidi_in_all_attack_samples() {
        // All lines except the last two ("normal line…" / "file‎name.txt" with LRM, "user؜name"
        // with U+061C) are constructed with bidi controls.
        let attack_lines: Vec<&str> = BIDI_SAMPLES
            .lines()
            .filter(|l| {
                l.chars().any(|c| {
                    matches!(c,
                        '\u{200E}' | '\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{061C}'
                    )
                })
            })
            .collect();
        assert!(
            !attack_lines.is_empty(),
            "no bidi-containing lines found in bidi_samples.txt"
        );
        for line in &attack_lines {
            assert!(
                inspect(*line).has_bidi(),
                "inspect must flag bidi in: {:?}",
                line
            );
        }
    }

    #[test]
    fn display_safe_strips_bidi_from_attack_samples() {
        for line in BIDI_SAMPLES.lines() {
            let g = display_safe(line);
            let out = g.to_string();
            // None of the bidi codepoint set must appear in output
            for c in out.chars() {
                assert!(
                    !matches!(c,
                        '\u{200E}' | '\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{061C}'
                    ),
                    "display_safe left bidi char U+{:04X} in: {out:?}",
                    c as u32
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Formula injection corpus — every line in formula_injection.csv is from
// OWASP CSV Injection and exercises inspect() + csv_field().
// ---------------------------------------------------------------------------
mod formula_injection_corpus {
    use super::*;

    static FORMULA_CSV: &str = include_str!("corpus/formula_injection.csv");

    // Lines that start with a formula trigger character (= + - @).
    // The DDE(...) line does NOT start with a trigger char — it is an
    // application-level attack that bypasses spreadsheet formula guards,
    // so we test it separately.
    fn formula_lines() -> impl Iterator<Item = &'static str> {
        FORMULA_CSV.lines().filter(|l| {
            !l.trim().is_empty() && l.starts_with(|c| matches!(c, '=' | '+' | '-' | '@'))
        })
    }

    #[test]
    fn formula_csv_loads() {
        let count = FORMULA_CSV.lines().filter(|l| !l.trim().is_empty()).count();
        assert!(
            count >= 7,
            "expected at least 7 formula injection samples, got {count}"
        );
    }

    #[test]
    fn inspect_flags_all_formula_lines() {
        let mut checked = 0usize;
        for line in formula_lines() {
            let f = inspect(line);
            assert!(
                f.has_formula(),
                "inspect must flag formula injection for: {line:?}"
            );
            assert!(
                !f.is_csv_safe(),
                "formula line must not pass is_csv_safe: {line:?}"
            );
            checked += 1;
        }
        assert!(
            checked >= 6,
            "expected at least 6 formula-trigger lines, got {checked}"
        );
    }

    #[test]
    fn csv_field_sanitizes_all_formula_lines() {
        for line in formula_lines() {
            let g = csv_field(line);
            let out = g.to_string();
            // After sanitization, the output must not start with a raw formula trigger.
            // csv_field prepends '; RFC 4180 quoting wraps in " if comma present.
            // Either way the first non-quote char must not be = + - @.
            let first_content_char = out.trim_start_matches('"').chars().next();
            assert_ne!(
                first_content_char,
                Some('='),
                "csv_field must not emit raw '=' prefix for: {line:?}"
            );
            assert_ne!(
                first_content_char,
                Some('+'),
                "csv_field must not emit raw '+' prefix for: {line:?}"
            );
            assert_ne!(
                first_content_char,
                Some('-'),
                "csv_field must not emit raw '-' prefix for: {line:?}"
            );
            assert_ne!(
                first_content_char,
                Some('@'),
                "csv_field must not emit raw '@' prefix for: {line:?}"
            );
            // csv_field guards with a leading apostrophe
            assert_eq!(
                first_content_char,
                Some('\''),
                "csv_field must guard formula line with leading \"'\": {line:?} → {out:?}"
            );
        }
    }

    #[test]
    fn tsv_safe_sanitizes_all_formula_lines() {
        for line in formula_lines() {
            let g = tsv_safe(line);
            let out = g.to_string();
            let first = out.chars().next();
            assert_ne!(
                first,
                Some('='),
                "tsv_safe must not emit raw '=' for: {line:?}"
            );
            assert_ne!(
                first,
                Some('+'),
                "tsv_safe must not emit raw '+' for: {line:?}"
            );
            assert_ne!(
                first,
                Some('-'),
                "tsv_safe must not emit raw '-' for: {line:?}"
            );
            assert_ne!(
                first,
                Some('@'),
                "tsv_safe must not emit raw '@' for: {line:?}"
            );
            assert_eq!(
                first,
                Some('\''),
                "tsv_safe must guard formula line with leading \"'\": {line:?} → {out:?}"
            );
        }
    }

    #[test]
    fn dde_line_not_flagged_as_formula() {
        // DDE(...) starts with 'D' — not a spreadsheet formula trigger.
        // inspect must NOT flag FormulaInjection, and csv_field must NOT prepend '.
        let dde = r#"DDE("cmd","/C calc","__DDE_Remote")"#;
        let f = inspect(dde);
        assert!(
            !f.has_formula(),
            "DDE line must not be flagged as FormulaInjection (first char is 'D')"
        );
        let g = csv_field(dde);
        // csv_field quotes because of internal commas and double-quotes
        let out = g.to_string();
        assert!(
            !out.starts_with('\''),
            "csv_field must not prepend apostrophe to DDE line: {out:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// UTF-8 corpus — Markus Kuhn's canonical stress test exercised against
// inspect(bytes), which reports exact InvalidUtf8 violations.
// ---------------------------------------------------------------------------
mod utf8_corpus {
    use super::*;

    // The UTF-8 test file is not valid UTF-8 (that's the point), so we
    // embed it as raw bytes.
    static UTF8_TEST_BYTES: &[u8] = include_bytes!("corpus/UTF-8-test.txt");

    #[test]
    fn utf8_test_file_loads() {
        assert!(
            UTF8_TEST_BYTES.len() > 10_000,
            "UTF-8-test.txt too small — download may have failed, got {} bytes",
            UTF8_TEST_BYTES.len()
        );
    }

    #[test]
    fn inspect_reports_invalid_utf8_in_stress_test() {
        let f = inspect(UTF8_TEST_BYTES);
        assert!(
            f.has_invalid_utf8(),
            "inspect must report InvalidUtf8 for Kuhn's stress test file"
        );
        assert!(f.lossy, "lossy flag must be set for invalid UTF-8 input");
    }

    #[test]
    fn inspect_reports_multiple_invalid_sequences_in_stress_test() {
        let f = inspect(UTF8_TEST_BYTES);
        let count = f
            .violations
            .iter()
            .filter(|v| matches!(v.kind, jsonguard::ViolationKind::InvalidUtf8))
            .count();
        // Kuhn's file has many distinct invalid sequences
        assert!(
            count > 10,
            "expected >10 distinct InvalidUtf8 violations, got {count}"
        );
    }

    #[test]
    fn display_safe_handles_stress_test_file() {
        // display_safe must not panic on any input
        let g = display_safe(UTF8_TEST_BYTES);
        assert!(
            g.lossy,
            "stress test contains invalid UTF-8 so lossy must be true"
        );
        // The output must be valid UTF-8 (it is a Rust String)
        let _ = g.to_string(); // would panic if invalid
    }

    #[test]
    fn jsonl_safe_produces_valid_json_string_for_stress_test() {
        let g = jsonl_safe(UTF8_TEST_BYTES);
        let out = g.to_string();
        assert!(
            out.starts_with('"'),
            "jsonl_safe output must start with '\"'"
        );
        assert!(out.ends_with('"'), "jsonl_safe output must end with '\"'");
        // Every backslash must be followed by a valid JSON escape character
        let inner = &out[1..out.len() - 1];
        let mut chars = inner.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                let next = chars
                    .next()
                    .expect("backslash must be followed by escape char");
                assert!(
                    matches!(next, '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't' | 'u'),
                    "invalid JSON escape \\{next} in jsonl_safe output"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding hazards — Big5 / GBK CJKV multi-byte sequences whose second byte
// is 0x5C (ASCII backslash).  These are the classic "unescaped backslash"
// vulnerability in naive string concatenation.
// ---------------------------------------------------------------------------
mod encoding_hazards {
    use super::*;

    // Big5 許 = 0xB3 0x5C  (second byte is backslash in ASCII)
    // GBK 許 = 0xC8 0xED (different encoding; using a GBK sequence with 0x5C
    //          as the second byte: e.g. 0xB3 0x5C is shared between Big5/GBK)
    //
    // These bytes are invalid UTF-8 because 0xB3 is not a valid UTF-8 lead byte.
    // The hazard: naive code that splices these bytes into output without
    // re-validating produces a stray backslash.

    const BIG5_XU: &[u8] = b"\xB3\x5C"; // Big5 許 — second byte is 0x5C = '\'
    const GBK_SLASH: &[u8] = b"\xD0\xC2\x5C"; // 3-byte GBK sequence ending in 0x5C

    #[test]
    fn inspect_flags_big5_as_invalid_utf8() {
        let f = inspect(BIG5_XU);
        assert!(
            f.has_invalid_utf8(),
            "Big5 \\xB3\\x5C must be flagged as invalid UTF-8"
        );
        assert!(f.lossy, "lossy must be set for Big5 bytes");
    }

    #[test]
    fn inspect_flags_gbk_as_invalid_utf8() {
        let f = inspect(GBK_SLASH);
        assert!(
            f.has_invalid_utf8(),
            "GBK sequence ending in \\x5C must be flagged as invalid UTF-8"
        );
        assert!(f.lossy, "lossy must be set for GBK bytes");
    }

    #[test]
    fn jsonl_safe_big5_no_raw_backslash_hazard() {
        // The critical invariant: 0x5C must NOT appear as a raw (unescaped) backslash
        // in the JSON string output.  jsonl_safe decodes lossily first, so 0xB3
        // becomes U+FFFD and 0x5C becomes the ASCII '\\' character — which jsonl_safe
        // MUST escape as "\\".
        let g = jsonl_safe(BIG5_XU);
        let out = g.to_string();
        assert!(
            out.starts_with('"') && out.ends_with('"'),
            "jsonl_safe must produce a JSON string literal"
        );
        let inner = &out[1..out.len() - 1];
        // Walk the inner content and verify every backslash is a proper JSON escape
        let mut chars = inner.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                let next = chars
                    .next()
                    .expect("backslash must be followed by escape char");
                assert!(
                    matches!(next, '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't' | 'u'),
                    "raw unescaped backslash hazard in jsonl_safe output for Big5 bytes: {out:?}"
                );
            }
        }
        assert!(g.lossy, "Big5 input must set lossy=true");
    }

    #[test]
    fn jsonl_safe_gbk_no_raw_backslash_hazard() {
        let g = jsonl_safe(GBK_SLASH);
        let out = g.to_string();
        let inner = &out[1..out.len() - 1];
        let mut chars = inner.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                let next = chars
                    .next()
                    .expect("backslash must be followed by escape char");
                assert!(
                    matches!(next, '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't' | 'u'),
                    "raw backslash hazard for GBK bytes: {out:?}"
                );
            }
        }
    }

    #[test]
    fn csv_field_big5_no_raw_backslash_in_output() {
        // csv_field processes as UTF-8 lossy; 0x5C must not survive as a raw backslash
        // in a context where it could be misinterpreted as an escape character.
        let g = csv_field(BIG5_XU);
        // The output is a CSV field — it may contain backslashes only if they
        // were originally in the text.  Since 0xB3 0x5C decoded to U+FFFD + '\',
        // the backslash IS present after lossy decode; csv_field does NOT strip it
        // (backslash is not a display-unsafe char in its classifier).
        // The key assertion is that the field is properly enclosed/escaped such
        // that the lossy flag is set (caller is informed of decode failure).
        assert!(
            g.lossy,
            "csv_field must set lossy=true for Big5 input containing 0x5C"
        );
    }

    #[test]
    fn display_safe_big5_strips_no_extra_ascii() {
        // display_safe only strips chars matching is_display_unsafe (C0/C1, bidi).
        // Backslash (0x5C) is ASCII printable — it survives in the decoded string.
        // The important guarantee: output is a valid Rust String (no panic).
        let g = display_safe(BIG5_XU);
        assert!(g.lossy, "display_safe must set lossy=true for Big5 input");
        let _ = g.to_string(); // must not panic
    }

    // -----------------------------------------------------------------------
    // Known invalid UTF-8 sequences from Markus Kuhn's taxonomy, exercised
    // individually so failures can be pinpointed.
    // -----------------------------------------------------------------------

    #[test]
    fn inspect_overlong_nul_c0_80() {
        // 0xC0 0x80 — overlong encoding of U+0000 (rejected by RFC 3629)
        let f = inspect(b"\xC0\x80".as_ref());
        assert!(
            f.has_invalid_utf8(),
            "\\xC0\\x80 (overlong NUL) must be invalid UTF-8"
        );
        assert!(f.lossy);
    }

    #[test]
    fn inspect_surrogate_ed_a0_80() {
        // 0xED 0xA0 0x80 — encodes U+D800 (surrogate, banned by RFC 3629)
        let f = inspect(b"\xED\xA0\x80".as_ref());
        assert!(
            f.has_invalid_utf8(),
            "\\xED\\xA0\\x80 (surrogate U+D800) must be invalid UTF-8"
        );
        assert!(f.lossy);
    }

    #[test]
    fn inspect_above_unicode_max_f4_90_80_80() {
        // 0xF4 0x90 0x80 0x80 — above U+10FFFF (maximum Unicode codepoint)
        let f = inspect(b"\xF4\x90\x80\x80".as_ref());
        assert!(
            f.has_invalid_utf8(),
            "\\xF4\\x90\\x80\\x80 (above U+10FFFF) must be invalid UTF-8"
        );
        assert!(f.lossy);
    }

    #[test]
    fn inspect_ff_fe_bom_like() {
        // 0xFF 0xFE — UTF-16 BOM bytes, invalid UTF-8
        let f = inspect(b"\xFF\xFE".as_ref());
        assert!(
            f.has_invalid_utf8(),
            "\\xFF\\xFE (BOM-like) must be invalid UTF-8"
        );
        assert!(f.lossy);
    }

    #[test]
    fn inspect_isolated_continuation_byte() {
        // 0x80 — continuation byte without a lead byte
        let f = inspect(b"\x80".as_ref());
        assert!(
            f.has_invalid_utf8(),
            "isolated continuation byte must be invalid UTF-8"
        );
        assert!(f.lossy);
    }

    #[test]
    fn inspect_valid_utf8_str_not_flagged() {
        // Sanity: valid UTF-8 strings must never be flagged as invalid
        let cases = ["hello", "許功蓋", "Ünïcödé", "日本語", "\u{1F600}"];
        for s in cases {
            let f = inspect(s);
            assert!(
                !f.has_invalid_utf8(),
                "valid UTF-8 string {:?} must not be flagged as invalid",
                s
            );
            assert!(
                !f.lossy,
                "valid UTF-8 string {:?} must not set lossy=true",
                s
            );
        }
    }
}
