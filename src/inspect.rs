#[cfg(feature = "alloc")]
use crate::guard_input::GuardInput;
#[cfg(feature = "alloc")]
use crate::types::{Findings, Violation, ViolationKind};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
fn is_bidi(c: char) -> bool {
    matches!(c,
        '\u{200E}' | '\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}'
        | '\u{061C}'
    )
}

#[cfg(feature = "alloc")]
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

    // Detect invalid UTF-8 sequences with exact byte offsets from the original bytes.
    // Only available for &[u8] input — raw_bytes() returns None for &str (always valid UTF-8).
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
    // A spreadsheet discards leading whitespace before parsing a cell, so the
    // character that reaches the formula parser is the first *non-discardable*
    // one — not necessarily the first character. Detecting it in this loop
    // (rather than in a pre-pass) keeps `violations` ordered by byte offset.
    let mut lead_in_pending = true;

    for ch in text.chars() {
        if lead_in_pending && !matches!(ch, ' ' | '\t' | '\r' | '\n') {
            lead_in_pending = false;
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

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::types::ViolationKind;
    use std::prelude::v1::*;

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
        let v = f
            .violations
            .iter()
            .find(|v| matches!(v.kind, ViolationKind::FormulaInjection))
            .unwrap();
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
        let v = f
            .violations
            .iter()
            .find(|v| matches!(v.kind, ViolationKind::BidiOverride))
            .unwrap();
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
        let v = f
            .violations
            .iter()
            .find(|v| matches!(v.kind, ViolationKind::ControlChar))
            .unwrap();
        assert_eq!(v.byte_offset, 1);
        assert_eq!(v.char, Some('\0'));
    }

    #[test]
    fn inspect_detects_c0_control() {
        let f = inspect("a\x01b");
        assert!(f.has_controls());
        let v = f
            .violations
            .iter()
            .find(|v| matches!(v.kind, ViolationKind::ControlChar))
            .unwrap();
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
        let v = f
            .violations
            .iter()
            .find(|v| matches!(v.kind, ViolationKind::ControlChar))
            .unwrap();
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
        let v = f
            .violations
            .iter()
            .find(|v| matches!(v.kind, ViolationKind::InvalidUtf8))
            .unwrap();
        assert_eq!(v.byte_offset, 0);
        assert!(v.char.is_none());
    }

    #[test]
    fn inspect_bytes_multiple_invalid_sequences() {
        // Two separate invalid sequences
        let f = inspect(b"\xFF hello \xFE".as_ref());
        let invalid: Vec<_> = f
            .violations
            .iter()
            .filter(|v| matches!(v.kind, ViolationKind::InvalidUtf8))
            .collect();
        assert_eq!(invalid.len(), 2);
        assert_eq!(invalid[0].byte_offset, 0);
        assert_eq!(invalid[1].byte_offset, 8); // \xFF(1) + " hello "(7) = offset 8
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

    /// A formula lead-in hidden behind discardable leading whitespace must be
    /// reported, or `is_csv_safe()` hands the caller a false clean verdict on a
    /// value that will execute on import.
    #[test]
    fn inspect_flags_formula_behind_leading_whitespace() {
        for pad in ["\r", "\n", "\t", " ", "\r\n", "  "] {
            for lead in ['=', '+', '-', '@'] {
                let s = alloc::format!("{pad}{lead}1+1");
                let f = inspect(s.as_str());
                assert!(
                    f.has_formula(),
                    "inspect missed {lead:?} behind {pad:?} in {s:?}"
                );
                assert!(
                    !f.is_csv_safe(),
                    "is_csv_safe passed {lead:?} behind {pad:?} in {s:?}"
                );
            }
        }
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

    /// `is_csv_safe()` is the verdict a caller trusts before emitting a value
    /// raw. A lead-in that survives the control-character filter must not buy
    /// a clean verdict — Unicode `White_Space` and General_Category `Cf` both
    /// sit outside a `{space, tab, CR, LF}` set.
    #[test]
    fn inspect_detects_formula_behind_unicode_whitespace() {
        for pad in [
            "\u{00A0}", // NO-BREAK SPACE
            "\u{1680}", // OGHAM SPACE MARK
            "\u{2000}", // EN QUAD
            "\u{2003}", // EM SPACE
            "\u{2028}", // LINE SEPARATOR
            "\u{2029}", // PARAGRAPH SEPARATOR
            "\u{202F}", // NARROW NO-BREAK SPACE
            "\u{205F}", // MEDIUM MATHEMATICAL SPACE
            "\u{3000}", // IDEOGRAPHIC SPACE
        ] {
            for lead in ['=', '+', '-', '@'] {
                let s = alloc::format!("{pad}{lead}1+1");
                let f = inspect(s.as_str());
                assert!(
                    f.has_formula(),
                    "inspect missed {lead:?} behind {pad:?} in {s:?}"
                );
                assert!(!f.is_csv_safe(), "inspect called {s:?} CSV-safe");
            }
        }
    }

    #[test]
    fn inspect_detects_formula_behind_invisible_format_chars() {
        for pad in [
            "\u{00AD}",  // SOFT HYPHEN
            "\u{180E}",  // MONGOLIAN VOWEL SEPARATOR
            "\u{200B}",  // ZERO WIDTH SPACE
            "\u{200C}",  // ZERO WIDTH NON-JOINER
            "\u{200D}",  // ZERO WIDTH JOINER
            "\u{2060}",  // WORD JOINER
            "\u{FEFF}",  // ZERO WIDTH NO-BREAK SPACE (BOM)
            "\u{E0020}", // TAG SPACE
        ] {
            for lead in ['=', '+', '-', '@'] {
                let s = alloc::format!("{pad}{lead}1+1");
                let f = inspect(s.as_str());
                assert!(
                    f.has_formula(),
                    "inspect missed {lead:?} behind {pad:?} in {s:?}"
                );
                assert!(!f.is_csv_safe(), "inspect called {s:?} CSV-safe");
            }
        }
    }

    /// The lead-in scan still ends at the first visible character, and the
    /// reported offset is the lead-in's own, not the pad's.
    #[test]
    fn inspect_visible_lead_in_ends_the_scan() {
        assert!(!inspect("x\u{00A0}=1+1").has_formula());
        let f = inspect("\u{00A0}=1+1");
        let v = f
            .violations
            .iter()
            .find(|v| v.kind == ViolationKind::FormulaInjection)
            .expect("formula violation");
        assert_eq!(v.char, Some('='));
        assert_eq!(v.byte_offset, "\u{00A0}".len());
    }
}
