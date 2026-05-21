#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use crate::guard_input::GuardInput;
#[cfg(feature = "alloc")]
use crate::types::{Findings, Violation, ViolationKind};

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
    use std::prelude::v1::*;
    use std::vec;
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
