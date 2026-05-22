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
    pub kind: ViolationKind,
    pub byte_offset: usize,
    pub char: Option<char>,
}

#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct Findings {
    pub violations: alloc::vec::Vec<Violation>,
    pub lossy: bool,
}

#[cfg(feature = "alloc")]
impl Findings {
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }

    pub fn has_formula(&self) -> bool {
        self.violations
            .iter()
            .any(|v| matches!(v.kind, ViolationKind::FormulaInjection))
    }

    pub fn has_bidi(&self) -> bool {
        self.violations
            .iter()
            .any(|v| matches!(v.kind, ViolationKind::BidiOverride))
    }

    pub fn has_controls(&self) -> bool {
        self.violations
            .iter()
            .any(|v| matches!(v.kind, ViolationKind::ControlChar))
    }

    pub fn has_invalid_utf8(&self) -> bool {
        self.violations
            .iter()
            .any(|v| matches!(v.kind, ViolationKind::InvalidUtf8))
    }

    pub fn is_csv_safe(&self) -> bool {
        !self.violations.iter().any(|v| match &v.kind {
            ViolationKind::FormulaInjection => true,
            ViolationKind::BidiOverride => true,
            ViolationKind::InvalidUtf8 => true,
            ViolationKind::ControlChar => !matches!(v.char, Some('\n') | Some('\r')),
        })
    }

    pub fn is_tsv_safe(&self) -> bool {
        self.is_clean()
    }

    pub fn is_jsonl_safe(&self) -> bool {
        !self.violations.iter().any(|v| {
            matches!(
                v.kind,
                ViolationKind::BidiOverride
                    | ViolationKind::ControlChar
                    | ViolationKind::InvalidUtf8
            )
        })
    }

    pub fn is_display_safe(&self) -> bool {
        self.is_jsonl_safe()
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use std::prelude::v1::*;
    use std::vec;

    #[test]
    fn guarded_display_emits_value() {
        let g = Guarded {
            value: "hello".to_string(),
            lossy: false,
        };
        assert_eq!(g.to_string(), "hello");
    }

    #[test]
    fn guarded_lossy_flag_accessible() {
        let g = Guarded {
            value: "x".to_string(),
            lossy: true,
        };
        assert!(g.lossy);
    }

    #[test]
    fn decoded_str_display_emits_text() {
        let d = DecodedStr {
            text: "world".to_string(),
            lossy: false,
        };
        assert_eq!(d.to_string(), "world");
    }

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
        let f = Findings {
            violations: Vec::new(),
            lossy: false,
        };
        assert!(f.violations.is_empty());
        assert!(!f.lossy);
    }

    #[test]
    fn findings_lossy_flag() {
        let f = Findings {
            violations: Vec::new(),
            lossy: true,
        };
        assert!(f.lossy);
    }

    // Helper used across Tasks 2 and 3
    fn v(kind: ViolationKind, byte_offset: usize, ch: Option<char>) -> Violation {
        Violation {
            kind,
            byte_offset,
            char: ch,
        }
    }

    fn findings(vs: Vec<Violation>) -> Findings {
        Findings {
            violations: vs,
            lossy: false,
        }
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

    #[test]
    fn csv_safe_false_for_control_char_none() {
        // char: None on ControlChar treated conservatively as unsafe (not \n or \r)
        assert!(!findings(vec![v(ViolationKind::ControlChar, 0, None)]).is_csv_safe());
    }

    #[test]
    fn csv_safe_false_when_formula_alongside_permitted_newline() {
        // mixed: \n is permitted but = is not — overall result must be false
        assert!(!findings(vec![
            v(ViolationKind::ControlChar, 5, Some('\n')),
            v(ViolationKind::FormulaInjection, 0, Some('=')),
        ])
        .is_csv_safe());
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
        assert!(
            !findings(vec![v(ViolationKind::BidiOverride, 5, Some('\u{202E}'))]).is_jsonl_safe()
        );
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
        assert!(
            !findings(vec![v(ViolationKind::BidiOverride, 0, Some('\u{061C}'))]).is_display_safe()
        );
    }

    #[test]
    fn display_safe_false_for_control() {
        assert!(!findings(vec![v(ViolationKind::ControlChar, 0, Some('\x7F'))]).is_display_safe());
    }

    #[test]
    fn display_safe_false_for_invalid_utf8() {
        assert!(!findings(vec![v(ViolationKind::InvalidUtf8, 0, None)]).is_display_safe());
    }
}
