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

#[cfg(test)]
mod tests {
    use std::prelude::v1::*;
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
}
