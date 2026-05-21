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
}
