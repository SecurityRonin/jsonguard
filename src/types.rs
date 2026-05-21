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
}
