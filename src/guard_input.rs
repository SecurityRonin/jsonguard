#[cfg(test)]
mod tests {
    use std::prelude::v1::*;
    use super::*;

    #[test]
    fn str_input_not_lossy() {
        let (text, lossy) = "hello".as_utf8_lossy();
        assert_eq!(text, "hello");
        assert!(!lossy);
    }

    #[test]
    fn bytes_valid_utf8_not_lossy() {
        let (text, lossy) = b"hello".as_utf8_lossy();
        assert_eq!(text, "hello");
        assert!(!lossy);
    }

    #[test]
    fn bytes_invalid_utf8_is_lossy() {
        let (text, lossy) = b"\xFF\xFE".as_utf8_lossy();
        assert!(text.contains('\u{FFFD}'));
        assert!(lossy);
    }

    #[test]
    fn bytes_big5_0x5c_second_byte() {
        // 許 in Big5 = 0xB3 0x5C. 0x5C is ASCII backslash.
        // After UTF-8 lossy decode: Big5 is not valid UTF-8, so replacement chars.
        // The 0x5C byte does NOT survive as '\' in the decoded string.
        let (text, lossy) = b"\xB3\x5C".as_utf8_lossy();
        assert!(lossy);
        assert!(!text.contains('\\'));
    }
}
