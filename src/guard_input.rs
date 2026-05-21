#[cfg(feature = "alloc")]
use alloc::string::String;

mod private {
    pub trait Sealed {}
    impl Sealed for &str {}
    impl Sealed for &[u8] {}
    impl<const N: usize> Sealed for &[u8; N] {}
    #[cfg(feature = "alloc")]
    impl Sealed for &alloc::string::String {}
}

#[cfg(feature = "alloc")]
pub trait GuardInput: private::Sealed {
    fn as_utf8_lossy(&self) -> (String, bool);
    fn raw_bytes(&self) -> Option<&[u8]>;
}

#[cfg(feature = "alloc")]
impl GuardInput for &str {
    fn as_utf8_lossy(&self) -> (String, bool) {
        (String::from(*self), false)
    }
    fn raw_bytes(&self) -> Option<&[u8]> { None }
}

#[cfg(feature = "alloc")]
impl GuardInput for &[u8] {
    fn as_utf8_lossy(&self) -> (String, bool) {
        use alloc::borrow::Cow;
        let cow = String::from_utf8_lossy(self);
        let lossy = matches!(cow, Cow::Owned(_));
        (cow.into_owned(), lossy)
    }
    fn raw_bytes(&self) -> Option<&[u8]> { Some(*self) }
}

// Allows callers to pass `&my_string` where `my_string: String` directly.
#[cfg(feature = "alloc")]
impl GuardInput for &alloc::string::String {
    fn as_utf8_lossy(&self) -> (String, bool) {
        ((*self).clone(), false)
    }
    fn raw_bytes(&self) -> Option<&[u8]> { None }
}

// Allows callers to pass `b"literal"` (which has type `&[u8; N]`) directly.
#[cfg(feature = "alloc")]
impl<const N: usize> GuardInput for &[u8; N] {
    fn as_utf8_lossy(&self) -> (String, bool) {
        use alloc::borrow::Cow;
        let cow = String::from_utf8_lossy(*self);
        let lossy = matches!(cow, Cow::Owned(_));
        (cow.into_owned(), lossy)
    }
    fn raw_bytes(&self) -> Option<&[u8]> { Some(*self) }
}

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
        // 許 in Big5 = 0xB3 0x5C. In Big5, 0x5C is the second byte of the character (no
        // backslash intended by the source). But when decoded as UTF-8:
        //   - 0xB3 is an invalid lead byte → replaced by U+FFFD
        //   - 0x5C is standalone valid ASCII → becomes '\' (backslash)
        // The decode is lossy (U+FFFD was inserted). The resulting string contains '\',
        // but that's fine — downstream sanitizers (jsonl_safe etc.) work with Unicode chars
        // and will properly escape this backslash. The danger of byte-level escaping without
        // prior UTF-8 decode is avoided.
        let (text, lossy) = b"\xB3\x5C".as_utf8_lossy();
        assert!(lossy);
        assert!(text.contains('\u{FFFD}')); // invalid lead byte replaced
        assert!(text.contains('\\')); // 0x5C survived as ASCII '\' — to be escaped downstream
    }
}
