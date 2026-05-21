#[cfg(feature = "alloc")]
use alloc::string::String;
use crate::types::DecodedStr;

#[cfg(test)]
mod tests {
    use std::prelude::v1::*;
    use super::*;

    // bytes_to_utf8_lossy_safe
    #[test]
    fn decode_valid_utf8_not_lossy() {
        let d = bytes_to_utf8_lossy_safe(b"hello");
        assert_eq!(d.text, "hello");
        assert!(!d.lossy);
    }

    #[test]
    fn decode_invalid_utf8_lossy() {
        let d = bytes_to_utf8_lossy_safe(b"\xFF\x80");
        assert!(d.lossy);
        assert!(d.text.contains('\u{FFFD}'));
    }

    #[test]
    fn decode_empty_bytes() {
        let d = bytes_to_utf8_lossy_safe(b"");
        assert_eq!(d.text, "");
        assert!(!d.lossy);
    }

    #[test]
    fn decode_valid_unicode() {
        let d = bytes_to_utf8_lossy_safe("許功蓋".as_bytes());
        assert_eq!(d.text, "許功蓋");
        assert!(!d.lossy);
    }

    #[test]
    fn decode_big5_bytes_are_lossy() {
        let d = bytes_to_utf8_lossy_safe(b"\xB3\x5C\xA6\x5C");
        assert!(d.lossy);
    }

    #[test]
    fn decode_display_works() {
        let d = bytes_to_utf8_lossy_safe(b"hello");
        assert_eq!(d.to_string(), "hello");
    }

    // display_safe
    #[test]
    fn display_safe_passthrough_normal_text() {
        let g = display_safe("hello world");
        assert_eq!(g.to_string(), "hello world");
        assert!(!g.lossy);
    }

    #[test]
    fn display_safe_strips_null_byte() {
        let g = display_safe("hel\x00lo");
        assert_eq!(g.to_string(), "hello");
    }

    #[test]
    fn display_safe_strips_c0_controls() {
        let g = display_safe("a\x01b\x1Fc");
        assert_eq!(g.to_string(), "abc");
    }

    #[test]
    fn display_safe_strips_bidi_rlo() {
        let g = display_safe("hello\u{202E}world");
        assert_eq!(g.to_string(), "helloworld");
    }

    #[test]
    fn display_safe_strips_c1_controls() {
        let g = display_safe("a\u{0085}b");
        assert_eq!(g.to_string(), "ab");
    }

    #[test]
    fn display_safe_preserves_unicode_text() {
        let g = display_safe("許功蓋 Ünïcödé");
        assert_eq!(g.to_string(), "許功蓋 Ünïcödé");
    }

    #[test]
    fn display_safe_bytes_input_invalid_utf8_lossy() {
        let g = display_safe(b"\xFF\xFE hello".as_ref());
        assert!(g.lossy);
        assert!(g.to_string().contains("hello"));
    }

    // cap_display
    #[test]
    fn cap_display_passthrough_short_text() {
        let g = cap_display("hi", 10);
        assert_eq!(g.to_string(), "hi");
    }

    #[test]
    fn cap_display_truncates_at_char_boundary() {
        let g = cap_display("hello world", 5);
        assert_eq!(g.to_string(), "hello\u{2026}");
    }

    #[test]
    fn cap_display_strips_unsafe_before_counting() {
        let g = cap_display("ab\u{202E}cd", 3);
        assert_eq!(g.to_string(), "abc\u{2026}");
    }

    #[test]
    fn cap_display_exact_length_no_ellipsis() {
        let g = cap_display("hello", 5);
        assert_eq!(g.to_string(), "hello");
    }

    #[test]
    fn cap_display_zero_limit() {
        let g = cap_display("hello", 0);
        assert_eq!(g.to_string(), "\u{2026}");
    }

    // tsv_safe
    #[test]
    fn tsv_safe_passthrough_normal() {
        let g = tsv_safe("hello world");
        assert_eq!(g.to_string(), "hello world");
        assert!(!g.lossy);
    }

    #[test]
    fn tsv_safe_replaces_tab_with_space() {
        let g = tsv_safe("col1\tcol2");
        assert_eq!(g.to_string(), "col1 col2");
    }

    #[test]
    fn tsv_safe_replaces_lf_with_space() {
        let g = tsv_safe("line1\nline2");
        assert_eq!(g.to_string(), "line1 line2");
    }

    #[test]
    fn tsv_safe_replaces_crlf_with_spaces() {
        let g = tsv_safe("row1\r\nrow2");
        assert_eq!(g.to_string(), "row1  row2");
    }

    #[test]
    fn tsv_safe_formula_injection_equals() {
        let g = tsv_safe("=SUM(A1:A10)");
        assert_eq!(g.to_string(), "'=SUM(A1:A10)");
    }

    #[test]
    fn tsv_safe_formula_injection_plus() {
        let g = tsv_safe("+1234");
        assert_eq!(g.to_string(), "'+1234");
    }

    #[test]
    fn tsv_safe_formula_injection_minus() {
        let g = tsv_safe("-1234");
        assert_eq!(g.to_string(), "'-1234");
    }

    #[test]
    fn tsv_safe_formula_injection_at() {
        let g = tsv_safe("@SUM");
        assert_eq!(g.to_string(), "'@SUM");
    }

    #[test]
    fn tsv_safe_no_formula_guard_midstring() {
        let g = tsv_safe("value=something");
        assert_eq!(g.to_string(), "value=something");
    }

    #[test]
    fn tsv_safe_strips_bidi_override() {
        let g = tsv_safe("hello\u{202E}world");
        assert_eq!(g.to_string(), "helloworld");
    }

    #[test]
    fn tsv_safe_strips_c0_nontab() {
        let g = tsv_safe("a\x01b");
        assert_eq!(g.to_string(), "ab");
    }

    #[test]
    fn tsv_safe_bytes_input() {
        let g = tsv_safe(b"=SUM\tval".as_ref());
        assert_eq!(g.to_string(), "'=SUM val");
        assert!(!g.lossy);
    }

    #[test]
    fn tsv_safe_unicode_preserved() {
        let g = tsv_safe("許功蓋");
        assert_eq!(g.to_string(), "許功蓋");
        assert!(!g.lossy);
    }

    // csv_field
    #[test]
    fn csv_field_passthrough_simple() {
        let g = csv_field("hello");
        assert_eq!(g.to_string(), "hello");
        assert!(!g.lossy);
    }

    #[test]
    fn csv_field_quotes_comma() {
        let g = csv_field("hello, world");
        assert_eq!(g.to_string(), r#""hello, world""#);
    }

    #[test]
    fn csv_field_doubles_internal_quotes() {
        let g = csv_field(r#"say "hi""#);
        assert_eq!(g.to_string(), r#""say ""hi"""#);
    }

    #[test]
    fn csv_field_quotes_newline() {
        let g = csv_field("line1\nline2");
        assert_eq!(g.to_string(), "\"line1\nline2\"");
    }

    #[test]
    fn csv_field_quotes_cr() {
        let g = csv_field("line1\rline2");
        assert_eq!(g.to_string(), "\"line1\rline2\"");
    }

    #[test]
    fn csv_field_formula_injection_bare() {
        let g = csv_field("=SUM(A1:A10)");
        assert_eq!(g.to_string(), "'=SUM(A1:A10)");
    }

    #[test]
    fn csv_field_formula_injection_with_comma() {
        let g = csv_field("=SUM(A1), total");
        assert_eq!(g.to_string(), r#""'=SUM(A1), total""#);
    }

    #[test]
    fn csv_field_formula_plus() {
        let g = csv_field("+1");
        assert_eq!(g.to_string(), "'+1");
    }

    #[test]
    fn csv_field_formula_minus() {
        let g = csv_field("-1");
        assert_eq!(g.to_string(), "'-1");
    }

    #[test]
    fn csv_field_formula_at() {
        let g = csv_field("@user");
        assert_eq!(g.to_string(), "'@user");
    }

    #[test]
    fn csv_field_strips_bidi() {
        let g = csv_field("hello\u{202E}world");
        assert_eq!(g.to_string(), "helloworld");
    }

    #[test]
    fn csv_field_strips_c0_not_newline() {
        let g = csv_field("a\x01b\nc");
        assert_eq!(g.to_string(), "\"ab\nc\"");
    }

    #[test]
    fn csv_field_obrien() {
        let g = csv_field("O'Brien");
        assert_eq!(g.to_string(), "O'Brien");
    }

    #[test]
    fn csv_field_obrien_with_comma() {
        let g = csv_field("O'Brien, Jr.");
        assert_eq!(g.to_string(), r#""O'Brien, Jr.""#);
    }

    #[test]
    fn csv_field_unicode_preserved() {
        let g = csv_field("許功蓋");
        assert_eq!(g.to_string(), "許功蓋");
        assert!(!g.lossy);
    }

    #[test]
    fn csv_field_empty_string() {
        let g = csv_field("");
        assert_eq!(g.to_string(), "");
    }

    // jsonl_safe
    #[test]
    fn jsonl_safe_wraps_in_quotes() {
        let g = jsonl_safe("hello");
        assert_eq!(g.to_string(), r#""hello""#);
        assert!(!g.lossy);
    }

    #[test]
    fn jsonl_safe_escapes_backslash() {
        let g = jsonl_safe(r#"C:\Users\foo"#);
        assert_eq!(g.to_string(), r#""C:\\Users\\foo""#);
    }

    #[test]
    fn jsonl_safe_escapes_double_quote() {
        let g = jsonl_safe(r#"say "hi""#);
        assert_eq!(g.to_string(), r#""say \"hi\"""#);
    }

    #[test]
    fn jsonl_safe_escapes_newline() {
        let g = jsonl_safe("line1\nline2");
        assert_eq!(g.to_string(), r#""line1\nline2""#);
    }

    #[test]
    fn jsonl_safe_escapes_tab() {
        let g = jsonl_safe("col1\tcol2");
        assert_eq!(g.to_string(), r#""col1\tcol2""#);
    }

    #[test]
    fn jsonl_safe_escapes_cr() {
        let g = jsonl_safe("row\r");
        assert_eq!(g.to_string(), r#""row\r""#);
    }

    #[test]
    fn jsonl_safe_escapes_c0_control_as_unicode() {
        let g = jsonl_safe("\x01");
        assert_eq!(g.to_string(), "\"\\u0001\"");
    }

    #[test]
    fn jsonl_safe_escapes_del_as_unicode() {
        let g = jsonl_safe("\x7F");
        assert_eq!(g.to_string(), "\"\\u007f\"");
    }

    #[test]
    fn jsonl_safe_escapes_c1_control_as_unicode() {
        let g = jsonl_safe("\u{0085}");
        assert_eq!(g.to_string(), "\"\\u0085\"");
    }

    #[test]
    fn jsonl_safe_escapes_bidi_rlo_as_unicode() {
        // U+202E: escaped as \uXXXX, NOT stripped — data preserved
        let g = jsonl_safe("hello\u{202E}world");
        assert_eq!(g.to_string(), "\"hello\\u202eworld\"");
    }

    #[test]
    fn jsonl_safe_preserves_unicode_text() {
        let g = jsonl_safe("許功蓋");
        assert_eq!(g.to_string(), r#""許功蓋""#);
        assert!(!g.lossy);
    }

    #[test]
    fn jsonl_safe_empty_string() {
        let g = jsonl_safe("");
        assert_eq!(g.to_string(), r#""""#);
    }
}
