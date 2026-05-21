#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use crate::guard_input::GuardInput;
#[cfg(feature = "alloc")]
use crate::types::{DecodedStr, Guarded};

#[cfg(feature = "alloc")]
pub fn bytes_to_utf8_lossy_safe(bytes: &[u8]) -> DecodedStr {
    use alloc::borrow::Cow;
    let cow = String::from_utf8_lossy(bytes);
    let lossy = matches!(cow, Cow::Owned(_));
    DecodedStr { text: cow.into_owned(), lossy }
}

fn is_display_unsafe(c: char) -> bool {
    matches!(c,
        '\u{0000}'..='\u{001F}'
        | '\u{007F}'
        | '\u{0080}'..='\u{009F}'
        | '\u{200E}' | '\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}'
        | '\u{061C}'
    )
}

fn is_bidi(c: char) -> bool {
    matches!(c,
        '\u{200E}' | '\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}'
        | '\u{061C}'
    )
}

#[cfg(feature = "alloc")]
pub fn display_safe<I: GuardInput>(input: I) -> Guarded {
    let (text, lossy) = input.as_utf8_lossy();
    let value: String = text.chars().filter(|&c| !is_display_unsafe(c)).collect();
    Guarded { value, lossy }
}

#[cfg(feature = "alloc")]
pub fn cap_display<I: GuardInput>(input: I, max_chars: usize) -> Guarded {
    let (text, lossy) = input.as_utf8_lossy();
    let safe: String = text.chars().filter(|&c| !is_display_unsafe(c)).collect();
    let value = if safe.chars().count() > max_chars {
        let truncated: String = safe.chars().take(max_chars).collect();
        alloc::format!("{truncated}\u{2026}")
    } else {
        safe
    };
    Guarded { value, lossy }
}

#[cfg(feature = "alloc")]
pub fn tsv_safe<I: GuardInput>(input: I) -> Guarded {
    let (text, lossy) = input.as_utf8_lossy();
    let cleaned: String = text.chars().filter_map(|c| match c {
        '\t' | '\n' | '\r' => Some(' '),
        c if is_display_unsafe(c) => None,
        c => Some(c),
    }).collect();
    let value = match cleaned.chars().next() {
        Some('=' | '+' | '-' | '@') => alloc::format!("'{cleaned}"),
        _ => cleaned,
    };
    Guarded { value, lossy }
}

fn needs_csv_quoting(s: &str) -> bool {
    s.chars().any(|c| matches!(c, ',' | '"' | '\n' | '\r'))
}

#[cfg(feature = "alloc")]
pub fn csv_field<I: GuardInput>(input: I) -> Guarded {
    let (text, lossy) = input.as_utf8_lossy();
    // Preserve \n and \r (they trigger RFC 4180 quoting); strip everything else unsafe.
    let cleaned: String = text.chars().filter(|&c| {
        if matches!(c, '\n' | '\r') { return true; }
        !is_display_unsafe(c)
    }).collect();
    let guarded = match cleaned.chars().next() {
        Some('=' | '+' | '-' | '@') => alloc::format!("'{cleaned}"),
        _ => cleaned,
    };
    let value = if needs_csv_quoting(&guarded) {
        let escaped = guarded.replace('"', "\"\"");
        alloc::format!("\"{escaped}\"")
    } else {
        guarded
    };
    Guarded { value, lossy }
}

#[cfg(feature = "alloc")]
pub fn jsonl_safe<I: GuardInput>(input: I) -> Guarded {
    let (text, lossy) = input.as_utf8_lossy();
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"'     => out.push_str("\\\""),
            '\\'    => out.push_str("\\\\"),
            '\x08'  => out.push_str("\\b"),
            '\t'    => out.push_str("\\t"),
            '\n'    => out.push_str("\\n"),
            '\x0C'  => out.push_str("\\f"),
            '\r'    => out.push_str("\\r"),
            '\u{0000}'..='\u{0007}' | '\u{000B}' | '\u{000E}'..='\u{001F}' => {
                out.push_str(&alloc::format!("\\u{:04x}", c as u32));
            }
            '\u{007F}'..='\u{009F}' => {
                out.push_str(&alloc::format!("\\u{:04x}", c as u32));
            }
            c if is_bidi(c) => {
                out.push_str(&alloc::format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    Guarded { value: out, lossy }
}

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
    fn tsv_safe_bytes_invalid_utf8_lossy_with_formula_guard() {
        let g = tsv_safe(b"=\xFF".as_ref());
        assert!(g.to_string().starts_with("'="));
        assert!(g.lossy);
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
        // say "hi" → each " doubled → "say ""hi""
        // Raw string can't end with " inside r#"..."#, so use regular string escaping.
        let g = csv_field(r#"say "hi""#);
        assert_eq!(g.to_string(), "\"say \"\"hi\"\"\"");
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

    #[test]
    fn csv_field_bytes_invalid_utf8_lossy() {
        let g = csv_field(b"\xFF\xFE hello".as_ref());
        assert!(g.lossy);
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
    fn jsonl_safe_bytes_big5_becomes_replacement_chars() {
        // Big5 bytes decoded lossy BEFORE JSON escaping.
        // 0x5C byte must NOT survive as a raw backslash.
        let g = jsonl_safe(b"\xB3\x5C".as_ref());
        assert!(g.lossy);
        let s = g.to_string();
        assert!(s.starts_with('"') && s.ends_with('"'),
            "output must be a valid JSON string literal");
        let inner = &s[1..s.len()-1];
        let mut chars = inner.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                let next = chars.next().expect("backslash must be followed by escape char");
                assert!(
                    matches!(next, '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't' | 'u'),
                    "invalid escape sequence \\{next}"
                );
            }
        }
    }

    #[test]
    fn jsonl_safe_empty_string() {
        let g = jsonl_safe("");
        assert_eq!(g.to_string(), r#""""#);
    }
}
