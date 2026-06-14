//! Serde-serializable safe JSON string wrapper (`feature = "serde"`).
//!
//! `serde_json` escapes C0 control characters (`< 0x20`) losslessly as `\u00XX`,
//! but passes bidirectional overrides, the C1 controls, and DEL through
//! literally — so an attacker-controlled string emitted via `serde_json::json!`
//! can still carry a terminal-spoofing override into the JSON output. [`JsonSafe`]
//! closes that gap structurally: it is the type, not a function the caller must
//! remember to invoke.

use alloc::string::String;
use serde::{Serialize, Serializer};

/// Codepoints `serde_json` renders literally but that are unsafe to display:
/// DEL, the C1 controls, and the bidirectional overrides. C0 controls (`< 0x20`)
/// are intentionally excluded — `serde_json` already escapes them losslessly.
fn is_json_display_unsafe(c: char) -> bool {
    matches!(c,
        '\u{007F}'
        | '\u{0080}'..='\u{009F}'
        | '\u{200E}' | '\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}'
        | '\u{061C}'
    )
}

/// A `&str` that serializes as a JSON string with terminal-spoofing codepoints
/// neutralized.
///
/// Bidi overrides, C1 controls, and DEL are replaced with `U+FFFD` (the Unicode
/// replacement character) so the count and position of scrubbed characters
/// survive as a visible tamper marker; C0 controls are left for the serializer
/// to escape losslessly. Wrap any attacker-controlled string going into JSON so
/// the safety is structural — a caller composing `serde_json::json!` cannot
/// forget to sanitize it.
#[derive(Debug, Clone, Copy)]
pub struct JsonSafe<'a>(pub &'a str);

impl Serialize for JsonSafe<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // STUB (RED): passthrough — does not yet neutralize anything.
        serializer.serialize_str(self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn clean_string_passes_through_unchanged() {
        let j = serde_json::to_string(&JsonSafe("System")).unwrap();
        assert_eq!(j, "\"System\"");
    }

    #[test]
    fn bidi_override_is_neutralized_to_replacement_char() {
        // U+202E RIGHT-TO-LEFT OVERRIDE in an EPROCESS ImageFileName.
        let j = serde_json::to_string(&JsonSafe("ev\u{202e}il.exe")).unwrap();
        assert!(!j.contains('\u{202e}'), "bidi override must not survive: {j}");
        assert!(j.contains('\u{FFFD}'), "scrubbed char marked with U+FFFD: {j}");
        // The output is still parseable JSON with exactly one marker.
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(
            v.as_str().unwrap().chars().filter(|&c| c == '\u{FFFD}').count(),
            1
        );
    }

    #[test]
    fn c1_and_del_are_neutralized() {
        let j = serde_json::to_string(&JsonSafe("a\u{0085}b\u{007f}c")).unwrap();
        assert!(!j.contains('\u{0085}'), "C1 NEL must not survive: {j}");
        assert!(!j.contains('\u{007f}'), "DEL must not survive: {j}");
    }

    #[test]
    fn c0_control_is_left_for_serde_to_escape_losslessly() {
        // serde_json escapes a tab as \t — lossless, no replacement needed.
        let j = serde_json::to_string(&JsonSafe("a\tb")).unwrap();
        assert_eq!(j, "\"a\\tb\"");
    }
}
