#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

// Re-enable std for the test harness (no_std crates still link std when `cargo test` runs).
#[cfg(test)]
extern crate std;

mod guard_input;
#[cfg(feature = "alloc")]
mod inspect;
mod text;
mod types;

#[cfg(feature = "alloc")]
pub use guard_input::GuardInput;
#[cfg(feature = "alloc")]
pub use inspect::inspect;
#[cfg(feature = "alloc")]
pub use text::{
    bytes_to_utf8_lossy_safe, cap_display, csv_field, display_safe, jsonl_safe, tsv_safe,
};
#[cfg(feature = "alloc")]
pub use types::{DecodedStr, Findings, Guarded, Violation, ViolationKind};
