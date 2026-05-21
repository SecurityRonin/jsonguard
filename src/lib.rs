#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

// Re-enable std for the test harness (no_std crates still link std when `cargo test` runs).
#[cfg(test)]
extern crate std;

mod guard_input;
mod types;

pub use guard_input::GuardInput;
#[cfg(feature = "alloc")]
pub use types::{DecodedStr, Guarded};
