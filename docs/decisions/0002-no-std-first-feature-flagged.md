# 2. no_std-first with alloc-gated APIs and granular feature flags

Date: 2026-07-24
Status: Accepted

## Context

jsonguard is a leaf dependency meant to be linked widely across the fleet
(memf uses it for safe CLI output) and potentially by outside consumers in
constrained environments. A leaf that unconditionally pulls in `std` forces that
cost onto every downstream, including embedded or `no_std` contexts that could
otherwise use the pure-computation sanitizers.

At the same time the crate's value comes from returning owned, transformed strings
(`Guarded { value: String }`, `Cow`-based lossy decode), which require an
allocator. So the crate needs allocation for its real API but should not require
the full `std` runtime.

## Decision

Make the crate **`no_std` by default, gated up in layers**:

- `lib.rs` declares `#![cfg_attr(not(feature = "std"), no_std)]` and pulls
  `extern crate alloc` only under `feature = "alloc"`.
- **`alloc`** (the default feature) enables the `Cow<'_, str>` / `String` return
  types — the real sanitizer and inspector API. Everything meaningful is gated on
  `alloc`.
- **`std`** implies `alloc` and currently adds nothing beyond it (the Cargo.toml
  comment says so); it is reserved for future `std::error::Error` and `Write`
  impls, none of which exist yet.
- **`serde`** (implies `alloc`) is the one capability feature that gates real
  code today — the `JsonSafe<'_>` wrapper in `src/serde_safe.rs` (see ADR 6).
- **`nosql`** and **`binary`** are reserved placeholder feature flags: they imply
  `alloc` but gate no code in `src/` yet (no `feature = "nosql"` or
  `feature = "binary"` items exist). Their Cargo.toml comments — NoSQL
  (MongoDB / Elasticsearch / Redis) and binary-format (BSON / MessagePack /
  Protocol Buffers) advisories — describe intended future scope, not shipped
  behavior. **`full` = std + nosql + binary** rolls them up.

Evidence: `Cargo.toml` `[features]` block (whose header comment reads "std adds
nothing yet"); `src/lib.rs` `cfg_attr`, the `#[cfg(feature = "alloc")]` gating on
every re-export, and `src/serde_safe.rs` under `#[cfg(feature = "serde")]`. No
`std::error::Error` impl and no `nosql`/`binary`-gated item is present in `src/`.

## Consequences

- A `no_std` consumer can use the crate with `default-features = false,
  features = ["alloc"]` (documented in the README install section) and gets the
  sanitizers without `std`.
- `serde` support is optional, so consumers that never emit serde JSON pay no
  `serde` dependency cost — consistent with the crate's leaf role.
- The `alloc` gate means the crate could, in principle, expose a small
  zero-allocation surface for `no_std`-without-`alloc` targets later; today the
  useful API is allocation-based and `alloc` is on by default, so the common path
  is batteries-included while the constrained path is available on request.
- Trade-off: nearly every public item is `#[cfg(feature = "alloc")]`, which adds
  cfg noise to the source. Accepted as the cost of the portability guarantee.
