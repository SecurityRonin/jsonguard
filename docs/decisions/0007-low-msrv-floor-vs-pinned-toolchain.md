# 7. Low published MSRV floor (1.75) decoupled from the pinned dev toolchain (1.96.0)

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV & toolchain policy (`~/src/ronin-issen/CLAUDE.md` inheriting
`CLAUDE.core.md`) separates two distinct things: the **dev toolchain** (what
contributors and CI build/fmt/clippy with — pinned to the current stable,
fleet-wide) and the **declared MSRV** (`rust-version` — a downstream-facing
compatibility promise). For **published libraries**, the declared MSRV is kept
**low and CI-verified** (e.g. 1.75 / 1.80) as a deliberate compatibility feature and
trust signal; it is raised only when the crate genuinely needs a newer-Rust feature.

jsonguard is a published library (a widely-linked leaf, ADR 1), so it is exactly the
case where a low MSRV is a feature: an outside consumer or a fleet crate on an older
toolchain must be able to link it.

## Decision

- Declare **`rust-version = "1.75"`** in `Cargo.toml` — the low, downstream-facing
  MSRV floor.
- Pin the **dev toolchain to the current fleet stable, `1.96.0`**, in
  `rust-toolchain.toml`, with `clippy` and `rustfmt` declared as components there
  (the single source of truth, so CI and local agree).

The two numbers are intentionally different: develop and lint on 1.96.0, but only
*promise* 1.75. The crate uses no post-1.75 language feature, so the low floor is a
real, honorable guarantee, not an aspiration.

Evidence: `Cargo.toml` `rust-version = "1.75"`; `rust-toolchain.toml`
`channel = "1.96.0"`, `components = ["clippy", "rustfmt"]`; git `e4f05e9`
("pin toolchain to 1.96.0 (fleet toolchain policy)").

## Consequences

- Consumers on Rust 1.75+ can depend on jsonguard; raising the MSRV later is a
  near-breaking change requiring an explicit reason (a genuinely-needed newer
  feature), not a drift to match the toolchain.
- Contributors get a single, consistent dev toolchain (1.96.0) with fmt/clippy
  behavior fixed, ending "which Rust am I on" churn.
- The MSRV floor should be CI-verified with a dedicated low-MSRV job so the promise
  stays real; the pinned toolchain must be bumped deliberately and fleet-wide, never
  by silently raising this crate's floor.
