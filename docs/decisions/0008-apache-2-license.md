# 8. Apache-2.0 license (relicensed from MIT)

Date: 2026-07-24
Status: Accepted

## Context

jsonguard was originally published under the MIT license (git `d5091d7` seeded the
crate with an MIT `LICENSE`). The SecurityRonin forensic fleet later standardized on
**Apache-2.0** for its **explicit patent grant** — a protection MIT lacks — and the
fleet README/licensing standard treats the Apache-2.0 badge linking to `LICENSE` as
the single source of truth (no `## License` prose section). Any residual MIT repos
are to be migrated.

## Decision

Relicense the crate to **Apache-2.0**: replace the `LICENSE` file with the verbatim
Apache-2.0 text, set `license = "Apache-2.0"` in `Cargo.toml`, and update the README
badge accordingly. Do not add a `## License` section — the badge → `LICENSE` is the
single source of truth.

Evidence: git `2fee66d` ("relicense MIT → Apache-2.0 (fleet standard)"), which states
the patent-grant rationale and touches `Cargo.toml`, `LICENSE`, and `README.md`; git
`0b3726e` ("use verbatim Apache-2.0 license text"); `Cargo.toml`
`license = "Apache-2.0"`.

## Consequences

- Downstream users receive Apache-2.0's explicit patent grant, aligning jsonguard
  with the rest of the fleet's licensing.
- The relicense is a one-time, deliberate change recorded in git history; the crate
  was single-owner at the time, so the change carried no third-party-contributor
  consent complication.
- The README carries the Apache-2.0 badge and no prose license section, per the
  fleet README standard.
