# 1. jsonguard is a single-crate utility leaf, not a reader/analyzer split

Date: 2026-07-24
Status: Accepted

## Context

The SecurityRonin fleet standardizes format repos on the reader/analyzer
(`core/` + `forensic/`) two-crate split and the Pattern-A / Pattern-B crate-naming
grammar (`~/src/ronin-issen/CLAUDE.md` → "Crate-structure standard" and "Crate
naming grammar"). Those patterns exist for repos that *decode an artifact format*:
a `<x>-core` reader and a `<x>-forensic` anomaly auditor.

jsonguard is a different kind of thing. The fleet constitution places it in the
KNOWLEDGE layer and describes it as an "output-sanitization utility leaf: RFC-4180
CSV / formula-injection guard, bidi/control stripping, serde `JsonSafe<'_>`;
cross-cutting (memf uses it for safe CLI output) — **not a forensic format
reader**." It parses no evidence container, navigates no address space, and emits
no `forensicnomicon::report::Finding`. It transforms untrusted strings/bytes into
output that is safe for a target sink (CSV, TSV, JSONL, a terminal, serde JSON) and
passively inspects input for dangerous patterns.

The repo confirms this shape: a single `Cargo.toml` with `name = "jsonguard"` and
no `[workspace]`, one flat `src/` (`guard_input.rs`, `text.rs`, `inspect.rs`,
`serde_safe.rs`, `types.rs`, `lib.rs`) — no `core/` or `forensic/` members.

## Decision

Ship jsonguard as **one crate** named `jsonguard`, with no reader/analyzer split
and no role-suffixed sibling crates. The crate name is the bare product name
because it is a self-contained, self-describing utility (it claims its own
crates.io namespace without a `-core`/`-forensic` qualifier).

The core/forensic split and the Pattern-A/B naming grammar **do not apply** here:
there is no format to read and no anomaly audit to separate out. Modules divide the
crate by concern instead — `guard_input` (input abstraction), `text` (sanitizers),
`inspect` (passive inspection), `serde_safe` (serde integration), `types` (return
types) — not by crate.

## Consequences

- Consumers depend on one crate (`jsonguard = "0.2"`) and get every sanitizer,
  the inspector, and the serde wrapper behind feature flags — no multi-crate
  wiring.
- The repo is exempt from the fleet's `-core`/`-forensic` realignment tracking; it
  is neither a container, filesystem, paging, log, nor parser repo.
- If a future need arises to separate, e.g., the byte-scanning primitives from the
  serde integration, that would be a deliberate split decided in a later ADR — it
  is intentionally not pre-built (YAGNI).
