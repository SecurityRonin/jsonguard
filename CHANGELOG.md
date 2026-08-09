# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.8](https://github.com/SecurityRonin/jsonguard/compare/jsonguard-v0.2.7...jsonguard-v0.2.8) - 2026-08-09

### Fixed

- *(gitignore)* unanchor the target rule so nested cargo projects are ignored

## [0.2.7](https://github.com/SecurityRonin/jsonguard/compare/jsonguard-v0.2.6...jsonguard-v0.2.7) - 2026-08-07

### Documentation

- backtick General_Category, which clippy::doc_markdown denies

## [0.2.6](https://github.com/SecurityRonin/jsonguard/compare/jsonguard-v0.2.5...jsonguard-v0.2.6) - 2026-08-06

### Fixed

- *(lints)* backtick General_Category so clippy -D warnings passes

### Other

- adopt the canonical lints block

## [0.2.5](https://github.com/SecurityRonin/jsonguard/compare/jsonguard-v0.2.4...jsonguard-v0.2.5) - 2026-08-02

### Fixed

- key the formula guard on the first visible character ([#5](https://github.com/SecurityRonin/jsonguard/pull/5))

### Other

- bump anyhow to 1.0.104 (RUSTSEC-2026-0190) ([#3](https://github.com/SecurityRonin/jsonguard/pull/3))

## [0.2.4](https://github.com/SecurityRonin/jsonguard/compare/jsonguard-v0.2.3...jsonguard-v0.2.4) - 2026-07-25

### Documentation

- reverse-write PRD + ADRs; mkdocs excludes governance docs (fleet standard)
- add MkDocs site with privacy/terms (fleet standard)
- use verbatim Apache-2.0 license text

### Fixed

- *(vet)* declare own crates first-party so version bumps don't break supply-chain audit
- *(ci)* apply cargo fmt to satisfy fmt --check gate
