# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.4](https://github.com/SecurityRonin/jsonguard/compare/jsonguard-v0.2.3...jsonguard-v0.2.4) - 2026-07-25

### Documentation

- reverse-write PRD + ADRs; mkdocs excludes governance docs (fleet standard)
- add MkDocs site with privacy/terms (fleet standard)
- use verbatim Apache-2.0 license text

### Fixed

- *(vet)* declare own crates first-party so version bumps don't break supply-chain audit
- *(ci)* apply cargo fmt to satisfy fmt --check gate
