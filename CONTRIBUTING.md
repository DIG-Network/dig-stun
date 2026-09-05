# Contributing to dig-stun

## Issues

Open an issue describing what you observed, what you expected, and how to reproduce it. For anything
touching address classification, include the exact address and the family it was observed over — this
crate's defects are almost always about a representation nobody enumerated.

**Do not open a public issue for a security defect that is still unfixed.** Report it privately to the
maintainers instead.

## Code

- `SPEC.md` is normative. A behaviour change that leaves it describing the old behaviour is incomplete.
- Every change is a PR to `main`; `main` is protected and takes squash merges only.
- Conventional Commits (`feat:`, `fix:`, `docs:`, …), enforced in CI.
- Bump the version in `Cargo.toml` as the last step before merge, and justify the SemVer choice.
- TDD: a failing test first, and check the test **count** — a filter that matches nothing exits 0 and
  prints `0 passed; N filtered out`, which reads exactly like success.
- Run what CI runs before pushing: `cargo fmt --all -- --check`, `cargo clippy --all-targets
  --all-features --locked -- -D warnings`, `cargo test --workspace --all-targets --all-features
  --locked`.

## The one rule specific to this crate

**Never add a second address-range table.** If a caller needs a different question answered about an
address, add a predicate derived from `Scope` here — do not re-implement the ranges elsewhere. Two
tables that disagree is how `192.88.99.0/24` came to be refused by one guard and accepted by another.
