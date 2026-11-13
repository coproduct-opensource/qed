# Contributing

Issues and pull requests are welcome. For a vulnerability, use `SECURITY.md`
instead.

## Before a pull request

- Tooling is Rust. Please do not add shell scripts, Python or JavaScript build
  steps; a command with branching or exit-code handling belongs in a Rust
  binary or test.
- Every crate you touch passes `cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings` and `cargo test --locked`, as
  `.github/workflows/ci.yml` runs them. If you change `proofs/commerce`,
  `lake build` passes there.
- A new check comes with a test that fails without it. Say in the pull
  request how you made it fail.

## Changes that change identities

Some changes alter what an order, a proof or a contract means:

- anything the proof programs link (`contracts/proof-acceptance/core`, the
  vendored checker, `crates/nucleus-proof-commerce` outside its wire module)
  changes the programs' image IDs;
- the contracts are immutable once deployed;
- the order format and journals are shared by contracts, programs and agents.

For these, open an issue first with the semantics written down: what changes,
what stays true, and which Lean model or theorem changes with it. Code follows
the written change. A new program ID also means new published binaries,
re-proved test fixtures, and for a base program a new registry.

## Licence

By contributing you agree that your contribution is licensed under MIT OR
Apache-2.0, as the rest of the repository.
