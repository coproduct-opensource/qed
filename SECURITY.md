# Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting:

https://github.com/coproduct-opensource/qed/security/advisories/new

Please do not open a public issue, pull request or discussion about a
vulnerability before it is fixed. There is no email address for reports.

## In scope

- The contracts: `contracts/vault` and `contracts/board` (`NucleusVault3`,
  `BaseRegistry`, `NucleusBoard`), and their deployments listed in
  `README.md`.
- The proof programs and the acceptance rule: `contracts/proof-acceptance`,
  including the published binaries and the vendored Lean checker as used here.
- The agents: `contracts/agents` (buyer, seller, transports, proof of
  possession, A2A over iroh).
- The website generator and agent card: `contracts/site`.
- The Lean models in `proofs/commerce`, where a theorem does not say what the
  contracts do.

Out of scope: RISC Zero's prover, verifier contract and circuit data, Circle's
token, and iroh's relays, except where this code uses them wrongly. Report
problems in those projects to them.

## What helps

- What an attacker can do, to whom, and what it costs them.
- The contract, function or file, and the commit.
- A transaction, a test, or steps that show it. A failing test in the style of
  `contracts/vault-conformance` is the most useful form for a contract issue.

## What to expect

There is no bounty programme yet. The contracts are unaudited and immutable:
a fix to a deployed contract means a new deployment, and the record of the
issue stays public once it is fixed.
