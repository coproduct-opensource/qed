# What each piece commits to

A summary for readers of the code. The sources and the Lean models are the
definition; where this page and they differ, they are right.

## Statement, artifact, policy

- A **statement** is a `lean4export` NDJSON export that ends by declaring
  `Nucleus.Claim : Prop`. The buyer writes it.
- An **artifact** is the bytes a seller appends: more declarations, among
  them a theorem or definition whose type is exactly `Nucleus.Claim`.
- A **policy** fixes the statement's SHA-256, the claim's name, the axioms the
  checker may admit, and a size limit for the artifact. Its hash is in the
  order.

A statement and an artifact may also be given in **export v2**, a binary
encoding of the same export, one record per NDJSON line. The order program
`704bdf3b…42ed` (and the earlier build `fbfdc68c…0081`) reads either form; a policy for it pins the SHA-256 of the v2
bytes. `export_v2_from_ndjson` (in `contracts/proof-acceptance/core`) converts
a Lean export, so anyone can recompute that hash from Lean's own output.

The acceptance rule (`contracts/proof-acceptance/core`): the statement is the
one pinned; the statement followed by the artifact passes the Lean checker
with only the permitted axioms; the artifact declares no axiom; and it
contains a proof of the claim.

## Order

`contracts/vault/src/NucleusVault3.sol`, reference
`crates/nucleus-proof-commerce/src/vault.rs`. An order names buyer, seller,
token, amount, verifier contract, proof program (image ID), policy hash, an
optional base library, a funding deadline, a delivery deadline, a salt and a
context. Its EIP-712 digest under the vault's domain (name `NucleusVault`,
version `3`, chain ID, vault address) identifies it everywhere.

The buyer agrees to an order by signing one EIP-3009
`receiveWithAuthorization` for the token: from the buyer, to the vault, for
the order's amount, valid until the funding deadline, with the order's digest
as its nonce. The token contract checks that signature. Nothing else is
signed.

## Vault

Model: `proofs/commerce/Vault3.lean`.

- `fund(order, authorization)`: pulls the deposit with that authorization.
  Refused if the order is malformed, the funding deadline has passed, the
  delivery deadline is more than the vault's maximum term away, or fee plus
  royalty would exceed the fee cap.
- `settle(order, artifact, seal)`: before the delivery deadline, asks the
  order's verifier whether `seal` proves that the order's program committed
  the journal `(tag, chain ID, vault, order digest, keccak256(artifact))`. If
  so it books the seller's share, the fee, and any royalty.
- `refund(order)`: after the delivery deadline, books the deposit to the
  buyer.
- `claim(payee, token)`: pays a payee everything booked for it in one token.

Nothing is paid out except by `claim`, so a payee the token refuses to pay
blocks only its own claim. Any account may call any of the four.

## Proof program

`contracts/proof-acceptance/zkvm/methods`. Given a chain ID, a vault, an
order, a policy, a statement and an artifact, it checks that the policy is the
one the order commits to, runs the acceptance rule, and commits the journal
above. It is a RISC Zero guest; the on-chain verifier is RISC Zero's Groth16
verifier.

## Board

`contracts/board/src/NucleusBoard.sol`, model `proofs/commerce/Board.lean`. A
post is an event carrying the task's terms. The board names one vault, holds
no funds, and records only who posted a task and whether it was withdrawn.

## Between the agents

x402 v2 objects with scheme `nucleus-vault`, carried over iroh (QUIC,
authenticated by node keys) or HTTP. Every request carries a DPoP proof signed
by the sender's P-256 key and bound to the method, the target, a time window,
a one-time identifier and the sender's node ID; the receiver compares that
node ID with the one the connection authenticated. The order's `context`
binds the task and the buyer's key.

## Base libraries

An order may name a base: the SHA-256 of a prefix of the statement that is by
itself a complete export. If a registry lists that base, a base program has
proved that the prefix type-checks, the order's proof may skip type-checking
it, and the registered payee is booked a royalty within the fee cap. The first
valid registration of a base wins, and its payee and rate are inside the
base program's proof. The registries listed in `README.md` hold test entries
whose payees are the authors' own keys.

