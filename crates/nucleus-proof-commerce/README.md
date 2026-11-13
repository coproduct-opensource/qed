# nucleus-proof-commerce

Verifies bilateral EIP-712 agreement on an immutable funding order. It does not
move or verify money. `AgreedOrder` is private-constructor, non-Clone and
non-Deserialize evidence of both wallet signatures; it is not a confirmed
deposit, proof of acceptance, transport authentication or a one-shot payment
capability. Repeating agreement verification is allowed. Canonical funding
authorization consumption must happen at the eventual settlement boundary.

Each order commits the complete FundingOrder type exposed by `ORDER_TYPE`:
buyer/seller, asset, uint256 atomic amount, request/policy/verifier hashes,
treasury/fee/epoch, funding nonce, funding/delivery deadlines, and both clients'
key bindings. The EIP-712 domain is NucleusProofCommerce version1, selected chain
ID and escrow contract. Selected deployment asset, treasury, verifier, fee and
epoch must match; the verified witness retains that protocol snapshot.

Wallet signatures use secp256k1 recovery through k256, canonical low-s and
v27/28. No personal-sign fallback, unknown version or EIP-1271 smart-contract
wallet support is implied. This is the EOA agreement profile; strict x402
authorization, fresh role-bound DPoP, chain receipt verification, finality and
replay consumption remain separate required checks. Public configuration does
not authorize activating a deployment, and successful agreement does not fund
an order.

`amounts` computes full-uint256 accepted/refund allocation data with checked
arithmetic. Ceil fees use a quotient/remainder decomposition to avoid overflowing
amount×rate. Agreement admission refuses trades whose rounded fee exceeds the
configured effective cap; thus the minimum atomic fee cannot silently violate
that cap. No production rate or minimum trade size is selected.

Current validation: eight tests and a sealed-constructor compile-fail test,
including the independent official EIP-712 Mail
signature vector, both real wallet signatures, all16committed fields, chain and
escrow separation, wrong roles, expiry, fee redirection, zero amount, bad deadline
ordering, high-s and noncanonical v rejection. Strict all-target Clippy passes.
Replacing the request hash in the signed encoding with a repeated policy hash
makes the field-binding regression fail exit101; restoration passes.

The Lean model lives in `proofs/commerce` (`lake build`, Lean4.34.1). It includes full-term
acceptance indexing, funding configuration, bilateral and confirmed-transfer
premises, unified funding/settlement history, terminal position preservation,
canonical nonce admission, and fee decomposition/bounds. Its external verification
predicates are not implemented by this crate, and Lean-to-Rust correspondence
has not been established. See `docs/rfcs/proof-gated-x402-commerce.md` for the
complete goal, evidence and missing settlement path.
