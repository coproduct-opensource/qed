# The vault contract

`src/NucleusVault2.sol` is the one vault. Its bytes are what is deployed on
Base mainnet at `0x30f522bc30d46b3a4089931d698f04656fa23b8d` and on Arbitrum
Sepolia at `0xce8d925b542b4c4b1c2d34a81abe21e4c5da4681`, so the file and
`out/NucleusVault2.*` are not edited or renamed.

Its header comment names `proofs/commerce/VaultPull.lean` as the model. That
file was merged into **`proofs/commerce/Vault.lean`** on 2026-11-12; the comment
cannot be corrected without changing the compiled bytes.

Built with solc 0.8.38:

    solc --optimize --optimize-runs 200 --evm-version paris --bin --bin-runtime --abi -o out src/NucleusVault2.sol

`TestVerifier.sol` and `HostileToken.sol` are test-only and are never deployed
to a chain that carries value. Tests: `contracts/vault-conformance`.

The first form, `NucleusVault` (it paid the treasury inside `settle`), was
removed from the tree on 2026-11-12. It remains deployed, unused, on Arbitrum
Sepolia at `0xd968d5659b3c63cd74d7b4d09345ff3417711038`; its source is in git
history at `e84d9f4df`.

## The third form

`src/NucleusVault3.sol` (model `proofs/commerce/Vault3.lean`, record
`docs/rfcs/proof-commerce-third-vault-2026-11-12.md`) is a separate contract,
not an upgrade: the second form on Base is unaffected. Built with the same
flags; 7,521 bytes of runtime. `EmptyRegistry.sol` is the registry it is
deployed against for now. `TestRegistry.sol` and `TestWallet.sol` are
test-only. On Arbitrum Sepolia it is at
`0x8c39e81d642719bb1f1c61a6eb71305f6fa39a6b`. It is on no mainnet.
