# The published proof programs

An order names the RISC Zero program whose proof releases its payment by image
ID. Each ID is computed from the binary, so anyone can check it without
building:

    nucleus-acceptance-host vault3-image-of FILE

The prover host embeds the third-form and base binaries and builds neither, so
a seller needs no RISC-V toolchain.

| file | ID file | image ID | SHA-256 of the file | what it proves |
|---|---|---|---|---|
| `nucleus-order-fmt2r.bin` | `IMAGE_ID_ORDER_FMT2R` | `704bdf3b650500801060d74c132acabbf3a01ef4c12445e656acab94d59142ed` | `5782c9f11b18a89d578314cff35b34452dd457e95973004e511feb0cd67cf91e` | as `nucleus-order-fmt2.bin`; bases committed by `nucleus-base-check-fmt2r.bin` only. **Reproducible**: `verify-programs` rebuilds these bytes |
| `nucleus-base-check-fmt2r.bin` | `IMAGE_ID_BASE_FMT2R` | `4e332565d72709224bbeeea36b92e6b8dab0c1a10e5d7aaf437789011357d440` | `a66caa75d21213558c09189fddf1c4915dae872ffe5b313e714a76350da062ce` | as `nucleus-base-check-fmt2.bin`. **Reproducible** |
| `nucleus-vault3-acceptance.bin` | `IMAGE_ID_VAULT3` | `fc879ae401564b093abb0dbe9a1d9f0d883020ec2a09b58791efcf73360440bb` | `85242aed4fa19657bd0497464ffb82a4fc37275a09315fd1c6aebfbe36c76b42` | a `NucleusVault3` order's delivery is accepted; for an order naming a base, on a verified commitment of the base program for that base and the order's axioms, with the base's declarations parsed and not re-checked |
| `nucleus-base-check.bin` | `IMAGE_ID_BASE` | `67bddd199136658cc6552facce96be32647c42ee44a10c54e79a0e1f4beccd3a` | `cfb3cade2615690311a3a8957c614d481c7f0c94c7aa90935d65e48377abd377` | a base library (a complete Lean export) parses and type-checks under a stated list of axioms; commits base id, axioms hash, payee and rate |
| `nucleus-vault-acceptance.bin` | `IMAGE_ID` | `f0f882fe7052e1ac22f7fec033e12c6874e1b5f72ae31f31bd8b939576fba1ca` | `5db02defbe1a6b0b55df95c524f40b858981e9934546b2182bb37497ba521f74` | a `NucleusVault2` order's delivery is accepted (the second form, live on Base) |
| `nucleus-order-fmt2.bin` | `IMAGE_ID_ORDER_FMT2` | `fbfdc68c5125272b354262386489e9e3bb44bc63f1b89850e244788cfe190081` | `a69d2abf7f93241720779d08da7dd3a593ebf1e2faa6ff54d62922acffd3c177` | as `nucleus-vault3-acceptance.bin`, reading the export once and in place, as NDJSON or as export v2; an order without a base is parsed once; bases committed by `nucleus-base-check-fmt2.bin` only |
| `nucleus-base-check-fmt2.bin` | `IMAGE_ID_BASE_FMT2` | `84309d9365584b89f0dbd269bd31d448d336b8da4ca714c23a9d90127a968237` | `feaa9a81f9165ac1c8030ab134a303a12c494de46e56c100f9c4435129361a07` | as `nucleus-base-check.bin`, reading the base as NDJSON or export v2 |

**The `-fmt2r` pair is current** (owner decision 2026-11-13, the switch to
reproducible programs; `docs/rfcs/qed-reproducible-switch-2026-11-13.md`). It
is the same source as the `-fmt2` pair except for the base program ID the
order guest names, built in RISC Zero's pinned builder image, so anyone can
rebuild it: `nucleus-acceptance-host verify-programs` (recipe
`REPRODUCIBLE`) rebuilds both guests and requires the recorded IDs and these
exact bytes. The Arbitrum Sepolia deployment of 2026-11-13 (registry, vault
and board of the switch) names it. Host commands `order2r-` and `base2r-`;
a seller's default (`proofProgram` absent or `"fmt2r"`).

**The `-fmt2` pair is retiring.** Statement format v2
(`docs/rfcs/proof-commerce-statement-format-v2-2026-11-13.md`), built with
the macOS guest toolchain; nobody can rebuild it elsewhere. The Base mainnet
deployment and its standing bounty name it until the mainnet switch, so it
stays published and the host keeps `order2-` and `base2-` (`proofProgram`
`"fmt2"`). On Arbitrum Sepolia it is retired: its registry, vault and board
stay on chain, unused. Its source is commit `a0cfceb2a`. The earlier third-form pair
(`fc879ae4…`, `67bddd19…`) stays published because testnet contracts and
posted tasks name it; its source is commit `37bc16b7d`.

Superseded and never deployed: the first `-fmt2` pair, order
`a453ccbbd4ea8312932a0d51395dde7ad07dc539f3ed63c2b2af9b9faec466a5` and base
`18276e7a7df4d2618c908c9a4ab8d66b56719f70c71b5a4947621d55e8f9985d` (source
at commit `293125ee3`). No contract, registry or posted task ever named them;
their files were replaced in place by the optimized pair.

Host commands: `vault3-*` for the order program, `base-*` for the base
program. `vault3-prove INPUT RECEIPT BASE_RECEIPT` proves an order naming a
base on the base program's succinct receipt. The `vault-*` commands for the
second form exist only in a host built with `--features second-form`.

## Built without the builder's paths (2026-11-13)

The two third-form binaries were rebuilt on 2026-11-13 so that they do not
carry the login name, home directory or checkout path of the machine that
built them (`docs/rfcs/proof-commerce-program-rebuild-2026-11-13.md`). Rust
records source paths in panic locations; those strings are loaded data and so
part of the image. `zkvm/methods/build.rs` now remaps them for every guest
build, and `zkvm/host/tests/paths.rs` scans the published binaries.

What still appears in them: four paths under `/Users/administrator/.cargo/`
from RISC Zero's prebuilt guest standard library, and, in the kernel half of
each file, RISC Zero's kernel's own build paths. Those are RISC Zero's, and
are in every program built with that toolchain.

The programs they replace are retired from this tree. Their IDs remain in the
records, and contracts on Arbitrum Sepolia that name them remain on chain:

| retired image ID | what it was | source at commit |
|---|---|---|
| `52fcab1102b1b0d7ab75010f3c3836b8cc7397dc9238f6523f931d58d1c55439` | third form, no bases | `00547d192` |
| `c24fc74fcab6075694d7fef64d056b96d8ff982af1de794d6681f3274081c0df` | third form with bases | `c99084e06` |
| `6fbdc98409a42f255b314f9bd62624b422c72d378c025313edbd9c045cb68443` | base program | `c99084e06` |

## The second-form program

`nucleus-vault-acceptance.bin` was built before that rule and does contain
such paths. It cannot be rebuilt to the same image ID, and that ID is the one
the settled order on Base names. So the file stays in this repository
unchanged, the prover host embeds it only with `--features second-form`, and
it is left out of a public release (`contracts/release/BOUNDARY`).

Its source is this tree at commit `c4f020370`
(`contracts/proof-acceptance/zkvm/methods/vault` there). The crates it links
have changed since, so a build at HEAD is a different program and no test
here rebuilds it. What is still checked at HEAD: its recorded ID is the ID of
the file (host test, with the feature); the encoder still writes the input
layout it reads (`core/tests/vault_program.rs`); and the vault test settles on
its real seal.

## Rebuilding from source (2026-11-13)

`nucleus-acceptance-host verify-programs` rebuilds the guests inside RISC
Zero's guest builder image, named by digest in `REPRODUCIBLE`, and compares
the image IDs and the published bytes (exit 0 match, 1 mismatch, 2 could not
run). It runs under `--runtime docker` or Apple `--runtime container`.

    cd contracts/proof-acceptance/zkvm && cargo build --release --locked -p nucleus-acceptance-host && cd -
    contracts/proof-acceptance/zkvm/target/release/nucleus-acceptance-host verify-programs --runtime docker --commit HEAD

The `-fmt2r` pair is what it rebuilds (Intel and AMD x86-64 VMs and a Mac
under Rosetta built byte-identical ELFs;
`docs/rfcs/qed-reproducible-programs-2026-11-13.md`). The other published IDs
here do **not** reproduce that way: the fmt2 pair's source builds to
`4e332565…d440` / `b2cab783…9fec` and the earlier third-form pair to
`96ec2ec6…2d38` / `5bf03472…e4bb`. They were built with the macOS guest
toolchain, whose output depends on the host compiler and the checkout path.

The `/Users/administrator/` paths described below come from the macOS build
of the guest toolchain only. Programs built in the Linux image carry none.

## What an ID does and does not give you

- An ID is a fact about the loaded program image. It is not a hash of the
  file: bytes that are never loaded (the file's last byte, for one) can change
  without changing the ID.
- That a binary does what `zkvm/methods/vault3`, `zkvm/methods/base` and their
  dependencies say rests on the source build. For the `-fmt2r` pair anyone
  can check that with `verify-programs` (above), on any x86-64 machine or
  under faithful translation. That the order program names the base program
  published beside it is a separate check: the host's test
  `the_order_guest_source_names_the_published_reproducible_base_program`.
- **Native builds do not reproduce across checkout paths or host
  toolchains.** The same commit built natively from a second directory on the
  same Mac gave different bytes and IDs (measured 2026-11-13). Source paths
  are remapped, but the compiler's per-crate symbol hashes still depend on
  where a path dependency lives. That is why the published pair is built in
  the pinned image, where the source is always at `/src`.
- Changing any non-wire code of `crates/nucleus-proof-commerce`, or
  `contracts/proof-acceptance/core`, or the vendored checker, changes both
  third-form IDs.
- Inside the third-form programs SHA-256 of the statement and of a base is
  the zkVM's own accelerated SHA-256.
