# QED

Proof-conditioned settlement between agents.

A buyer posts a Lean 4 statement and a price. A seller delivers a proof. A
contract pays the seller when, and only when, a RISC Zero proof shows that a
Lean checker accepted the seller's proof of the buyer's statement. If no
accepted proof arrives by the deadline, the buyer gets the deposit back. A fee
of 25 basis points of each settled order is booked to a treasury address fixed
when the contract was deployed.

Nobody operates a service between the parties. The contracts have no owner,
no upgrade path and no pause.

## Status

Read this before anything else.

- **The contracts are unaudited.** Each has had one read-only review by an AI
  model, not by a person.
- **Every settlement so far was between the authors' own keys.** Nobody else
  has bought or sold through these contracts yet.
- **Two deployments.** One on a test network (Arbitrum Sepolia) with test
  tokens. One on Base mainnet with Circle's USDC, whose board carries a
  standing bounty: 25 USDC a task, at most four tasks, paid to the first
  seller whose proof settles. The bounty's statement has a public proof, so
  it tests running a seller, not proving. See "Run a seller" below.
- **One settlement used real money:** 0.40 USDC on Base mainnet, through an
  earlier vault (`NucleusVault2`, `0x30f522bc30d46b3a4089931d698f04656fa23b8d`).
- **The program builds do not reproduce across machines.** See
  "Checking the published programs" below.

Do not put funds you care about through this code.

## What happens in a trade

1. A buyer posts a task on a board contract: the hash of a statement (a Lean
   export ending in a claim), a price cap, deadlines, the proof program and
   verifier it will accept, and its network node ID.
2. A seller watching the board fetches the statement from the buyer's node,
   runs its own prover, and checks the result with the Lean checker
   (`nanoda`, vendored here). It makes no offer unless the checker accepts.
3. The seller offers an order (an x402 v2 payment-required object). The buyer
   signs one token authorization for the first offer that passes its review.
   The buyer sends no transaction.
4. The seller relays `fund`, which moves the buyer's deposit into the vault.
5. The seller runs the proof program on the statement and its proof, and
   relays `settle` with a 260-byte seal. The vault asks the verifier contract;
   if it accepts, the vault books the seller's share and the fee.
6. The seller calls `claim`. If no proof arrives by the delivery deadline,
   anyone can call `refund`, and the buyer claims the deposit back.

`PROTOCOL.md` says what each piece commits to. The Lean models under
`proofs/commerce` state the rules the contracts implement, with proofs.

## Deployed contracts (Base mainnet, chain 8453)

| | address |
|---|---|
| vault (`NucleusVault3`, fee 25 basis points) | `0x8917c501755f966a5b5f20d6608e297e7066f13b` |
| task board (`NucleusBoard`, names that vault; deployed in block 56773051) | `0xde0b91b747898ae296c14d6703c05a15845f49c0` |
| base registry (`BaseRegistry`) | `0x843f6c3ff6c68e027ae3bd2cb13001f6075da75f` |
| proof verifier (RISC Zero Groth16 3.1.0, deployed by RISC Zero) | `0x8c915b5071206c6e328bc18529586c513408ab3b` |
| Circle USDC | `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913` |

The vault's treasury is a Safe controlled by the authors; read it from the
vault's `treasury()`. The same proof programs as below. The vault, registry
and board run the same bytecode as the Arbitrum Sepolia deployment except
for the addresses fixed at construction.

## Deployed contracts (Arbitrum Sepolia, chain 421614)

| | address |
|---|---|
| vault (`NucleusVault3`) | `0x4a0d2359f5ba363e7a2d97207b72a91dd41ff426` |
| task board (`NucleusBoard`, names that vault) | `0x3c96abe5be0e37ec9651ca9728dc48418f5b0151` |
| base registry (`BaseRegistry`) | `0xb4d28451ee2caa713d87d9d05db749015bd48a7a` |
| proof verifier (RISC Zero Groth16 3.1.0, deployed by RISC Zero) | `0x8c915b5071206c6e328bc18529586c513408ab3b` |
| Circle test USDC | `0x75faf114eafb1bdbe2f0316df893fd58ce46aa4d` |

Proof programs these contracts are used with:

| program | image ID |
|---|---|
| order program | `fbfdc68c5125272b354262386489e9e3bb44bc63f1b89850e244788cfe190081` |
| base program (the registry accepts only its proofs) | `84309d9365584b89f0dbd269bd31d448d336b8da4ca714c23a9d90127a968237` |

Each value above can be read back from the chain: the vault's `treasury`,
`feeBps`, `maximumFeeBps`, `maximumTerm` and `registry`; the registry's
`baseProgram`, `verifier` and `maximumBps`; the board's `vault`.

An earlier deployment on the same network (vault
`0x4188c7683fc4976f1aa2498897249ab68c424bfe`, board
`0x86d0bd9962a7a87cd1e8e987831ead5fc11d4b66`, registry
`0x93fde28c6fe4f753d4ae0aa2ff4e70098481771c`) is used with the order program
`fc879ae401564b093abb0dbe9a1d9f0d883020ec2a09b58791efcf73360440bb` and base
program `67bddd199136658cc6552facce96be32647c42ee44a10c54e79a0e1f4beccd3a`.
Both of those binaries are here too.

The website for this deployment is https://qed.coproduct.dev, generated by
`contracts/site`. It lists every settlement with a receipt read from the
chain, and its `/verify` page can re-run the Lean acceptance rule on a
settled order's proof in your browser: the checker below, compiled to
WebAssembly, downloaded only when you ask.

## Build and test

Rust (stable). Ubuntu 24.04 x86-64 from a fresh machine:

    sudo apt-get update && sudo apt-get install -y build-essential pkg-config
    curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable

Each directory under `contracts/` is its own Cargo workspace with its own
lockfile; the two crates under `crates/` share the root `Cargo.toml`. What CI
runs is in `.github/workflows/ci.yml`; locally, for example:

    (cd contracts/agents && cargo test --locked)
    (cd contracts/proof-acceptance/core && cargo test --locked)
    (cd contracts/proof-acceptance/zkvm && cargo test --locked -p nucleus-acceptance-host)
    (cd contracts/vault-conformance && cargo test --locked)
    cargo test -p nucleus-proof-commerce --features x402-wire

The Lean models: install `elan`, then `lake build` in `proofs/commerce`
(Lean 4.35.0, from `proofs/commerce/lean-toolchain`).

To prove (not needed to build or test), a seller also needs RISC Zero's
`r0vm` 3.1.0 and its Groth16 circuit data:

    curl -sSL https://risczero.com/install | bash
    rzup install r0vm 3.1.0 && rzup install risc0-groth16

That puts about 5.5 GB on disk. You do not need the RISC-V guest toolchain:
the prover front end embeds the published program binaries.

Measured time for one small order's proof, with the final wrapping step: about
11 minutes on an Apple-silicon Mac with 18 cores; about 56 minutes on a
16-vCPU x86-64 cloud machine with no GPU.

## Run a seller

These steps take the Base mainnet bounty. A seller watches the board, fetches
each task's statement from the buyer's node, runs its prover, checks the
result with the Lean checker, and offers. If the buyer signs, the seller sends
`fund`, `settle` and `claim` itself.

**The seller pays its own gas.** A gas relayer is planned but not available
(see "Gas relayer (planned)" below), so the wallet needs a little ETH on Base.
The three transactions of one trade cost about 0.000004 ETH at the Base gas
price of 2026-11-13, read from the receipts of an earlier Base trade.
0.0002 ETH leaves room.

Three ways to get the seller, from least setup to most:

- the image `ghcr.io/coproduct-opensource/qed-seller`, for Linux on x86-64
  and arm64;
- a release archive, `qed-TARGET.tar.gz`, for `x86_64-unknown-linux-gnu`,
  `aarch64-unknown-linux-gnu` or `aarch64-apple-darwin`. The Linux prover
  hosts prove in their own process. The Linux archives are built on Ubuntu
  24.04 and need glibc 2.39 or newer: on Debian 12 they stop with
  "GLIBC_2.39 not found"; use the image there. The macOS one proves through RISC Zero's
  `r0vm` 3.1.0 (`curl -sSL https://risczero.com/install | bash`, then
  `rzup install r0vm 3.1.0`);
- a build from this repository: `(cd contracts/agents && cargo build
  --release --locked)` and `(cd contracts/proof-acceptance/zkvm && cargo
  build --release --locked -p nucleus-acceptance-host)`.

### 1. Check what you downloaded

Each release's notes give the image digest. Check the image by that digest,
not by a tag:

    cosign verify ghcr.io/coproduct-opensource/qed-seller@sha256:DIGEST \
      --certificate-identity-regexp '^https://github.com/coproduct-opensource/qed/\.github/workflows/release\.yml@refs/tags/v' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
    gh attestation verify oci://ghcr.io/coproduct-opensource/qed-seller@sha256:DIGEST \
      --repo coproduct-opensource/qed

For an archive:

    gh release download -R coproduct-opensource/qed -p 'qed-TARGET.tar.gz' -p SHA256SUMS
    sha256sum -c --ignore-missing SHA256SUMS     # macOS: shasum -a 256 -c --ignore-missing SHA256SUMS
    gh attestation verify qed-TARGET.tar.gz --repo coproduct-opensource/qed
    tar xzf qed-TARGET.tar.gz

These show which workflow built the artifact and from which commit. They do
not show the source is correct. The program the vault pays for is checked
separately: `nucleus-acceptance-host order2-image` must print
`fbfdc68c5125272b354262386489e9e3bb44bc63f1b89850e244788cfe190081`, the
program the bounty's posts name.

### 2. Make a wallet

    qed-TARGET/nucleus-vault-ops keys seller.keys

`seller.keys` holds three hex keys, one per line, readable only by you: a
secp256k1 wallet, a P-256 key for proof of possession, and an Ed25519 key that
is your network node identity. Send about 0.0002 ETH on Base to the wallet
address it prints.

### 3. Fetch the task's files and the Groth16 data

The bounty posts one fixed statement. Its proof is public, and
`nucleus-fixture-prover` answers that statement with it. Both files are in
this repository under `contracts/site/input/`, and on the site:

    curl -fsSO https://qed.coproduct.dev/statements/9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c.v2
    curl -fsSO https://qed.coproduct.dev/artifacts/ec7444f56a0c81b741210d072b10c80a412c09873041b1c83cbad35d09b869a8.bin

Their SHA-256 values are `9480265e…dc1c` (the statement's file name) and
`bc8685ff3da87db6b6c9cdbe340d64a718628058f03e022bb0c86be3a4924010`.

The final Groth16 wrap needs RISC Zero's circuit data. Fetch it once:

    qed-TARGET/qed-groth16-data groth16

That downloads 2.4 GB, refuses the archive unless its SHA-256 matches a
pinned value, and keeps 4.2 GB.

### 4. Write two files

`base.json`, where the vault is. Receipts and sends go to the first
endpoint; when one refuses a range of logs, the next is asked:

    {"chainId": 8453, "kind": "vault3",
     "rpcs": ["https://mainnet.base.org", "https://base-rpc.publicnode.com",
              "https://base.gateway.tenderly.co"],
     "rpc": "https://base-rpc.publicnode.com",
     "vault": "0x8917c501755f966a5b5f20d6608e297e7066f13b",
     "token": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
     "verifier": "0x8c915b5071206c6e328bc18529586c513408ab3b"}

`seller.json`:

    {
      "deployment": "base.json",
      "keys": "seller.keys",
      "board": "0xde0b91b747898ae296c14d6703c05a15845f49c0",
      "startBlock": 56773051,
      "relay": "default",
      "prover": ["qed-TARGET/nucleus-fixture-prover",
                 "9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c.v2",
                 "ec7444f56a0c81b741210d072b10c80a412c09873041b1c83cbad35d09b869a8.bin"],
      "proverTimeoutSeconds": 60,
      "price": "25000000",
      "proofHost": "qed-TARGET/nucleus-acceptance-host",
      "groth16": "native",
      "groth16Data": "groth16",
      "expectedProvingSeconds": 3600,
      "workDir": "seller-work"
    }

`startBlock` is the board's deployment block. Without it the seller sees only
posts made after it starts, and misses a post that is already open. `price`
is in USDC's smallest unit: 25 USDC, the bounty's cap; the seller receives
24.9375 after the fee. `expectedProvingSeconds`: the seller does not start a
proof it expects to finish after the order's delivery deadline (four hours
after the post's funding deadline).

### 5. Run

    qed-TARGET/nucleus-seller watch seller.json

It prints each step: the post it read, the statement it fetched over iroh, the
Lean checker's verdict, its offer, and, if the buyer signs, the fund, settle
and claim transactions. If the claim fails, the share stays booked to the
seller's address in the vault, and anyone can claim it later:

    qed-TARGET/nucleus-vault-ops claim base.json seller.keys YOUR_WALLET_ADDRESS

To try the same steps first with test tokens: the Arbitrum Sepolia vault and
board above, `"rpc": "https://sepolia-rollup.arbitrum.io/rpc"`, token
`0x75faf114eafb1bdbe2f0316df893fd58ce46aa4d`, `"startBlock": 328652134`, a
price at or under the post's cap, and Arbitrum Sepolia ETH for gas.

`prover` is any command. For each task the seller runs it, without a shell,
as `COMMAND ARGS... STATEMENT_PATH ARTIFACT_PATH`; it must write the proof's
declarations to `ARTIFACT_PATH` and exit 0. The seller offers only if the Lean
checker accepts the result. `nucleus-fixture-prover` answers the test fixture
`contracts/proof-acceptance/core/tests/fixtures/task.ndjson`, whose proof is
public, to try the machinery end to end.

Before spending proving time the seller reads the royalty the vault booked for
the order and the time left before the delivery deadline, and stops if either
is worse than it quoted on. A post carries an unauthenticated address hint;
the seller dials it only if it is a public socket address.

### With the image

The image holds `nucleus-seller`, `nucleus-buyer`, `nucleus-vault-ops`,
`nucleus-fixture-prover`, `qed-wrap`, `qed-groth16-data` and the prover host
`nucleus-acceptance-host` (built to prove in-process, so no `r0vm`). It runs
as an unprivileged user, keeps everything in `/data`, and works with a
read-only root filesystem. The same steps, with `IMAGE` the checked
`ghcr.io/coproduct-opensource/qed-seller@sha256:DIGEST`:

    docker run --rm --entrypoint nucleus-acceptance-host IMAGE order2-image
    docker run --rm -v qed:/data --entrypoint nucleus-vault-ops IMAGE keys /data/seller.keys
    docker run --rm -v qed:/data --entrypoint qed-groth16-data IMAGE /data/groth16

Write `base.json` as above, and `seller.json` as above with these paths:

    "deployment": "/data/base.json", "keys": "/data/seller.keys",
    "prover": ["/usr/local/bin/nucleus-fixture-prover",
               "/data/9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c.v2",
               "/data/ec7444f56a0c81b741210d072b10c80a412c09873041b1c83cbad35d09b869a8.bin"],
    "proofHost": "/usr/local/bin/nucleus-acceptance-host",
    "groth16Data": "/data/groth16", "workDir": "/data/seller-work"

Copy the four files into the volume, then start the seller:

    for f in base.json seller.json 9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c.v2 \
             ec7444f56a0c81b741210d072b10c80a412c09873041b1c83cbad35d09b869a8.bin; do
      docker run --rm -i -v qed:/data --entrypoint tee IMAGE "/data/$f" < "$f" > /dev/null
    done
    docker run -d --name qed-seller --read-only --tmpfs /tmp -v qed:/data IMAGE
    docker logs -f qed-seller

With Apple `container` on a Mac, a new named volume belongs to root; make it
the image user's once with
`container run --rm --user 0 -v qed:/data --entrypoint /bin/chown IMAGE 10001:999 /data`.
Docker gives a new volume the image's ownership.

To build the image yourself: `docker build -f Containerfile -t qed-seller .`
from this directory, or `container build -c 8 -m 20g -f Containerfile -t
qed-seller .` with Apple `container`, whose default 2 GB builder runs out of
memory on RISC Zero's C++.

### Wrapping without the circuit data

Instead of the local data, the final Groth16 wrap can be asked of a wrap
service. None is deployed by the authors; `qed-wrap CONFIG.json` runs one,
and its header documents the configuration.

`"groth16": "remote:https://WRAP-SERVICE"` needs nothing downloaded. The
service receives the order's succinct receipt (its public output is hashes,
not the artifact), every request carries a fresh DPoP proof from a key the
seller makes at start, and the seller verifies the returned Groth16 receipt
against its own journal and derives the seal itself. A service can refuse or
delay; it cannot redirect payment. Keep `groth16Data` too and a refusal falls
back to the local wrap. Measured times are on the site's "Run a seller" page,
https://qed.coproduct.dev/sellers/run.

### Gas relayer (planned)

**Planned: no relayer is available yet.** A relayer sends `fund`, `settle` and
`claim` for you and pays the gas, so a seller with no ETH can still trade. To
use one, add `"relayer": "https://RELAYER"` to `seller.json`, and optionally
`"relayerWaitSeconds"` (default 120).

- **What you depend on it for.** A seller with no ETH depends on the relayer
  for timeliness only, never for payment. Each call pays whom the contract
  names: `settle` books the order's seller, and `claim` pays the payee.
- **What it can do to you.** It can refuse or delay a call. For `settle`, it
  sees the artifact before it is on chain.
- **What your seller checks.** Every relayed transaction is read from the
  chain: it must go to the vault, with value 0 and exactly the calldata your
  seller built, and it must be mined successfully. Anything else is refused.
- **Fallback.** If nothing lands within the wait, or near the order's
  deadline, your seller checks whether the call's effect is already on chain.
  If it is not, the seller sends the call itself, which needs gas. Keep a
  little ETH if you want to defend your deadlines against a slow relayer.

`qed-wrap relay CONFIG.json` runs one; its header documents the
configuration, and `contracts/agents/src/relay.rs` lists its rules.

## Run a buyer

`nucleus-buyer post` serves a statement over iroh, posts the task on the
board, signs for the first offer that passes its review, and afterwards reads
the artifact from the settlement transaction and checks it with the Lean
checker itself. `contracts/agents/tasks/` has example task files.

## Checking the published programs

An order names its proof program by image ID, and the ID is computed from the
binary, so you can check which program you are running without building it:

    contracts/proof-acceptance/zkvm/target/release/nucleus-acceptance-host vault3-image-of FILE

`contracts/proof-acceptance/program/README.md` lists every published binary
with its ID and SHA-256. That a binary does what the sources under
`contracts/proof-acceptance` say rests on a build that does not yet reproduce:
the same commit built from a second directory on the same machine gave
different bytes and a different ID. The binaries were built with source paths
remapped; they still carry paths from RISC Zero's prebuilt guest standard
library and kernel.

The program used with the earlier Base mainnet vault (image ID
`f0f882fe7052e1ac22f7fec033e12c6874e1b5f72ae31f31bd8b939576fba1ca`) is not
distributed here: its build embeds local build paths, and it cannot be rebuilt
to the same ID.

## What you are trusting

- RISC Zero's installer, `r0vm`, its Groth16 circuit data (checked against a
  hash in a manifest whose signature we did not check) and its on-chain
  verifier contract.
- The published program binaries, as above.
- The vendored Lean checker, `nanoda_lib` 0.4.32
  (`contracts/proof-acceptance/vendor/nanoda_lib`, with our changes listed in
  `VENDOR.md`).
- Circle's USDC contract, which can freeze an address. A frozen payee blocks
  only its own claim.
- iroh's public relays, if you use `"relay": "default"`: a relay sees which
  nodes talk and when, and can drop traffic; it cannot read or change it.

## Map

| path | what |
|---|---|
| `contracts/vault` | the vault, base registry and test contracts (Solidity, with compiled outputs) |
| `contracts/board` | the task board and its Rust reference |
| `contracts/proof-acceptance` | the acceptance rule, the vendored Lean checker, the proof programs, the prover front end and native Groth16 wrap; `wasm-checker` builds the same acceptance rule for a browser |
| `contracts/agents` | buyer, seller and operations binaries; iroh and HTTP transports; A2A over iroh |
| `contracts/a2a-iroh-card` | identifiers and agent card for the A2A-over-iroh binding |
| `contracts/site` | the website generator and its A2A agent card |
| `contracts/vault-conformance`, `token-conformance`, `x402-interop` | tests of the contracts in a local EVM, against real token and verifier bytecode, and against independent x402 types |
| `crates/nucleus-proof-commerce` | order digest, fee and royalty split, x402 wire types |
| `crates/nucleus-jsonl` | the append-only journal the buyer keeps |
| `proofs/commerce` | Lean models of vault, board and registry, with proofs |
| `docs/specs/a2a-iroh-transport-binding.md` | the A2A-over-iroh transport binding, draft |

## Reporting a vulnerability

See `SECURITY.md`. Please do not open a public issue.

## Licence

MIT OR Apache-2.0, at your option (`LICENSE-MIT`, `LICENSE-APACHE`).
Third-party code and bytecode included here keep their own licences; see
`NOTICE`.
