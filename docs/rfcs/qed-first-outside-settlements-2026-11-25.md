# QED: the bounty's first settlements by a seller outside the authors

Measured 2026-11-25 from Base (chain 8453), read-only JSON-RPC against
`https://base-rpc.publicnode.com`: `nucleus-site snapshot` for each
settlement, and `eth_getLogs` / `eth_getTransactionByHash` for the claims.

## What happened

All four tasks of the standing bounty on vault
`0x952c31aa208dd129059f6065a26b57c930c6ab3c` were settled by one seller,
`0xe7747c9034cb460080f95a438e76c9d3ac740f82`.

- The seller is not in the authors' wallet list, and the authors confirmed
  on 2026-11-25 that it is not theirs.
- Its nonce was 0 when read: it has never sent a transaction itself.
  Every fund, settle and claim for these orders was sent by the gas
  relayer `0x7dca2f7e7e06b155f74a3dfb0ea90f8de776c218`.
- The buyer is the bounty buyer, `0x133c25a80fb323de143e8ad5c6c620bf8713edfd`.

| task | order digest | funded (UTC) | settled (UTC) | claimed (UTC) |
|---|---|---|---|---|
| 1 | `0xcdea51489e4a4e03a07d63d5443a4f978e93b94a6ca1850ab242458fe8946c24` | 02:32:23 | 03:04:20 | 03:04:25 |
| 2 | `0xb5c5bdf7feaeb0d2b93d188facfd17812fe78e0047ef458067ecf4e0fbf7859a` | 03:28:30 | 04:00:18 | 04:00:20 |
| 3 | `0xf894cd7e822b16dfc96059edb16ef0226a4453fb7e9bcc3f91411d44d9f14881` | 04:01:51 | 04:33:54 | 04:33:58 |
| 4 | `0x47e69316147efd3853a60912e499b84f8a9c42e6ff265bb85197c10d97906885` | 04:35:21 | 05:07:30 | 05:07:34 |

| task | fund transaction | settle transaction | claim transaction |
|---|---|---|---|
| 1 | `0x8a8abe9b44946f32a7efc90040543717cd6499937672a3f38f849aa84d3c0948` | `0x5b2a55604a0abfbb5d5b1a2f8ccb4fe782e000f6ab7186aa71b90f1e8e0d9b59` | `0xc6d3c92aadd61922c7107f738788da9cc67eac9477779142d17c8823991d8643` |
| 2 | `0xd72be857a91970a2d6a7c6b3dcc1946f09d6923a4719ca2a2b2cfe81e5c18cd2` | `0xa4c899060ecb19aa16c1b3f5889c1daf5687576dd13aa3b92e2f0b83a55394d7` | `0xc671ff2135328872342b01fc94690cf466509d0c0db948a820f9214dcc058153` |
| 3 | `0xc5bf0e53ef4e5eafb63232cb7163ae3945f06b56f5e7e38b3b0f38920248819b` | `0x0f9deaa1e05f26bf02894939ecc1d8285d9a5226d06571b035195693c2dc01b7` | `0xae7398b87c328cd2b668c19161856ba9d4423e778b1c368119d80837d56a6a23` |
| 4 | `0xc0f11fa0b13b1993f66c44213e08bb23fb69c9e060687bc27750ad3eaa124eaa` | `0xaac441097d14b8f20d047099edb92364e2449f1958c0d4466c87d4487bd986c2` | `0xf217a9cd07be4b546abf6af9e29524341a0cc0e76b6993e7f1480f6905a21e4f` |

Each order was for 25 USDC. Each `Settled` log booked 24.9375 USDC to the
seller and a 0.0625 USDC fee, and each claim moved 24.9375 USDC from the
vault to the seller (USDC `Transfer`, value `0x17c841c`).

Each delivered artifact is 285 bytes with keccak-256
`0xec7444f56a0c81b741210d072b10c80a412c09873041b1c83cbad35d09b869a8`, byte
for byte the published `contracts/site/input/artifacts/ec7444f5….bin`. The
vault records that hash for each order, and each settlement carried its own
seal. The order program is `bfe27f64…` (statement format v2, refuses
kernel-reserved names).

## What it shows, and what it does not

It shows that a party the authors do not know found the posts, ran a
seller, and was paid by the contract four times without contacting the
authors, with no ETH of its own.

It does not show theorem discovery. The bounty's proof is public, and its
terms say the bounty tests the integration (board, transport, proof,
settlement and claim). The seller delivered that published proof.

## What changed on the site

- `contracts/site/input/ledger.json` records the four settlements, each
  with an `outsideParty` note. The snapshot keeps those notes, and from them
  the site moves off "authors only" (`Snapshot::counterparties`).
- `/bounty` counts the bounty's settlements whose note names a party other
  than the authors, and links each one. It said "None has yet" until this
  change.
- `/status` shows the buyer's signed record of delivery attempts unchanged
  (one attempt, signed 2026-11-14 21:10 UTC), and now says the record is
  silent on anything after it was signed, pointing to the ledger. An empty
  record reads "from … to …", where it used to say "since 2026-11-14".
  Whatever offers led to these settlements came after that record was
  signed, so they are not in it.
