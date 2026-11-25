# QED: the market index, every post joined to its orders from the chain

2026-11-25. Model `proofs/commerce/Market.lean`; code
`contracts/site/src/market.rs` and `src/market/view.rs`; pages `/market`,
`/status`, `/bounty`.

## What it does

The site reads every `Posted` and `Withdrawn` of the board and every
`Funded`, `Settled`, `Refunded` and `Claimed` of the vaults the input names,
and joins each order to the post it answers:

- **Join rule.** An order joins a post iff its `context` is
  `keccak256(keccak256("NucleusContextV1") ‖ post id ‖ buyerKeyBinding)` and its
  `policyHash` is the post's.
- **Where `context` comes from.** It is in no event, only in calldata. The
  indexer decodes the `fund` call (the twelve-field `Order`, or the eleven-field
  one). It recomputes the order's EIP-712 digest with the vault's domain and
  keeps the terms only when that digest equals the `Funded` topic. When the
  fund call was not a direct call to the vault, the terms are taken from the
  `settle` or `refund` call the same way. An order whose terms cannot be
  recovered joins nothing.
- **A post's state.** It is the furthest phase any joined order reached:
  funded < refunded < settled < claimed. Without one, the post is withdrawn,
  expired (past `fundBy`), or listed.
- **A claim.** `Claimed(payee, asset)` marks claimed every settled order whose
  seller and asset hash to the same key (`payeeKey`). A claim pays what is
  owed at that moment, so orders settled later are not marked.
- **Rounds.** Each round comes from the input: name, price, budget, tasks and
  first task. It starts at the block where its first task was posted, read
  from the chain, and holds the bounty buyer's posts until the next round
  starts.
  - **Remaining** = budget − (Σ funded − Σ refunded) over orders joined to the
    round's posts.
  - When a round funded beyond its budget net of refunds, the page says "over
    budget" rather than a truncated zero.
- **A statement is taken** once an order joined to any post of it has
  settled.

## What is proved (`lake build` in `proofs/commerce`, exit 0)

Core Lean 4.35.0, no Mathlib. Every theorem depends on `propext`,
`Quot.sound` and at most `Classical.choice` (checked by `#guard_msgs` on
`#print axioms`). There is no `sorry` and no `native_decide`.

| theorem | says |
|---|---|
| `state_forward`, `state_forward_replay` | no event, and no replay, moves a post's state back |
| `settled_has_joined_order` | settled or claimed only with a joined order settled or claimed |
| `settles_only_by_joined_settled` | a post becomes settled only by a `Settled` event whose order joins it and was funded |
| `join_unique`, `order_joins_one_post` | with `ctx` injective (keccak-256 collision resistance, a hypothesis) and the board's unique IDs, an order joins at most one post |
| `refunds_le_funded`, `remaining_exact`, `remaining_tasks_exact` | remaining + (funded − refunded) = budget whenever the round kept its commitment: no truncation |
| `rounds_disjoint` | two rounds with no post in common count no order twice |
| `taken_iff`, `taken_stays` | taken iff some post of the statement has a joined order settled; once taken, always taken |

Each theorem has a mutant whose failure `lake build` checks (namespace
`Mutants`). Each is a decided counterexample:

| mutant | breaks | counterexample |
|---|---|---|
| M1: a post shows its *latest* joined order's phase | `state_forward` | a refunded order, then a new funded one: refunded → funded |
| M2: join on `context` alone | `settles_only_by_joined_settled` | an order with the post's context and another policy settles the post |
| M3: `ctx` ignores the post ID | `join_unique` | one order joins two posts |
| M4: remaining from `Funded` without refunds | `remaining_exact` | a round refunds one of two orders; also on the real round 1: 125 USDC counted against 100 |
| M5: taken once funded | `taken_iff` | a funded, unsettled post takes its statement |
| M6: a claim marks unsettled orders | `settles_only_by_joined_settled` | a funded order shows claimed |

`contracts/site/src/market/tests.rs` repeats M1–M6 against the Rust mirror,
which uses the real keccak context.

## Real events (Base, chain 8453)

`nucleus-site market-capture` scanned the board
`0xd968d5659b3c63cd74d7b4d09345ff3417711038` and the vaults
`0x952c31aa208dd129059f6065a26b57c930c6ab3c` and
`0x8917c501755f966a5b5f20d6608e297e7066f13b`.

- The scan covered blocks 56772992 to 62256533 (2026-11-25 21:21 UTC) in 146
  JSON-RPC calls: 110 `eth_getLogs` over all three addresses at once, in
  ranges of 49,999 blocks, and 36 `eth_getTransactionByHash`.
- It wrote `contracts/site/tests/fixtures/market-base.json`: 73 events, with
  addresses filtered as the site publishes them.
- `Market.lean` (namespace `Real`) and `contracts/site/tests/market.rs` decide
  the same facts on it.

| fact | value |
|---|---|
| posts | 25: 2 listed, 12 withdrawn, 1 refunded, 10 claimed, 0 expired |
| orders | 12, every one's terms decoded from its `fund` call and checked against its digest |
| unjoined orders | 1: `0x91e79768…`, the first relayed trade on the earlier vault, funded at block 57023099, before the board was deployed |
| the four outside settlements (`qed-first-outside-settlements-2026-11-25.md`) | each joins its own round-1 post, which shows claimed |
| round 1 (25 USDC × 4, 100 USDC; first post block 57110912) | 5 funded (125 USDC), 1 refunded (25 USDC, post `0x2ca29bcf…`), 4 settled: **0 of 4 tasks, 0 of 100 USDC left** |
| round r1 (1 USDC × 5, 5 USDC; first post `0xafa53fb0…82394727`, block 62001659) | at its first post: listed, **5 of 5 tasks and 5 of 5 USDC left**, and its statement already taken by round 1 |
| round r1 at block 62256533 | 5 posts, 5 funded, 5 settled and claimed: **0 of 5 tasks, 0 of 5 USDC left** |
| the two listed posts | the ladder buyer's, funding deadline 2026-12-03; a replay ticked past it reads both expired |

The snapshot behind the build (`input/status.snapshot.json`, block 62259932,
2026-11-25 21:32 UTC) has the same counts.

## Findings

**r1 was spent within the day it opened.** Its five posts were funded
between blocks 62037477 and 62049231 and settled at once. All five orders
name the same payee key, `0xad239bb5…`. That key differs from the key of the
seller of round 1's four outside settlements (`0x39171149…`) and from the key
of the refunded round-1 order. Who that seller is was not checked: the site
elides sellers.

**All 30 posts' statements so far are two.** Every bounty post, in both
rounds, names `9480265e…`, whose proof is public; the ladder posts name two
others. "Taken" therefore marks every bounty post after the first
settlement. That is correct by the rule, and it shows that the bounty still
pays for a published proof.

**Wrong assumption: the status page's "Remaining" was a round.** It
subtracted all of the bounty buyer's `Funded` less `Refunded` events, on the
bounty's vault, from one hard-coded 4 × 25 USDC budget. It read "0 of 4
tasks" while r1 was open with 5 of 5, because r1's buyer is the same wallet.
Remaining is now per round, over orders joined to that round's posts.

**Wrong assumption: the browser listing could scan from the deploy block.**
At 5,000,000 blocks a query it stopped at 40 queries. On Base, with a
49,999-block range, the board's history is 103 ranges at block 62259932, so
the listing had already failed. It now reads `/market/market.json`. On
request it re-reads each listed post's `Posted` log at its block, and the
board's logs after the index's block.

**Wrong assumption: one query per range is a page anyone reads.** The
status page printed one reproduction query per 49,999-block range for each
contract: more than 300 at block 62259932. Each query's "Copy" control is a
counted word, so the regenerated snapshot alone put the site at 3,719
counted words against the limit of 3,500. Ranges with logs, and the first
range, keep their own query; the empty ones are one template with
`0xFROM`/`0xTO` and the block span. The limit holds again.

**The seller's QuickStart price tracked the round.** `price` in the
generated `seller.json` was round 1's 25 USDC. A seller that asks 25 USDC
answers no 1 USDC post. It is now the open round's price, in `README.md` too.

**A royalty payee of zero read as a wallet.** A `Settled` with no royalty
carries the zero address. The site's address scan (`status::addresses`)
counts any 40-digit run, so the fixture first failed the "names no other
wallet" test. A zero royalty payee is now stored empty.

**Version "1" for the eleven-field vault.** `NucleusVault2`'s EIP-712 domain
version is `"1"` and `NucleusVault3`'s is `"3"`. The digest check uses each.

## What is not done, and limits

- **Posters by address need the authors' wallet list.** Public code cannot
  tell the authors' unpublished wallets from anyone else's. Posters other
  than the bounty buyer and the ladder buyer are shown by address only when
  the reader holds `authors-wallets.txt`: beside the input for
  `snapshot-status`, in the state directory for `refresh-status`, and ignored
  by git. Without the list they read "elided". This build had no list, so the
  two posts by other wallets (`0x9a0dc25b…`, `0x2a1acff4…`) read elided.
  `render_market` refuses to write a page that names a listed wallet.
  `tests/market.rs` drives that refusal red.
- **Sellers, buyers and payees are not shown.** Claims match on `payeeKey` =
  keccak256(seller ‖ asset), which is stored in the published index. It names
  no address, and the `Funded` log names the same seller on chain.
- **The reader's private state holds full addresses.** The last good
  snapshot (mode 0600) keeps the unfiltered index, because claims and the
  sweep search need full payees and an index can only be resumed from its
  unfiltered form. The committed snapshot and every served file are filtered.
  A filtered index is never resumed: `snapshot-status` scans from the deploy
  blocks each time (146 calls on 2026-11-25).
- **Resuming.** `refresh-status` resumes from the cursor when that block's
  hash is unchanged. Otherwise (a reorg, another deployment, another schema,
  a filtered or absent index) it scans from the deploy blocks. The unit test
  `an_incremental_scan_equals_a_full_one_and_a_reorg_rescans` checks that a
  resumed index equals a full one and that a changed cursor hash rescans.
  Against Base, two `refresh-status` runs into an empty state directory
  (2026-11-25): the first a full scan, blocks 56772992 to 62262309, 146 calls;
  the second incremental, blocks 62262310 to 62262972, 2 calls (the cursor
  hash, one `eth_getLogs`). Both runs exited 0 and wrote `site/market/`.
- **The sweep search is not incremental.** Every reread still searches each
  paid seller's USDC transfers from its first claim to the head: 280
  `eth_getLogs` at block 62262309. The market index made the board and vault
  reads incremental; the sweeps are the remaining cost of a 10-minute reread
  (the incremental run above took 86 seconds, the full one 133).
- **The join ignores the vault.** The rule, as decided, does not compare the
  order's vault with the vault the post names. Only the input's vaults are
  read. An order in one of them whose context matches a post naming another
  vault would still join. None does on Base.
- **Statements are linked only when the site has the file**
  (`input/statements/`). Fetching other posters' statements from their nodes
  is the next step of the plan and is not built.
- **check-live on `/market`** admits as addresses exactly the posters the
  served `market.json` shows. Which of them are the authors' it cannot know.
  The reader's list and the release audit decide that.

## Host side

The reader (`nucleus-site refresh-status INPUT STATE_DIR SITE_URL`) now also
writes, atomically and mode 0644:

- `STATE_DIR/site/market/index.html`
- `STATE_DIR/site/market/index.md`
- `STATE_DIR/site/market/market.json`

It reads `STATE_DIR/authors-wallets.txt` when present.

The web server must serve these files as it serves `site/status/`:

- `/market` and `/market/` as a document, with HTML or Markdown chosen by
  `Accept`;
- `/market/market.json` as `application/json`, `cache-control: public,
  max-age=300`;
- the release's copies as the fallback when the reader has written nothing.

The `/bounty` and `/transactions` pages fetch `/market/market.json` from the
same origin.
