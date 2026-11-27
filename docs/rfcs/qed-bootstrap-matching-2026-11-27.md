# QED: bootstrap matching, paid to the seller of a first proof

2026-11-27. Model `proofs/commerce/Promotion.lean`; code
`contracts/site/src/market/promotion.rs` and `src/market/view.rs`; page
`/market`. Built on the market index (`qed-market-index-2026-11-25.md`).

## The rule

A pool matches the first settlement of a statement on a reviewed list. The
match goes to that settlement's seller. A `Settled` event earns a match when
all of these hold:

- its order was funded and joins a post (the market index's join rule);
- the post's statement SHA-256 is on the reviewed list;
- the settlement's block is at or after the promotion's start block;
- the statement was not taken before it: no order joined to any post of that
  statement had settled (`Market.taken`);
- what the caps leave is above zero.

The match is the least of four amounts:

- `fractionBps` of the order's amount or the post's price (`maximumAmount`),
  whichever is lower;
- `perStatement`;
- what is left of `pool`;
- what is left of `perPoster` for the post's poster.

The match names the settled order's payee key (its seller and asset). The
poster counts only toward the per-poster cap.

The first month's terms: a 100 USDC pool, +50 % (`fractionBps` 5000), at most
20 USDC per statement. The first live case is the authors' own S0006 post at
40 USDC (statement SHA-256 `fff47ea3…6d191db37`): its first settlement earns
its seller +20 USDC.

## Why not a reward for listing, or a match on any settlement

On chain, one party can play both sides:

1. post a statement whose proof it already has;
2. fund the order;
3. settle it from a second wallet;
4. collect the reward.

The board and the vault cannot tell the two wallets apart. A reward per
listing is collected at step 1. A match on any settlement is collected at
step 4. A match only on the **first** settlement of a **reviewed** statement
with no known proof can be earned only by producing a new proof, whoever
produces it.

The market fixture shows the farming case on real data. The bounty
statement (`9480265e…56f6dc1c`) settled five times. The first was the
authors' own 1 USDC trade, at block 57144774. The poster, buyer and seller
are all the authors' unpublished wallets, which read `elided`. The outside
seller's four settlements came later. Had the statement been listed before
block 57144774, the authors' own trade would have earned the match (+0.5
USDC) and the outside seller nothing. With it listed from block 57144775,
nobody earns one. The statement is not listed: its proof is public. Only the
review keeps such a statement off the list
(`on_base_only_the_first_settlement_of_a_listed_statement_is_matched` in
`contracts/site/tests/market.rs`).

## What is proved (`lake build` in `proofs/commerce`, exit 0)

Core Lean 4.35.0, no Mathlib. Every theorem depends only on `propext`,
`Quot.sound` and, for some, `Classical.choice` (checked by `#guard_msgs` on
`#print axioms`). There is no `sorry` and no `native_decide`. Every run-level
theorem holds for any log replayed from the empty market (`reachable`).

| theorem | says |
|---|---|
| `admitted_only_first` | a match is admitted only on the `Settled` event of a funded order joined to a post of a listed statement, at or after the start, with the statement not taken before |
| `never_twice` | no two matches share a statement, across any number of posts of it |
| `within_pool`, `within_poster` | the sum of matches ≤ the pool; per poster ≤ the per-poster cap |
| `within_fraction`, `price_is_posts` | each match × 10000 ≤ `bps` × the post's price, and ≤ the per-statement cap |
| `paid_to_seller` | the match names the settled order's payee |
| `nothing_unlisted_or_early`, `early_settlement_blocks` | every match is of a listed statement at or after the start; a statement taken before (settled before the start included) gets nothing later |
| `monotone` | the matches of a log are a prefix of those of any extension: nothing admitted is revoked or changed |

Decided examples (`Examples`): +20 USDC on the 40 USDC S0006 post; nothing for
self-dealing on the bounty statement; nothing for a second S0006 post after
the first settled; a 30 USDC pool paying 20, then 10, then nothing; one
poster's 40 USDC cap paying 20, 20, then nothing; +5 USDC on a 10 USDC post;
nothing for a settlement before the start, nor for the later one it blocks.

Each theorem has a mutant whose failure `lake build` checks (namespace
`Mutants`). Each mutant is the model with one switch of `Rule` turned:

| mutant | breaks | counterexample |
|---|---|---|
| P1, no first-settlement check | `admitted_only_first` | settled before the start, then again on a second post: the second is matched |
| P2, first per post | `never_twice` | a second S0006 post: two matches, one statement |
| P3, no pool clamp | `within_pool` | 60 USDC paid from a 30 USDC pool |
| P4, no poster clamp | `within_poster` | 60 USDC to one poster capped at 40 |
| P5, a flat match | `within_fraction` | 20 USDC on a 10 USDC post |
| P6, pay the poster | `paid_to_seller` | the S0006 match names the poster |
| P7, no list check | `nothing_unlisted_or_early` | the self-dealing trade on the bounty statement collects 20 USDC |
| P8, no start check | `nothing_unlisted_or_early` | the settlement at block 90 is matched |
| P9, the pool split at read time | `monotone` | a second settlement cuts an admitted 20 USDC match to 15 |

The Rust mirror replays the same entries, examples and mutants
(`src/market/promotion_tests.rs`). It also checks the caps and the prefix
property after every step of five logs. As a red-first check, the model was
run with each of its eight switches turned: each turn fails 1 to 4 of the 17
tests. In Lean, the model with P2's switch fails `lake build` in `candidate_spec`, in two examples (`second_post_gets_nothing`, `early_gets_nothing`) and in mutant P8.

## The input and the page

`mainnet.promotion` in the site input. Absent by default: then `/market`
has no promotion section and `market.json` has `"promotion": null`.

```json
"promotion": {
  "startBlock": 0,
  "pool": 100000000,
  "perPoster": 40000000,
  "fractionBps": 5000,
  "perStatement": 20000000,
  "listed": ["0xfff47ea357d16945a265b84f905c991b1e1c64a593afcd571e9c6a76d191db37"],
  "matchingBuyer": "0x…"
}
```

`Input::check` refuses `fractionBps` above 10000, a listed value that is not
`0x` and 64 lower-case hex digits, and a matching buyer that is not an
address.

When the promotion is present:

- each admitted post's state reads, for example, "claimed, matched +0.5 USDC";
- a "Bootstrap matching" section gives the terms, the total matched, what is
  left of the pool, and the reviewed list;
- the section says that a match shown is owed, not yet paid, and that the
  matching buyer pays it as a second order on the same statement.

The matching buyer's address appears only with `publishWallets`. Only then
is it in the address guard's allow-list and the published names. Without
`publishWallets`, the page says "its address is not listed here".

## Limits

- **The decision runs over the index the page is built from.** On a filtered
  index, the authors' unpublished wallets all read `elided` and share one
  per-poster cap. Anyone can re-derive the decision from `market.json`. The
  payment step should decide from the same published index, or both deciders
  must be shown to agree.
- **"No known proof" is the review's job.** The model knows only this
  market. A statement proved elsewhere, or settled on a board this index does
  not read, is still first here.
- **The per-poster cap does not stop one party using many wallets.** It bounds
  one wallet. What stops farming is the list: each listed statement can pay
  once, and only for a new proof.
- **A match can be partial.** When the pool or a poster's cap is nearly spent,
  the match is what is left, not refused.
- **The price is the post's `maximumAmount` or the order's amount, whichever
  is lower.** The vault does not check the board, so a joined order may carry
  more than the post asked. The lower figure is used.
- **Rust arithmetic saturates at 2^128.** Lean's `Nat` does not. At USDC
  scale the two cannot differ.

## Not built

- **The payment.** Each match is meant to be paid by our matching buyer as a
  second order on the same statement after the first settles. That is a later
  step on the host. Until then `/market` says a match is owed, not paid. The
  second order settles a taken statement, so it earns no match of its own.
  It also needs a post to join, with that post's key binding. Which post it
  joins is the host step's decision.
- **The review process for the list.** The list starts as the nucleus
  `open-statements.toml` rows plus vetted formal open problems. Review is the
  bottleneck: a statement that says the wrong thing gets a match for a
  meaningless proof. Who reviews, and how a row is added or removed, is not
  written yet.
- **Time-based start or end.** The start is a block, and there is no end
  block. The month ends when the input's promotion is removed. A removal
  drops the shown matches from the page, owed or not.

## Decisions, 2026-11-27

- **Per-poster cap: 40 USDC,** two full 20 USDC matches per poster.
- **The matching buyer is a new, dedicated wallet,** published like the bounty and ladder
  buyers, so the matching pool's budget is separate from any poster's. It is made when the
  payment step is built; until then the promotion stays absent from the input.
