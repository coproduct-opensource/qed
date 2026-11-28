# QED: proof-carrying savings

2026-11-28. Models `proofs/commerce/Savings.lean`, `Window.lean` and
`Payout.lean`. Code: `contracts/savings` (the split), `contracts/agents`
(`desk.rs`, `watch.rs`, `seller.rs`, `savings.rs`, `payout.rs`),
`crates/nucleus-proof-commerce/src/vault/wire.rs` (the referral),
`contracts/proof-acceptance/vendor/nanoda_lib/src/acceptance.rs` (the walk),
`contracts/site/src/market/savings.rs` (`/market`).

## What it is

A buyer posts a task with a cap (`maximumAmount`). A seller that fulfils it
for less saves the buyer the difference. The saving is measured from the
chain, and it is split:

| party | share of the saving | when it is 0 |
|---|---|---|
| the referrer bound into the funded order | 30 %, rounded down | the order names no referrer |
| the authors of the lemmas the settled proof reused | 20 %, divided equally among the distinct authors, each share rounded down | the proof reused no seller's declaration |
| the buyer | the rest, and every rounding remainder | never below half |

Worked example (`Savings.Examples.s0006_split`, replayed in
`contracts/savings/src/tests.rs`): S0006 posted at 40 USDC, settled at 25,
referred, one author. Saving 15 USDC: 4.5 to the referrer, 3 to the author,
7.5 to the buyer.

Owner decisions, 2026-11-28:

- an offer window in which the lowest offer wins, ties to the earliest;
- the split 30 % referrer / 20 % lemma authors / 50 % buyer, the remainder
  to the buyer;
- v1 is paid off chain by the buyer's desk after settlement, checkable from
  the chain. A v2 vault, splitting at settlement, comes later.

## Owner decision 6 is superseded

Decision 6 was "the first offer that passes review wins". It is superseded
on 2026-11-28 by the offer window.

The reason: with the first offer winning, a seller has no reason to offer
less than the cap. The first passing offer is at the cap, so the saving is
always zero and there is nothing to split. Every settlement on Base so far
paid its post's cap (`on_base_no_settlement_saved_its_buyer_anything` in
`contracts/site/tests/market.rs`). With the lowest offer in a window
winning, the saving is whatever competition finds.

The old rule stays the default. A desk collects offers only with
`NUCLEUS_OFFER_WINDOW=W` (seconds) or `Desk::collect_offers(W)`.

## The window (`Window.lean`)

The window opens at a post's first offer that passes review. It closes `W`
seconds later, or at the post's funding deadline if that is sooner. At the
close, each held offer is reviewed again at the closing time: its order must
still leave 60 s to relay `fund`. Of the offers that pass, the least amount
is signed for, and the earliest of equal amounts. The others are refused as
`outbid`. If none passes, nothing is signed and the next offer opens a new
window.

Proved:

- `signs_min`: the signed offer was held, passed the second review, and is
  no dearer than any held offer that passed; of equals, it arrived first.
- `single_winner_preserved`: at most one signature, so the row's
  `LadderMulti` `.offer` act happens at most once.
- `no_sign_before_close`.
- `window_within_fundBy`.

Each has a mutant that is decided to fail: first-offer, first-held,
later-of-equals, no second review, a second window, no funding cap.

### What changes on the wire for sellers

| | a desk without a window | a desk with a window |
|---|---|---|
| `POST /task/<id>/offer` | `200` with `PAYMENT-SIGNATURE`, or a refusal (unchanged) | `202 {"ticket", "closesAt"}`, or a refusal |
| `GET /task/<id>/offer/<ticket>` | `404` | `202` while open; then `200` with `PAYMENT-SIGNATURE` to the winner, `409` outbid to the rest |

The ticket is the offered order's digest. Only the seller key that offered
can read its answer (DPoP, as for every route). A seller built from this
change takes either reply. A seller built before it reads a `202` as a
refusal, so it never funds an order it was not signed for. It loses that
post, and nothing else.

`qed-deliveries` gains two refusal reasons, `outbid` and `bad-referral`. A
held offer is recorded once, at the close, with how it ended.

## Referrals

A seller binds a referrer by its order's salt:

```text
salt = keccak256("NucleusReferralV1" ‖ referrer (20 bytes) ‖ nonce (32 bytes))
```

It sends the opening in the offer, as `extra.referral = {referrer, nonce}`.
The desk opens the salt before it signs, and refuses a bad opening as
`bad-referral`. The buyer's signature covers the order digest, and the
digest covers the salt, so the referrer is fixed at funding and cannot be
added or changed later (`Savings.referral_bound_before_funding`). No new
vault is needed.

A referral is stripped before the requirements comparison. So the payment
echoes the plain requirements, which a seller recomputes from its order. An
unreferred header is byte for byte what it was before. A desk built before
this change refuses an offer that carries `extra.referral`, because `Extra`
is `deny_unknown_fields`, and reports it as malformed.

Self-referral is allowed. A seller that names itself collects 30 % of the
saving its own lower price made. It never collects more than the buyer saved
(`seller_revenue_monotone`: everything the split pays to anyone but the
buyer falls as the price rises).

## Who authored a reused lemma

A settled artifact is walked from its proof through the type and value of
every constant reached (`used_constants`, VENDOR.md item 13).
Kernel-reserved names are left out. Each seller-side declaration is keyed
by its name and by Merkle digests of its type and value. The digests do not
depend on the export's back-references: the bounty's v2 artifact and the
NDJSON fixture give the same digests. The provenance index maps a key to the
payee of the first settlement whose artifact carried it. The authors of a
settlement are the payees the index names for its keys, distinct, less its
own seller (`Savings.authorsOf`, `authors_from_artifact`).

### Library declarations: a v1 limit, measured

*I assumed a seller's artifact holds only declarations the seller wrote. It
does not.* The Nucleus fixture's seller side, and the 285-byte artifact
settled four times for the bounty, are each four declarations: `rfl`,
`Nat.add_succ`, `Nucleus.helper`, `Nucleus.proof`. The artifact re-exports
two Lean library declarations that its statement did not carry.

Under a pure first-carrier rule, the first seller to settle such an artifact
is credited with `rfl` and `Nat.add_succ`. Every later proof that carries
them would then pay that seller part of the authors' 20 %.

The fix, owner decision 2026-11-28: an exclusion set. `lean4export Init`
with Lean 4.30.0 and the exporter statements use, hashed into 57,425 keys,
is committed as `contracts/savings/library/lean-4.30.0-init.keys` (method,
export SHA-256 and timings in `library/README.md`). No declaration in it
earns a share (`Savings.excluded_never_earns`, mutant S12). On the bounty's
settled artifact the set leaves out `rfl` and `Nat.add_succ`, and only
`Nucleus.helper` and `Nucleus.proof` remain attributable
(`contracts/savings/src/walk/tests.rs`). Author shares are paid only while
the set is present; without it the 20 % stays with the buyer.

Still credited to a first carrier: declarations of `Std` or `Lean`, which
the set does not cover, and library declarations whose terms differ under
another toolchain. A change of the statements' Lean version needs a new set.
Every key that appeared on the statement side of a statement read is also
left out.

The other v1 limits:

- only artifacts settled through the indexed vaults count;
- base-library authors do not count until a base is registered.

## Payout, v1 (`Payout.lean`)

Each share (an order, a role, a party, an amount) is paid by one EIP-3009
`transferWithAuthorization` from the buyer's wallet. Its nonce is
`keccak256("NucleusSavingsPayoutV1" ‖ order ‖ role ‖ party ‖ amount)`.

The token records a used nonce and refuses it again. So exactly-once is the
token's state, not the desk's memory. After a restart, the desk asks
`authorizationState` and pays only what is unpaid. Anyone holding the split
can recompute each nonce and ask the token whether that share was paid.

A share is paid only when the wallet covers it on top of what open rows
could still be funded for.

Proved:

- `paid_once`;
- `only_owed`;
- `no_overcommit`, which extends `LadderMulti.no_overcommit` to payouts from
  the same wallet;
- `restart_safe`.

Each has a mutant decided to fail.

## `/market`

`market.json` carries, per settled order, `saving` (the cap, the amount, the
saving, the referrer and the split). The top level carries `savings`,
naming the model and the rule. The page adds "saved N USDC (M of it to the
referrer)" to a post's state.

A referral reaches the page through the site input's `referrals`. It counts
only when it opens the order's salt, as decoded from the vault call, so the
input cannot add a referral the order did not bind.

## Not yet

- **Wiring the payout.** The executor is not yet called from the desk's loop
  after a settlement joins a row. There is no live `Wallet` over the chain,
  and the signed order's referral is not yet journaled. `Signed.referral`
  holds it in memory only.
- **Authors on `/market`.** The page does not walk artifacts, so author
  shares read 0 there and their 20 % reads as the buyer's. A desk that pays
  authors will disagree with the page until it does.
- **The base guest's image ID** after the nanoda addition has not been
  rebuilt here. The `verify-programs` workflow is the check.
- **Live checks.** Neither the improvement bounty on S0001 nor a referred
  lower offer on a live row has run.
- **The v2 vault**, which splits at settlement, is not built.

## Published attribution, checked by the site (owner decision 2026-11-28)

The desk publishes each settled order's attribution in its signed delivery
record. It writes one `{"attribution": {order, authors, excluded}}` line per
order, and the signed summary carries them as `attributions`. Authors are
payee keys, never addresses.

The site recomputes the attribution with the same code
(`qed_savings::walk`, feature `walk`). It reads every settlement in chain
order from the artifacts, policies and statements it holds. Each order in
`market.json` gets `attribution.check`, which is one of:

- `agrees`;
- `mismatch`, with both author lists, and the page shows "attribution
  mismatch";
- `not recomputed`, when this artifact or an earlier one is not held.

A summary with no attributions serializes exactly as before. Two kinds of
older software read the new lines badly:

- A desk older than this change counts an attribution line as unreadable.
  It shows the line as unreadable; it does not hide it.
- A site older than this change refuses a summary that carries
  `attributions`, because the summary type is `deny_unknown_fields`.

Measured on the Base fixture (`a_tampered_published_attribution_is_flagged`):

- **Recomputation:** the site holds the artifact of all 11 settlements and
  recomputes every one.
- **Authors:** the first settlement has no author. Each of the next ten has
  one: the payee of the authors' own first trade of the bounty proof, which
  first carried `Nucleus.helper` and `Nucleus.proof`. The outside seller
  reused nothing of its own, and it is not its own author.
- **What this means:** a first-carrier rule credits whoever settles a public
  proof first. Here that was the authors' 1 USDC trade.
