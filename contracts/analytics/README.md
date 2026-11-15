# qed-analytics

Visit counts for qed.coproduct.dev. Each page view sends one beacon: the
page's label and whether this browser sent one earlier that UTC day. The
collector counts beacons per day, label and that bit, and publishes each
finished day once, with noise, suppressing a cell when its count plus noise
is under 10. `/visits` on the site shows the last published day, the theorem
statements and this crate's file digests.

## What is proved, and over what

| theorem | file | over |
|---|---|---|
| `core_handle_noninterference` | `lean/QedAnalytics/Refines.lean` | the Aeneas translation of `core::handle`: two requests that agree on (path, first, day) leave the same state, whatever their peer address, port, time within the day and sizes |
| `core_handle_total`, `count_refines`, `step_refines`, `limit_refines`, `handle_refines` | `Refines.lean` | the translation: every call returns `ok` (never panics) with the spec's value |
| `core_publish_suppresses` | `Refines.lean` | the translation of `core::publish_cell`: a cell whose count plus `g1 - g2` is under 10 is `Suppressed` |
| `core_publish_at_least_k` | `Refines.lean` | the translation: every published `Count v` has `10 ≤ v` |
| `core_publish_is_post` | `Refines.lean` | the translation: the output is `post (c + g1 - g2)`, a function of the noisy value alone |
| `core_publish_is_spec`, `publish_cell_refines` | `Refines.lean` | the translation computes `publish c (g1 - g2)` |
| `sensitivity` | `lean/QedAnalytics/Spec.lean` | the model: two days whose beacons differ by one beacon end at L1 distance at most 1 |
| `lap_total`, `difference_nonneg`, `difference_neg` | `Spec.lean` | the model: `P(z) = 2^-abs(z) / 3` is a distribution and is the law of `G1 - G2` for two fair-coin head counts |
| `postprocess`, `push_mass` | `Spec.lean` | any law: a bound `r` on every set of inputs is a bound `r` on every set of outputs of a function of the input |
| `day_is_post`, `noisy_dp` | `Spec.lean` | the model: the published day's law is the noisy day's law pushed through `publishDay`; the noisy day is ε = ln 2 |
| `day_dp`, `visit_dp`, `day_ratio` | `Spec.lean` | the model, every day, no condition on the counts: any set of published days is at most twice as likely under one beacon more as without it (ε = ln 2); `m` beacons, `2^m` |
| `shown_below_k`, `shown_zero`, `shown_nine`, `shown_below_k_le` | `Spec.lean` | the model: a cell with true count `c < 10` is shown with probability exactly `1 / (3 · 2^(9 - c))`: 1/1536 at 0, 1/3 at 9, at most 1/3 for every `c < 10` |
| `TrueCount.threshold_breaks_dp` | `lean/QedAnalytics/History.lean` | the rule used until 2026-11-15 (suppress on the true count): at 9 a cell is suppressed with probability 1, at 10 with probability 0, so it is not DP for any ε at that boundary. Why the rule changed |

Lean 4.30.0, Mathlib v4.30.0, the Aeneas Lean library at
`5138c03bd39e870abe1ad3a572865cf8c15f43d6`. `#print axioms` on each:
`propext`, `Classical.choice`, `Quot.sound`. The Aeneas library carries
`sorry` in `Std/Slice.lean` and `Std/StringIter.lean`; none of these theorems
depends on it.

Each theorem was driven red before it was accepted: four mutations of
`core.rs`, each re-extracted and rebuilt (handle reads `peer_port`; the
threshold compared against `K - K`; a beacon counted twice; the noise
`2·g1 - g2`), and four of the model. For the noisy-count rule (2026-11-15),
two more of `core.rs`: suppressing on the true count again (`count < K`), for
which Lean proves the statements of `publish_cell_refines` and
`core_publish_is_post` false at `(9, 1, 0)`; and the threshold `K - 1`, for
which it proves `core_publish_suppresses` and `core_publish_at_least_k` false
at `(9, 0, 0)`. Two more of the model: the true-count rule breaks
`publish_is_post`, so `day_is_post`, `day_dp` and `visit_dp` lose their
proofs; the threshold `K - 1` breaks `publish_suppresses` and
`publish_at_least_k`.

## The translation

`lean/QedAnalytics/Types.lean` and `Funs.lean` are generated; do not edit
them. With the Charon and Aeneas binaries of Aeneas release
`nightly-2026.06.10` (Charon 0.1.212) and Rust `nightly-2026-06-01`:

    rustup run nightly-2026-06-01 charon cargo --preset aeneas \
      --start-from qed_analytics::core::handle --start-from qed_analytics::core::limit \
      --start-from qed_analytics::core::publish_cell --start-from qed_analytics::core::fresh \
      --dest-file /tmp/qed_analytics.llbc -- --lib
    aeneas -backend lean -split-files /tmp/qed_analytics.llbc -dest /tmp/out

then compare `/tmp/out/{Types,Funs}.lean` with the committed files. Charon
writes nothing unless the crate recompiles: touch `src/core.rs` first.

## What is stored

In the state directory, and nothing else:

- `today.json`: the day being counted, `{"record":"qed-visits-today/1","day":N,"cells":[34 counts]}`, replaced whole at most once a minute and at each new day. Not append-only: a log of checkpoints would keep the order in which cells grew.
- `published.jsonl`: one line per finished day, appended once and synced, never rewritten. Its noise is drawn once. Each line names its rule, `"suppressed":"count plus noise under k"`; a line without that field would have been suppressed on the true count. None was: the first day, 2026-11-15, is published by the noisy-count collector.

## Parameters

- **k = 10.** A cell whose count plus noise is under 10 is suppressed, and no published value is under 10. A cell with true count `c` under 10 is shown with probability `1 / (3 · 2^(9 - c))`: 1/1536 at 0, 1/3 at 9. At the noise's standard deviation of 2, a shown count is within ±2 of its true value with probability 5/6.
- **ε = ln 2 per day, per beacon, on every day.** One beacon changes one cell by one, which changes the noisy day's likelihood by at most a factor of 2; suppression reads only the noisy value, so the published day inherits the bound (post-processing). Beacons of different cells and different days are disjoint, so the whole publication is ln 2 at the level of one beacon (parallel composition). A browser that sends m beacons in a day is covered at m · ln 2.
- **Rate limit.** 600 at once, 5 a second, for all senders together. Refused beacons are counted in their own cell.

## What the theorems do not cover

- That the binary serving `/analytics/beacon` is built from this source: compare its SHA-256 with a build of this commit (`/visits` names both).
- That nothing else on the path keeps a request: the host's proxy configuration and logging are a fact about one machine, checked by hand (`/visits`).
- That `/dev/urandom` is fair, and that the sampler's count stops only at `u32::MAX` heads.
- The shell (`server.rs`, `store.rs`): that it calls only `handle`, `limit` and `publish_cell` to change or publish counts, draws fresh noise per cell, and never publishes a day twice. Tests, not proofs.
- That a cell under 10 is never shown: it is shown with the probability above (`shown_below_k`). The rule that never showed one, suppressing on the true count, was not differentially private between 9 and 10 (`TrueCount.threshold_breaks_dp`) and was replaced on 2026-11-15.

## SampCert

SampCert (github.com/leanprover/SampCert) proves discrete Laplace and
Gaussian samplers and pure DP, zCDP and composition in Lean. Its main branch
is on Lean 4.34.1, with tags v4.28.0 and v4.29.0 only; it cannot be built in
one Lake workspace with this package's Lean 4.30.0, Mathlib v4.30.0 and
Aeneas pins. The DP statements here are proved directly instead, for the one
noise law used.

## Persistence

No SQLite. The native Olog store is not available to this public tree, so the
published days use the synced JSON-lines append of `crates/nucleus-jsonl`,
as the bounty buyer's journal does.
