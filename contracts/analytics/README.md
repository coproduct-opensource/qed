# qed-analytics

Visit counts for qed.coproduct.dev. Each page view sends at most one
beacon per page label per UTC day from a browser: the page's label and
whether this browser sent one earlier that UTC day. The collector counts
beacons per week (Monday 00:00 UTC to Sunday 24:00 UTC), label and that
bit, and publishes each finished week once, with noise, suppressing a cell
when its count plus noise is under 10. Until 2026-11-18 the window was a UTC
day; those lines stay published as history. `/visits` on the site shows the
published weeks and days, the theorem statements, this crate's file digests,
and a button that checks the noise's pointwise ratio in the browser.

## What is proved, and over what

| theorem | file | over |
|---|---|---|
| `core_handle_noninterference` | `lean/QedAnalytics/Refines.lean` | the Aeneas translation of `core::handle`: two requests that agree on (path, first, day) leave the same state, whatever their peer address, port, time within the day and sizes |
| `core_handle_total`, `count_refines`, `week_refines`, `step_refines`, `limit_refines`, `handle_refines` | `Refines.lean` | the translation: every call returns `ok` (never panics) with the spec's value; `week_refines`: the translated `core::week` computes `(d + 3) / 7` |
| `core_publish_suppresses` | `Refines.lean` | the translation of `core::publish_cell`: a cell whose count plus `g1 - g2` is under 10 is `Suppressed` |
| `core_publish_at_least_k` | `Refines.lean` | the translation: every published `Count v` has `10 ≤ v` |
| `core_publish_is_post` | `Refines.lean` | the translation: the output is `post (c + g1 - g2)`, a function of the noisy value alone |
| `core_publish_is_spec`, `publish_cell_refines` | `Refines.lean` | the translation computes `publish c (g1 - g2)` |
| `week_iff`, `week_starts`, `week_mono` | `lean/QedAnalytics/Spec.lean` | the model: window `w` holds the days `d` with `7w ≤ d + 3 < 7w + 7` (Monday to Sunday, day 4 = 1970-01-05 the first Monday) |
| `sensitivity` | `Spec.lean` | the model: two windows whose beacons differ by one beacon end at L1 distance at most 1 |
| `one_window`, `other_windows` | `Spec.lean` | the model: one more beacon dated `d` moves window `week d` by at most 1 and every other window by 0 |
| `lap_total`, `difference_nonneg`, `difference_neg` | `Spec.lean` | the model: `P(z) = 2^-abs(z) / 3` is a distribution and is the law of `G1 - G2` for two fair-coin head counts |
| `postprocess`, `push_mass` | `Spec.lean` | any law: a bound `r` on every set of inputs is a bound `r` on every set of outputs of a function of the input |
| `window_is_post`, `noisy_dp` | `Spec.lean` | the model: the published window's law is the noisy window's law pushed through `publishWindow`; the noisy window is ε = ln 2 |
| `window_dp`, `visit_dp`, `window_ratio` | `Spec.lean` | the model, every window, no condition on the counts: any set of published windows is at most twice as likely under one beacon more as without it (ε = ln 2); `m` beacons, `2^m` |
| `windows_moved`, `publication_ratio`, `publication_dp` | `Spec.lean` | the model, the whole publication: for any finite set of windows published with independent noise, any set of their publications is at most twice as likely under one beacon more (ε = ln 2 per beacon, parallel composition proved) |
| `shown_below_k`, `shown_zero`, `shown_nine`, `shown_below_k_le` | `Spec.lean` | the model: a cell with true count `c < 10` is shown with probability exactly `1 / (3 · 2^(9 - c))`: 1/1536 at 0, 1/3 at 9, at most 1/3 for every `c < 10` |
| `TrueCount.threshold_breaks_dp` | `lean/QedAnalytics/History.lean` | the rule used until 2026-11-15 (suppress on the true count): at 9 a cell is suppressed with probability 1, at 10 with probability 0, so it is not DP for any ε at that boundary. Why the rule changed |
| `QedVisits.proof : QedVisits.claim` | `browser-check/QedVisits/Proof.lean` | Lean core only (no Mathlib), axiom `propext`: for counts at most one apart, `2^abs(o - c') ≤ 2 · 2^abs(o - c)` for every noisy value `o`; the published cell is `post (c + z)`; and the same factor of 2 on the scaled mass of every finite list of noisy values, and of those that publish as any given value. This is what `/visits` checks in the browser |

Lean 4.30.0, Mathlib v4.30.0, the Aeneas Lean library at
`5138c03bd39e870abe1ad3a572865cf8c15f43d6`. `#print axioms` on each:
`propext`, `Classical.choice`, `Quot.sound` (or fewer). The Aeneas library carries
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
`publish_is_post`, so `day_is_post`, `day_dp` and `visit_dp` (now `window_is_post`, `window_dp`, `visit_dp`) lose their
proofs; the threshold `K - 1` breaks `publish_suppresses` and
`publish_at_least_k`. For weekly windows (2026-11-18), two more of each: weeks starting Thursday (`week d = d / 7`) and a beacon counted in its window and every later one break `week_iff` and `one_window` (the latter also refuted outright); `core::week` with `> 4` and `core::step` counting in the day break `week_refines` and `step_refines`. The RFC (§11.4) has the table.

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

- `window.json`: the week being counted, `{"record":"qed-visits-window/1","window":W,"from":D,"cells":[34 counts]}`, replaced whole at most once a minute and at each new week. `from` is the first day counted: the week's Monday, or the day the weekly collector first started (2026-11-18 at the earliest) for the week in which it replaced the daily one. Not append-only: a log of checkpoints would keep the order in which cells grew.
- `published.jsonl`: one line per finished week (`"record":"qed-visits-week/1"`, with `from`, `to` and `days`), appended once and synced, never rewritten. Its noise is drawn once. Lines written before 2026-11-18 are days (`"record":"qed-visits/1"`) and stay as history; no beacon is in a day line and a week line both. Each line names its rule, `"suppressed":"count plus noise under k"`; a line without that field would have been suppressed on the true count. None was.
- Until 2026-11-18, `today.json` held the day being counted. The weekly collector reads it once at start, carries its counts into that day's week (`from` = that day), writes `window.json`, and removes it.

## Parameters

- **Window: a week, Monday 00:00 UTC to Sunday 24:00 UTC** (owner decision 2026-11-18). Daily and weekly cells are never published side by side: each beacon reaches one published cell, so the per-beacon bound stays ln 2.
- **k = 10.** A cell whose count plus noise is under 10 is suppressed, and no published value is under 10. A cell with true count `c` under 10 is shown with probability `1 / (3 · 2^(9 - c))`: 1/1536 at 0, 1/3 at 9. At the noise's standard deviation of 2, a shown count is within ±2 of its true value with probability 5/6.
- **ε = ln 2 per beacon, for the whole publication.** One beacon changes one cell of one window by one (`one_window`), which changes that window's noisy likelihood by at most a factor of 2; suppression reads only the noisy value, so the published window inherits the bound (post-processing), and the publication of any finite set of windows does too (`publication_dp`). A browser that sends m beacons is covered at m · ln 2 (`window_ratio`).
- **At most one beacon per label per UTC day from a browser that runs the site's script** (owner decision 2026-11-18). The script keeps today's date and the labels sent today under one localStorage key and sends nothing if storage fails. With 16 labels that is at most 16 beacons, 16 · ln 2, a day, and 112 · ln 2 a week. This is a convention of the script, **not enforced by the collector**, which cannot tell browsers apart: a sender that does not run the script is limited only by the rate limit.
- **Rate limit.** 600 at once, 5 a second, for all senders together. Refused beacons are counted in their own cell.

## The browser check

`browser-check/` is a Lean package with no dependencies (Lean 4.30.0 core).
`QedVisits/Statement.lean` states `QedVisits.claim`, the finite part of the
argument; `QedVisits/Proof.lean` proves it (axiom `propext`). The export is
made and checked natively by

    cd contracts/proof-acceptance/wasm-checker
    cargo run --release --example visits_claim -- \
      ../../analytics/browser-check LEAN4EXPORT ../../site/input/visits-check

(`lean4export` 3.1.0 built for Lean 4.30.0), which writes the statement and
proof in export format v2, the policy and a record. `/visits` serves them
and runs the site's checker module (`qed_check(policy, statement, artifact)`,
the one `/verify` runs) on them when asked. The browser check covers the
pointwise ratio, post-processing and finite sets of noisy values; that the
noise's law sums to one, infinite sums over sets of outputs, composition
across cells and windows, the sampler's law and the code's refinement are
in the Mathlib proofs only.

## What the theorems do not cover

- That the binary serving `/analytics/beacon` is built from this source: compare its SHA-256 with a build of this commit (`/visits` names both).
- That nothing else on the path keeps a request: the host's proxy configuration and logging are a fact about one machine, checked by hand (`/visits`).
- That `/dev/urandom` is fair, and that the sampler's count stops only at `u32::MAX` heads.
- The shell (`server.rs`, `store.rs`): that it calls only `handle`, `limit` and `publish_cell` to change or publish counts, draws fresh noise per cell and window, never publishes a window twice, and carries the daily checkpoint into its week once. Tests, not proofs.
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
