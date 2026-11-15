# qed-analytics

Visit counts for qed.coproduct.dev. Each page view sends one beacon: the
page's label and whether this browser sent one earlier that UTC day. The
collector counts beacons per day, label and that bit, and publishes each
finished day once, with noise, suppressing cells under 10. `/visits` on the
site shows the last published day, the theorem statements and this crate's
file digests.

## What is proved, and over what

| theorem | file | over |
|---|---|---|
| `core_handle_noninterference` | `lean/QedAnalytics/Refines.lean` | the Aeneas translation of `core::handle`: two requests that agree on (path, first, day) leave the same state, whatever their peer address, port, time within the day and sizes |
| `core_handle_total`, `count_refines`, `step_refines`, `limit_refines`, `handle_refines` | `Refines.lean` | the translation: every call returns `ok` (never panics) with the spec's value |
| `core_publish_suppresses` | `Refines.lean` | the translation of `core::publish_cell`: a true count under 10 is `Suppressed`, whatever the noise |
| `core_publish_is_spec`, `publish_cell_refines` | `Refines.lean` | the translation: a published value is the true count plus `g1 - g2` |
| `sensitivity` | `lean/QedAnalytics/Spec.lean` | the model: two days whose beacons differ by one beacon end at L1 distance at most 1 |
| `lap_total`, `difference_nonneg`, `difference_neg` | `Spec.lean` | the model: `P(z) = 2^-abs(z) / 3` is a distribution and is the law of `G1 - G2` for two fair-coin head counts |
| `day_dp`, `visit_dp` | `Spec.lean` | the model: for days whose cells sit on the same sides of 10, any set of published days is at most twice as likely under one as under the other (ε = ln 2) |
| `threshold_breaks_dp` | `Spec.lean` | the model: at 9 a cell is suppressed with probability 1, at 10 with probability 0; thresholding on the true count is not DP for any ε at that boundary |

Lean 4.30.0, Mathlib v4.30.0, the Aeneas Lean library at
`5138c03bd39e870abe1ad3a572865cf8c15f43d6`. `#print axioms` on each:
`propext`, `Classical.choice`, `Quot.sound`. The Aeneas library carries
`sorry` in `Std/Slice.lean` and `Std/StringIter.lean`; none of these theorems
depends on it.

Each theorem was driven red before it was accepted: four mutations of
`core.rs`, each re-extracted and rebuilt (handle reads `peer_port`; the
threshold compared against `K - K`; a beacon counted twice; the noise
`2·g1 - g2`), and four of the model.

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
- `published.jsonl`: one line per finished day, appended once and synced, never rewritten. Its noise is drawn once.

## Parameters

- **k = 10.** A cell under 10 beacons is suppressed. At the noise's standard deviation of 2, a shown count is within ±2 of its true value with probability 5/6.
- **ε = ln 2 per day, per beacon.** One beacon changes one cell by one, which changes any output's likelihood by at most a factor of 2. Beacons of different cells and different days are disjoint, so the whole publication is ln 2 at the level of one beacon (parallel composition). A browser that sends m beacons in a day is covered at m · ln 2.
- **Rate limit.** 600 at once, 5 a second, for all senders together. Refused beacons are counted in their own cell.

## What the theorems do not cover

- That the binary serving `/analytics/beacon` is built from this source: compare its SHA-256 with a build of this commit (`/visits` names both).
- That nothing else on the path keeps a request: the host's proxy configuration and logging are a fact about one machine, checked by hand (`/visits`).
- That `/dev/urandom` is fair, and that the sampler's count stops only at `u32::MAX` heads.
- The shell (`server.rs`, `store.rs`): that it calls only `handle`, `limit` and `publish_cell` to change or publish counts, draws fresh noise per cell, and never publishes a day twice. Tests, not proofs.
- Thresholding on the true count is not differentially private where a cell moves between 9 and 10 (`threshold_breaks_dp`).

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
