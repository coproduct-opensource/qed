# QED: one desk for several ladder rows

2026-11-27. Model `proofs/commerce/LadderMulti.lean`; code
`contracts/agents/src/ladder.rs`, `contracts/agents/src/tasks.rs` and the hub
in `contracts/agents/src/bounty.rs`.

    nucleus-buyer post-tasks    DEPLOYMENT BOARD KEYFILE BIND OUT_DIR TASK.json [OUT_DIR TASK.json]...
    nucleus-buyer task-withdraw DEPLOYMENT BOARD KEYFILE BIND OUT_DIR TASK.json [OUT_DIR TASK.json]...
    nucleus-buyer task-refund   DEPLOYMENT BOARD KEYFILE BIND OUT_DIR TASK.json [OUT_DIR TASK.json]...

Each `OUT_DIR TASK.json` pair is a row: one task file, one journal at
`OUT_DIR/journal.jsonl`, one status file beside it. `post-tasks` serves every
row from one process, one iroh node and one listener. With one pair it is
the one-row command of 2026-11-16, and runs the same code (`bounty::run`).

## The finding

A ladder buyer with one key posts one single-winner task per row. Until this
change, `post-tasks` took one task file, so N rows meant N processes. The
ladder buyer had two on 2026-11-19 (S0001 at 40 USDC, S0007 at 30 USDC, both
open until 2026-12-03) and was to add S0006 at 40 USDC. Two problems follow
from the code; neither needs a seller to show it.

- **One node, N processes.** Every post carries the buyer's node ID
  (`board.rs`, "An iroh node ID as the 32 bytes a task carries"), and the
  node key is the third line of the buyer's key file. Both desks on the Mac
  logged the same node. The relay keeps one active connection per node: a
  second client for a node deactivates the first. So a seller reached only
  the process that connected last. An offer for any other row reached a desk
  that does not hold that task, which answers 404, "no such task".
- **Rule 8 on one journal.** A restarting desk checks every `Funded` deposit
  from its buyer since its checkpoint against its own journal
  (`bounty::attribute`). Once one row's order is funded, every other row's
  desk that restarts stops with `UnknownDeposit`, and stays down.

The wrong belief, as `tasks.rs` stated it since 2026-11-16: "two ladder posts
from one wallet at once are refused at the second's first deposit". That
counted only the deposit. The two posts also shared one node, so from the
moment both processes ran, one of the two posts was already unreachable.

A third consequence, found while building: one node serves one
`GET /deliveries`. The desk therefore keeps one delivery record, beside the
first pair's journal (`OUT_DIR/journal.deliveries.jsonl` and `.jws`, with
`ours.txt` beside it). Other rows' existing records are kept as they are, and
nothing more is appended to them.

## The rules, the model and the code

| rule | Lean (`LadderMulti.lean`) | Rust | test |
|---|---|---|---|
| A signature is journaled in the row whose post it is for; for a task no row holds, nothing is signed | `offer_routed`, `offer_refused` | `ladder::route`, `ladder::record_signature` (the desk's `on_sign`) | `a_signature_is_journaled_in_the_row_whose_post_it_is_for` |
| At most one post per row, over any crashes and restarts | `at_most_one_post`, `posted_at_most_once`, by projecting each row onto `LadderPost` | each row is `bounty::step` with `tasks::limits` (`posts: Some(1)`) | `the_v024_journals_and_a_new_row_run_as_one_desk` |
| One funded order per row | `single_winner` | `Ledger::apply`: a signature only for an open post | `the_lean_table` G7 |
| No overcommit: a row posts only if the wallet covers its cap on top of what every other row could still be funded for | `no_overcommit`, `funding_covered` | `ladder::exposure`, `ladder::covered`, `step`'s `reserved` | `a_row_is_not_posted_when_the_wallet_covers_it_only_alone` |
| The restart's deposit check is over the union of the journals | `restart_admitted` | `bounty::attribute_all`, `ladder::unexplained` | `a_funded_row_does_not_stop_another_rows_restart` |
| A withdrawal or lapse changes no other row's journal | `withdraw_frame`, `lapsed_frame`, `journal_frame` | one journal file per row; `ladder::run` steps each row against its own | `the_lean_table` G8 |
| A deposit no row signed for stops the whole desk | `explainsWith` | `ladder::run` before its first round | `a_deposit_no_row_signed_for_stops_the_desk` |
| A row that fails leaves the others running and takes its post off the desk | (outside the model) | `ladder::run` | `a_row_that_fails_leaves_the_others_running` |

What a row "could still be funded for" (`expo`, `ladder::exposure`):

- its cap while an intent or a post is open;
- its cap while a signed order is unfunded and inside its funding window;
- nothing otherwise, since a funded order's deposit has already left the
  wallet.

The model funds an order at its row's cap. The desk never signs above the
cap, so this is the most the wallet can be asked for.

The rows are stepped in turn in one thread, so the wallet's one nonce lane
is used by one row at a time. A one-row desk passes `reserved = 0` and checks
`cap ≤ wallet`, the check of 2026-11-16.

## Proved (`lake build` in `proofs/commerce`, exit 0)

- Each theorem's axioms are pinned with `#guard_msgs`:
  `[propext, Quot.sound]`, and `restart_admitted` also uses
  `Classical.choice`. The file has no `sorry` and no `native_decide`.
- The invariant `MInv` holds in every reachable state (`reachable_minv`).
  It carries `LadderPost.Inv` for every row through `proj`. Every step is
  either a `LadderPost.Step` of that row's projection, or it leaves the five
  fields `LadderPost.Inv` reads alone.

Worked examples, for the three rows against 110 USDC, each closed by `decide`:

| | run | result |
|---|---|---|
| G1 | S0001 and S0007 posted, the host desk restarted; then S0006 | committed 70, then 110 |
| G2 | the same with 109.999999 USDC | S0006 refused |
| G3 | S0006 at 40.000001 USDC | refused |
| G4 | an offer for S0001's task; one for a task no row holds | routed to row 1; refused |
| G5 | S0001 signed for, unfunded | still committed at 40; total 110 |
| G6 | S0001 funded; restart | wallet 70, committed 70; restart admitted |
| G7 | a second offer for S0001 | refused |
| G8 | S0001 past its funding deadline unfunded, then lapsed | commits 0; S0007 and S0006 still posted |

Each mutant, also closed by `decide`, is a run the broken desk would allow:

| mutant | what it breaks | the run |
|---|---|---|
| `lastDesk`: one process per row, the relay reaches the last | `offer_routed` | the offer for S0001 is refused although S0001 is open |
| `first`: no one-shot limit | `at_most_one_post` | S0001 withdrawn and posted again: two posts |
| `rearm`: signing leaves the post open | `single_winner` | S0001 funded twice |
| `overcommit`: each row checks only its own cap | `no_overcommit` | with 100 USDC all three are posted; committed 110 |
| `perRow`: deposits checked per journal | `restart_admitted` | after S0001 is funded, the restart is refused |
| `shared`: one journal for every row | `journal_frame` | S0007 cannot be posted while S0001 is open; withdrawing S0001 changes what S0007 reads |

## Red, then green

Each new check was reverted to the one-row behaviour on a scratch copy, and
its test run. Every test failed as below. The tree was then restored, and
`cargo test --locked` in `contracts/agents` passed: 177 tests, 6 ignored,
exit 0.

| | reverted to | test | failure |
|---|---|---|---|
| R1 | `reserved = 0` | `a_row_is_not_posted_when_the_wallet_covers_it_only_alone` | panicked: "the wallet cannot fund this order" (the third row was posted and funded against 30 left) |
| R2 | deposits checked against S0007's journal only | `a_funded_row_does_not_stop_another_rows_restart` | `Err(UnknownDeposit(..))` on the restart |
| R3 | every signature to the first journal | `a_signature_is_journaled_in_the_row_whose_post_it_is_for` | "a signature for a task that is not posted" |
| R4 | a failed row stops the desk | `a_row_that_fails_leaves_the_others_running` | `Err(PostMissing(..))` from the whole run |
| R5 | a row or `OUT_DIR` may be named twice | `task_files_come_in_pairs_one_row_each` | `named_twice(.., "s0001/out")` was false |

`a_funded_row_does_not_stop_another_rows_restart` also runs S0007 the old
way, as its own process with its own journal, and asserts the
`UnknownDeposit`.

## Backward compatibility with the journals v0.2.4 wrote

The S0001 and S0007 journals the v0.2.4 build wrote are in
`contracts/agents/src/ladder/tests.rs`, verbatim. Each is three lines:
`opened`, `intent` with its salt, `posted`.

- **Replay** (`the_v024_journals_replay_unchanged`). Each replays to an
  open post with its price, funding deadline and salt. Opening it writes
  nothing. Both name one buyer, vault, board and token, so one desk can hold
  them.
- **One row** (`a_v024_journal_resumes_alone_as_before`). S0001's journal
  runs alone, through `bounty::run` as `post-tasks` with one pair runs it.
  The post is resumed, not posted again, and withdrawn at its deadline. The
  journal still holds one `intent`.
- **Three rows on one desk**
  (`the_v024_journals_and_a_new_row_run_as_one_desk`). Both journals run on
  one desk with a new S0006 against 110 USDC. S0006 is posted (40 on top of
  70); S0001 and S0007 are not posted again; each post is withdrawn at its
  own deadline.
- **The refactor alone.** After the hub split and before any new test, the
  33 existing `bounty` and `tasks` tests passed unchanged.

## For the host (`install-ladder`)

The host command installs one systemd template, `qed-ladder@<row>`, one
instance per row. With this change it should install one unit for all rows:

- `qed-ladder.service`, with one `ExecStart`:

      /opt/qed-ladder/bin/nucleus-buyer post-tasks /var/lib/qed-ladder/deployment.json ${BOARD} /var/lib/qed-ladder/keys ${BIND} \
          /var/lib/qed-ladder/s0001/out /var/lib/qed-ladder/s0001/task-s0001.json \
          /var/lib/qed-ladder/s0007/out /var/lib/qed-ladder/s0007/task-s0007.json \
          /var/lib/qed-ladder/s0006/out /var/lib/qed-ladder/s0006/task-s0006.json

  The pairs come from the plan's rows, in order. The first pair's `out` keeps
  the desk's delivery record, so the row with the existing record goes
  first.
- One `ConditionPathExists=` per task file and one `ReadWritePaths=` per row
  directory, in place of `%i`. Each row's directory stays separate.
- The binary probe requires `[OUT_DIR TASK.json]...` in the usage text. A
  binary without this change exits 1 on more than six arguments, and would
  restart until the start limit.
- One unit to list, start, poll and stop. Rollback stops that one unit.
- Changing the rows means rewriting `ExecStart` and restarting the unit.
  Every row then resumes from its journal (`restart_admitted`, and
  `at_most_one_post` over restarts).

## Not established

- **No live run.** This was not run against a chain, a relay, a host or a
  seller. Everything above is the Lean model and the fake chain.
- **Gas is checked per row.** Each row checks `LADDER_GAS` against the
  ether at twice today's price, alone. Three rows do not check three times
  that.
- **Exit status.** The desk exits when every row has stopped, and exits 0
  only if every row settled. Under `Restart=on-failure`, a desk whose rows
  all ended unsettled (a withdrawal at the deadline ends as `PostLimit`)
  restarts until the start limit. The one-row units had the same behaviour.
- **Task IDs across rows.** `route` takes the first row whose journal holds
  the task. Two rows cannot hold one ID, since an ID commits to the row's
  statement and a fresh salt, but nothing here checks that.
- **Rust against Lean.** The Rust is held to the model by golden tests, not
  by a proof of refinement.
- **The host's binary.** It must be a build with this change. The v0.2.4
  release does not take more than one pair.
