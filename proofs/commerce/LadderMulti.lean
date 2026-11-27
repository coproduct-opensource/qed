import LadderPost
set_option warningAsError true

/-! # LadderMulti: one desk, several ladder rows, one node

`nucleus-buyer post-tasks` with several task files: one process, one iroh
node and one listener for every row a ladder buyer holds, each row with its
own journal (`OUT_DIR/journal.jsonl`). A model; it moves no funds.
docs/rfcs/qed-ladder-multi-row-desk-2026-11-27.md.

Why one process. Every post names the buyer's node, and the node key is the
buyer's, so N one-row processes on one key are N processes claiming one node.
The relay keeps one active connection per node, so a seller reaches only the
desk that connected last, and an offer for any other row reaches a desk that
does not hold it (`lastDesk` below). And each one-row desk checks every
deposit from the shared wallet against its own journal (rule 8), so once one
row's order is funded, any other row's desk that restarts refuses to run
(`perRow` below).

What the model rests on, and does not re-prove: each row's journal is
`LadderPost`'s one-shot journal. `proj s r` is row `r` seen as a one-row
desk, and every step here is a `LadderPost.Step` of that projection or leaves
the fields `LadderPost.Inv` reads alone, so `LadderPost.reachable_inv` holds
for every row.

What it adds:
- an offer is routed by the task ID it names to the row whose journal holds
  that post, and refused when no row does (`offer_routed`, `offer_refused`);
- at most one post per row, whatever crashes and restarts happen
  (`at_most_one_post`, `posted_at_most_once`);
- one funded order per row (`single_winner`);
- no overcommit: what every row could still be funded for is covered by the
  wallet, in every reachable state and so at every funding
  (`no_overcommit`, `funding_covered`);
- the restart's deposit check is over the union of the rows' journals, and
  never refuses (`restart_admitted`);
- a row's withdrawal or lapse changes no other row's journal
  (`withdraw_frame`, `lapsed_frame`, and `journal_frame` for every step).

Rows are named by number (S0001 is `1`), task IDs and digests by small
numbers. Amounts are USDC base units (6 decimals). An order is funded at the
row's cap: the desk never signs above it, so the cap is what the wallet must
cover.

Core Lean only (no Mathlib). No `sorry`, no `native_decide`: every worked
example and mutant is closed by `decide`, which the kernel checks. -/
namespace Nucleus.ProofCommerce.LadderMulti

open Nucleus.ProofCommerce

abbrev Open := LadderPost.Open
abbrev Phase := LadderPost.Phase

/-- The rows one desk holds, fixed by its task files. -/
structure Config where
  ids : List Nat
  price : Nat → Nat
  fundBy : Nat → Nat
  deliverBy : Nat → Nat

/-- One row's journal, replayed: what it has open, its `posted` lines, and
the digests of the orders it signed for. -/
structure Journal where
  open_ : Open
  posted : Nat
  signed : List Nat
  deriving DecidableEq

def Journal.empty : Journal := ⟨.none, 0, []⟩

structure State where
  /-- Each row's journal. -/
  j : Nat → Journal
  /-- Each row's posts on the board: task ID and whether withdrawn. -/
  board : Nat → List (Nat × Bool)
  /-- The one nonce lane of the one wallet: a post sent for a row and
      neither mined nor dropped. -/
  inflight : Option (Nat × Nat)
  /-- Lost on a crash: this process journaled the row's intent and has not
      sent its post. -/
  fresh : Nat → Bool
  /-- The vault's phase of each row's order. -/
  phase : Nat → Phase
  /-- Fundings of each row's orders, ever. -/
  funds : Nat → Nat
  /-- Digests of the deposits the vault took from this buyer: the chain's
      `Funded` log, which names no row. -/
  deposits : List Nat
  /-- What refunds booked to the buyer and no claim has paid. -/
  owed : Nat
  now : Nat
  /-- The wallet's USDC. -/
  usdc : Nat

def upd {α : Type} (f : Nat → α) (i : Nat) (v : α) : Nat → α :=
  fun k => if k = i then v else f k

@[simp] theorem upd_same {α : Type} (f : Nat → α) (i : Nat) (v : α) : upd f i v i = v := by
  simp [upd]

@[simp] theorem upd_other {α : Type} (f : Nat → α) {i k : Nat} (v : α) (h : k ≠ i) :
    upd f i v k = f k := by
  simp [upd, h]

/-- What row `r` could still be funded for: its cap while an intent or a post
is open, and while a signed order is unfunded and inside its funding window;
nothing otherwise. A funded order's deposit has already left the wallet. -/
def expo (c : Config) (r : Nat) (jr : Journal) (ph : Phase) (now : Nat) : Nat :=
  match jr.open_ with
  | .intent _ => c.price r
  | .posted _ => c.price r
  | _ => if jr.signed ≠ [] ∧ ph = .empty ∧ now ≤ c.fundBy r then c.price r else 0

def exposure (c : Config) (s : State) (r : Nat) : Nat := expo c r (s.j r) (s.phase r) s.now

/-- What the desk has committed the wallet to, over all its rows. -/
def committed (c : Config) (s : State) : Nat := (c.ids.map (exposure c s)).sum

/-- One conjunct switched off, or one structure changed: the mutants. -/
inductive Drop where
  | model
  /-- One process per row: an offer reaches the desk that connected to the
      relay last, which holds only its own row. -/
  | lastDesk
  /-- No one-shot limit: a row may post again once its post is withdrawn. -/
  | first
  /-- Signing leaves the post open. -/
  | rearm
  /-- Each row checks only its own cap against the wallet (today's check in
      a one-row process). -/
  | overcommit
  /-- Each row's restart checks the deposits against its own journal (rule
      8 in a one-row process). -/
  | perRow
  /-- One journal for every row. -/
  | shared
  deriving DecidableEq, Repr

def key (d : Drop) (r : Nat) : Nat := if d = .shared then 0 else r
def jOf (d : Drop) (s : State) (r : Nat) : Journal := s.j (key d r)
def setJ (d : Drop) (s : State) (r : Nat) (v : Journal) : Nat → Journal := upd s.j (key d r) v

@[simp] theorem jOf_model (s : State) (r : Nat) : jOf .model s r = s.j r := rfl
@[simp] theorem setJ_model (s : State) (r : Nat) (v : Journal) : setJ .model s r v = upd s.j r v := rfl

/-- The row an offer for task `id` is routed to. -/
def routeWith (d : Drop) (c : Config) (s : State) (id : Nat) : Option Nat :=
  match d with
  | .lastDesk =>
    match c.ids.getLast? with
    | some r => if (jOf d s r).open_ = .posted id then some r else none
    | none => none
  | _ => c.ids.find? fun r => (jOf d s r).open_ == .posted id

def route (c : Config) (s : State) (id : Nat) : Option Nat := routeWith .model c s id

@[simp] theorem routeWith_model (c : Config) (s : State) (id : Nat) :
    routeWith .model c s id = c.ids.find? fun r => (s.j r).open_ == .posted id := rfl

/-- The wallet check before a row's intent: its cap and what every row has
committed (its own is nothing while nothing is open). -/
def coveredWith (d : Drop) (c : Config) (s : State) (r : Nat) : Bool :=
  match d with
  | .overcommit => decide (c.price r ≤ s.usdc)
  | _ => decide (c.price r + committed c s ≤ s.usdc)

@[simp] theorem coveredWith_model (c : Config) (s : State) (r : Nat) :
    coveredWith .model c s r = decide (c.price r + committed c s ≤ s.usdc) := rfl

/-- The restart's deposit check: every deposit from this buyer is an order
some row's journal signed for. -/
def explainsWith (d : Drop) (c : Config) (s : State) : Bool :=
  match d with
  | .perRow => c.ids.all fun r => s.deposits.all fun g => (jOf d s r).signed.contains g
  | _ => s.deposits.all fun g => c.ids.any fun r => (jOf d s r).signed.contains g

@[simp] theorem explainsWith_model (c : Config) (s : State) :
    explainsWith .model c s = s.deposits.all fun g => c.ids.any fun r => (s.j r).signed.contains g :=
  rfl

abbrev onBoard (s : State) (r id : Nat) : Prop := (id, false) ∈ s.board r ∨ (id, true) ∈ s.board r

inductive Act where
  | intent (row id : Nat)
  | send (row : Nat)
  | mine
  | drop
  /-- A crash and a restart: every row resumes from its journal. -/
  | restart
  | found (row : Nat)
  | abandon (row : Nat)
  | withdraw (row : Nat)
  /-- A seller's offer for a task ID, signed for at `digest` if it passes. -/
  | offer (id digest : Nat)
  | fund (row : Nat)
  | settle (row : Nat)
  | refund (row : Nat)
  | claim
  | settled (row : Nat)
  | refunded (row : Nat)
  | lapsed (row : Nat)
  | tick (seconds : Nat)
  deriving DecidableEq, Repr

def execWith (d : Drop) (c : Config) (s : State) : Act → Option State
  | .intent r id =>
    if r ∈ c.ids ∧ (jOf d s r).open_ = .none ∧ (d = .first ∨ (jOf d s r).posted = 0)
        ∧ ¬ onBoard s r id ∧ coveredWith d c s r = true then
      some { s with j := setJ d s r { jOf d s r with open_ := .intent id },
                    fresh := upd s.fresh r true }
    else none
  | .send r =>
    match (jOf d s r).open_ with
    | .intent id =>
      if r ∈ c.ids ∧ s.fresh r = true ∧ s.inflight = none then
        some { s with inflight := some (r, id), fresh := upd s.fresh r false }
      else none
    | _ => none
  | .mine =>
    match s.inflight with
    | some (r, id) => some { s with inflight := none, board := upd s.board r ((id, false) :: s.board r) }
    | none => none
  | .drop =>
    match s.inflight with
    | some _ => some { s with inflight := none }
    | none => none
  | .restart =>
    if explainsWith d c s = true then some { s with fresh := fun _ => false } else none
  | .found r =>
    match (jOf d s r).open_ with
    | .intent id =>
      if r ∈ c.ids ∧ (id, false) ∈ s.board r then
        some { s with j := setJ d s r { jOf d s r with open_ := .posted id,
                                                        posted := (jOf d s r).posted + 1 } }
      else none
    | _ => none
  | .abandon r =>
    match (jOf d s r).open_ with
    | .intent id =>
      if r ∈ c.ids ∧ ¬ onBoard s r id ∧ s.inflight = none ∧ s.fresh r = false then
        some { s with j := setJ d s r { jOf d s r with open_ := .none } }
      else none
    | _ => none
  | .withdraw r =>
    match (jOf d s r).open_ with
    | .posted id =>
      if r ∈ c.ids ∧ (id, false) ∈ s.board r then
        some { s with j := setJ d s r { jOf d s r with open_ := .none },
                      board := upd s.board r (LadderPost.withdrawIn id (s.board r)) }
      else none
    | _ => none
  | .offer id g =>
    match routeWith d c s id with
    | none => none
    | some r =>
      if r ∈ c.ids ∧ (jOf d s r).open_ = .posted id ∧ s.now ≤ c.fundBy r then
        some { s with
          j := setJ d s r { jOf d s r with
            open_ := if d = .rearm then .posted id else .signed id,
            signed := g :: (jOf d s r).signed },
          phase := upd s.phase r .empty }
      else none
  | .fund r =>
    match (jOf d s r).signed with
    | g :: _ =>
      if r ∈ c.ids ∧ s.phase r = .empty ∧ s.now ≤ c.fundBy r ∧ c.price r ≤ s.usdc then
        some { s with phase := upd s.phase r .funded, usdc := s.usdc - c.price r,
                      deposits := g :: s.deposits, funds := upd s.funds r (s.funds r + 1) }
      else none
    | [] => none
  | .settle r =>
    if r ∈ c.ids ∧ s.phase r = .funded ∧ s.now ≤ c.deliverBy r then
      some { s with phase := upd s.phase r .settled }
    else none
  | .refund r =>
    match (jOf d s r).open_ with
    | .signed _ =>
      if r ∈ c.ids ∧ s.phase r = .funded ∧ c.deliverBy r < s.now then
        some { s with phase := upd s.phase r .refunded, owed := s.owed + c.price r }
      else none
    | _ => none
  | .claim => some { s with owed := 0, usdc := s.usdc + s.owed }
  | .settled r =>
    match (jOf d s r).open_ with
    | .signed _ =>
      if r ∈ c.ids ∧ s.phase r = .settled then
        some { s with j := setJ d s r { jOf d s r with open_ := .none } }
      else none
    | _ => none
  | .refunded r =>
    match (jOf d s r).open_ with
    | .signed _ =>
      if r ∈ c.ids ∧ s.phase r = .refunded ∧ s.owed = 0 then
        some { s with j := setJ d s r { jOf d s r with open_ := .none } }
      else none
    | _ => none
  | .lapsed r =>
    match (jOf d s r).open_ with
    | .signed _ =>
      if r ∈ c.ids ∧ s.phase r = .empty ∧ c.fundBy r < s.now then
        some { s with j := setJ d s r { jOf d s r with open_ := .none } }
      else none
    | _ => none
  | .tick n => some { s with now := s.now + n }

/-- The desk. -/
def exec : Config → State → Act → Option State := execWith .model

/-- Run actions in order; `none` at the first one refused. -/
def runWith (d : Drop) (c : Config) : State → List Act → Option State
  | s, [] => some s
  | s, a :: as => (execWith d c s a).bind fun t => runWith d c t as

/-- Fresh journals, nothing posted, nothing in flight. -/
def initial (usdc now : Nat) : State :=
  { j := fun _ => Journal.empty, board := fun _ => [], inflight := none,
    fresh := fun _ => false, phase := fun _ => .empty, funds := fun _ => 0,
    deposits := [], owed := 0, now, usdc }

inductive Reachable (c : Config) (start : State) : State → Prop where
  | start : Reachable c start start
  | next {s t : State} (a : Act) : Reachable c start s → exec c s a = some t → Reachable c start t

/-! ## Each row is a one-row desk -/

def flightOf (f : Option (Nat × Nat)) (r : Nat) : Option Nat :=
  match f with
  | some (x, id) => if x = r then some id else none
  | none => none

/-- Row `r` as `LadderPost` sees a one-row desk. -/
def proj (s : State) (r : Nat) : LadderPost.State :=
  { open_ := (s.j r).open_, posted := (s.j r).posted, board := s.board r,
    inflight := flightOf s.inflight r, fresh := s.fresh r, phase := s.phase r,
    owed := s.owed, now := s.now, usdc := s.usdc, eth := 0 }

def terms (c : Config) (r : Nat) : LadderPost.Terms := ⟨c.price r, 0, c.fundBy r, c.deliverBy r⟩

/-- `LadderPost.Inv` reads only these five fields. -/
theorem inv_congr {a b : LadderPost.State} (h : LadderPost.Inv a)
    (e1 : b.open_ = a.open_) (e2 : b.posted = a.posted) (e3 : b.board = a.board)
    (e4 : b.inflight = a.inflight) (e5 : b.fresh = a.fresh) : LadderPost.Inv b := by
  obtain ⟨one, flight, fresh, before, intentFirst, after, live, atMostOne⟩ := h
  exact ⟨by rw [e3, e4]; exact one, by rw [e4, e1]; exact flight,
    by rw [e5, e4, e3, e1]; exact fresh, by rw [e2, e3, e1]; exact before,
    by rw [e1, e2]; exact intentFirst, by rw [e1, e2]; exact after,
    by rw [e1, e3]; exact live, by rw [e2]; exact atMostOne⟩

theorem step_to {k : LadderPost.Terms} {a b b' : LadderPost.State}
    (h : LadderPost.Step k a b) (e : b' = b) : LadderPost.Step k a b' := e ▸ h

theorem flightOf_none (r : Nat) : flightOf none r = none := rfl

theorem onBoard_iff {s : State} {r id : Nat} :
    onBoard s r id ↔ LadderPost.State.onBoard (proj s r) id := by
  constructor
  · rintro (h | h)
    · exact ⟨false, h⟩
    · exact ⟨true, h⟩
  · rintro ⟨w, h⟩
    cases w
    · exact Or.inl h
    · exact Or.inr h

/-! ## Sums over rows -/

theorem sum_le_sum {L : List Nat} {e e' : Nat → Nat} (h : ∀ x ∈ L, e' x ≤ e x) :
    (L.map e').sum ≤ (L.map e).sum := by
  induction L with
  | nil => simp
  | cons x xs ih =>
    simp only [List.map_cons, List.sum_cons]
    have h1 := h x (by simp)
    have h2 := ih (fun y hy => h y (by simp [hy]))
    omega

theorem sum_bump {L : List Nat} (nd : L.Nodup) {r : Nat} (hr : r ∈ L) {e e' : Nat → Nat}
    (other : ∀ x ∈ L, x ≠ r → e' x ≤ e x) :
    (L.map e').sum + e r ≤ (L.map e).sum + e' r := by
  induction L with
  | nil => simp at hr
  | cons x xs ih =>
    simp only [List.map_cons, List.sum_cons]
    rw [List.nodup_cons] at nd
    by_cases hx : x = r
    · subst hx
      have := sum_le_sum (L := xs) (e := e) (e' := e')
        (fun y hy => other y (by simp [hy]) (fun h => nd.1 (h ▸ hy)))
      omega
    · have hr' : r ∈ xs := by
        rcases List.mem_cons.mp hr with h | h
        · exact absurd h.symm hx
        · exact h
      have h1 := other x (by simp) hx
      have h2 := ih nd.2 hr' (fun y hy hne => other y (by simp [hy]) hne)
      omega

theorem sum_drop {L : List Nat} {r : Nat} (hr : r ∈ L) {e e' : Nat → Nat} {p : Nat}
    (all : ∀ x ∈ L, e' x ≤ e x) (at_r : e' r + p ≤ e r) :
    (L.map e').sum + p ≤ (L.map e).sum := by
  induction L with
  | nil => simp at hr
  | cons x xs ih =>
    simp only [List.map_cons, List.sum_cons]
    by_cases hx : x = r
    · subst hx
      have := sum_le_sum (L := xs) (e := e) (e' := e') (fun y hy => all y (by simp [hy]))
      omega
    · have hr' : r ∈ xs := by
        rcases List.mem_cons.mp hr with h | h
        · exact absurd h.symm hx
        · exact h
      have h1 := all x (by simp)
      have h2 := ih hr' (fun y hy => all y (by simp [hy]))
      omega

theorem expo_le_price (c : Config) (r : Nat) (jr : Journal) (ph : Phase) (now : Nat) :
    expo c r jr ph now ≤ c.price r := by
  unfold expo
  split
  · exact Nat.le_refl _
  · exact Nat.le_refl _
  · split <;> omega

theorem expo_open (c : Config) (r : Nat) (jr : Journal) (ph : Phase) (now : Nat)
    (h : (∃ id, jr.open_ = .intent id) ∨ (∃ id, jr.open_ = .posted id)) :
    expo c r jr ph now = c.price r := by
  unfold expo
  rcases h with ⟨id, h⟩ | ⟨id, h⟩ <;> rw [h]

/-- Outside an intent or a post, a row's exposure reads only its signed
orders, its phase and the clock. -/
theorem expo_closed (c : Config) (r : Nat) (jr : Journal) (ph : Phase) (now : Nat)
    (h1 : ∀ id, jr.open_ ≠ .intent id) (h2 : ∀ id, jr.open_ ≠ .posted id) :
    expo c r jr ph now
      = if jr.signed ≠ [] ∧ ph = .empty ∧ now ≤ c.fundBy r then c.price r else 0 := by
  unfold expo
  split
  · rename_i id h; exact absurd h (h1 id)
  · rename_i id h; exact absurd h (h2 id)
  · rfl

/-! ## The invariant -/

structure MInv (c : Config) (s : State) : Prop where
  lp : ∀ r ∈ c.ids, LadderPost.Inv (proj s r)
  /-- A row signs only for its own post, so no more often than it posted. -/
  sl : ∀ r ∈ c.ids, (s.j r).signed.length ≤ (s.j r).posted
  /-- After a signature, no intent or post is open again. -/
  so : ∀ r ∈ c.ids, (s.j r).signed ≠ [] →
    ∀ id, (s.j r).open_ ≠ .intent id ∧ (s.j r).open_ ≠ .posted id
  fl : ∀ r ∈ c.ids, s.funds r ≤ (s.j r).signed.length
  fe : ∀ r ∈ c.ids, s.phase r = .empty → s.funds r = 0
  /-- Every deposit is an order some row's journal signed for. -/
  ex : ∀ g ∈ s.deposits, ∃ r ∈ c.ids, g ∈ (s.j r).signed
  over : committed c s ≤ s.usdc

theorem ite_some {p : Prop} [Decidable p] {α : Type} {x y : α}
    (h : (if p then some x else none) = some y) : p ∧ x = y := by
  by_cases hp : p
  · simp only [hp, ↓reduceIte, Option.some.injEq] at h; exact ⟨hp, h⟩
  · simp [hp] at h

theorem sum_zero {L : List Nat} {e : Nat → Nat} (h : ∀ x ∈ L, e x = 0) : (L.map e).sum = 0 := by
  induction L with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.map_cons, List.sum_cons]
    rw [h x (by simp), ih (fun y hy => h y (by simp [hy]))]

theorem initial_minv (c : Config) (usdc now : Nat) : MInv c (initial usdc now) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro r _
    exact inv_congr (LadderPost.initial_inv usdc 0 now) rfl rfl rfl rfl rfl
  · intro r _; simp [initial, Journal.empty]
  · intro r _ h; simp [initial, Journal.empty] at h
  · intro r _; simp [initial]
  · intro r _ _; rfl
  · intro g hg; simp [initial] at hg
  · have : committed c (initial usdc now) = 0 :=
      sum_zero (fun r _ => by simp [exposure, expo, initial, Journal.empty])
    rw [this]; exact Nat.zero_le _

theorem ex_keep {c : Config} {s t : State}
    (h : ∀ g ∈ s.deposits, ∃ r ∈ c.ids, g ∈ (s.j r).signed)
    (dep : t.deposits = s.deposits) (keep : ∀ r, ∀ g ∈ (s.j r).signed, g ∈ (t.j r).signed) :
    ∀ g ∈ t.deposits, ∃ r ∈ c.ids, g ∈ (t.j r).signed := by
  intro g hg
  rw [dep] at hg
  obtain ⟨r, hr, hs⟩ := h g hg
  exact ⟨r, hr, keep r g hs⟩

/-- The wallet check, once for each way a step moves exposure. -/
theorem over_mono {c : Config} {s t : State} (over : committed c s ≤ s.usdc)
    (each : ∀ x ∈ c.ids, exposure c t x ≤ exposure c s x) (u : s.usdc ≤ t.usdc) :
    committed c t ≤ t.usdc :=
  Nat.le_trans (sum_le_sum each) (Nat.le_trans over u)

theorem over_intent {c : Config} (wf : c.ids.Nodup) {r : Nat} (hr : r ∈ c.ids) {s t : State}
    (other : ∀ x ∈ c.ids, x ≠ r → exposure c t x ≤ exposure c s x)
    (zero : exposure c s r = 0) (cov : c.price r + committed c s ≤ s.usdc)
    (u : t.usdc = s.usdc) : committed c t ≤ t.usdc := by
  have := sum_bump wf hr (e := exposure c s) (e' := exposure c t) other
  have hp : exposure c t r ≤ c.price r := expo_le_price _ _ _ _ _
  unfold committed at cov ⊢
  omega

theorem over_fund {c : Config} {r : Nat} (hr : r ∈ c.ids) {s t : State}
    (over : committed c s ≤ s.usdc)
    (all : ∀ x ∈ c.ids, exposure c t x ≤ exposure c s x)
    (at_r : exposure c t r + c.price r ≤ exposure c s r)
    (covered : c.price r ≤ s.usdc) (u : t.usdc = s.usdc - c.price r) :
    committed c t ≤ t.usdc := by
  have := sum_drop hr all at_r
  unfold committed at over ⊢
  omega

theorem expo_phase (c : Config) (r : Nat) (jr : Journal) {ph ph' : Phase} (now : Nat)
    (h : ph' ≠ .empty) : expo c r jr ph' now ≤ expo c r jr ph now := by
  unfold expo
  split
  · exact Nat.le_refl _
  · exact Nat.le_refl _
  · simp [h]

theorem expo_now (c : Config) (r : Nat) (jr : Journal) (ph : Phase) {now now' : Nat}
    (h : now ≤ now') : expo c r jr ph now' ≤ expo c r jr ph now := by
  unfold expo
  split
  · exact Nat.le_refl _
  · exact Nat.le_refl _
  · by_cases g : jr.signed ≠ [] ∧ ph = .empty ∧ now' ≤ c.fundBy r
    · simp [g, Nat.le_trans h g.2.2]
    · simp only [g, ↓reduceIte]; exact Nat.zero_le _

/-- A row whose intent or post is open is exposed at its cap, and closing it
can only lower that. -/
theorem expo_from_open (c : Config) (r : Nat) (jr jr' : Journal) (ph ph' : Phase) (now : Nat)
    (h : (∃ id, jr.open_ = .intent id) ∨ (∃ id, jr.open_ = .posted id)) :
    expo c r jr' ph' now ≤ expo c r jr ph now := by
  rw [expo_open c r jr ph now h]; exact expo_le_price _ _ _ _ _

theorem no_open_of_signed {c : Config} {s : State} (h : MInv c s) {r : Nat} (hr : r ∈ c.ids)
    {g : Nat} {rest : List Nat} (hs : (s.j r).signed = g :: rest) :
    ∀ id, (s.j r).open_ ≠ .intent id ∧ (s.j r).open_ ≠ .posted id :=
  h.so r hr (by rw [hs]; exact List.cons_ne_nil _ _)

theorem signed_nil_of_open {c : Config} {s : State} (h : MInv c s) {r : Nat} (hr : r ∈ c.ids)
    (ho : (∃ id, (s.j r).open_ = .intent id) ∨ (∃ id, (s.j r).open_ = .posted id)) :
    (s.j r).signed = [] := by
  cases hs : (s.j r).signed with
  | nil => rfl
  | cons g rest =>
    have := no_open_of_signed h hr hs
    rcases ho with ⟨id, ho⟩ | ⟨id, ho⟩
    · exact absurd ho (this id).1
    · exact absurd ho (this id).2

/-- The invariant for a step that rewrites row `r`'s journal to `jr` with the
same signed orders and posts no more than once more, touching nothing else
the invariant reads but the board. Used for `found`, `abandon`, `withdraw`,
`settled`, `refunded` and `lapsed`; the `LadderPost` part is the caller's. -/
theorem minv_rewrite {c : Config} {s t : State} (h : MInv c s) {r : Nat} (hr : r ∈ c.ids)
    {jr : Journal} (tj : t.j = upd s.j r jr)
    (lp : ∀ x ∈ c.ids, LadderPost.Inv (proj t x))
    (signed : jr.signed = (s.j r).signed) (posted : (s.j r).posted ≤ jr.posted)
    (closes : jr.signed ≠ [] → ∀ id, jr.open_ ≠ .intent id ∧ jr.open_ ≠ .posted id)
    (tp : t.phase = s.phase) (tf : t.funds = s.funds) (td : t.deposits = s.deposits)
    (tn : t.now = s.now) (tu : t.usdc = s.usdc)
    (exp : expo c r jr (s.phase r) s.now ≤ expo c r (s.j r) (s.phase r) s.now) : MInv c t := by
  refine ⟨lp, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro x hx
    by_cases hxr : x = r
    · subst hxr; rw [tj, upd_same, signed]; exact Nat.le_trans (h.sl x hx) posted
    · rw [tj, upd_other _ _ hxr]; exact h.sl x hx
  · intro x hx
    by_cases hxr : x = r
    · subst hxr; rw [tj, upd_same]; exact closes
    · rw [tj, upd_other _ _ hxr]; exact h.so x hx
  · intro x hx
    by_cases hxr : x = r
    · subst hxr; rw [tj, upd_same, signed, tf]; exact h.fl x hx
    · rw [tj, upd_other _ _ hxr, tf]; exact h.fl x hx
  · intro x hx; rw [tp, tf]; exact h.fe x hx
  · exact ex_keep h.ex td (fun x g hg => by
      by_cases hxr : x = r
      · subst hxr; rw [tj, upd_same, signed]; exact hg
      · rw [tj, upd_other _ _ hxr]; exact hg)
  · refine over_mono h.over (fun x _ => ?_) (by rw [tu]; exact Nat.le_refl _)
    unfold exposure
    rw [tj, tp, tn]
    by_cases hxr : x = r
    · subst hxr; rw [upd_same]; exact exp
    · rw [upd_other _ _ hxr]; exact Nat.le_refl _

theorem lp_frame {s t : State} {r : Nat} (h : LadderPost.Inv (proj s r))
    (j : t.j r = s.j r) (b : t.board r = s.board r) (f : flightOf t.inflight r = flightOf s.inflight r)
    (fr : t.fresh r = s.fresh r) : LadderPost.Inv (proj t r) :=
  inv_congr h (by simp [proj, j]) (by simp [proj, j]) (by simp [proj, b]) (by simp [proj, f])
    (by simp [proj, fr])

theorem step_minv {c : Config} (wf : c.ids.Nodup) {s t : State} {a : Act}
    (h : MInv c s) (e : exec c s a = some t) : MInv c t := by
  cases a with
  | intent r id =>
    simp only [exec, execWith, jOf_model, setJ_model, coveredWith_model] at e
    obtain ⟨⟨hr, idle, first, fresh_, cov⟩, rfl⟩ := ite_some e
    have first : (s.j r).posted = 0 := by simpa using first
    simp only [decide_eq_true_eq] at cov
    have signed0 : (s.j r).signed = [] := by
      have := h.sl r hr; rw [first] at this
      exact List.eq_nil_of_length_eq_zero (by omega)
    refine ⟨?_, ?_, ?_, ?_, h.fe, ?_, ?_⟩
    · intro x hx
      by_cases hxr : x = r
      · subst hxr
        refine LadderPost.step_inv (k := terms c x) (h.lp x hx) <| step_to (LadderPost.Step.intent (proj s x) id idle first
          ((not_congr onBoard_iff).mp fresh_) (by simp [proj, terms]; omega) (by simp [terms, proj])) ?_
        simp [proj, upd]
      · exact lp_frame (h.lp x hx) (by simp [upd, hxr]) rfl rfl (by simp [upd, hxr])
    · intro x hx
      by_cases hxr : x = r
      · subst hxr; simp [signed0]
      · simp only [upd_other _ _ hxr]; exact h.sl x hx
    · intro x hx hne
      by_cases hxr : x = r
      · subst hxr; simp [signed0] at hne
      · simp only [upd_other _ _ hxr] at hne ⊢; exact h.so x hx hne
    · intro x hx
      by_cases hxr : x = r
      · subst hxr; simp only [upd_same]; exact h.fl x hx
      · simp only [upd_other _ _ hxr]; exact h.fl x hx
    · exact ex_keep h.ex rfl (fun x g hg => by
        by_cases hxr : x = r
        · subst hxr; simpa using hg
        · simpa [upd_other _ _ hxr] using hg)
    · refine over_intent wf hr (fun x _ hxr => ?_) ?_ cov rfl
      · simp [exposure, upd_other _ _ hxr]
      · simp [exposure, expo, idle, signed0]
  | send r =>
    simp only [exec, execWith, jOf_model] at e
    split at e
    · rename_i id ho
      obtain ⟨⟨hr, here, quiet⟩, rfl⟩ := ite_some e
      refine ⟨?_, h.sl, h.so, h.fl, h.fe, h.ex, h.over⟩
      intro x hx
      by_cases hxr : x = r
      · subst hxr
        refine LadderPost.step_inv (k := terms c x) (h.lp x hx) <| step_to (LadderPost.Step.send (proj s x) id ho here (by simp [proj, quiet, flightOf])) ?_
        simp [proj, upd, flightOf]
      · exact lp_frame (h.lp x hx) rfl rfl
          (by simp [flightOf, quiet, Ne.symm hxr]) (by simp [upd, hxr])
    · cases e
  | mine =>
    simp only [exec, execWith] at e
    split at e
    · rename_i r id hf
      cases e
      refine ⟨?_, h.sl, h.so, h.fl, h.fe, h.ex, h.over⟩
      intro x hx
      by_cases hxr : x = r
      · subst hxr
        refine LadderPost.step_inv (k := terms c x) (h.lp x hx) <| step_to (LadderPost.Step.mine (proj s x) id (by simp [proj, hf, flightOf])) ?_
        simp [proj, upd, flightOf]
      · exact lp_frame (h.lp x hx) rfl (by simp [upd, hxr])
          (by simp [flightOf, hf, Ne.symm hxr]) rfl
    · cases e
  | drop =>
    simp only [exec, execWith] at e
    split at e
    · rename_i f hf
      cases e
      obtain ⟨r, id⟩ := f
      refine ⟨?_, h.sl, h.so, h.fl, h.fe, h.ex, h.over⟩
      intro x hx
      by_cases hxr : x = r
      · subst hxr
        refine LadderPost.step_inv (k := terms c x) (h.lp x hx) <| step_to (LadderPost.Step.drop (proj s x) id (by simp [proj, hf, flightOf])) ?_
        simp [proj, flightOf]
      · exact lp_frame (h.lp x hx) rfl rfl (by simp [flightOf, hf, Ne.symm hxr]) rfl
    · cases e
  | restart =>
    simp only [exec, execWith, explainsWith_model] at e
    obtain ⟨_, rfl⟩ := ite_some e
    refine ⟨?_, h.sl, h.so, h.fl, h.fe, h.ex, h.over⟩
    intro x hx
    exact LadderPost.step_inv (k := terms c x) (h.lp x hx) <| step_to (LadderPost.Step.crash (proj s x)) (by simp [proj])
  | found r =>
    simp only [exec, execWith, jOf_model, setJ_model] at e
    split at e
    · rename_i id ho
      obtain ⟨⟨hr, there⟩, rfl⟩ := ite_some e
      have s0 := signed_nil_of_open h hr (Or.inl ⟨id, ho⟩)
      refine minv_rewrite h hr rfl ?_ rfl (Nat.le_succ _) (by simp [s0]) rfl rfl rfl rfl rfl
        (expo_from_open _ _ _ _ _ _ _ (Or.inl ⟨id, ho⟩))
      intro x hx
      by_cases hxr : x = r
      · subst hxr
        refine LadderPost.step_inv (k := terms c x) (h.lp x hx) <| step_to (LadderPost.Step.found (proj s x) id ho there) ?_
        simp [proj, upd]
      · exact lp_frame (h.lp x hx) (by simp [upd, hxr]) rfl rfl rfl
    · cases e
  | abandon r =>
    simp only [exec, execWith, jOf_model, setJ_model] at e
    split at e
    · rename_i id ho
      obtain ⟨⟨hr, gone, quiet, restarted⟩, rfl⟩ := ite_some e
      refine minv_rewrite h hr rfl ?_ rfl (Nat.le_refl _) (by simp) rfl rfl rfl rfl rfl
        (expo_from_open _ _ _ _ _ _ _ (Or.inl ⟨id, ho⟩))
      intro x hx
      by_cases hxr : x = r
      · subst hxr
        refine LadderPost.step_inv (k := terms c x) (h.lp x hx) <| step_to (LadderPost.Step.abandon (proj s x) id ho ((not_congr onBoard_iff).mp gone)
          (by simp [proj, quiet, flightOf]) restarted) ?_
        simp [proj, upd]
      · exact lp_frame (h.lp x hx) (by simp [upd, hxr]) rfl rfl rfl
    · cases e
  | withdraw r =>
    simp only [exec, execWith, jOf_model, setJ_model] at e
    split at e
    · rename_i id ho
      obtain ⟨⟨hr, live⟩, rfl⟩ := ite_some e
      refine minv_rewrite h hr rfl ?_ rfl (Nat.le_refl _) (by simp) rfl rfl rfl rfl rfl
        (expo_from_open _ _ _ _ _ _ _ (Or.inr ⟨id, ho⟩))
      intro x hx
      by_cases hxr : x = r
      · subst hxr
        refine LadderPost.step_inv (k := terms c x) (h.lp x hx) <| step_to (LadderPost.Step.withdraw (proj s x) id ho live) ?_
        simp [proj, upd]
      · exact lp_frame (h.lp x hx) (by simp [upd, hxr]) (by simp [upd, hxr]) rfl rfl
    · cases e
  | offer id g =>
    simp only [exec, execWith, jOf_model, setJ_model, routeWith_model] at e
    split at e
    · cases e
    · rename_i r _
      obtain ⟨⟨hr, ho, _⟩, rfl⟩ := ite_some e
      have s0 := signed_nil_of_open h hr (Or.inr ⟨id, ho⟩)
      have p1 : 1 ≤ (s.j r).posted := (h.lp r hr).after id (Or.inl ho)
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
      · intro x hx
        by_cases hxr : x = r
        · subst hxr
          refine LadderPost.step_inv (k := terms c x) (h.lp x hx) <| step_to (LadderPost.Step.sign (proj s x) id ho) ?_
          simp [proj, upd]
        · exact lp_frame (h.lp x hx) (by simp [upd, hxr]) rfl rfl rfl
      · intro x hx
        by_cases hxr : x = r
        · subst hxr; simp [s0]; exact p1
        · simp only [upd_other _ _ hxr]; exact h.sl x hx
      · intro x hx
        by_cases hxr : x = r
        · subst hxr; simp
        · simp only [upd_other _ _ hxr]; exact h.so x hx
      · intro x hx
        by_cases hxr : x = r
        · subst hxr; simp only [upd_same]; have := h.fl x hx; simp [s0] at this ⊢; omega
        · simp only [upd_other _ _ hxr]; exact h.fl x hx
      · intro x hx hp
        by_cases hxr : x = r
        · subst hxr; have := h.fl x hx; simp [s0] at this; exact this
        · simp only [upd_other _ _ hxr] at hp; exact h.fe x hx hp
      · exact ex_keep h.ex rfl (fun x g' hg => by
          by_cases hxr : x = r
          · subst hxr; simp [hg]
          · simpa [upd_other _ _ hxr] using hg)
      · refine over_mono h.over (fun x _ => ?_) (Nat.le_refl _)
        unfold exposure
        by_cases hxr : x = r
        · subst hxr; simp only [upd_same]
          exact expo_from_open _ _ _ _ _ _ _ (Or.inr ⟨id, ho⟩)
        · simp only [upd_other _ _ hxr]; exact Nat.le_refl _
  | fund r =>
    simp only [exec, execWith, jOf_model] at e
    split at e
    · rename_i g rest hs
      obtain ⟨⟨hr, empty, inTime, covered⟩, rfl⟩ := ite_some e
      have closed := no_open_of_signed h hr hs
      refine ⟨?_, h.sl, h.so, ?_, ?_, ?_, ?_⟩
      · intro x hx; exact lp_frame (h.lp x hx) rfl rfl rfl rfl
      · intro x hx
        by_cases hxr : x = r
        · subst hxr; simp only [upd_same]; have := h.fe x hx empty; rw [this, hs]; simp
        · simp only [upd_other _ _ hxr]; exact h.fl x hx
      · intro x hx hp
        by_cases hxr : x = r
        · subst hxr; simp at hp
        · simp only [upd_other _ _ hxr] at hp ⊢; exact h.fe x hx hp
      · intro g' hg
        rcases List.mem_cons.mp hg with hg | hg
        · exact ⟨r, hr, by rw [hg, hs]; simp⟩
        · exact h.ex g' hg
      · refine over_fund hr h.over (fun x _ => ?_) ?_ covered rfl
        · unfold exposure
          by_cases hxr : x = r
          · subst hxr; simp only [upd_same]; exact expo_phase _ _ _ _ (by simp)
          · simp only [upd_other _ _ hxr]; exact Nat.le_refl _
        · unfold exposure
          simp only [upd_same]
          rw [expo_closed _ _ _ _ _ (fun id => (closed id).1) (fun id => (closed id).2),
            expo_closed _ _ _ _ _ (fun id => (closed id).1) (fun id => (closed id).2)]
          simp [hs, empty, inTime]
    · cases e
  | settle r =>
    simp only [exec, execWith] at e
    obtain ⟨⟨hr, funded, _⟩, rfl⟩ := ite_some e
    refine ⟨fun x hx => lp_frame (h.lp x hx) rfl rfl rfl rfl, h.sl, h.so, h.fl, ?_, h.ex, ?_⟩
    · intro x hx hp
      by_cases hxr : x = r
      · subst hxr; simp at hp
      · simp only [upd_other _ _ hxr] at hp; exact h.fe x hx hp
    · refine over_mono h.over (fun x _ => ?_) (Nat.le_refl _)
      unfold exposure
      by_cases hxr : x = r
      · subst hxr; simp only [upd_same]
        exact expo_phase _ _ _ _ (by simp)
      · simp only [upd_other _ _ hxr]; exact Nat.le_refl _

  | refund r =>
    simp only [exec, execWith, jOf_model] at e
    split at e
    · obtain ⟨⟨hr, funded, _⟩, rfl⟩ := ite_some e
      refine ⟨fun x hx => lp_frame (h.lp x hx) rfl rfl rfl rfl, h.sl, h.so, h.fl, ?_, h.ex, ?_⟩
      · intro x hx hp
        by_cases hxr : x = r
        · subst hxr; simp at hp
        · simp only [upd_other _ _ hxr] at hp; exact h.fe x hx hp
      · refine over_mono h.over (fun x _ => ?_) (Nat.le_refl _)
        unfold exposure
        by_cases hxr : x = r
        · subst hxr; simp only [upd_same]; exact expo_phase _ _ _ _ (by simp)
        · simp only [upd_other _ _ hxr]; exact Nat.le_refl _
    · cases e
  | claim =>
    simp only [exec, execWith] at e
    cases e
    exact ⟨fun x hx => lp_frame (h.lp x hx) rfl rfl rfl rfl, h.sl, h.so, h.fl, h.fe, h.ex,
      Nat.le_trans h.over (Nat.le_add_right _ _)⟩
  | settled r =>
    simp only [exec, execWith, jOf_model, setJ_model] at e
    split at e
    · rename_i id ho
      obtain ⟨⟨hr, done⟩, rfl⟩ := ite_some e
      refine minv_rewrite h hr rfl ?_ rfl (Nat.le_refl _) (by simp) rfl rfl rfl rfl rfl
        (by rw [expo_closed _ _ _ _ _ (by simp) (by simp),
              expo_closed _ _ _ _ _ (by simp [ho]) (by simp [ho])]; exact Nat.le_refl _)
      intro x hx
      by_cases hxr : x = r
      · subst hxr
        refine LadderPost.step_inv (k := terms c x) (h.lp x hx) <| step_to (LadderPost.Step.settled (proj s x) id ho done) ?_
        simp [proj, upd]
      · exact lp_frame (h.lp x hx) (by simp [upd, hxr]) rfl rfl rfl
    · cases e
  | refunded r =>
    simp only [exec, execWith, jOf_model, setJ_model] at e
    split at e
    · rename_i id ho
      obtain ⟨⟨hr, done, paid⟩, rfl⟩ := ite_some e
      refine minv_rewrite h hr rfl ?_ rfl (Nat.le_refl _) (by simp) rfl rfl rfl rfl rfl
        (by rw [expo_closed _ _ _ _ _ (by simp) (by simp),
              expo_closed _ _ _ _ _ (by simp [ho]) (by simp [ho])]; exact Nat.le_refl _)
      intro x hx
      by_cases hxr : x = r
      · subst hxr
        refine LadderPost.step_inv (k := terms c x) (h.lp x hx) <| step_to (LadderPost.Step.refunded (proj s x) id ho done paid) ?_
        simp [proj, upd]
      · exact lp_frame (h.lp x hx) (by simp [upd, hxr]) rfl rfl rfl
    · cases e
  | lapsed r =>
    simp only [exec, execWith, jOf_model, setJ_model] at e
    split at e
    · rename_i id ho
      obtain ⟨⟨hr, empty, late⟩, rfl⟩ := ite_some e
      refine minv_rewrite h hr rfl ?_ rfl (Nat.le_refl _) (by simp) rfl rfl rfl rfl rfl
        (by rw [expo_closed _ _ _ _ _ (by simp) (by simp),
              expo_closed _ _ _ _ _ (by simp [ho]) (by simp [ho])]; exact Nat.le_refl _)
      intro x hx
      by_cases hxr : x = r
      · subst hxr
        refine LadderPost.step_inv (k := terms c x) (h.lp x hx) <| step_to (LadderPost.Step.lapsed (proj s x) id ho empty late) ?_
        simp [proj, upd]
      · exact lp_frame (h.lp x hx) (by simp [upd, hxr]) rfl rfl rfl
    · cases e
  | tick n =>
    simp only [exec, execWith] at e
    cases e
    exact ⟨fun x hx => lp_frame (h.lp x hx) rfl rfl rfl rfl, h.sl, h.so, h.fl, h.fe, h.ex,
      over_mono h.over (fun x _ => expo_now _ _ _ _ (Nat.le_add_right _ _)) (Nat.le_refl _)⟩

theorem reachable_minv {c : Config} (wf : c.ids.Nodup) {usdc now : Nat} {s : State}
    (r : Reachable c (initial usdc now) s) : MInv c s := by
  induction r with
  | start => exact initial_minv c usdc now
  | next _ _ e ih => exact step_minv wf ih e

/-! ## What the desk guarantees -/

theorem le_sum_of_mem {L : List Nat} {r : Nat} (hr : r ∈ L) (e : Nat → Nat) :
    e r ≤ (L.map e).sum := by
  induction L with
  | nil => simp at hr
  | cons x xs ih =>
    simp only [List.map_cons, List.sum_cons]
    rcases List.mem_cons.mp hr with h | h
    · subst h; omega
    · have := ih h; omega

/-- **An offer goes to the row its task ID names.** The row is the one whose
journal holds that post; it is signed for there and in no other journal. -/
theorem offer_routed {c : Config} {s t : State} {id g : Nat}
    (e : exec c s (.offer id g) = some t) :
    ∃ r, route c s id = some r ∧ r ∈ c.ids ∧ (s.j r).open_ = .posted id ∧
      (t.j r).open_ = .signed id ∧ g ∈ (t.j r).signed ∧ ∀ x, x ≠ r → t.j x = s.j x := by
  simp only [exec, execWith, jOf_model, setJ_model, routeWith_model] at e
  split at e
  · cases e
  · rename_i r hroute
    obtain ⟨⟨hr, ho, _⟩, rfl⟩ := ite_some e
    exact ⟨r, hroute, hr, ho, by simp, by simp, fun x hx => by simp [upd, hx]⟩

/-- **An offer naming no held task is refused.** -/
theorem offer_refused {c : Config} {s : State} {id : Nat} (g : Nat)
    (none_ : ∀ r ∈ c.ids, (s.j r).open_ ≠ .posted id) : exec c s (.offer id g) = none := by
  have : c.ids.find? (fun r => (s.j r).open_ == .posted id) = none := by
    rw [List.find?_eq_none]; intro r hr; simpa using none_ r hr
  simp only [exec, execWith, routeWith_model, this]

/-- **At most one post per row, ever**, whatever crashes, restarts, dropped
transactions and resumptions happen. -/
theorem at_most_one_post {c : Config} (wf : c.ids.Nodup) {usdc now : Nat} {s : State}
    (reach : Reachable c (initial usdc now) s) {r : Nat} (hr : r ∈ c.ids) :
    (s.board r).length ≤ 1 :=
  Nat.le_trans (Nat.le_add_right _ _) ((reachable_minv wf reach).lp r hr).one

theorem posted_at_most_once {c : Config} (wf : c.ids.Nodup) {usdc now : Nat} {s : State}
    (reach : Reachable c (initial usdc now) s) {r : Nat} (hr : r ∈ c.ids) :
    (s.j r).posted ≤ 1 :=
  ((reachable_minv wf reach).lp r hr).atMostOne

/-- **Single winner per row.** A row signs for one order at most, and its
orders are funded once at most: once funded, settled or refunded, no second
order for the row is funded. -/
theorem single_winner {c : Config} (wf : c.ids.Nodup) {usdc now : Nat} {s : State}
    (reach : Reachable c (initial usdc now) s) {r : Nat} (hr : r ∈ c.ids) :
    (s.j r).signed.length ≤ 1 ∧ s.funds r ≤ 1 := by
  have h := reachable_minv wf reach
  have := h.sl r hr
  have := h.fl r hr
  have := (h.lp r hr).atMostOne
  exact ⟨by simp [proj] at *; omega, by simp [proj] at *; omega⟩

/-- **No overcommit.** What every row could still be funded for is covered by
the wallet. -/
theorem no_overcommit {c : Config} (wf : c.ids.Nodup) {usdc now : Nat} {s : State}
    (reach : Reachable c (initial usdc now) s) : committed c s ≤ s.usdc :=
  (reachable_minv wf reach).over

/-- **At each funding** the row being funded is counted in what the desk has
committed, and the sum of every row still fundable is within the wallet: no
funding ever finds the wallet short. -/
theorem funding_covered {c : Config} (wf : c.ids.Nodup) {usdc now : Nat} {s : State}
    (reach : Reachable c (initial usdc now) s) {r : Nat} (hr : r ∈ c.ids) {g : Nat}
    {rest : List Nat} (hs : (s.j r).signed = g :: rest) (empty : s.phase r = .empty)
    (inTime : s.now ≤ c.fundBy r) :
    c.price r ≤ committed c s ∧ committed c s ≤ s.usdc := by
  have h := reachable_minv wf reach
  have closed := no_open_of_signed h hr hs
  have : exposure c s r = c.price r := by
    unfold exposure
    rw [expo_closed _ _ _ _ _ (fun id => (closed id).1) (fun id => (closed id).2)]
    simp [hs, empty, inTime]
  exact ⟨this ▸ le_sum_of_mem hr (exposure c s), h.over⟩

/-- **A restart never refuses over another row's deposit.** The check is over
the union of the rows' journals, and every deposit is an order one of them
signed for. -/
theorem restart_admitted {c : Config} (wf : c.ids.Nodup) {usdc now : Nat} {s : State}
    (reach : Reachable c (initial usdc now) s) : exec c s .restart ≠ none := by
  have h := reachable_minv wf reach
  simp [exec, execWith, explainsWith_model]
  exact h.ex

/-- **Removing a row touches no other row.** A withdrawal changes no other
row's journal or posts. -/
theorem withdraw_frame {c : Config} {s t : State} {r : Nat}
    (e : exec c s (.withdraw r) = some t) : ∀ x, x ≠ r → t.j x = s.j x ∧ t.board x = s.board x := by
  simp only [exec, execWith, jOf_model, setJ_model] at e
  split at e
  · obtain ⟨_, rfl⟩ := ite_some e
    intro x hx; exact ⟨by simp [upd, hx], by simp [upd, hx]⟩
  · cases e

/-- A lapse at the funding deadline changes no other row's journal. -/
theorem lapsed_frame {c : Config} {s t : State} {r : Nat}
    (e : exec c s (.lapsed r) = some t) : ∀ x, x ≠ r → t.j x = s.j x := by
  simp only [exec, execWith, jOf_model, setJ_model] at e
  split at e
  · obtain ⟨_, rfl⟩ := ite_some e
    intro x hx; simp [upd, hx]
  · cases e

/-- Every step writes one row's journal at most. -/
theorem journal_frame {c : Config} {s t : State} {a : Act} (e : exec c s a = some t) :
    ∃ r, ∀ x, x ≠ r → t.j x = s.j x := by
  cases a <;> simp only [exec, execWith, jOf_model, setJ_model, routeWith_model] at e
  case intent r id =>
    obtain ⟨_, rfl⟩ := ite_some e; exact ⟨r, fun x hx => by simp [upd, hx]⟩
  case found r | abandon r | withdraw r | settled r | refunded r | lapsed r =>
    split at e
    · obtain ⟨_, rfl⟩ := ite_some e; exact ⟨r, fun x hx => by simp [upd, hx]⟩
    · cases e
  case offer id g =>
    split at e
    · cases e
    · rename_i r _
      obtain ⟨_, rfl⟩ := ite_some e; exact ⟨r, fun x hx => by simp [upd, hx]⟩
  case send r | refund r =>
    split at e
    · obtain ⟨_, rfl⟩ := ite_some e; exact ⟨0, fun _ _ => rfl⟩
    · cases e
  case mine | drop =>
    split at e
    · cases e; exact ⟨0, fun _ _ => rfl⟩
    · cases e
  case fund r =>
    split at e
    · obtain ⟨_, rfl⟩ := ite_some e; exact ⟨0, fun _ _ => rfl⟩
    · cases e
  case restart | settle r =>
    obtain ⟨_, rfl⟩ := ite_some e; exact ⟨0, fun _ _ => rfl⟩
  case claim | tick n =>
    cases e; exact ⟨0, fun _ _ => rfl⟩

/-! ## The three rows

S0001 (40 USDC) and S0007 (30 USDC) as their journals have them, posted on
2026-11-19; S0006 (40 USDC) posted from the same desk on 2026-11-27, with a
14-day funding and 16-day delivery window; the wallet's 110 USDC. Task IDs
are 11, 17 and 16, digests 101, 107 and 106. The Rust desk's golden test
(`contracts/agents/src/ladder.rs`, `the_lean_table`) replays G1 to G8. -/

def price : Nat → Nat
  | 1 => 40000000
  | 7 => 30000000
  | 6 => 40000000
  | _ => 0

def ladderWith (p : Nat → Nat) : Config :=
  { ids := [1, 7, 6], price := p,
    fundBy := fun r => if r = 1 then 1796286711 else if r = 7 then 1796286740 else 1796979600,
    deliverBy := fun r => if r = 1 then 1796459511 else if r = 7 then 1796459540 else 1797152400 }

def ladder : Config := ladderWith price

theorem ladder_wf : ladder.ids.Nodup := by decide

/-- Posted on 2026-11-19 08:31:51. -/
def s₀ (usdc : Nat) : State := initial usdc 1795077111

def post (r id : Nat) : List Act := [.intent r id, .send r, .mine, .found r]

/-- The history: S0001 and S0007 posted, the desks lost, the host desk
started on 2026-11-27 resuming both. -/
def resumed : List Act := post 1 11 ++ post 7 17 ++ [.tick 693000, .restart]

def three : List Act := resumed ++ post 6 16

def after (d : Drop) (c : Config) (usdc : Nat) (acts : List Act) : Option State :=
  runWith d c (s₀ usdc) acts

/-- G1: S0001 and S0007 posted commit 70 USDC; S0006 at 40 is admitted
against 110, and then all 110 are committed. -/
example : (after .model ladder 110000000 resumed).map (committed ladder) = some 70000000 := by decide
example : (after .model ladder 110000000 three).map (committed ladder) = some 110000000 := by decide

/-- G2: one base unit short, S0006 is refused. -/
example : (after .model ladder 109999999 three).isSome = false := by decide

/-- G3: S0006 at one base unit over 40 USDC is refused against 110. -/
example : (after .model (ladderWith fun r => if r = 6 then 40000001 else price r) 110000000 three).isSome
    = false := by decide

/-- G4: an offer for S0001's task routes to row 1; an offer for a task no row
holds is refused. -/
example : (after .model ladder 110000000 three).map (fun s => route ladder s 11) = some (some 1) := by
  decide
example : (after .model ladder 110000000 (three ++ [.offer 99 199])).isSome = false := by decide

/-- G5: S0001 signed for and not yet funded is still committed at its cap. -/
example : (after .model ladder 110000000 (three ++ [.offer 11 101])).map (committed ladder)
    = some 110000000 := by decide

/-- G6: S0001 funded: the wallet holds 70, S0001 commits nothing more, and the
restart's union check admits the deposit; S0007's own journal could not. -/
def funded : List Act := three ++ [.offer 11 101, .fund 1]
example : (after .model ladder 110000000 funded).map (fun s => (s.usdc, committed ladder s))
    = some (70000000, 70000000) := by decide
example : (after .model ladder 110000000 (funded ++ [.restart])).isSome = true := by decide

/-- G7: a second order for S0001 is refused: the row is signed for. -/
example : (after .model ladder 110000000 (funded ++ [.offer 11 102])).isSome = false := by decide

/-- G8: past S0001's funding deadline unfunded, its signed order commits
nothing, and lapsing it leaves S0007's and S0006's journals as they were. -/
example : (after .model ladder 110000000 (three ++ [.offer 11 101, .tick 1209601])).map
    (fun s => exposure ladder s 1) = some 0 := by decide
example : (after .model ladder 110000000 (three ++ [.offer 11 101, .tick 1209601, .lapsed 1])).map
    (fun s => ((s.j 1).open_ == .none, (s.j 7).open_ == .posted 17, (s.j 6).open_ == .posted 16))
    = some (true, true, true) := by decide

/-- A restarted desk does not post S0001 again: its journal counts the post. -/
example : (after .model ladder 110000000 (resumed ++ [.intent 1 12])).isSome = false := by decide

/-! ## Mutants

Each theorem above has a mutant that breaks it, shown by a run the kernel
checks. If a guard or a structure of the desk changes this way, one of these
is the run it would admit. -/

/-- One process per row: an offer reaches the desk that connected last
(S0006's), so an offer for S0001's post is refused although it is open. -/
theorem mutant_lastDesk_breaks_offer_routed :
    (after .lastDesk ladder 110000000 (three ++ [.offer 11 101])).isSome = false ∧
    (after .model ladder 110000000 (three ++ [.offer 11 101])).isSome = true := by decide

/-- No one-shot limit: S0001 withdrawn and posted again, two posts on the
board for one row. -/
theorem mutant_first_breaks_at_most_one_post :
    (after .first ladder 110000000 (post 1 11 ++ [.withdraw 1] ++ post 1 12)).map
      (fun s => (s.board 1).length) = some 2 ∧
    (after .model ladder 110000000 (post 1 11 ++ [.withdraw 1] ++ post 1 12)).isSome = false := by
  decide

/-- Signing leaves the post open: a second seller is signed for and funds,
and S0001 is paid for twice. -/
theorem mutant_rearm_breaks_single_winner :
    (after .rearm ladder 110000000 (three ++ [.offer 11 101, .fund 1, .offer 11 102, .fund 1])).map
      (fun s => s.funds 1) = some 2 := by decide

/-- Each row checks only its own cap: with 100 USDC, S0006 is posted on top
of S0001 and S0007 and the desk is committed to 110. -/
theorem mutant_overcommit_breaks_no_overcommit :
    (after .overcommit ladder 100000000 three).map (fun s => (committed ladder s, s.usdc))
      = some (110000000, 100000000) ∧
    (after .model ladder 100000000 three).isSome = false := by decide

/-- Each row checks deposits against its own journal: once S0001 is funded,
the restart is refused. -/
theorem mutant_perRow_breaks_restart_admitted :
    (after .perRow ladder 110000000 (funded ++ [.restart])).isSome = false := by decide

/-- One journal for every row (the standing bounty's ledger): S0007 cannot be
posted while S0001 is open, and withdrawing S0001 changes what S0007 reads. -/
theorem mutant_shared_breaks_journal_frame :
    (after .shared ladder 110000000 (post 1 11 ++ post 7 17)).isSome = false ∧
    (after .shared ladder 110000000 (post 1 11)).map (fun s => (jOf .shared s 7).open_ == .posted 11)
      = some true := by decide

end Nucleus.ProofCommerce.LadderMulti

namespace Nucleus.ProofCommerce.LadderMulti
/-- info: 'Nucleus.ProofCommerce.LadderMulti.offer_routed' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms offer_routed
/-- info: 'Nucleus.ProofCommerce.LadderMulti.offer_refused' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms offer_refused
/-- info: 'Nucleus.ProofCommerce.LadderMulti.at_most_one_post' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms at_most_one_post
/-- info: 'Nucleus.ProofCommerce.LadderMulti.posted_at_most_once' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms posted_at_most_once
/-- info: 'Nucleus.ProofCommerce.LadderMulti.single_winner' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms single_winner
/-- info: 'Nucleus.ProofCommerce.LadderMulti.no_overcommit' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms no_overcommit
/-- info: 'Nucleus.ProofCommerce.LadderMulti.funding_covered' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms funding_covered
/-- info: 'Nucleus.ProofCommerce.LadderMulti.restart_admitted' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms restart_admitted
/-- info: 'Nucleus.ProofCommerce.LadderMulti.withdraw_frame' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms withdraw_frame
/-- info: 'Nucleus.ProofCommerce.LadderMulti.lapsed_frame' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms lapsed_frame
/-- info: 'Nucleus.ProofCommerce.LadderMulti.journal_frame' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms journal_frame
end Nucleus.ProofCommerce.LadderMulti
