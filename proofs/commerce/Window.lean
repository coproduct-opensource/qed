import Std
set_option warningAsError true

/- The offer window of one posted row: offers are collected, and at the
   window's close exactly one is signed for, the lowest. A model of the
   window in `contracts/agents/src/desk.rs`; it signs nothing.
   docs/rfcs/qed-proof-carrying-savings-2026-11-28.md, which supersedes owner
   decision 6 ("first offer that passes review wins").

   The window opens at the first offer that passes review and closes `W`
   seconds later, or at the post's funding deadline if that is sooner. An
   offer that arrives once the window is due, or at or after the funding
   deadline, is refused. At the close each held offer is reviewed again at
   the closing time (its order must still leave `lead` seconds to relay
   `fund`), and of those that pass, the one with the least amount is
   signed for; between equal amounts, the earliest. The others are refused.
   If none passes, nothing is signed, the window is discarded, and the
   next offer opens a new one.

   Why a window and not the first offer: with the first offer winning, a
   seller has no reason to offer less than the post's cap, and the saving
   (`Savings.lean`) is always zero. With the lowest offer in a window
   winning, the saving is what competition finds.

   `LadderMulti.lean` models a row signing for one offer (`.offer id g`);
   the window decides which `g`, and releases at most one, so its
   `single_winner` still holds. -/
namespace Nucleus.ProofCommerce.Window

/-- An offer that passed review: its ticket (the order's digest), amount,
    arrival (stamped by the desk) and its order's funding deadline. -/
structure Offer where
  ticket : Nat
  amount : Nat
  arrival : Nat
  fundBy : Nat
  deriving DecidableEq, Repr

structure Params where
  /-- `W`: how long the window stays open after its first offer. -/
  window : Nat
  /-- The post's funding deadline. -/
  fundBy : Nat
  /-- How long an order must leave to relay `fund` when it is signed. -/
  lead : Nat

inductive Ev where
  /-- An offer that passed review, at `o.arrival`. -/
  | offer (o : Offer)
  | tick (now : Nat)

structure St where
  now : Nat
  /-- When the window opened: the first held offer's arrival. -/
  first : Option Nat
  /-- Held offers, in arrival order. -/
  held : List Offer
  /-- When the window closed. -/
  closedAt : Option Nat
  /-- The offers signed for. -/
  signed : List Offer

def init : St := ⟨0, none, [], none, []⟩

/-- The rules, as switches; the model is `Rule.model`. -/
structure Rule where
  /-- Off: the first offer is signed for on arrival (owner decision 6). -/
  window : Bool := true
  /-- Off: the first held offer is signed for, not the least. -/
  minimum : Bool := true
  /-- Off: between equal amounts the later wins. -/
  earliest : Bool := true
  /-- Off: offers are not reviewed again at the close. -/
  recheck : Bool := true
  /-- Off: an offer after the close opens a new window. -/
  once : Bool := true
  /-- Off: the window may run past the post's funding deadline. -/
  capFund : Bool := true

def Rule.model : Rule := {}

def closeAt (r : Rule) (P : Params) (first : Nat) : Nat :=
  if r.capFund then min (first + P.window) P.fundBy else first + P.window

def eligible (r : Rule) (P : Params) (now : Nat) (o : Offer) : Bool :=
  !r.recheck || decide (now + P.lead ≤ o.fundBy)

/-- The least amount, the earliest of equals (the list is in arrival order). -/
def pick (r : Rule) : List Offer → Option Offer
  | [] => none
  | o :: rest =>
    match pick r rest with
    | none => some o
    | some b =>
      if !r.minimum then some o
      else if b.amount < o.amount || (!r.earliest && b.amount == o.amount) then some b
      else some o

def due (r : Rule) (P : Params) (s : St) (now : Nat) : Bool :=
  match s.first, s.closedAt with
  | some f, none => decide (closeAt r P f ≤ now)
  | _, _ => false

/-- The close: the pick is signed for. When no held offer still passes
    review, nothing is signed and the window is discarded; the post stays
    open and the next offer opens a new window. -/
def close (r : Rule) (P : Params) (s : St) : St :=
  if due r P s s.now then
    match pick r (s.held.filter (eligible r P s.now)) with
    | some g => { s with closedAt := some s.now, signed := s.signed ++ [g] }
    | none => { s with first := none, held := [], closedAt := none }
  else s

def admit (r : Rule) (P : Params) (s : St) (o : Offer) : St :=
  let o' := { o with arrival := s.now }
  if !r.window then
    (if s.signed = [] ∧ s.now < P.fundBy then
      { s with first := some s.now, held := [o'], closedAt := some s.now, signed := [o'] }
    else s)
  else if s.closedAt.isSome then
    (if r.once then s else { s with first := some s.now, held := [o'], closedAt := none })
  else if P.fundBy ≤ s.now then s
  else { s with held := s.held ++ [o'], first := some (s.first.getD s.now) }

def step (r : Rule) (P : Params) (s : St) : Ev → St
  | .tick t => close r P { s with now := max s.now t }
  | .offer o => admit r P (close r P { s with now := max s.now o.arrival }) o

def run (r : Rule) (P : Params) (s : St) (es : List Ev) : St := es.foldl (step r P) s

/-! ## Lemmas -/

theorem pick_some (r : Rule) : ∀ l : List Offer, l ≠ [] → (pick r l).isSome
  | [], h => absurd rfl h
  | o :: rest, _ => by
      simp only [pick]; split
      · rfl
      · split
        · rfl
        · split <;> rfl

/-- What the model's pick is: a member, least, and earliest of equals. -/
theorem pick_spec : ∀ (l : List Offer) (g : Offer), l.Pairwise (·.arrival ≤ ·.arrival) →
    pick .model l = some g →
    g ∈ l ∧ ∀ o ∈ l, g.amount ≤ o.amount ∧ (o.amount = g.amount → g.arrival ≤ o.arrival)
  | [], _, _, h => by simp [pick] at h
  | o :: rest, g, hs, h => by
      have hs' := List.pairwise_cons.mp hs
      simp only [pick, Rule.model] at h
      split at h
      · rename_i hn
        simp only [Option.some.injEq] at h; subst h
        have : rest = [] := by
          cases rest with
          | nil => rfl
          | cons x xs => have := pick_some ({} : Rule) (x :: xs) (by simp); rw [hn] at this; simp at this
        subst this
        simp
      · rename_i b hb
        obtain ⟨bm, bl⟩ := pick_spec rest b hs'.2 hb
        simp only [Bool.not_true, Bool.false_and, Bool.or_false,
          decide_eq_true_eq, Bool.false_eq_true, ↓reduceIte] at h
        split at h
        · rename_i hlt
          simp only [Option.some.injEq] at h; subst h
          refine ⟨List.mem_cons_of_mem _ bm, ?_⟩
          intro x hx
          rcases List.mem_cons.mp hx with rfl | hx
          · exact ⟨Nat.le_of_lt hlt, fun e => absurd e (by omega)⟩
          · exact bl x hx
        · rename_i hlt
          simp only [Option.some.injEq] at h; subst h
          refine ⟨List.mem_cons_self, ?_⟩
          intro x hx
          rcases List.mem_cons.mp hx with rfl | hx
          · exact ⟨Nat.le_refl _, fun _ => Nat.le_refl _⟩
          · have := bl x hx
            exact ⟨by omega, fun _ => hs'.1 x hx⟩

theorem pick_length (r : Rule) (l : List Offer) : (pick r l).toList.length ≤ 1 := by
  cases pick r l <;> simp

/-- The invariant every reachable state keeps. -/
structure Inv (P : Params) (s : St) : Prop where
  sorted : s.held.Pairwise (·.arrival ≤ ·.arrival)
  le_now : ∀ o ∈ s.held, o.arrival ≤ s.now
  before_fund : ∀ o ∈ s.held, o.arrival < P.fundBy
  closed : match s.closedAt with
    | none => s.signed = []
    | some t => ∃ f, s.first = some f ∧ closeAt .model P f ≤ t ∧ t ≤ s.now ∧
        s.signed = (pick .model (s.held.filter (eligible .model P t))).toList

theorem inv_init (P : Params) : Inv P init :=
  ⟨by simp [init], by simp [init], by simp [init], by simp [init]⟩

/-- Moving the clock forward keeps the invariant. -/
theorem inv_later (P : Params) (s : St) (t : Nat) (h : Inv P s) (ht : s.now ≤ t) :
    Inv P { s with now := t } := by
  refine ⟨h.sorted, fun o ho => Nat.le_trans (h.le_now o ho) ht, h.before_fund, ?_⟩
  have hc := h.closed
  simp only
  split
  · rename_i e; rw [e] at hc; exact hc
  · rename_i t' e; rw [e] at hc
    obtain ⟨f, hf, hle, hn, hs⟩ := hc
    exact ⟨f, hf, hle, Nat.le_trans hn ht, hs⟩

theorem inv_close (P : Params) (s : St) (h : Inv P s) : Inv P (close .model P s) := by
  unfold close
  split
  · rename_i hd
    unfold due at hd
    split at hd
    · rename_i f hf hc
      have hs : s.signed = [] := by have := h.closed; rw [hc] at this; exact this
      split
      · rename_i g hp
        refine ⟨h.sorted, h.le_now, h.before_fund, ?_⟩
        simp only
        refine ⟨f, hf, by simpa using hd, Nat.le_refl _, ?_⟩
        rw [hs, List.nil_append, hp]; rfl
      · refine ⟨by simp, by simp, by simp, ?_⟩
        simp only; exact hs
    · simp at hd
  · exact h

theorem inv_admit (P : Params) (s : St) (o : Offer) (h : Inv P s) : Inv P (admit .model P s o) := by
  unfold admit
  simp only [Rule.model, Bool.not_true, Bool.false_eq_true, ↓reduceIte]
  split
  · exact h
  · split
    · exact h
    · rename_i hc hf
      have hnone : s.closedAt = none := by
        cases e : s.closedAt with
        | none => rfl
        | some _ => rw [e] at hc; simp at hc
      have hcl := h.closed
      rw [hnone] at hcl
      refine ⟨?_, ?_, ?_, ?_⟩
      · simp only
        rw [List.pairwise_append]
        refine ⟨h.sorted, List.pairwise_singleton _ _, ?_⟩
        intro a ha b hb
        simp only [List.mem_singleton] at hb; subst hb
        exact h.le_now a ha
      · simp only [List.mem_append, List.mem_singleton]
        rintro x (hx | rfl)
        · exact h.le_now x hx
        · exact Nat.le_refl _
      · simp only [List.mem_append, List.mem_singleton]
        rintro x (hx | rfl)
        · exact h.before_fund x hx
        · simp only; omega
      · simp only [hnone]; exact hcl

theorem inv_step (P : Params) (s : St) (e : Ev) (h : Inv P s) : Inv P (step .model P s e) := by
  cases e with
  | tick t => exact inv_close P _ (inv_later P s _ h (Nat.le_max_left _ _))
  | offer o => exact inv_admit P _ o (inv_close P _ (inv_later P s _ h (Nat.le_max_left _ _)))

theorem inv_run (P : Params) : ∀ (es : List Ev) (s : St), Inv P s → Inv P (run .model P s es)
  | [], _, h => h
  | e :: es, s, h => inv_run P es (step .model P s e) (inv_step P s e h)

theorem reachable (P : Params) (es : List Ev) : Inv P (run .model P init es) :=
  inv_run P es init (inv_init P)

/-! ## Theorems -/

/-- **The lowest offer is signed for**: the signed offer was held, still
    passed review at the close, and every held offer that did is at least
    as dear; of equal amounts it arrived first. -/
theorem signs_min (P : Params) (es : List Ev) (g : Offer)
    (hg : g ∈ (run .model P init es).signed) :
    let s := run .model P init es
    g ∈ s.held ∧ ∃ t, s.closedAt = some t ∧ eligible .model P t g = true ∧
      ∀ o ∈ s.held, eligible .model P t o = true →
        g.amount ≤ o.amount ∧ (o.amount = g.amount → g.arrival ≤ o.arrival) := by
  intro s
  have h := reachable P es
  have hc := h.closed
  split at hc
  · rename_i e; rw [hc] at hg; simp at hg
  · rename_i t e
    obtain ⟨_, _, _, _, hs⟩ := hc
    rw [hs] at hg
    cases hp : pick .model ((run .model P init es).held.filter (eligible .model P t)) with
    | none => rw [hp] at hg; simp at hg
    | some g' =>
      rw [hp] at hg
      simp only [Option.toList_some, List.mem_singleton] at hg; subst hg
      obtain ⟨gm, gl⟩ := pick_spec _ _ (h.sorted.filter _) hp
      have gm' := List.mem_filter.mp gm
      refine ⟨gm'.1, t, e, gm'.2, fun o ho oe => gl o (List.mem_filter.mpr ⟨ho, oe⟩)⟩

/-- **One winner**: at most one offer is ever signed for, so the row's
    `.offer` act of `LadderMulti.lean` happens at most once and its
    `single_winner` is preserved. -/
theorem single_winner_preserved (P : Params) (es : List Ev) :
    (run .model P init es).signed.length ≤ 1 := by
  have hc := (reachable P es).closed
  split at hc
  · rw [hc]; simp
  · obtain ⟨_, _, _, _, hs⟩ := hc; rw [hs]; exact pick_length _ _

/-- **Nothing is signed before the close**: when an offer has been signed
    for, the window closed at or after its due time, `W` after its first
    offer or the funding deadline. -/
theorem no_sign_before_close (P : Params) (es : List Ev)
    (hne : (run .model P init es).signed ≠ []) :
    ∃ f t, (run .model P init es).first = some f ∧ (run .model P init es).closedAt = some t ∧
      min (f + P.window) P.fundBy ≤ t := by
  have hc := (reachable P es).closed
  split at hc
  · exact absurd hc hne
  · rename_i t e
    obtain ⟨f, hf, hle, _, _⟩ := hc
    exact ⟨f, t, hf, e, by simpa [closeAt, Rule.model] using hle⟩

/-- **The window ends by the funding deadline**, and no offer is held at
    or after it. -/
theorem window_within_fundBy (P : Params) (es : List Ev) :
    (∀ f, closeAt .model P f ≤ P.fundBy) ∧
      ∀ o ∈ (run .model P init es).held, o.arrival < P.fundBy :=
  ⟨fun f => by simp only [closeAt, Rule.model, ↓reduceIte]; exact Nat.min_le_right _ _, (reachable P es).before_fund⟩

end Nucleus.ProofCommerce.Window

/-! ## Examples and mutants

A 10-minute window on a post whose funding deadline is 10000; an order
must leave 60 s to relay `fund`. Offers: A at 100 for 30, B at 200 for 25,
C at 300 for 25. -/
namespace Nucleus.ProofCommerce.Window.Examples
open Nucleus.ProofCommerce.Window

def P : Params := ⟨600, 10000, 60⟩
def A : Offer := ⟨1, 30, 100, 9000⟩
def B : Offer := ⟨2, 25, 200, 9000⟩
def C : Offer := ⟨3, 25, 300, 9000⟩
def three : List Ev := [.offer A, .offer B, .offer C, .tick 700]

def signed (r : Rule) (P : Params) (es : List Ev) : List Nat :=
  (run r P init es).signed.map (·.ticket)

/-- B, the least, earlier than C at the same amount; at 700. -/
theorem lowest_signed :
    signed .model P three = [2] ∧ (run .model P init three).closedAt = some 700 := by decide

/-- Before 700 nothing is signed. -/
theorem nothing_before_close : signed .model P [.offer A, .offer B, .tick 699] = [] := by decide

/-- An offer after the close is refused; nothing more is signed. -/
theorem late_offer_refused :
    signed .model P (three ++ [.offer ⟨4, 1, 800, 9000⟩, .tick 2000]) = [2] := by decide

/-- B's order would leave too little time to relay `fund` at the close:
    C is signed for. -/
def staleB : List Ev := [.offer A, .offer ⟨2, 25, 200, 700⟩, .offer C, .tick 700]
theorem stale_skipped : signed .model P staleB = [3] := by decide

/-- Every held offer stale at the close: nothing is signed, and the next
    offer opens a new window, signed for at its own close. -/
def allStale : List Ev :=
  [.offer ⟨1, 30, 100, 650⟩, .tick 700, .offer ⟨5, 28, 800, 9000⟩, .tick 1399, .tick 1400]
theorem all_stale_reopens :
    signed .model P (allStale.take 2) = [] ∧ signed .model P (allStale.take 4) = [] ∧
      signed .model P allStale = [5] := by decide

/-- A funding deadline at 500 closes the window then, before its 10 minutes. -/
def early : Params := ⟨600, 500, 60⟩
theorem closes_at_fundBy :
    (run .model early init [.offer A, .tick 500]).closedAt = some 500 := by decide

/-! ### Mutants: each theorem with one switch turned -/

/-- W1, against `signs_min` and `no_sign_before_close`: the first offer
    wins on arrival (owner decision 6). A, the dearest, at 100. -/
theorem mutant_window_breaks_signs_min :
    signed { window := false } P three = [1] ∧
      (run { window := false } P init three).closedAt = some 100 := by decide

/-- W2, against `signs_min`: the first held offer, not the least. -/
theorem mutant_minimum_breaks_signs_min : signed { minimum := false } P three = [1] := by decide

/-- W3, against `signs_min`: of equal amounts the later. -/
theorem mutant_earliest_breaks_signs_min : signed { earliest := false } P three = [3] := by decide

/-- W4, against `signs_min`: no review at the close. B is signed for with
    too little time left to fund. -/
theorem mutant_recheck_breaks_signs_min : signed { recheck := false } P staleB = [2] := by decide

/-- W5, against `single_winner_preserved`: a late offer opens a second window. -/
theorem mutant_once_breaks_single_winner :
    signed { once := false } P (three ++ [.offer ⟨4, 1, 800, 9000⟩, .tick 2000]) = [2, 4] := by
  decide

/-- W6, against `window_within_fundBy`: the window runs to 700, past 500. -/
theorem mutant_capFund_breaks_window_within_fundBy :
    early.fundBy < closeAt { capFund := false } early 100 := by decide

end Nucleus.ProofCommerce.Window.Examples

namespace Nucleus.ProofCommerce.Window
/-- info: 'Nucleus.ProofCommerce.Window.signs_min' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms signs_min
/-- info: 'Nucleus.ProofCommerce.Window.single_winner_preserved' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms single_winner_preserved
/-- info: 'Nucleus.ProofCommerce.Window.no_sign_before_close' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms no_sign_before_close
/-- info: 'Nucleus.ProofCommerce.Window.window_within_fundBy' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms window_within_fundBy
end Nucleus.ProofCommerce.Window
