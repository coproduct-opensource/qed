import Std
set_option warningAsError true

/- Paying the shares of a saving (`Savings.lean`), v1: off chain, by the
   buyer's desk, from the buyer's wallet. A model of
   `contracts/agents/src/payout.rs`; it moves no funds.
   docs/rfcs/qed-proof-carrying-savings-2026-11-28.md.

   Each share owed (an order, a role, a party, an amount) is paid by one
   EIP-3009 `transferWithAuthorization` whose nonce is derived from those
   four. The token records a used nonce and refuses it again, so the
   exactly-once rule is the token's state, not the desk's memory: a desk
   that restarts reads the token and pays only what is unpaid.

   A payment is admitted only when:
   * the share is owed (it is one of the shares the split names);
   * its nonce is unused on the token;
   * the wallet covers it on top of everything the desk has committed to
     open rows (`LadderMulti.committed`): paying a share never leaves a
     row's possible funding uncovered.
   * the wallet's ether covers the transfer's gas: the buyer pays its own
     gas (owner decision, 2026-11-28), and a share it cannot pay gas for is
     journaled owed and alerted, never attempted. -/
namespace Nucleus.ProofCommerce.Payout

structure Share where
  order : Nat
  /-- 0: the referrer; 1: an author. -/
  role : Nat
  party : Nat
  amount : Nat
  deriving DecidableEq, Repr

/-- The nonce a share's transfer carries: a function of the share alone. -/
def nonce (x : Share) : Nat × Nat × Nat × Nat := (x.order, x.role, x.party, x.amount)

structure St where
  /-- The buyer wallet's balance. -/
  balance : Nat
  /-- What open rows could still be funded for. -/
  committed : Nat
  /-- Nonces the token has recorded as used. -/
  used : List (Nat × Nat × Nat × Nat)
  /-- Transfers made, in order. -/
  paid : List Share
  /-- The wallet's ether, which pays each transfer's gas. -/
  eth : Nat
  /-- What one transfer's gas would cost now. -/
  fee : Nat

inductive Act where
  /-- Pay a share. -/
  | pay (x : Share)
  /-- Commit `c` more to an open row (LadderMulti's intent and post). -/
  | commit (c : Nat)
  /-- A row's commitment of `c` ends (funded, lapsed, withdrawn). -/
  | release (c : Nat)
  /-- The wallet receives `n`. -/
  | deposit (n : Nat)
  /-- The wallet receives `n` ether. -/
  | ether (n : Nat)
  /-- The desk restarts: the token's state and the wallet persist. -/
  | restart

/-- The rules, as switches; the model is `Rule.model`. -/
structure Rule where
  owed : Bool := true
  once : Bool := true
  cover : Bool := true
  gas : Bool := true

def Rule.model : Rule := {}

def admits (r : Rule) (owed : List Share) (s : St) (x : Share) : Bool :=
  (!r.owed || owed.contains x) && (!r.once || !s.used.contains (nonce x)) &&
    (!r.cover || decide (x.amount + s.committed ≤ s.balance)) &&
    (!r.gas || decide (s.fee ≤ s.eth))

def step (r : Rule) (owed : List Share) (s : St) : Act → St
  | .pay x =>
    if admits r owed s x then
      { s with balance := s.balance - x.amount, used := nonce x :: s.used, paid := s.paid ++ [x],
               eth := s.eth - s.fee }
    else s
  | .commit c => if s.committed + c ≤ s.balance then { s with committed := s.committed + c } else s
  | .release c => { s with committed := s.committed - c }
  | .deposit n => { s with balance := s.balance + n }
  | .ether n => { s with eth := s.eth + n }
  | .restart => s

def run (r : Rule) (owed : List Share) (s : St) (as : List Act) : St := as.foldl (step r owed) s

/-- The invariant every reachable state keeps. -/
structure Inv (owed : List Share) (s : St) : Prop where
  covered : s.committed ≤ s.balance
  owed_ : ∀ x ∈ s.paid, x ∈ owed
  used_ : ∀ x ∈ s.paid, nonce x ∈ s.used
  once : s.paid.Pairwise (fun a b => nonce a ≠ nonce b)

theorem inv_step (owed : List Share) (s : St) (a : Act) (h : Inv owed s) :
    Inv owed (step .model owed s a) := by
  cases a with
  | pay x =>
    simp only [step]
    split
    · rename_i hx
      simp only [admits, Rule.model, Bool.not_true, Bool.false_or, Bool.and_eq_true,
        List.contains_iff_mem, Bool.not_eq_true', decide_eq_true_eq] at hx
      obtain ⟨⟨⟨ho, hu⟩, hc⟩, _⟩ := hx
      have hu' : nonce x ∉ s.used := by simpa using hu
      refine ⟨by simp only; omega, ?_, ?_, ?_⟩
      · simp only [List.mem_append, List.mem_singleton]
        rintro y (hy | rfl)
        · exact h.owed_ y hy
        · exact ho
      · intro y hy
        rcases List.mem_append.mp hy with hy | hy
        · exact List.mem_cons_of_mem _ (h.used_ y hy)
        · rw [List.mem_singleton.mp hy]; exact List.mem_cons_self
      · simp only
        rw [List.pairwise_append]
        refine ⟨h.once, List.pairwise_singleton _ _, ?_⟩
        intro a ha b hb e
        simp only [List.mem_singleton] at hb; subst hb
        exact hu' (e ▸ h.used_ a ha)
    · exact h
  | commit c =>
    simp only [step]; split
    · rename_i hc; exact ⟨by simp only; omega, h.owed_, h.used_, h.once⟩
    · exact h
  | release c => exact ⟨by simp only [step]; have := h.covered; omega, h.owed_, h.used_, h.once⟩
  | deposit n => exact ⟨by simp only [step]; have := h.covered; omega, h.owed_, h.used_, h.once⟩
  | ether n => exact ⟨by simp only [step]; exact h.covered, h.owed_, h.used_, h.once⟩
  | restart => exact h

theorem inv_run (owed : List Share) :
    ∀ (as : List Act) (s : St), Inv owed s → Inv owed (run .model owed s as)
  | [], _, h => h
  | a :: as, s, h => inv_run owed as (step .model owed s a) (inv_step owed s a h)

/-! ## Theorems -/

/-- **Exactly once**: no two transfers carry one share's nonce, whatever
    restarts and retries happen. -/
theorem paid_once (owed : List Share) (s : St) (h : Inv owed s) (as : List Act) :
    (run .model owed s as).paid.Pairwise (fun a b => nonce a ≠ nonce b) :=
  (inv_run owed as s h).once

/-- **Only what is owed is paid.** -/
theorem only_owed (owed : List Share) (s : St) (h : Inv owed s) (as : List Act) :
    ∀ x ∈ (run .model owed s as).paid, x ∈ owed :=
  (inv_run owed as s h).owed_

/-- **No overcommit**: paying shares never leaves the open rows' possible
    funding uncovered (`LadderMulti.no_overcommit`, with the payouts drawn
    from the same wallet). -/
theorem no_overcommit (owed : List Share) (s : St) (h : Inv owed s) (as : List Act) :
    (run .model owed s as).committed ≤ (run .model owed s as).balance :=
  (inv_run owed as s h).covered

/-- **No unaffordable send**: a transfer is made only when the wallet's
    ether covers its gas. A share the desk cannot pay gas for is not
    attempted; the code journals it owed and raises an alert. -/
theorem no_unaffordable_send (owed : List Share) (s : St) (x : Share)
    (h : (step .model owed s (.pay x)).paid ≠ s.paid) : s.fee ≤ s.eth := by
  simp only [step] at h
  split at h
  · rename_i hx
    simp only [admits, Rule.model, Bool.not_true, Bool.false_or, Bool.and_eq_true,
      decide_eq_true_eq] at hx
    exact hx.2
  · exact absurd rfl h

/-- **A restart pays nothing twice**: a share paid before a restart is
    refused after it. -/
theorem restart_safe (owed : List Share) (s : St) (h : Inv owed s) (x : Share)
    (hx : x ∈ s.paid) : step .model owed (step .model owed s .restart) (.pay x) = s := by
  simp only [step, admits, Rule.model, Bool.not_true, Bool.false_or]
  have hm := h.used_ x hx
  simp [hm]

end Nucleus.ProofCommerce.Payout

namespace Nucleus.ProofCommerce.Payout.Examples
open Nucleus.ProofCommerce.Payout

/-- The S0006 split of `Savings.Examples.s0006_split`: 4.5 USDC to the
    referrer, 3 to the author. A 40 USDC row is open. -/
def referrer : Share := ⟨106, 0, 0xF00, 4500000⟩
def author : Share := ⟨106, 1, 0xA1, 3000000⟩
def owed : List Share := [referrer, author]
def s₀ : St := ⟨50000000, 40000000, [], [], 1000, 10⟩

def paidAfter (r : Rule) (as : List Act) : List Share := (run r owed s₀ as).paid

theorem both_paid : paidAfter .model [.pay referrer, .pay author] = [referrer, author] := by decide

theorem retry_after_restart :
    paidAfter .model [.pay referrer, .restart, .pay referrer, .pay author] = [referrer, author] := by
  decide

/-- With 40 committed of 44, the 4.5 USDC share waits; the 3 is paid. -/
def tight : St := ⟨44000000, 40000000, [], [], 1000, 10⟩
theorem waits_for_cover :
    (run .model owed tight [.pay referrer, .pay author]).paid = [author] := by decide

/-! ### Mutants -/

/-- P1, against `paid_once`: no nonce check; the retry pays again. -/
theorem mutant_once_breaks_paid_once :
    paidAfter { once := false } [.pay referrer, .restart, .pay referrer] = [referrer, referrer] := by
  decide

/-- P2, against `only_owed`: a share nobody owes is paid. -/
theorem mutant_owed_breaks_only_owed :
    paidAfter { owed := false } [.pay ⟨106, 0, 0xBAD, 9000000⟩] = [⟨106, 0, 0xBAD, 9000000⟩] := by
  decide

/-- P3, against `no_overcommit`: no cover check; 40 committed, 39.5 left. -/
theorem mutant_cover_breaks_no_overcommit :
    let s := run { cover := false } owed tight [.pay referrer]
    s.balance < s.committed := by decide

/-- No ether for gas: nothing is sent. -/
def dry : St := ⟨50000000, 40000000, [], [], 5, 10⟩
theorem no_gas_no_send : (run .model owed dry [.pay referrer, .pay author]).paid = [] := by decide

/-- P4, against `no_unaffordable_send`: no gas check; a transfer is sent
    with 5 of the 10 its gas costs. -/
theorem mutant_gas_breaks_no_unaffordable_send :
    (run { gas := false } owed dry [.pay referrer]).paid = [referrer] ∧ dry.eth < dry.fee := by
  decide

end Nucleus.ProofCommerce.Payout.Examples

namespace Nucleus.ProofCommerce.Payout
/-- info: 'Nucleus.ProofCommerce.Payout.paid_once' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms paid_once
/-- info: 'Nucleus.ProofCommerce.Payout.only_owed' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms only_owed
/-- info: 'Nucleus.ProofCommerce.Payout.no_overcommit' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms no_overcommit
/-- info: 'Nucleus.ProofCommerce.Payout.restart_safe' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms restart_safe
/-- info: 'Nucleus.ProofCommerce.Payout.no_unaffordable_send' depends on axioms: [propext] -/
#guard_msgs in #print axioms no_unaffordable_send
end Nucleus.ProofCommerce.Payout
