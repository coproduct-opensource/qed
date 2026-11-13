import Std
set_option warningAsError true

/- The base registry (contracts/vault/src/BaseRegistry.sol). A model; it
   holds no funds and moves none.

   An entry says who is paid when an order builds on a base, and at what
   rate. `Proved base axioms payee bps` is an external fact: the proof
   verifier accepted a proof by the base program whose journal names exactly
   that base, axioms hash, payee and rate. Checked on chain by code this file
   does not model.

   What the model says: an entry is made only on such a proof, it is within
   the registry's ceiling, and once made it never changes. `Vault3.lean`
   takes the registry as a fixed function for exactly that reason; the vault
   also reads an order's entry once, at funding, and keeps what it read.

   What it does not say: that the base type-checks (that is the base
   program's proof, not this file), or that the payee deserves the royalty.
   The first valid proof for a base decides its entry; a later proof with
   other terms is refused. -/
namespace Nucleus.ProofCommerce.Registry

structure Entry where
  axioms : Nat
  payee : Nat
  bps : Nat
  deriving DecidableEq

structure Deployment where
  maximumBps : Nat
  ceilingBounded : maximumBps ≤ 10000

structure State where
  entry : Nat → Option Entry

def initial : State := ⟨fun _ => none⟩

/-- One call. Any caller. -/
inductive Step (d : Deployment) (Proved : Nat → Nat → Nat → Nat → Prop) : State → State → Prop where
  | register (s : State) (base axioms payee bps : Nat)
      (named : base ≠ 0)
      (payable : payee ≠ 0)
      (within : bps ≤ d.maximumBps)
      (fresh : s.entry base = none)
      (proved : Proved base axioms payee bps) :
      Step d Proved s ⟨fun b => if b = base then some ⟨axioms, payee, bps⟩ else s.entry b⟩

inductive Reachable (d : Deployment) (Proved : Nat → Nat → Nat → Nat → Prop) : State → Prop where
  | start : Reachable d Proved initial
  | next {s t : State} : Reachable d Proved s → Step d Proved s t → Reachable d Proved t

variable {d : Deployment} {Proved : Nat → Nat → Nat → Nat → Prop}

/-- An entry, once made, is the same after any call. -/
theorem an_entry_never_changes {s t : State} (step : Step d Proved s t) (base : Nat) (e : Entry)
    (made : s.entry base = some e) : t.entry base = some e := by
  cases step with
  | register b axioms payee bps named payable within fresh proved =>
      by_cases same : base = b
      · subst same; rw [made] at fresh; cases fresh
      · simp [same, made]

/-- Every entry was proved, for exactly its terms, and is within the ceiling
    and payable. -/
theorem every_entry_was_proved {s : State} (reach : Reachable d Proved s) (base : Nat) (e : Entry)
    (made : s.entry base = some e) :
    Proved base e.axioms e.payee e.bps ∧ e.bps ≤ d.maximumBps ∧ e.payee ≠ 0 ∧ base ≠ 0 := by
  induction reach with
  | start => simp [initial] at made
  | next _ step ih =>
      cases step with
      | register b axioms payee bps named payable within fresh proved =>
          by_cases same : base = b
          · subst same
            simp at made
            subst made
            exact ⟨proved, within, payable, named⟩
          · simp [same] at made
            exact ih made

/-- A rate in the registry is never more than the whole of an order. -/
theorem a_rate_is_at_most_the_whole {s : State} (reach : Reachable d Proved s) (base : Nat)
    (e : Entry) (made : s.entry base = some e) : e.bps ≤ 10000 :=
  Nat.le_trans (every_entry_was_proved reach base e made).2.1 d.ceilingBounded

/-- info: 'Nucleus.ProofCommerce.Registry.an_entry_never_changes' depends on axioms: [propext] -/
#guard_msgs in #print axioms an_entry_never_changes
/-- info: 'Nucleus.ProofCommerce.Registry.every_entry_was_proved' depends on axioms: [propext] -/
#guard_msgs in #print axioms every_entry_was_proved

end Nucleus.ProofCommerce.Registry
