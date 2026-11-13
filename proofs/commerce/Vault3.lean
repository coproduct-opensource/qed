import Std
set_option warningAsError true

/- PROPOSAL for the third vault. A model; it moves no funds, and no contract
   implements it yet. Owner decisions 13 and 18 of 2026-11-12
   (docs/rfcs/proof-commerce-marketplace-decisions-2026-11-12.md).

   What changes from the deployed vault (Vault.lean):

   * Nothing is paid inside `fund`, `settle` or `refund`. A settlement books
     what the seller, the treasury and a base library's payee are owed; a
     refund books what the buyer is owed. `claim`, open to any caller, pays
     one payee everything it is owed in one token. So no payee the token
     refuses to pay can block any order, the buyer included.
   * An order may name a base library. If the registry knows that base, its
     payee is owed a royalty out of the order, inside the fee cap the buyer
     agreed at funding.
   * The delivery deadline is at most `maximumTerm` after funding.

   External facts, checked on chain by code this file does not model:
   `Deposited` (the token honoured the buyer's authorization, by an ordinary
   or a contract-wallet signature), `Accepts` (the order's verifier accepted a
   proof for the artifact), and `registry` (who registered a base, and at
   what rate; entries never change).

   Correspondence with the contract (contracts/vault/src/NucleusVault3.sol):
   the model reads `royalty reg o` at funding (in `WithinCap`) and again at
   settlement (in the seller's credit and `creditBase`). The contract reads
   its registry once, at funding, and stores the payee and amount for the
   order; settlement uses what was stored. For a registry whose entries never
   change the two agree, and the stored answer is how the contract keeps the
   model's assumption true for a funded order whatever the registry does
   later. A payee of zero or the vault itself is treated by the contract as
   no entry, which here is `reg` returning `none`. -/
namespace Nucleus.ProofCommerce.Vault3

structure Deployment where
  address : Nat
  treasury : Nat
  feeBps : Nat
  maximumFeeBps : Nat
  maximumTerm : Nat
  feePositive : 0 < feeBps
  feeWithinCap : feeBps ≤ maximumFeeBps
  capBounded : maximumFeeBps ≤ 10000

structure Order where
  buyer : Nat
  seller : Nat
  asset : Nat
  amount : Nat
  verifier : Nat
  program : Nat
  policy : Nat
  /-- The checked base library the statement builds on, if any. -/
  base : Option Nat
  fundBy : Nat
  deliverBy : Nat
  salt : Nat
  context : Nat
  amountPositive : 0 < amount
  deadlinesOrdered : fundBy < deliverBy
  deriving DecidableEq

/-- A registered base: who is paid for its use, and at what rate. -/
structure Entry where
  payee : Nat
  bps : Nat

abbrev Registry := Nat → Option Entry

def fee (d : Deployment) (o : Order) : Nat := (o.amount * d.feeBps + 9999) / 10000

/-- The base's entry for this order, if it names a registered base. -/
def entry (reg : Registry) (o : Order) : Option Entry := o.base.bind reg

/-- Royalty, rounded down: a base never takes more than its rate. -/
def royalty (reg : Registry) (o : Order) : Nat :=
  match entry reg o with
  | some e => o.amount * e.bps / 10000
  | none => 0

/-- Fee and royalty together stay within the cap fixed at deployment. Checked
    at funding, so what the buyer authorised cannot cost the seller more
    later: registry entries never change. -/
def WithinCap (d : Deployment) (reg : Registry) (o : Order) : Prop :=
  (fee d o + royalty reg o) * 10000 ≤ o.amount * d.maximumFeeBps

theorem charges_le_amount {d : Deployment} {reg : Registry} {o : Order}
    (capped : WithinCap d reg o) : fee d o + royalty reg o ≤ o.amount := by
  have bound := Nat.mul_le_mul_left o.amount d.capBounded
  unfold WithinCap at capped
  omega

theorem fee_positive (d : Deployment) (o : Order) : 0 < fee d o := by
  have hm := Nat.mul_pos o.amountPositive d.feePositive
  have h : 1 * 10000 ≤ o.amount * d.feeBps + 9999 := by omega
  have hd := (Nat.le_div_iff_mul_le (by decide : 0 < 10000)).2 h
  unfold fee
  omega

inductive Phase where
  | empty
  | funded
  | settled (artifact : Nat)
  | refunded
  deriving DecidableEq

structure Transfer where
  asset : Nat
  source : Nat
  target : Nat
  amount : Nat

structure State where
  phase : Order → Phase
  /-- Booked and not yet claimed, per payee and token. -/
  owed : Nat → Nat → Nat

def initial : State := ⟨fun _ => .empty, fun _ _ => 0⟩

def State.setPhase (s : State) (o : Order) (p : Phase) : State :=
  { s with phase := fun x => if x = o then p else s.phase x }

def State.credit (s : State) (payee asset amount : Nat) : State :=
  { s with owed := fun p a => if p = payee ∧ a = asset then s.owed p a + amount else s.owed p a }

def State.clear (s : State) (payee asset : Nat) : State :=
  { s with owed := fun p a => if p = payee ∧ a = asset then 0 else s.owed p a }

/-- The royalty credit of a settlement: to the base's payee, or nothing. -/
def State.creditBase (s : State) (reg : Registry) (o : Order) : State :=
  match entry reg o with
  | some e => s.credit e.payee o.asset (royalty reg o)
  | none => s

inductive Kind where
  | fund | settle | refund | claim

inductive Step (d : Deployment) (reg : Registry) (Deposited : Order → Prop)
    (Accepts : Order → Nat → Prop) : Kind → State → List Transfer → State → Prop where
  | fund (s : State) (o : Order) (now : Nat)
      (fresh : s.phase o = .empty)
      (inTime : now ≤ o.fundBy)
      (term : o.deliverBy ≤ now + d.maximumTerm)
      (capped : WithinCap d reg o)
      (outside : o.buyer ≠ d.address)
      (deposited : Deposited o) :
      Step d reg Deposited Accepts .fund s [⟨o.asset, o.buyer, d.address, o.amount⟩]
        (s.setPhase o .funded)
  | settle (s : State) (o : Order) (artifact now : Nat)
      (held : s.phase o = .funded)
      (inTime : now ≤ o.deliverBy)
      (accepted : Accepts o artifact) :
      Step d reg Deposited Accepts .settle s []
        ((((s.setPhase o (.settled artifact)).credit o.seller o.asset
            (o.amount - fee d o - royalty reg o)).credit d.treasury o.asset (fee d o)).creditBase
          reg o)
  | refund (s : State) (o : Order) (now : Nat)
      (held : s.phase o = .funded)
      (late : o.deliverBy < now) :
      Step d reg Deposited Accepts .refund s []
        ((s.setPhase o .refunded).credit o.buyer o.asset o.amount)
  | claim (s : State) (payee asset : Nat) (some : 0 < s.owed payee asset) :
      Step d reg Deposited Accepts .claim s [⟨asset, d.address, payee, s.owed payee asset⟩]
        (s.clear payee asset)

inductive Reachable (d : Deployment) (reg : Registry) (Deposited : Order → Prop)
    (Accepts : Order → Nat → Prop) : State → Prop where
  | start : Reachable d reg Deposited Accepts initial
  | next {s t : State} {k : Kind} {moved : List Transfer} :
      Reachable d reg Deposited Accepts s → Step d reg Deposited Accepts k s moved t →
      Reachable d reg Deposited Accepts t

variable {d : Deployment} {reg : Registry} {Deposited : Order → Prop}
  {Accepts : Order → Nat → Prop}

/-- Funding, settling and refunding send nothing out of the vault. Whether
    any payee can receive is therefore irrelevant to every order. -/
theorem only_a_claim_pays_out {k : Kind} {s t : State} {moved : List Transfer}
    (step : Step d reg Deposited Accepts k s moved t) :
    (∃ m ∈ moved, m.source = d.address) → k = .claim := by
  cases step with
  | fund _ o now fresh inTime term capped outside deposited =>
      intro ⟨m, hm, src⟩; simp at hm; subst hm; exact absurd src outside
  | settle _ o artifact now holding inTime accepted => intro ⟨m, hm, _⟩; simp at hm
  | refund _ o now holding late => intro ⟨m, hm, _⟩; simp at hm
  | claim _ payee asset some => intro _; rfl

/-- A claim pays one payee exactly what it was owed in that token, leaves it
    owed nothing there, and changes no order and no other balance. -/
theorem claim_pays_what_is_owed {s t : State} {moved : List Transfer}
    (step : Step d reg Deposited Accepts .claim s moved t) :
    ∃ payee asset, moved = [⟨asset, d.address, payee, s.owed payee asset⟩]
      ∧ t.owed payee asset = 0 ∧ t.phase = s.phase
      ∧ ∀ p a, ¬ (p = payee ∧ a = asset) → t.owed p a = s.owed p a := by
  cases step with
  | claim _ payee asset some =>
      refine ⟨payee, asset, rfl, by simp [State.clear], rfl, ?_⟩
      intro p a other
      simp [State.clear, other]

/-- What a settlement books adds up to the deposit, when seller, treasury and
    base payee are three different accounts. -/
theorem settlement_books_the_deposit (o : Order) (capped : WithinCap d reg o) :
    (o.amount - fee d o - royalty reg o) + fee d o + royalty reg o = o.amount := by
  have bound := charges_le_amount capped
  omega

theorem credit_ge (s : State) (q b n p a : Nat) : s.owed p a ≤ (s.credit q b n).owed p a := by
  simp only [State.credit]
  split <;> omega

theorem creditBase_ge (s : State) (reg : Registry) (o : Order) (p a : Nat) :
    s.owed p a ≤ (s.creditBase reg o).owed p a := by
  unfold State.creditBase
  split
  · exact credit_ge s _ _ _ p a
  · exact Nat.le_refl _

theorem creditBase_phase (s : State) (reg : Registry) (o : Order) :
    (s.creditBase reg o).phase = s.phase := by
  unfold State.creditBase
  split <;> rfl

/-- Nothing but a claim lowers what anyone is owed. -/
theorem owed_falls_only_by_a_claim {k : Kind} {s t : State} {moved : List Transfer}
    (step : Step d reg Deposited Accepts k s moved t) (p a : Nat)
    (fell : t.owed p a < s.owed p a) : k = .claim := by
  cases step with
  | fund _ o now fresh inTime term capped outside deposited =>
      simp [State.setPhase] at fell
  | settle _ o artifact now holding inTime accepted =>
      exfalso
      have h1 := credit_ge (s.setPhase o (.settled artifact)) o.seller o.asset
        (o.amount - fee d o - royalty reg o) p a
      have h2 := credit_ge ((s.setPhase o (.settled artifact)).credit o.seller o.asset
        (o.amount - fee d o - royalty reg o)) d.treasury o.asset (fee d o) p a
      have h3 := creditBase_ge (((s.setPhase o (.settled artifact)).credit o.seller o.asset
        (o.amount - fee d o - royalty reg o)).credit d.treasury o.asset (fee d o)) reg o p a
      have h0 : (s.setPhase o (.settled artifact)).owed p a = s.owed p a := rfl
      omega
  | refund _ o now holding late =>
      exfalso
      have h1 := credit_ge (s.setPhase o .refunded) o.buyer o.asset o.amount p a
      have h0 : (s.setPhase o .refunded).owed p a = s.owed p a := rfl
      omega
  | claim _ payee asset some => rfl

/-- `fund` admits an order at time `now` only if its delivery deadline is at
    most `maximumTerm` later (the `term` premise of `Step.fund`). So the
    refund's time condition holds at every moment after `now + maximumTerm`:
    a deposit cannot be locked longer by a mistaken or hostile deadline. -/
theorem refund_opens_within_the_term (d : Deployment) (o : Order) (now : Nat)
    (term : o.deliverBy ≤ now + d.maximumTerm) :
    ∀ later, now + d.maximumTerm < later → o.deliverBy < later := by
  intro later h
  omega

/-- A settled order was accepted, for that artifact, by the order's own terms. -/
theorem settled_was_accepted {s : State} (reach : Reachable d reg Deposited Accepts s)
    (o : Order) (artifact : Nat) (done : s.phase o = .settled artifact) :
    Accepts o artifact := by
  induction reach with
  | start => simp [initial] at done
  | next _ step ih =>
      cases step with
      | fund _ x now fresh inTime term capped outside deposited =>
          by_cases same : o = x
          · subst same; simp [State.setPhase] at done
          · simp [State.setPhase, same] at done; exact ih done
      | settle _ x a now holding inTime accepted =>
          by_cases same : o = x
          · subst same
            simp [creditBase_phase, State.credit, State.setPhase] at done
            exact done ▸ accepted
          · simp [creditBase_phase, State.credit, State.setPhase, same] at done
            exact ih done
      | refund _ x now holding late =>
          by_cases same : o = x
          · subst same; simp [State.setPhase, State.credit] at done
          · simp [State.setPhase, State.credit, same] at done; exact ih done
      | claim _ payee asset some => simp [State.clear] at done; exact ih done

end Nucleus.ProofCommerce.Vault3

namespace Nucleus.ProofCommerce.Vault3
/-- info: 'Nucleus.ProofCommerce.Vault3.only_a_claim_pays_out' depends on axioms: [propext] -/
#guard_msgs in #print axioms only_a_claim_pays_out
/-- info: 'Nucleus.ProofCommerce.Vault3.claim_pays_what_is_owed' depends on axioms: [propext] -/
#guard_msgs in #print axioms claim_pays_what_is_owed
/-- info: 'Nucleus.ProofCommerce.Vault3.settled_was_accepted' depends on axioms: [propext] -/
#guard_msgs in #print axioms settled_was_accepted
/-- info: 'Nucleus.ProofCommerce.Vault3.owed_falls_only_by_a_claim' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms owed_falls_only_by_a_claim
end Nucleus.ProofCommerce.Vault3
