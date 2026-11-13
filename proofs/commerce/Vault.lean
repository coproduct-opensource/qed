import Std
set_option warningAsError true

/- The thin vault. A model; it moves no funds. The contract it describes is
   contracts/vault/src/NucleusVault2.sol.

   One contract holds a buyer's payment for one order and obeys these rules:
   it takes the deposit only under the buyer's own token authorization for
   exactly this order; it pays the seller, less a fixed protocol fee, only when
   the verifier the order names accepts a proof for the delivered artifact;
   and after the delivery deadline it returns the whole deposit to the buyer.

   A settlement does not pay the treasury. It books the fee per token, and a
   separate call, `sweep`, open to any caller, sends a token's booked fees to
   the treasury. A treasury that cannot receive then delays the protocol's own
   revenue and blocks no order. (The first deployed form paid the treasury
   inside `settle`; an independent read found that a treasury the token
   refuses to pay would then block every settlement in that token.)

   The vault has no owner and no upgrade. Its fee rate and treasury are fixed
   at deployment. Each order names its own token, verifier and program, so a
   new proof system needs no new vault.

   `Deposited` and `Accepts` are external facts here: the token contract
   honouring the buyer's signed authorization, and the verifier contract
   accepting a proof. Both are checked on chain by code this file does not
   model. Callers carry no authority: any account may submit any step.

   Not proved here: a global solvency invariant (the vault's balance in a
   token covers every funded order plus the booked fees). The per-call
   theorems imply it only informally. The token itself is not modelled. -/
namespace Nucleus.ProofCommerce.Vault

/-- Fixed at deployment. -/
structure Deployment where
  chain : Nat
  address : Nat
  treasury : Nat
  feeBps : Nat
  maximumFeeBps : Nat
  feePositive : 0 < feeBps
  feeWithinCap : feeBps ≤ maximumFeeBps
  capBounded : maximumFeeBps ≤ 10000

/-- Everything the two parties agree. The buyer commits to all of it by
    signing a token authorization whose nonce is this order's digest. -/
structure Order where
  buyer : Nat
  seller : Nat
  asset : Nat
  amount : Nat
  verifier : Nat
  program : Nat
  policy : Nat
  fundBy : Nat
  deliverBy : Nat
  salt : Nat
  context : Nat
  amountPositive : 0 < amount
  deadlinesOrdered : fundBy < deliverBy
  deriving DecidableEq

/-- Protocol fee, rounded up: a settled order of any size pays at least one unit. -/
def fee (d : Deployment) (o : Order) : Nat := (o.amount * d.feeBps + 9999) / 10000

theorem fee_le_amount (d : Deployment) (o : Order) : fee d o ≤ o.amount := by
  have bound : d.feeBps ≤ 10000 := Nat.le_trans d.feeWithinCap d.capBounded
  have hm := Nat.mul_le_mul_left o.amount bound
  have hlt : o.amount * d.feeBps + 9999 < (o.amount + 1) * 10000 := by omega
  have hd := (Nat.div_lt_iff_lt_mul (by decide : 0 < 10000)).2 hlt
  unfold fee
  omega

theorem fee_positive (d : Deployment) (o : Order) : 0 < fee d o := by
  have hm := Nat.mul_pos o.amountPositive d.feePositive
  have h : 1 * 10000 ≤ o.amount * d.feeBps + 9999 := by omega
  have hd := (Nat.le_div_iff_mul_le (by decide : 0 < 10000)).2 h
  unfold fee
  omega

/-- A trade so small that rounding would push the fee past the agreed cap is
    not admitted at all. -/
def WithinCap (d : Deployment) (o : Order) : Prop :=
  fee d o * 10000 ≤ o.amount * d.maximumFeeBps

inductive Phase where
  | empty
  | funded
  | settled (artifact : Nat)
  | refunded
  deriving DecidableEq

/-- A token movement the vault causes or receives, tagged with its order. -/
structure Transfer where
  order : Order
  source : Nat
  target : Nat
  amount : Nat

structure State where
  phase : Order → Phase
  /-- Fees booked and not yet swept, per token. -/
  accrued : Nat → Nat

def initial : State := ⟨fun _ => .empty, fun _ => 0⟩

def State.setPhase (s : State) (o : Order) (p : Phase) : State :=
  { s with phase := fun x => if x = o then p else s.phase x }

def State.setAccrued (s : State) (asset amount : Nat) : State :=
  { s with accrued := fun a => if a = asset then amount else s.accrued a }

/-- One call. `order` is the order a transfer is booked against; a sweep is
    not about any order, so it reports its transfer separately. -/
inductive Step (d : Deployment) (Deposited : Order → Prop) (Accepts : Order → Nat → Prop) :
    State → List Transfer → Option (Nat × Nat) → State → Prop where
  | fund (s : State) (o : Order) (now : Nat)
      (fresh : s.phase o = .empty)
      (inTime : now ≤ o.fundBy)
      (capped : WithinCap d o)
      (deposited : Deposited o) :
      Step d Deposited Accepts s [⟨o, o.buyer, d.address, o.amount⟩] none (s.setPhase o .funded)
  | settle (s : State) (o : Order) (artifact now : Nat)
      (held : s.phase o = .funded)
      (inTime : now ≤ o.deliverBy)
      (accepted : Accepts o artifact) :
      Step d Deposited Accepts s
        [⟨o, d.address, o.seller, o.amount - fee d o⟩] none
        ((s.setPhase o (.settled artifact)).setAccrued o.asset (s.accrued o.asset + fee d o))
  | refund (s : State) (o : Order) (now : Nat)
      (held : s.phase o = .funded)
      (late : o.deliverBy < now) :
      Step d Deposited Accepts s [⟨o, d.address, o.buyer, o.amount⟩] none (s.setPhase o .refunded)
  /-- Any caller. Sends everything accrued in one token to the treasury. -/
  | sweep (s : State) (asset : Nat) (some : 0 < s.accrued asset) :
      Step d Deposited Accepts s [] (.some (asset, s.accrued asset)) (s.setAccrued asset 0)

inductive Reachable (d : Deployment) (Deposited : Order → Prop) (Accepts : Order → Nat → Prop) :
    State → Prop where
  | start : Reachable d Deposited Accepts initial
  | next {s t : State} {moved : List Transfer} {swept : Option (Nat × Nat)} :
      Reachable d Deposited Accepts s → Step d Deposited Accepts s moved swept t →
      Reachable d Deposited Accepts t

variable {d : Deployment} {Deposited : Order → Prop} {Accepts : Order → Nat → Prop}

/-- What the vault holds for an order in each phase. -/
def held (o : Order) : Phase → Nat
  | .funded => o.amount
  | _ => 0

/-- Units entering the vault for `o` in a list of transfers. -/
def inflow (d : Deployment) (o : Order) : List Transfer → Nat
  | [] => 0
  | t :: rest => (if t.order = o ∧ t.target = d.address then t.amount else 0) + inflow d o rest

/-- Units leaving the vault for `o`. -/
def outflow (d : Deployment) (o : Order) : List Transfer → Nat
  | [] => 0
  | t :: rest => (if t.order = o ∧ t.source = d.address then t.amount else 0) + outflow d o rest


/-- No call that funds, settles or refunds an order sends anything to the
    treasury: whether the treasury can receive is irrelevant to every order. -/
theorem orders_never_pay_the_treasury {s t : State} {moved : List Transfer}
    {swept : Option (Nat × Nat)} (step : Step d Deposited Accepts s moved swept t)
    (sellerNotTreasury : ∀ x : Order, x.seller ≠ d.treasury)
    (buyerNotTreasury : ∀ x : Order, x.buyer ≠ d.treasury)
    (vaultNotTreasury : d.address ≠ d.treasury) :
    ∀ m ∈ moved, m.target ≠ d.treasury := by
  cases step with
  | fund o now fresh inTime capped deposited =>
      intro m hm; simp at hm; subst hm; exact vaultNotTreasury
  | settle o artifact now holding inTime accepted =>
      intro m hm; simp at hm; subst hm; exact sellerNotTreasury o
  | refund o now holding late =>
      intro m hm; simp at hm; subst hm; exact buyerNotTreasury o
  | sweep asset some => intro m hm; simp at hm

/-- The fee an order books when a call takes it from funded to settled. -/
def booked (d : Deployment) (o : Order) : Phase → Phase → Nat
  | .funded, .settled _ => fee d o
  | _, _ => 0

/-- Per order and per call, the books balance once the booked fee is counted:
    what the vault held for the order, plus what came in, equals what it holds
    for the order after, plus what went out to the parties, plus the fee it
    booked as accrued. A sweep changes none of these. -/
theorem conservation {s t : State} {moved : List Transfer} {swept : Option (Nat × Nat)}
    (step : Step d Deposited Accepts s moved swept t) (o : Order)
    (buyerOutside : ∀ x : Order, x.buyer ≠ d.address)
    (sellerOutside : ∀ x : Order, x.seller ≠ d.address) :
    held o (s.phase o) + inflow d o moved
      = held o (t.phase o) + outflow d o moved + booked d o (s.phase o) (t.phase o) := by
  cases step with
  | fund x now fresh inTime capped deposited =>
      by_cases same : o = x
      · subst same
        simp [State.setPhase, inflow, outflow, held, booked, fresh, buyerOutside]
      · have other : x ≠ o := fun h => same h.symm
        cases h : s.phase o <;> simp [State.setPhase, inflow, outflow, booked, same, other, h]
  | settle x artifact now holding inTime accepted =>
      by_cases same : o = x
      · subst same
        have bound := fee_le_amount d o
        simp [State.setPhase, State.setAccrued, inflow, outflow, held, booked, holding,
          sellerOutside]
        omega
      · have other : x ≠ o := fun h => same h.symm
        cases h : s.phase o <;>
          simp [State.setPhase, State.setAccrued, inflow, outflow, booked, same, other, h]
  | refund x now holding late =>
      by_cases same : o = x
      · subst same
        simp [State.setPhase, inflow, outflow, held, booked, holding, buyerOutside]
      · have other : x ≠ o := fun h => same h.symm
        cases h : s.phase o <;> simp [State.setPhase, inflow, outflow, booked, same, other, h]
  | sweep asset some =>
      cases h : s.phase o <;> simp [State.setAccrued, inflow, outflow, booked, h]

/-- A sweep sends exactly what was accrued in that token and leaves none. -/
theorem sweep_sends_all_and_only_accrued {s t : State} {moved : List Transfer}
    {asset amount : Nat}
    (step : Step d Deposited Accepts s moved (.some (asset, amount)) t) :
    amount = s.accrued asset ∧ t.accrued asset = 0 ∧ t.phase = s.phase ∧ moved = [] := by
  cases step with
  | sweep a some => simp [State.setAccrued]

/-- Accrued fees in a token change only by a settlement in that token (up, by
    that order's fee) or by a sweep of that token (to zero). No call can
    direct them anywhere but the treasury, because no other step touches them. -/
theorem accrued_changes_only_by_settle_or_sweep {s t : State} {moved : List Transfer}
    {swept : Option (Nat × Nat)} (step : Step d Deposited Accepts s moved swept t) (asset : Nat) :
    t.accrued asset = s.accrued asset
    ∨ (∃ o : Order, o.asset = asset ∧ t.accrued asset = s.accrued asset + fee d o)
    ∨ (swept = .some (asset, s.accrued asset) ∧ t.accrued asset = 0) := by
  cases step with
  | fund o now fresh inTime capped deposited => left; simp [State.setPhase]
  | settle o artifact now holding inTime accepted =>
      by_cases same : asset = o.asset
      · right; left; exact ⟨o, same.symm, by simp [State.setPhase, State.setAccrued, same]⟩
      · left; simp [State.setPhase, State.setAccrued, same]
  | refund o now holding late => left; simp [State.setPhase]
  | sweep a some =>
      by_cases same : asset = a
      · subst same; right; right; simp [State.setAccrued]
      · left; simp [State.setAccrued, same]

/-- As in the deployed vault: a settled order was accepted for that artifact. -/
theorem settled_was_accepted {s : State} (reach : Reachable d Deposited Accepts s)
    (o : Order) (artifact : Nat) (done : s.phase o = .settled artifact) :
    Accepts o artifact := by
  induction reach with
  | start => simp [initial] at done
  | next _ step ih =>
      cases step with
      | fund x now fresh inTime capped deposited =>
          by_cases same : o = x
          · subst same; simp [State.setPhase] at done
          · simp [State.setPhase, same] at done; exact ih done
      | settle x a now holding inTime accepted =>
          by_cases same : o = x
          · subst same
            simp [State.setPhase, State.setAccrued] at done
            exact done ▸ accepted
          · simp [State.setPhase, State.setAccrued, same] at done; exact ih done
      | refund x now holding late =>
          by_cases same : o = x
          · subst same; simp [State.setPhase] at done
          · simp [State.setPhase, same] at done; exact ih done
      | sweep asset some => simp [State.setAccrued] at done; exact ih done

/-- Anything past empty was deposited by the buyer's own authorization. -/
theorem held_was_deposited {s : State} (reach : Reachable d Deposited Accepts s)
    (o : Order) (past : s.phase o ≠ .empty) : Deposited o := by
  induction reach with
  | start => simp [initial] at past
  | next _ step ih =>
      cases step with
      | fund x now fresh inTime capped deposited =>
          by_cases same : o = x
          · subst same; exact deposited
          · simp [State.setPhase, same] at past; exact ih past
      | settle x a now holding inTime accepted =>
          by_cases same : o = x
          · subst same; exact ih (by simp [holding])
          · simp [State.setPhase, State.setAccrued, same] at past; exact ih past
      | refund x now holding late =>
          by_cases same : o = x
          · subst same; exact ih (by simp [holding])
          · simp [State.setPhase, same] at past; exact ih past
      | sweep asset some => simp [State.setAccrued] at past; exact ih past

/-- Settled and refunded are final: no later call changes them, so no order
    pays out twice or pays out after a refund. -/
theorem terminal_is_final {s t : State} {moved : List Transfer} {swept : Option (Nat × Nat)}
    (step : Step d Deposited Accepts s moved swept t) (o : Order)
    (final : (∃ a, s.phase o = .settled a) ∨ s.phase o = .refunded) :
    t.phase o = s.phase o := by
  cases step with
  | fund x now fresh inTime capped deposited =>
      by_cases same : o = x
      · subst same; rcases final with ⟨a, h⟩ | h <;> simp [fresh] at h
      · simp [State.setPhase, same]
  | settle x a now holding inTime accepted =>
      by_cases same : o = x
      · subst same; rcases final with ⟨b, h⟩ | h <;> simp [holding] at h
      · simp [State.setPhase, State.setAccrued, same]
  | refund x now holding late =>
      by_cases same : o = x
      · subst same; rcases final with ⟨b, h⟩ | h <;> simp [holding] at h
      · simp [State.setPhase, same]
  | sweep asset some => simp [State.setAccrued]

/-- Every settlement books a positive fee and pays the seller the rest;
    together they are exactly the deposit. -/
theorem settlement_splits_the_deposit (o : Order) :
    0 < fee d o ∧ (o.amount - fee d o) + fee d o = o.amount := by
  have bound := fee_le_amount d o
  exact ⟨fee_positive d o, by omega⟩

/-- A refund is only possible after the delivery deadline and a settlement
    only up to it, so for one funded order at one time exactly one is open. -/
theorem settle_and_refund_exclude (o : Order) (now : Nat) :
    ¬ (now ≤ o.deliverBy ∧ o.deliverBy < now) := by omega

/-- info: 'Nucleus.ProofCommerce.Vault.settled_was_accepted' depends on axioms: [propext] -/
#guard_msgs in #print axioms settled_was_accepted
/-- info: 'Nucleus.ProofCommerce.Vault.held_was_deposited' depends on axioms: [propext] -/
#guard_msgs in #print axioms held_was_deposited
/-- info: 'Nucleus.ProofCommerce.Vault.conservation' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms conservation
/-- info: 'Nucleus.ProofCommerce.Vault.terminal_is_final' depends on axioms: [propext] -/
#guard_msgs in #print axioms terminal_is_final
/-- info: 'Nucleus.ProofCommerce.Vault.orders_never_pay_the_treasury' depends on axioms: [propext] -/
#guard_msgs in #print axioms orders_never_pay_the_treasury
/-- info: 'Nucleus.ProofCommerce.Vault.sweep_sends_all_and_only_accrued' depends on axioms: [propext] -/
#guard_msgs in #print axioms sweep_sends_all_and_only_accrued
/-- info: 'Nucleus.ProofCommerce.Vault.accrued_changes_only_by_settle_or_sweep' depends on axioms: [propext] -/
#guard_msgs in #print axioms accrued_changes_only_by_settle_or_sweep

end Nucleus.ProofCommerce.Vault
