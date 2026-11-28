import Promotion
set_option warningAsError true

/- Proof-carrying savings: what a settlement saved its buyer, and who is
   owed a share of the saving. A model of `contracts/savings` and
   `contracts/site/src/market/savings.rs`; it moves no funds.
   docs/rfcs/qed-proof-carrying-savings-2026-11-28.md.

   The saving of a settled order is the post's price (its `maximumAmount`,
   the most the buyer said it would pay) minus the order's amount, 0 when
   the order paid the price or more. It is split three ways:
   * the referrer bound into the funded order (its `salt` preimage), 30 %,
     rounded down; 0 when the order names no referrer;
   * the authors of the lemmas the settled proof reused, 20 %, divided
     equally among the distinct authors, each share rounded down; 0 when
     the proof reused none;
   * the buyer, the rest: at least half, and every rounding remainder.

   The fee and the royalty of the vault apply to the order's amount only
   (`Vault3.lean`); the saving never enters the vault, so the split does
   not touch its arithmetic.

   Who the authors are is decided from the settled artifact and a
   provenance index: each declaration (its name, type and value, one
   number here) maps to the payee of the first settlement whose artifact
   carried it. The authors of a settlement are the payees the index names
   for its artifact's declarations, less the seller itself. -/
namespace Nucleus.ProofCommerce.Savings
open Nucleus.ProofCommerce.Market

/-- The rules, as switches, so each mutant below is the model with one
    switch turned. The model is `Rule.model`, every switch in its place. -/
structure Rule where
  /-- The saving is the price minus the amount (off: the amount itself). -/
  saving : Bool := true
  /-- An unreferred order pays no referrer share (off: 30 % to nobody). -/
  unrefToBuyer : Bool := true
  /-- The authors' 20 % is divided among them (off: 20 % to each). -/
  divide : Bool := true
  /-- The buyer takes the remainder (off: half, rounded down). -/
  remainder : Bool := true
  /-- Only a funded order settles a split (off: any order of the digest). -/
  phase : Bool := true
  /-- Only a `Settled` event splits (off: a `Refunded` one too). -/
  onSettle : Bool := true
  /-- The referrer is the one bound at funding (off: named at settlement). -/
  boundRef : Bool := true
  /-- The authors come from the artifact (off: the ones the settlement claims). -/
  fromArtifact : Bool := true
  /-- The seller is not its own author (off: it can be). -/
  notSeller : Bool := true

def Rule.model : Rule := {}

/-- One split of one saving: the referrer's share, each author's share and
    their number, and the buyer's share. -/
structure Split where
  referrer : Nat
  perAuthor : Nat
  authors : Nat
  buyer : Nat
  deriving DecidableEq, Repr

/-- Everything the split pays. -/
def Split.total (x : Split) : Nat := x.referrer + x.authors * x.perAuthor + x.buyer

/-- What the split pays to others than the buyer. -/
def Split.others (x : Split) : Nat := x.referrer + x.authors * x.perAuthor

/-- The split of the saving of an order of `amount` on a post priced `cap`,
    with or without a referrer, among `n` authors. -/
def split (r : Rule) (cap amount : Nat) (referred : Bool) (n : Nat) : Split :=
  let s := if r.saving then cap - amount else amount
  let ref := if referred || !r.unrefToBuyer then s * 3000 / 10000 else 0
  let pool := s * 2000 / 10000
  let each := if n = 0 then 0 else if r.divide then pool / n else pool
  ⟨ref, each, n, if r.remainder then s - ref - n * each else s / 2⟩

/-! ## The split -/

theorem split_model (cap amount : Nat) (ref : Bool) (n : Nat) :
    split .model cap amount ref n =
      ⟨if ref then (cap - amount) * 3000 / 10000 else 0,
       if n = 0 then 0 else (cap - amount) * 2000 / 10000 / n, n,
       (cap - amount) - (if ref then (cap - amount) * 3000 / 10000 else 0) -
         n * (if n = 0 then 0 else (cap - amount) * 2000 / 10000 / n)⟩ := by
  simp [split, Rule.model]

theorem authors_le (P n : Nat) : n * (if n = 0 then 0 else P / n) ≤ P := by
  split
  · simp
  · exact Nat.mul_div_le P n

theorem referrer_le (s : Nat) (ref : Bool) :
    (if ref then s * 3000 / 10000 else 0) ≤ s * 3000 / 10000 := by
  split <;> omega

/-- **The shares sum to the saving.** -/
theorem split_exact (cap amount : Nat) (ref : Bool) (n : Nat) :
    (split .model cap amount ref n).total = cap - amount := by
  rw [split_model]; simp only [Split.total]
  have a := authors_le ((cap - amount) * 2000 / 10000) n
  have b := referrer_le (cap - amount) ref
  generalize (if n = 0 then 0 else (cap - amount) * 2000 / 10000 / n) = e at a ⊢
  generalize (if ref then (cap - amount) * 3000 / 10000 else 0) = r at b ⊢
  generalize cap - amount = s at a b ⊢
  omega

/-- **The buyer keeps at least half**, rounded up. -/
theorem buyer_keeps_half (cap amount : Nat) (ref : Bool) (n : Nat) :
    (cap - amount + 1) / 2 ≤ (split .model cap amount ref n).buyer := by
  rw [split_model]; simp only
  have a := authors_le ((cap - amount) * 2000 / 10000) n
  have b := referrer_le (cap - amount) ref
  generalize (if n = 0 then 0 else (cap - amount) * 2000 / 10000 / n) = e at a ⊢
  generalize (if ref then (cap - amount) * 3000 / 10000 else 0) = r at b ⊢
  generalize cap - amount = s at a b ⊢
  omega

/-- **The buyer never pays above its price**: the amount paid to the seller
    and the shares paid to the referrer and the authors are within the
    post's price. With no saving there is nothing to share. -/
theorem buyer_net_le_cap (cap amount : Nat) (ref : Bool) (n : Nat) :
    (split .model cap amount ref n).others ≤ cap - amount ∧
      (amount ≤ cap → amount + (split .model cap amount ref n).others ≤ cap) := by
  have := split_exact cap amount ref n
  simp only [Split.total] at this
  simp only [Split.others]
  omega

/-- **The split never rewards a seller for raising its price.** What the
    split pays to anyone but the buyer (a seller can be its own referrer,
    or an author) falls or stays as the amount rises, share by share. -/
theorem seller_revenue_monotone (cap a₁ a₂ : Nat) (ref : Bool) (n : Nat) (h : a₁ ≤ a₂) :
    (split .model cap a₂ ref n).referrer ≤ (split .model cap a₁ ref n).referrer ∧
      (split .model cap a₂ ref n).perAuthor ≤ (split .model cap a₁ ref n).perAuthor ∧
      (split .model cap a₂ ref n).others ≤ (split .model cap a₁ ref n).others := by
  rw [split_model, split_model]
  simp only [Split.others]
  have hs : cap - a₂ ≤ cap - a₁ := by omega
  have r : (cap - a₂) * 3000 / 10000 ≤ (cap - a₁) * 3000 / 10000 :=
    Nat.div_le_div_right (Nat.mul_le_mul_right _ hs)
  have p : (cap - a₂) * 2000 / 10000 ≤ (cap - a₁) * 2000 / 10000 :=
    Nat.div_le_div_right (Nat.mul_le_mul_right _ hs)
  have e : (if n = 0 then 0 else (cap - a₂) * 2000 / 10000 / n) ≤
      (if n = 0 then 0 else (cap - a₁) * 2000 / 10000 / n) := by
    split
    · exact Nat.le_refl _
    · exact Nat.div_le_div_right p
  have r' : (if ref then (cap - a₂) * 3000 / 10000 else 0) ≤
      (if ref then (cap - a₁) * 3000 / 10000 else 0) := by
    split
    · exact r
    · exact Nat.le_refl _
  refine ⟨r', e, ?_⟩
  have := Nat.mul_le_mul_left n e
  omega

/-- **An unreferred order pays no referrer**: its 30 % stays with the buyer. -/
theorem unreferred_goes_to_buyer (cap amount n : Nat) :
    (split .model cap amount false n).referrer = 0 ∧
      (split .model cap amount false n).buyer =
        cap - amount - n * (split .model cap amount false n).perAuthor := by
  rw [split_model]; simp

/-! ## Who is owed: the model over the market's events -/

/-- One market event with its block and what the split reads from it:
    a post's price; a funded order's referrer, checked against its salt
    when the order was funded; a settlement's artifact, as the
    declarations it carries (the statement's own declarations left out);
    and, for a mutant only, authors a settlement claims. -/
structure Entry where
  block : Nat
  event : Event
  price : Nat := 0
  referral : Option Nat := none
  decls : List Nat := []
  claimed : List Nat := []

/-- A settled order's saving, and who is owed what. `buyer` is the post's
    poster, `seller` the order's payee. -/
structure Record where
  digest : Nat
  post : Nat
  statement : Nat
  buyer : Nat
  seller : Nat
  block : Nat
  cap : Nat
  amount : Nat
  referrer : Option Nat
  authors : List Nat
  split : Split
  deriving DecidableEq, Repr

structure St where
  market : Market
  /-- Post ID → price, first post of an ID first. -/
  prices : List (Nat × Nat)
  /-- Order digest → the referrer bound when it was funded. -/
  refs : List (Nat × Option Nat)
  /-- Declaration → the payee of the first settlement that carried it. -/
  prov : List (Nat × Nat)
  records : List Record

def init : St := ⟨empty, [], [], [], []⟩

def priceOf (s : St) (id : Nat) : Nat := ((s.prices.find? (·.1 == id)).map (·.2)).getD 0

def refOf (s : St) (d : Nat) : Option Nat := ((s.refs.find? (·.1 == d)).map (·.2)).getD none

def lookup (prov : List (Nat × Nat)) (d : Nat) : Option Nat := (prov.find? (·.1 == d)).map (·.2)

/-- The authors of an artifact's declarations, distinct, less the seller. -/
def authorsOf (r : Rule) (prov : List (Nat × Nat)) (decls : List Nat) (seller : Nat) : List Nat :=
  ((decls.filterMap (lookup prov)).filter (fun a => !r.notSeller || a != seller)).eraseDups

/-- The record a settlement of `d` writes, if any. -/
def candidate (r : Rule) (ctx : Ctx) (s : St) (x : Entry) (d : Nat) : Option Record :=
  match s.market.orders.find? (fun o => o.digest == d && (!r.phase || o.phase == .funded)) with
  | none => none
  | some o =>
    match s.market.posts.find? (fun p => joins ctx p o) with
    | none => none
    | some p =>
      let ref := if r.boundRef then refOf s d else x.referral
      let au := if r.fromArtifact then authorsOf r s.prov x.decls o.payee else x.claimed
      some ⟨d, p.id, p.statement, p.poster, o.payee, x.block, priceOf s p.id, o.amount, ref, au,
        split r (priceOf s p.id) o.amount ref.isSome au.length⟩

def newRecord (r : Rule) (ctx : Ctx) (s : St) (x : Entry) : Option Record :=
  match x.event with
  | .settled d => candidate r ctx s x d
  | .refunded d => if r.onSettle then none else candidate r ctx s x d
  | _ => none

def newRefs (s : St) (x : Entry) : List (Nat × Option Nat) :=
  match x.event with
  | .funded d _ _ _ _ => if s.market.orders.any (·.digest == d) then s.refs else s.refs ++ [(d, x.referral)]
  | _ => s.refs

def newProv (s : St) (x : Entry) : Option Record → List (Nat × Nat)
  | some m => s.prov ++ x.decls.map (·, m.seller)
  | none => s.prov

def step (r : Rule) (ctx : Ctx) (s : St) (x : Entry) : St where
  market := apply s.market x.event
  prices := match x.event with
    | .posted p => s.prices ++ [(p.id, x.price)]
    | _ => s.prices
  refs := newRefs s x
  prov := newProv s x (newRecord r ctx s x)
  records := s.records ++ (newRecord r ctx s x).toList

def run (r : Rule) (ctx : Ctx) (s : St) (xs : List Entry) : St :=
  xs.foldl (step r ctx) s

/-! ## Lemmas -/

/-- What a record is, under the model's rules. -/
structure Spec (ctx : Ctx) (s : St) (x : Entry) (d : Nat) (m : Record) : Prop where
  order : ∃ o ∈ s.market.orders, o.digest = d ∧ o.phase = .funded ∧ ∃ p ∈ s.market.posts,
    joins ctx p o = true ∧ m = ⟨d, p.id, p.statement, p.poster, o.payee, x.block, priceOf s p.id,
      o.amount, refOf s d, authorsOf .model s.prov x.decls o.payee,
      split .model (priceOf s p.id) o.amount (refOf s d).isSome
        (authorsOf .model s.prov x.decls o.payee).length⟩

theorem candidate_spec (ctx : Ctx) (s : St) (x : Entry) (d : Nat) (m : Record)
    (h : candidate .model ctx s x d = some m) : Spec ctx s x d m := by
  unfold candidate at h
  split at h
  · simp at h
  · rename_i o ho
    split at h
    · simp at h
    · rename_i p hp
      simp only [Option.some.injEq] at h
      subst h
      have ho' := List.find?_some ho
      have hp' := List.find?_some hp
      simp only [Rule.model, Bool.not_true, Bool.false_or, Bool.and_eq_true, beq_iff_eq] at ho'
      exact ⟨⟨o, List.mem_of_find?_eq_some ho, ho'.1, ho'.2, p, List.mem_of_find?_eq_some hp,
        hp', by simp [Rule.model]⟩⟩

theorem newRecord_spec (ctx : Ctx) (s : St) (x : Entry) (m : Record)
    (h : newRecord .model ctx s x = some m) :
    ∃ d, x.event = .settled d ∧ m.digest = d ∧ Spec ctx s x d m := by
  unfold newRecord at h
  split at h
  · rename_i d hd
    have sp := candidate_spec ctx s x d m h
    obtain ⟨o, _, _, _, p, _, _, rfl⟩ := sp.order
    exact ⟨d, hd, rfl, sp⟩
  · simp [Rule.model] at h
  all_goals simp at h

theorem setPhase_digest (d : Nat) (to : Phase) (o : Order) : (setPhase d to o).digest = o.digest := by
  unfold setPhase; split <;> rfl

theorem claimOne_digest (pay : Nat) (o : Order) : (claimOne pay o).digest = o.digest := by
  unfold claimOne; split <;> rfl

theorem setPhase_spent (d : Nat) (to : Phase) (o : Order) (h : o.phase ≠ .funded) :
    (setPhase d to o).phase ≠ .funded := by
  unfold setPhase; split
  · rename_i c; exact absurd c.2 h
  · exact h

theorem claimOne_spent (pay : Nat) (o : Order) (h : o.phase ≠ .funded) :
    (claimOne pay o).phase ≠ .funded := by
  unfold claimOne; split
  · simp
  · exact h

/-- An order of a digest stays in the market. -/
theorem present_stays (m : Market) (e : Event) (d : Nat)
    (h : m.orders.any (·.digest == d) = true) : (apply m e).orders.any (·.digest == d) = true := by
  cases e with
  | posted p => simp only [apply]; split <;> exact h
  | funded d' c pol pay amt =>
      simp only [apply]; split
      · exact h
      · simp only [List.any_append, h, Bool.true_or]
  | settled d' =>
      simp only [apply, List.any_map, List.any_eq_true, Function.comp_def, setPhase_digest] at h ⊢
      exact h
  | refunded d' =>
      simp only [apply, List.any_map, List.any_eq_true, Function.comp_def, setPhase_digest] at h ⊢
      exact h
  | claimed pay =>
      simp only [apply, List.any_map, List.any_eq_true, Function.comp_def, claimOne_digest] at h ⊢
      exact h
  | _ => exact h

/-- Once no order of a digest is funded, none ever is again. -/
theorem spent_stays (m : Market) (e : Event) (d : Nat)
    (pr : m.orders.any (·.digest == d) = true)
    (h : ∀ o ∈ m.orders, o.digest = d → o.phase ≠ .funded) :
    ∀ o ∈ (apply m e).orders, o.digest = d → o.phase ≠ .funded := by
  cases e with
  | posted p => simp only [apply]; split <;> exact h
  | funded d' c pol pay amt =>
      simp only [apply]; split
      · exact h
      · rename_i hn
        intro o ho hd
        rcases List.mem_append.mp ho with ho | ho
        · exact h o ho hd
        · simp only [List.mem_singleton] at ho; subst ho
          simp only at hd; subst hd
          exact absurd pr hn
  | settled d' =>
      simp only [apply, List.mem_map]
      rintro _ ⟨o, ho, rfl⟩ hd
      rw [setPhase_digest] at hd
      exact setPhase_spent _ _ _ (h o ho hd)
  | refunded d' =>
      simp only [apply, List.mem_map]
      rintro _ ⟨o, ho, rfl⟩ hd
      rw [setPhase_digest] at hd
      exact setPhase_spent _ _ _ (h o ho hd)
  | claimed pay =>
      simp only [apply, List.mem_map]
      rintro _ ⟨o, ho, rfl⟩ hd
      rw [claimOne_digest] at hd
      exact claimOne_spent _ _ (h o ho hd)
  | _ => exact h

/-- A settlement of `d` leaves no order of `d` funded. -/
theorem settled_spends (m : Market) (d : Nat) :
    ∀ o ∈ (apply m (.settled d)).orders, o.digest = d → o.phase ≠ .funded := by
  simp only [apply, List.mem_map]
  rintro _ ⟨o, _, rfl⟩ hd
  rw [setPhase_digest] at hd
  unfold setPhase; split
  · simp
  · rename_i c; intro hf; exact c ⟨hd, hf⟩

/-- The invariant every reachable state keeps. -/
structure Inv (ctx : Ctx) (s : St) : Prop where
  present : ∀ m ∈ s.records, s.market.orders.any (·.digest == m.digest) = true
  spent : ∀ m ∈ s.records, ∀ o ∈ s.market.orders, o.digest = m.digest → o.phase ≠ .funded
  distinct : s.records.Pairwise (fun a b => a.digest ≠ b.digest)
  taken : ∀ m ∈ s.records, taken ctx s.market m.statement = true

theorem inv_init (ctx : Ctx) : Inv ctx init :=
  ⟨by simp [init], by simp [init], by simp [init], by simp [init]⟩

theorem inv_step (ctx : Ctx) (s : St) (x : Entry) (h : Inv ctx s) :
    Inv ctx (step .model ctx s x) := by
  cases hn : newRecord .model ctx s x with
  | none =>
      have hm : (step .model ctx s x).records = s.records := by simp [step, hn]
      have hk : (step .model ctx s x).market = apply s.market x.event := rfl
      refine ⟨?_, ?_, hm ▸ h.distinct, ?_⟩
      · rw [hm, hk]; intro m hmem; exact present_stays _ _ _ (h.present m hmem)
      · rw [hm, hk]; intro m hmem; exact spent_stays _ _ _ (h.present m hmem) (h.spent m hmem)
      · rw [hm, hk]; intro m hmem; exact taken_stays ctx _ _ _ (h.taken m hmem)
  | some m =>
      obtain ⟨d, hd, md, sp⟩ := newRecord_spec ctx s x m hn
      obtain ⟨o, ho, od, ofun, p, hp, j, hmeq⟩ := sp.order
      have hm : (step .model ctx s x).records = s.records ++ [m] := by simp [step, hn]
      have hk : (step .model ctx s x).market = apply s.market (.settled d) := by simp [step, hd]
      have hpr : s.market.orders.any (·.digest == d) = true :=
        List.any_eq_true.mpr ⟨o, ho, by simp [od]⟩
      refine ⟨?_, ?_, ?_, ?_⟩
      · rw [hm, hk]; intro m' hmem
        rcases List.mem_append.mp hmem with hmem | hmem
        · exact present_stays _ _ _ (h.present m' hmem)
        · simp only [List.mem_singleton] at hmem; subst hmem; rw [md]
          exact present_stays _ _ _ hpr
      · rw [hm, hk]; intro m' hmem
        rcases List.mem_append.mp hmem with hmem | hmem
        · exact spent_stays _ _ _ (h.present m' hmem) (h.spent m' hmem)
        · simp only [List.mem_singleton] at hmem; subst hmem; rw [md]
          exact settled_spends _ _
      · rw [hm, List.pairwise_append]
        refine ⟨h.distinct, List.pairwise_singleton _ _, ?_⟩
        intro a ha b hb heq
        simp only [List.mem_singleton] at hb; subst hb
        rw [md] at heq
        exact h.spent a ha o ho (by rw [od, heq]) ofun
      · rw [hm, hk]; intro m' hmem
        rcases List.mem_append.mp hmem with hmem | hmem
        · exact taken_stays ctx _ _ _ (h.taken m' hmem)
        · simp only [List.mem_singleton] at hmem; rw [hmem]
          have : m.statement = p.statement := by rw [hmeq]
          rw [this]
          exact Promotion.settled_takes ctx s.market d o ho od ofun p hp j

theorem inv_run (ctx : Ctx) :
    ∀ (xs : List Entry) (s : St), Inv ctx s → Inv ctx (run .model ctx s xs)
  | [], _, h => h
  | x :: xs, s, h => inv_run ctx xs (step .model ctx s x) (inv_step ctx s x h)

theorem reachable (ctx : Ctx) (xs : List Entry) : Inv ctx (run .model ctx init xs) :=
  inv_run ctx xs init (inv_init ctx)

theorem refOf_append (refs : List (Nat × Option Nat)) (d d' : Nat) (v : Option Nat) (h : d' ≠ d) :
    ((refs ++ [(d', v)]).find? (·.1 == d)) = refs.find? (·.1 == d) := by
  rw [List.find?_append]
  have : [(d', v)].find? (·.1 == d) = none := by simp [h]
  rw [this]; cases refs.find? (·.1 == d) <;> rfl

/-- A digest's referrer, once its order is in the market, never changes. -/
theorem refOf_fixed (r : Rule) (ctx : Ctx) (s : St) (y : Entry) (d : Nat)
    (h : s.market.orders.any (·.digest == d) = true) :
    refOf (step r ctx s y) d = refOf s d := by
  simp only [refOf, step, newRefs]
  split
  · rename_i d' _ _ _ _ _
    split
    · rfl
    · rename_i hn
      have : d' ≠ d := by intro e; subst e; exact hn h
      rw [refOf_append _ _ _ _ this]
  · rfl

/-! ## Theorems -/

/-- **One split per order**: no two records name the same digest, however
    often a settlement is replayed or a digest funded again. -/
theorem one_split_per_order (ctx : Ctx) (xs : List Entry) :
    (run .model ctx init xs).records.Pairwise (fun a b => a.digest ≠ b.digest) :=
  (reachable ctx xs).distinct

/-- **No split without settlement**: a record is written only by the
    `Settled` event of a funded order joined to a post, at that post's
    price; and every recorded statement is taken. -/
theorem no_split_without_settlement (ctx : Ctx) (s : St) (x : Entry) (m : Record)
    (h : newRecord .model ctx s x = some m) :
    x.event = .settled m.digest ∧ ∃ o ∈ s.market.orders, o.digest = m.digest ∧
      o.phase = .funded ∧ o.amount = m.amount ∧ o.payee = m.seller ∧
      ∃ p ∈ s.market.posts, joins ctx p o = true ∧ p.id = m.post ∧ m.cap = priceOf s p.id := by
  obtain ⟨d, hd, md, sp⟩ := newRecord_spec ctx s x m h
  obtain ⟨o, ho, od, ofun, p, hp, j, rfl⟩ := sp.order
  exact ⟨hd, o, ho, od, ofun, rfl, rfl, p, hp, j, rfl, rfl⟩

theorem recorded_taken (ctx : Ctx) (xs : List Entry) :
    ∀ m ∈ (run .model ctx init xs).records, taken ctx (run .model ctx init xs).market m.statement = true :=
  (reachable ctx xs).taken

/-- **The referrer was bound before funding**: a record's referrer is the
    one recorded when its order was funded, and no later event changes it. -/
theorem referral_bound_before_funding (ctx : Ctx) (s : St) (x : Entry) (m : Record)
    (h : newRecord .model ctx s x = some m) :
    m.referrer = refOf s m.digest ∧ ∀ r y, refOf (step r ctx s y) m.digest = refOf s m.digest := by
  obtain ⟨d, _, md, sp⟩ := newRecord_spec ctx s x m h
  obtain ⟨o, ho, od, _, p, _, _, hmeq⟩ := sp.order
  have hpr : s.market.orders.any (·.digest == m.digest) = true :=
    List.any_eq_true.mpr ⟨o, ho, by simp [od, md]⟩
  refine ⟨?_, fun r y => refOf_fixed r ctx s y m.digest hpr⟩
  rw [md, hmeq]

/-- **The authors come from the artifact**: a record's authors are a
    function of the settled artifact's declarations and the provenance
    index alone, and never include the seller. The shares are the split
    of the record's own price, amount, referrer and authors. -/
theorem authors_from_artifact (ctx : Ctx) (s : St) (x : Entry) (m : Record)
    (h : newRecord .model ctx s x = some m) :
    m.authors = authorsOf .model s.prov x.decls m.seller ∧ m.seller ∉ m.authors ∧
      m.split = split .model m.cap m.amount m.referrer.isSome m.authors.length := by
  obtain ⟨d, _, md, sp⟩ := newRecord_spec ctx s x m h
  obtain ⟨o, _, _, _, p, _, _, rfl⟩ := sp.order
  refine ⟨rfl, ?_, rfl⟩
  simp only [authorsOf, Rule.model, Bool.not_true, Bool.false_or]
  intro hm
  have := (List.mem_filter.mp (List.mem_eraseDups.mp hm)).2
  simp at this

theorem run_prefix (r : Rule) (ctx : Ctx) :
    ∀ (ys : List Entry) (s : St), ∃ extra, (run r ctx s ys).records = s.records ++ extra
  | [], s => ⟨[], by simp [run]⟩
  | y :: ys, s => by
      obtain ⟨e, he⟩ := run_prefix r ctx ys (step r ctx s y)
      refine ⟨(newRecord r ctx s y).toList ++ e, ?_⟩
      simp only [run, List.foldl_cons] at he ⊢
      rw [he]; simp [step]

/-- **Monotone**: later events never revoke or change a share already owed;
    the records of a log are a prefix of those of any extension. -/
theorem monotone (ctx : Ctx) (xs ys : List Entry) :
    ∃ extra, (run .model ctx init (xs ++ ys)).records = (run .model ctx init xs).records ++ extra := by
  have : run .model ctx init (xs ++ ys) = run .model ctx (run .model ctx init xs) ys := by
    simp [run, List.foldl_append]
  rw [this]; exact run_prefix _ ctx ys _

end Nucleus.ProofCommerce.Savings

/-! ## Examples

USDC has six decimals. S0006 is posted at 40 USDC; an offer of 25 USDC
saves its buyer 15. -/
namespace Nucleus.ProofCommerce.Savings.Examples
open Nucleus.ProofCommerce.Market Nucleus.ProofCommerce.Savings

def usdc (n : Nat) : Nat := n * 1000000

def s0006 : Nat := 0xfff47ea357d16945a265b84f905c991b1e1c64a593afcd571e9c6a76d191db37

def tctx : Ctx := fun id kb => 1000 * id + kb

def buyer : Nat := 0xA
def sellerKey : Nat := 0xB0B
def referrer : Nat := 0xF00
def authorA : Nat := 0xA1
def authorB : Nat := 0xB1

/-- 40 USDC cap, 25 USDC paid, referred, one author: 4.5 to the referrer,
    3 to the author, 7.5 to the buyer. -/
theorem s0006_split :
    split .model (usdc 40) (usdc 25) true 1 = ⟨4500000, usdc 3, 1, 7500000⟩ := by decide

/-- The same saving, two authors: 1.5 each. -/
theorem two_authors :
    split .model (usdc 40) (usdc 25) true 2 = ⟨4500000, 1500000, 2, 7500000⟩ := by decide

/-- No referrer, no authors: the whole saving to the buyer. -/
theorem unreferred :
    split .model (usdc 40) (usdc 25) false 0 = ⟨0, 0, 0, usdc 15⟩ := by decide

/-- No saving: the order paid the price, or more. All shares 0. -/
theorem no_saving :
    split .model (usdc 40) (usdc 40) true 3 = ⟨0, 0, 3, 0⟩ ∧
      split .model (usdc 40) (usdc 41) true 3 = ⟨0, 0, 3, 0⟩ := by decide

/-- Rounding: a 7-unit saving, three authors. 2 to the referrer, 1 of the
    pool (⌊1.4⌋) left undivided by three, so 0 each; 5 to the buyer. -/
theorem rounding :
    split .model 7 0 true 3 = ⟨2, 0, 3, 5⟩ := by decide

def postAt (id statement poster block : Nat) : Post := ⟨id, 7, 50, statement, 10000, poster, block⟩

/-- Post at `price`, fund at `amount` with a referral, settle with an artifact. -/
def trade (id statement price amount payee : Nat) (ref : Option Nat) (decls : List Nat)
    (blk : Nat) : List Entry :=
  [{ block := blk, event := .posted (postAt id statement buyer blk), price := price },
   { block := blk + 1, event := .funded (100 + id) (tctx id 7) 50 payee amount, referral := ref },
   { block := blk + 2, event := .settled (100 + id), decls := decls }]

def records (r : Rule) (xs : List Entry) : List Record := (run r tctx init xs).records

/-- A first proof by author A, at its price: no saving; it introduces
    declarations 1 and 2. Then S0006 at 25 USDC, referred, by a seller
    whose artifact reuses declaration 2 and carries its own declaration 3. -/
def first : List Entry := trade 5 0x5 (usdc 10) (usdc 10) authorA none [1, 2] 100
def second : List Entry := trade 6 s0006 (usdc 40) (usdc 25) sellerKey (some referrer) [2, 3] 110
def both : List Entry := first ++ second

theorem both_records :
    (records .model both).map (fun m => (m.digest, m.referrer, m.authors, m.split)) =
      [(105, none, [], ⟨0, 0, 0, 0⟩),
       (106, some referrer, [authorA], ⟨4500000, usdc 3, 1, 7500000⟩)] := by decide

/-- Self-referral: the seller names itself. It collects 4.5 USDC of the
    buyer's saving, never more than the saving its own lower price made. -/
def selfRef : List Entry := trade 6 s0006 (usdc 40) (usdc 25) sellerKey (some sellerKey) [] 110

theorem self_referral_bounded :
    (records .model selfRef).map (fun m => (m.referrer, m.split)) =
      [(some sellerKey, ⟨4500000, 0, 0, 10500000⟩)] := by decide

/-- The seller reusing its own earlier declaration is not its own author. -/
def ownLemma : List Entry :=
  trade 5 0x5 (usdc 10) (usdc 10) sellerKey none [1] 100 ++
  trade 6 s0006 (usdc 40) (usdc 25) sellerKey none [1] 110

theorem own_lemma_not_authored :
    (records .model ownLemma).map (·.authors) = [[], []] := by decide

/-- A second `Settled` of the same digest writes nothing. -/
def replayed : List Entry := second ++ [{ block := 200, event := .settled 106 }]

theorem replay_writes_nothing : records .model replayed = records .model second := by decide

/-- A referral named at settlement, not at funding, is ignored. -/
def lateReferral : List Entry :=
  trade 6 s0006 (usdc 40) (usdc 25) sellerKey none [] 110 |>.map fun x =>
    match x.event with
    | .settled _ => { x with referral := some referrer }
    | _ => x

theorem late_referral_ignored :
    (records .model lateReferral).map (·.referrer) = [none] := by decide

/-- A refunded order: no record. -/
def refunded : List Entry :=
  [{ block := 110, event := .posted (postAt 6 s0006 buyer 110), price := usdc 40 },
   { block := 111, event := .funded 106 (tctx 6 7) 50 sellerKey (usdc 25), referral := some referrer },
   { block := 112, event := .refunded 106 }]

theorem refunded_records_nothing : records .model refunded = [] := by decide

end Nucleus.ProofCommerce.Savings.Examples

/-! ## Mutants

Each theorem above, with one switch of `Rule` turned (and, for
monotonicity, a decision recomputed at read time); each mutant's failure
is a checked statement here, so `lake build` fails if a mutant stops
failing. `contracts/savings` replays the same. -/
namespace Nucleus.ProofCommerce.Savings.Mutants
open Nucleus.ProofCommerce.Market Nucleus.ProofCommerce.Savings
open Nucleus.ProofCommerce.Savings.Examples

/-- S1, against `split_exact`: the buyer takes a flat half. On an odd
    saving one unit is paid to no one. -/
theorem mutant_remainder_breaks_split_exact :
    (split { remainder := false } 7 0 true 0).total ≠ 7 := by decide

/-- S2, against `buyer_keeps_half`: 20 % to each author, not divided. With
    three authors the buyer's share underflows to 0 of a 15 USDC saving. -/
theorem mutant_divide_breaks_buyer_keeps_half :
    (split { divide := false } (usdc 40) (usdc 25) true 3).buyer < (usdc 15 + 1) / 2 := by decide

/-- S3, against `buyer_net_le_cap`: shares of the amount, not the saving.
    A 40 USDC order on a 40 USDC post pays 20 more. -/
theorem mutant_saving_breaks_buyer_net_le_cap :
    usdc 40 < usdc 40 + (split { saving := false } (usdc 40) (usdc 40) true 1).others := by decide

/-- S4, against `seller_revenue_monotone`: the same mutant. A seller that is
    its own referrer collects more at 30 USDC than at 25. -/
theorem mutant_saving_breaks_seller_revenue_monotone :
    (split { saving := false } (usdc 40) (usdc 25) true 0).referrer <
      (split { saving := false } (usdc 40) (usdc 30) true 0).referrer := by decide

/-- S5, against `unreferred_goes_to_buyer`: 30 % paid out with no referrer. -/
theorem mutant_unref_breaks_unreferred_goes_to_buyer :
    (split { unrefToBuyer := false } (usdc 40) (usdc 25) false 0).referrer = 4500000 := by decide

/-- S6, against `one_split_per_order`: any order of the digest, settled or
    not, splits. The replayed `Settled` writes a second record. -/
theorem mutant_phase_breaks_one_split_per_order :
    (records { phase := false } replayed).map (·.digest) = [106, 106] := by decide

/-- S7, against `no_split_without_settlement`: a refund splits too. -/
theorem mutant_onSettle_breaks_no_split_without_settlement :
    (records { onSettle := false } refunded).map (·.digest) = [106] := by decide

/-- S8, against `referral_bound_before_funding`: the referrer named at
    settlement counts. -/
theorem mutant_boundRef_breaks_referral_bound_before_funding :
    (records { boundRef := false } lateReferral).map (·.referrer) = [some referrer] := by decide

/-- S9, against `authors_from_artifact`: the authors the settlement claims. -/
def claims : List Entry :=
  trade 6 s0006 (usdc 40) (usdc 25) sellerKey none [] 110 |>.map fun x =>
    match x.event with
    | .settled _ => { x with claimed := [authorB] }
    | _ => x

theorem mutant_fromArtifact_breaks_authors_from_artifact :
    (records { fromArtifact := false } claims).map (·.authors) = [[authorB]] ∧
      (records .model claims).map (·.authors) = [[]] := by decide

/-- S10, against `authors_from_artifact`: the seller as its own author. -/
theorem mutant_notSeller_breaks_authors_from_artifact :
    (records { notSeller := false } ownLemma).map (·.authors) = [[], [sellerKey]] := by decide

/-- S11, against `monotone`: authors recomputed at read time from an index
    where the last settlement carrying a declaration wins. A later
    settlement carrying declaration 1 takes author A's share of an earlier
    record. -/
def lastWins (xs : List Entry) : List (Nat × Nat) :=
  ((run .model tctx init xs).records.zip
    (xs.filter (fun x => match x.event with | .settled _ => true | _ => false))).foldl
    (fun acc (m, x) => x.decls.map (·, m.seller) ++ acc) []

def readTime (xs : List Entry) : List (List Nat) :=
  ((run .model tctx init xs).records.zip
    (xs.filter (fun x => match x.event with | .settled _ => true | _ => false))).map
    fun (m, x) => authorsOf .model (lastWins xs) x.decls m.seller

def later : List Entry := both ++ trade 7 0x7 (usdc 10) (usdc 10) authorB none [1, 2] 120

theorem mutant_readTime_breaks_monotone : (readTime later).take 2 ≠ readTime both := by decide

theorem model_keeps :
    (records .model later).take 2 = records .model both := by decide

end Nucleus.ProofCommerce.Savings.Mutants

namespace Nucleus.ProofCommerce.Savings
/-- info: 'Nucleus.ProofCommerce.Savings.split_exact' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms split_exact
/-- info: 'Nucleus.ProofCommerce.Savings.buyer_keeps_half' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms buyer_keeps_half
/-- info: 'Nucleus.ProofCommerce.Savings.buyer_net_le_cap' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms buyer_net_le_cap
/-- info: 'Nucleus.ProofCommerce.Savings.seller_revenue_monotone' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms seller_revenue_monotone
/-- info: 'Nucleus.ProofCommerce.Savings.unreferred_goes_to_buyer' depends on axioms: [propext] -/
#guard_msgs in #print axioms unreferred_goes_to_buyer
/-- info: 'Nucleus.ProofCommerce.Savings.one_split_per_order' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms one_split_per_order
/-- info: 'Nucleus.ProofCommerce.Savings.no_split_without_settlement' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms no_split_without_settlement
/-- info: 'Nucleus.ProofCommerce.Savings.recorded_taken' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms recorded_taken
/-- info: 'Nucleus.ProofCommerce.Savings.referral_bound_before_funding' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms referral_bound_before_funding
/-- info: 'Nucleus.ProofCommerce.Savings.authors_from_artifact' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms authors_from_artifact
/-- info: 'Nucleus.ProofCommerce.Savings.monotone' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms monotone
end Nucleus.ProofCommerce.Savings
