import Market
set_option warningAsError true

/- The bootstrap promotion: a pool that matches the price of the first
   settlement of a statement on a reviewed list, paid to that settlement's
   seller. A model of `contracts/site/src/market/promotion.rs`; it moves no
   funds. docs/rfcs/qed-bootstrap-matching-2026-11-27.md.

   Why the seller and why the first settlement: a reward per listing, or a
   match paid on any settlement, is collected by one party playing both
   sides. Post a statement with a known proof, fund the order, settle it
   from a second wallet of one's own, collect. The board and the vault do
   not tell the two wallets apart. A match paid only on the first
   settlement of a reviewed statement with no known proof is earned by
   producing a new proof, whoever produces it.

   The decisions are derived from the market's events (`Market.lean`) in
   chain order, each with its block, and a post's price (the board's
   `maximumAmount`). A `Settled` event of an order admits a match when:
   * the order was funded and joins a post (`Market.joins`);
   * the post's statement is on the reviewed list;
   * the settlement's block is at or after the promotion's start;
   * the statement was not taken before it (`Market.taken`: no order
     joined to any post of it had settled);
   * the amount left after the caps is positive.
   The amount is the least of: the fraction (`bps`, basis points) of the
   lesser of the order's amount and the post's price; the per-statement
   cap; what is left of the pool; what is left of the poster's cap. -/
namespace Nucleus.ProofCommerce.Promotion
open Nucleus.ProofCommerce.Market

/-- The promotion's terms, from the site input. -/
structure Params where
  /-- The first block whose settlements count. -/
  start : Nat
  pool : Nat
  perPoster : Nat
  /-- The match's cap as a fraction of the price, in basis points. -/
  bps : Nat
  perStatement : Nat
  /-- The reviewed list: statement SHA-256 values. -/
  listed : List Nat

/-- One event of the market, with its block and, for a post, its price. -/
structure Entry where
  block : Nat
  event : Event
  price : Nat := 0

/-- An admitted match. `seller` is the settled order's payee key (its
    seller and asset), `price` the post's price. -/
structure Match where
  post : Nat
  statement : Nat
  poster : Nat
  digest : Nat
  seller : Nat
  block : Nat
  price : Nat
  amount : Nat
  deriving DecidableEq, Repr

structure St where
  market : Market
  /-- Post ID → price, first post of an ID first. -/
  prices : List (Nat × Nat)
  granted : List Match

def init : St := ⟨empty, [], []⟩

def paid : List Match → Nat
  | [] => 0
  | m :: rest => m.amount + paid rest

def paidTo (q : Nat) : List Match → Nat
  | [] => 0
  | m :: rest => (if m.poster = q then m.amount else 0) + paidTo q rest

def priceOf (s : St) (id : Nat) : Nat := ((s.prices.find? (·.1 == id)).map (·.2)).getD 0

/-- Which earlier settlement disqualifies one: any of the statement (the
    model), one of the same post (mutant M2), none (mutant M1). -/
inductive First where
  | statement
  | post
  | none
  deriving DecidableEq

/-- The rules, as switches, so each mutant below is the model with one
    switch turned. The model is `Rule.model`, every switch on. -/
structure Rule where
  first : First := .statement
  listed : Bool := true
  started : Bool := true
  fraction : Bool := true
  pool : Bool := true
  perPoster : Bool := true
  toSeller : Bool := true

def Rule.model : Rule := {}

def fresh (r : Rule) (ctx : Ctx) (m : Market) (p : Post) : Bool :=
  match r.first with
  | .statement => !taken ctx m p.statement
  | .post => decide (rankOf ctx m p < 5)
  | .none => true

def amountFor (r : Rule) (P : Params) (s : St) (p : Post) (o : Order) : Nat :=
  let frac := if r.fraction then min o.amount (priceOf s p.id) * P.bps / 10000 else P.perStatement
  let a := min frac P.perStatement
  let a := if r.pool then min a (P.pool - paid s.granted) else a
  if r.perPoster then min a (P.perPoster - paidTo p.poster s.granted) else a

def admits (r : Rule) (ctx : Ctx) (P : Params) (s : St) (blk : Nat) (p : Post) : Bool :=
  (!r.listed || P.listed.contains p.statement) && (!r.started || decide (P.start ≤ blk)) &&
    fresh r ctx s.market p

/-- The match a `Settled d` at block `blk` admits, if any. -/
def candidate (r : Rule) (ctx : Ctx) (P : Params) (s : St) (blk d : Nat) : Option Match :=
  match s.market.orders.find? (fun o => o.digest == d && o.phase == .funded) with
  | none => none
  | some o =>
    match s.market.posts.find? (fun p => joins ctx p o) with
    | none => none
    | some p =>
      if admits r ctx P s blk p ∧ 0 < amountFor r P s p o then
        some ⟨p.id, p.statement, p.poster, d, if r.toSeller then o.payee else p.poster, blk,
          priceOf s p.id, amountFor r P s p o⟩
      else none

def newMatch (r : Rule) (ctx : Ctx) (P : Params) (s : St) (x : Entry) : Option Match :=
  match x.event with
  | .settled d => candidate r ctx P s x.block d
  | _ => none

def step (r : Rule) (ctx : Ctx) (P : Params) (s : St) (x : Entry) : St where
  market := apply s.market x.event
  prices := match x.event with
    | .posted p => s.prices ++ [(p.id, x.price)]
    | _ => s.prices
  granted := s.granted ++ (newMatch r ctx P s x).toList

def run (r : Rule) (ctx : Ctx) (P : Params) (s : St) (xs : List Entry) : St :=
  xs.foldl (step r ctx P) s

/-! ## Lemmas -/

theorem paid_append (l : List Match) (m : Match) : paid (l ++ [m]) = paid l + m.amount := by
  induction l with
  | nil => simp [paid]
  | cons x rest ih => simp only [List.cons_append, paid, ih]; omega

theorem paidTo_append (q : Nat) (l : List Match) (m : Match) :
    paidTo q (l ++ [m]) = paidTo q l + (if m.poster = q then m.amount else 0) := by
  induction l with
  | nil => simp [paidTo]
  | cons x rest ih => simp only [List.cons_append, paidTo, ih]; omega

/-- What an admitted match is, under the model's rules. -/
structure Spec (ctx : Ctx) (P : Params) (s : St) (blk d : Nat) (m : Match) : Prop where
  order : ∃ o ∈ s.market.orders, o.digest = d ∧ o.phase = .funded ∧ ∃ p ∈ s.market.posts,
    joins ctx p o = true ∧ m = ⟨p.id, p.statement, p.poster, d, o.payee, blk, priceOf s p.id,
      amountFor .model P s p o⟩
  listed : P.listed.contains m.statement = true
  started : P.start ≤ blk
  first : taken ctx s.market m.statement = false
  positive : 0 < m.amount

theorem candidate_spec (ctx : Ctx) (P : Params) (s : St) (blk d : Nat) (m : Match)
    (h : candidate .model ctx P s blk d = some m) : Spec ctx P s blk d m := by
  unfold candidate at h
  split at h
  · simp at h
  · rename_i o ho
    split at h
    · simp at h
    · rename_i p hp
      split at h
      · rename_i hc
        simp only [Option.some.injEq] at h
        subst h
        have ho' := List.find?_some ho
        have hp' := List.find?_some hp
        simp only [Bool.and_eq_true, beq_iff_eq] at ho'
        obtain ⟨ha, hpos⟩ := hc
        simp only [admits, Rule.model, fresh, Bool.not_true, Bool.false_or, Bool.and_eq_true,
          decide_eq_true_eq, Bool.not_eq_true'] at ha
        exact {
          order := ⟨o, List.mem_of_find?_eq_some ho, ho'.1, ho'.2, p, List.mem_of_find?_eq_some hp,
            hp', by simp [Rule.model]⟩
          listed := ha.1.1
          started := ha.1.2
          first := ha.2
          positive := hpos }
      · simp at h

theorem newMatch_spec (ctx : Ctx) (P : Params) (s : St) (x : Entry) (m : Match)
    (h : newMatch .model ctx P s x = some m) :
    ∃ d, x.event = .settled d ∧ Spec ctx P s x.block d m := by
  unfold newMatch at h
  split at h
  · rename_i d hd; exact ⟨d, hd, candidate_spec ctx P s x.block d m h⟩
  all_goals simp at h

theorem amountFor_model (P : Params) (s : St) (p : Post) (o : Order) :
    amountFor .model P s p o =
      min (min (min (min o.amount (priceOf s p.id) * P.bps / 10000) P.perStatement)
        (P.pool - paid s.granted)) (P.perPoster - paidTo p.poster s.granted) := rfl

theorem amount_le (P : Params) (s : St) (p : Post) (o : Order) :
    amountFor .model P s p o ≤ P.pool - paid s.granted ∧
      amountFor .model P s p o ≤ P.perPoster - paidTo p.poster s.granted ∧
      amountFor .model P s p o ≤ P.perStatement ∧
      amountFor .model P s p o * 10000 ≤ P.bps * priceOf s p.id := by
  rw [amountFor_model]
  have h1 := Nat.div_mul_le_self (min o.amount (priceOf s p.id) * P.bps) 10000
  have h2 : min o.amount (priceOf s p.id) * P.bps ≤ priceOf s p.id * P.bps :=
    Nat.mul_le_mul_right _ (Nat.min_le_right _ _)
  rw [Nat.mul_comm P.bps]
  generalize min o.amount (priceOf s p.id) * P.bps = X at h1 h2
  generalize X / 10000 = F at h1
  generalize P.pool - paid s.granted = A
  generalize P.perPoster - paidTo p.poster s.granted = B
  have hle : min (min (min F P.perStatement) A) B ≤ F := by omega
  have := Nat.mul_le_mul_right 10000 hle
  omega

/-- A settlement leaves its statement taken. -/
theorem settled_takes (ctx : Ctx) (m : Market) (d : Nat) (o : Order) (ho : o ∈ m.orders)
    (hd : o.digest = d) (hf : o.phase = .funded) (p : Post) (hp : p ∈ m.posts)
    (j : joins ctx p o = true) : taken ctx (apply m (.settled d)) p.statement = true := by
  rw [taken_iff]
  refine ⟨p, posts_grow m _ p hp, rfl, setPhase d .settled o, ?_, ?_, ?_⟩
  · simp only [apply]; exact List.mem_map_of_mem ho
  · simpa [joins, setPhase_context, setPhase_policy] using j
  · left; unfold setPhase; simp only [hd, hf, and_self, ↓reduceIte]

/-- The invariant every reachable state keeps. -/
structure Inv (ctx : Ctx) (P : Params) (s : St) : Prop where
  pool : paid s.granted ≤ P.pool
  poster : ∀ q, paidTo q s.granted ≤ P.perPoster
  distinct : s.granted.Pairwise (fun a b => a.statement ≠ b.statement)
  each : ∀ m ∈ s.granted, taken ctx s.market m.statement = true ∧
    P.listed.contains m.statement = true ∧ P.start ≤ m.block ∧
    m.amount ≤ P.perStatement ∧ m.amount * 10000 ≤ P.bps * m.price

theorem inv_init (ctx : Ctx) (P : Params) : Inv ctx P init :=
  ⟨by simp [init, paid], by simp [init, paidTo], by simp [init], by simp [init]⟩

theorem inv_step (ctx : Ctx) (P : Params) (s : St) (x : Entry) (h : Inv ctx P s) :
    Inv ctx P (step .model ctx P s x) := by
  cases hn : newMatch .model ctx P s x with
  | none =>
      have hm : (step .model ctx P s x).granted = s.granted := by simp [step, hn]
      refine ⟨hm ▸ h.pool, hm ▸ h.poster, hm ▸ h.distinct, ?_⟩
      rw [hm]; intro m hmem
      obtain ⟨t, l, st, ps, fr⟩ := h.each m hmem
      exact ⟨taken_stays ctx s.market x.event _ t, l, st, ps, fr⟩
  | some m =>
      obtain ⟨d, hd, sp⟩ := newMatch_spec ctx P s x m hn
      obtain ⟨o, ho, od, ofun, p, hp, j, hmeq⟩ := sp.order
      have hm : (step .model ctx P s x).granted = s.granted ++ [m] := by simp [step, hn]
      have hmk : (step .model ctx P s x).market = apply s.market (.settled d) := by simp [step, hd]
      obtain ⟨apool, aposter, acap, afrac⟩ := amount_le P s p o
      have mamt : m.amount = amountFor .model P s p o := by rw [hmeq]
      have mst : m.statement = p.statement := by rw [hmeq]
      have mpo : m.poster = p.poster := by rw [hmeq]
      have mpr : m.price = priceOf s p.id := by rw [hmeq]
      have hpool := h.pool
      refine ⟨?_, ?_, ?_, ?_⟩
      · rw [hm, paid_append]; omega
      · intro q; rw [hm, paidTo_append]; have := h.poster q
        split
        · rename_i hq; rw [mpo] at hq; subst hq; omega
        · omega
      · rw [hm, List.pairwise_append]
        refine ⟨h.distinct, List.pairwise_singleton _ _, ?_⟩
        intro a ha b hb heq
        simp only [List.mem_singleton] at hb; subst hb
        have t := (h.each a ha).1
        have f := sp.first
        rw [heq] at t; rw [t] at f; exact absurd f (by decide)
      · rw [hm, hmk]; intro m' hmem
        simp only [List.mem_append, List.mem_singleton] at hmem
        rcases hmem with hmem | rfl
        · obtain ⟨t, l, st, ps, fr⟩ := h.each m' hmem
          exact ⟨taken_stays ctx s.market _ _ t, l, st, ps, fr⟩
        · refine ⟨?_, sp.listed, ?_, by omega, by rw [mamt, mpr]; exact afrac⟩
          · rw [mst]; exact settled_takes ctx s.market d o ho od ofun p hp j
          · have := sp.started; rw [hmeq]; exact this

theorem inv_run (ctx : Ctx) (P : Params) :
    ∀ (xs : List Entry) (s : St), Inv ctx P s → Inv ctx P (run .model ctx P s xs)
  | [], _, h => h
  | x :: xs, s, h => inv_run ctx P xs (step .model ctx P s x) (inv_step ctx P s x h)

theorem reachable (ctx : Ctx) (P : Params) (xs : List Entry) :
    Inv ctx P (run .model ctx P init xs) := inv_run ctx P xs init (inv_init ctx P)

/-! ## Theorems -/

/-- **A match is admitted only for a listed statement, and only for its
    first joined settlement**: the event is the `Settled` of a funded order
    joined to a post of the statement, at or after the start, and no order
    joined to any post of the statement had settled before it. -/
theorem admitted_only_first (ctx : Ctx) (P : Params) (s : St) (x : Entry) (m : Match)
    (h : newMatch .model ctx P s x = some m) :
    x.event = .settled m.digest ∧ P.listed.contains m.statement = true ∧ P.start ≤ x.block ∧
      taken ctx s.market m.statement = false ∧
      ∃ o ∈ s.market.orders, o.digest = m.digest ∧ o.phase = .funded ∧
        ∃ p ∈ s.market.posts, joins ctx p o = true ∧ p.id = m.post ∧ p.statement = m.statement := by
  obtain ⟨d, hd, sp⟩ := newMatch_spec ctx P s x m h
  obtain ⟨o, ho, od, ofun, p, hp, j, rfl⟩ := sp.order
  exact ⟨hd, sp.listed, sp.started, sp.first, o, ho, od, ofun, p, hp, j, rfl, rfl⟩

/-- **Paid to the seller, never the poster**: the match names the settled
    order's payee (its seller and asset); the post's poster enters only
    the per-poster cap. -/
theorem paid_to_seller (ctx : Ctx) (P : Params) (s : St) (x : Entry) (m : Match)
    (h : newMatch .model ctx P s x = some m) :
    ∃ o ∈ s.market.orders, o.digest = m.digest ∧ o.phase = .funded ∧ m.seller = o.payee ∧
      ∃ p ∈ s.market.posts, joins ctx p o = true ∧ p.id = m.post := by
  obtain ⟨d, _, sp⟩ := newMatch_spec ctx P s x m h
  obtain ⟨o, ho, od, ofun, p, hp, j, rfl⟩ := sp.order
  exact ⟨o, ho, od, ofun, rfl, p, hp, j, rfl⟩

/-- **Never twice per statement**, across any number of posts of it. -/
theorem never_twice (ctx : Ctx) (P : Params) (xs : List Entry) :
    (run .model ctx P init xs).granted.Pairwise (fun a b => a.statement ≠ b.statement) :=
  (reachable ctx P xs).distinct

/-- **The pool cap and the per-poster cap are never exceeded.** -/
theorem within_pool (ctx : Ctx) (P : Params) (xs : List Entry) :
    paid (run .model ctx P init xs).granted ≤ P.pool := (reachable ctx P xs).pool

theorem within_poster (ctx : Ctx) (P : Params) (xs : List Entry) (q : Nat) :
    paidTo q (run .model ctx P init xs).granted ≤ P.perPoster := (reachable ctx P xs).poster q

/-- **Each match is at most min(fraction × price, per-statement cap)**,
    the price being the post's own. -/
theorem within_fraction (ctx : Ctx) (P : Params) (xs : List Entry) :
    ∀ m ∈ (run .model ctx P init xs).granted,
      m.amount * 10000 ≤ P.bps * m.price ∧ m.amount ≤ P.perStatement := fun m hm =>
  have e := (reachable ctx P xs).each m hm
  ⟨e.2.2.2.2, e.2.2.2.1⟩

theorem price_is_posts (ctx : Ctx) (P : Params) (s : St) (x : Entry) (m : Match)
    (h : newMatch .model ctx P s x = some m) : m.price = priceOf s m.post := by
  obtain ⟨_, _, sp⟩ := newMatch_spec ctx P s x m h
  obtain ⟨o, _, _, _, p, _, _, rfl⟩ := sp.order
  rfl

/-- **A statement not on the list, or settled before the start, gets
    nothing.** -/
theorem nothing_unlisted_or_early (ctx : Ctx) (P : Params) (xs : List Entry) :
    ∀ m ∈ (run .model ctx P init xs).granted,
      P.listed.contains m.statement = true ∧ P.start ≤ m.block := fun m hm =>
  have e := (reachable ctx P xs).each m hm
  ⟨e.2.1, e.2.2.1⟩

/-- A settlement before the start makes the statement taken: no later
    settlement of it is first. -/
theorem early_settlement_blocks (ctx : Ctx) (P : Params) (s : St) (x : Entry) (m : Match)
    (t : taken ctx s.market m.statement = true) : newMatch .model ctx P s x ≠ some m := by
  intro h
  have := (admitted_only_first ctx P s x m h).2.2.2.1
  rw [t] at this; exact absurd this (by decide)

theorem run_prefix (r : Rule) (ctx : Ctx) (P : Params) :
    ∀ (ys : List Entry) (s : St), ∃ extra, (run r ctx P s ys).granted = s.granted ++ extra
  | [], s => ⟨[], by simp [run]⟩
  | y :: ys, s => by
      obtain ⟨e, he⟩ := run_prefix r ctx P ys (step r ctx P s y)
      refine ⟨(newMatch r ctx P s y).toList ++ e, ?_⟩
      simp only [run, List.foldl_cons] at he ⊢
      rw [he]; simp [step]

/-- **Monotone**: adding events never revokes or changes a match already
    admitted; the matches of a log are a prefix of those of any extension. -/
theorem monotone (ctx : Ctx) (P : Params) (xs ys : List Entry) :
    ∃ extra, (run .model ctx P init (xs ++ ys)).granted = (run .model ctx P init xs).granted ++ extra := by
  have : run .model ctx P init (xs ++ ys) = run .model ctx P (run .model ctx P init xs) ys := by
    simp [run, List.foldl_append]
  rw [this]; exact run_prefix _ ctx P ys _

end Nucleus.ProofCommerce.Promotion

/-! ## Examples

USDC has six decimals. The poster, seller and buyer numbers are stand-ins;
the statements are SHA-256 values: S0006 (Nucleus's open statement, posted
at 40 USDC), the already-public bounty statement (not on the list), and two
stand-ins for further listed rows. -/
namespace Nucleus.ProofCommerce.Promotion.Examples
open Nucleus.ProofCommerce.Market Nucleus.ProofCommerce.Promotion

def usdc (n : Nat) : Nat := n * 1000000

def s0006 : Nat := 0xfff47ea357d16945a265b84f905c991b1e1c64a593afcd571e9c6a76d191db37
def bounty : Nat := 0x9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c
def sA : Nat := 0xa1
def sB : Nat := 0xb1

/-- A test context function: injective on the small numbers used here. -/
def tctx : Ctx := fun id kb => 1000 * id + kb

/-- The first month's terms: a 100 USDC pool, at most 40 USDC to one
    poster's statements, +50 %, at most 20 USDC per statement, from block 100. -/
def P : Params := ⟨100, usdc 100, usdc 40, 5000, usdc 20, [s0006, sA, sB]⟩

def ladder : Nat := 0xA
def stranger : Nat := 0xC
def sellerKey : Nat := 0xB0B

def postAt (id statement poster block : Nat) : Post := ⟨id, 7, 50, statement, 10000, poster, block⟩

/-- Post, fund at the post's price, settle: three entries. -/
def trade (id statement poster price payee postBlock settleBlock : Nat) : List Entry :=
  [⟨postBlock, .posted (postAt id statement poster postBlock), price⟩,
   ⟨postBlock + 1, .funded (100 + id) (tctx id 7) 50 payee price, 0⟩,
   ⟨settleBlock, .settled (100 + id), 0⟩]

def grants (r : Rule) (P : Params) (xs : List Entry) : List Match := (run r tctx P init xs).granted

/-- S0006, posted at 40 USDC by the ladder buyer and settled at block 130
    by a seller: +20 USDC to that seller (50 % of 40, at the 20 USDC cap). -/
def s0006Trade : List Entry := trade 6 s0006 ladder (usdc 40) sellerKey 110 130

theorem s0006_matched :
    grants .model P s0006Trade = [⟨6, s0006, ladder, 106, sellerKey, 130, usdc 40, usdc 20⟩] := by
  decide

/-- Self-dealing on the bounty statement, whose proof is public: the
    poster settles its own post from its own second wallet. Not on the
    list: nothing. -/
def selfDeal : List Entry := trade 9 bounty stranger (usdc 40) (stranger + 1) 110 130

theorem self_dealing_gets_nothing : grants .model P selfDeal = [] := by decide

/-- A second post of S0006, after the first settled: nothing more. -/
def secondPost : List Entry := s0006Trade ++ trade 16 s0006 stranger (usdc 40) 0xD 140 150

theorem second_post_gets_nothing :
    grants .model P secondPost = grants .model P s0006Trade := by decide

/-- Pool exhaustion: a 30 USDC pool, three listed statements by three
    posters: 20, then the 10 left, then nothing. -/
def Psmall : Params := { P with pool := usdc 30 }
def three : List Entry :=
  trade 6 s0006 ladder (usdc 40) sellerKey 110 130 ++
  trade 7 sA stranger (usdc 40) sellerKey 110 131 ++
  trade 8 sB 0xE (usdc 40) sellerKey 110 132

theorem pool_exhausts :
    (grants .model Psmall three).map (·.amount) = [usdc 20, usdc 10] ∧
      paid (grants .model Psmall three) = Psmall.pool := by decide

/-- One poster's three listed statements: 20, 20, then its 40 USDC cap is spent. -/
def onePoster : List Entry :=
  trade 6 s0006 ladder (usdc 40) sellerKey 110 130 ++
  trade 7 sA ladder (usdc 40) sellerKey 110 131 ++
  trade 8 sB ladder (usdc 40) sellerKey 110 132

theorem poster_cap :
    (grants .model P onePoster).map (·.amount) = [usdc 20, usdc 20] := by decide

/-- A 10 USDC post: +5 USDC, half its price. -/
def cheap : List Entry := trade 6 s0006 ladder (usdc 10) sellerKey 110 130

theorem half_the_price : (grants .model P cheap).map (·.amount) = [usdc 5] := by decide

/-- S0006 settled at block 90, before the start, then again at 130 on a
    second post: nothing either time. -/
def early : List Entry :=
  trade 6 s0006 ladder (usdc 40) sellerKey 80 90 ++ trade 16 s0006 stranger (usdc 40) 0xD 120 130

theorem early_gets_nothing : grants .model P early = [] := by decide

end Nucleus.ProofCommerce.Promotion.Examples

/-! ## Mutants

Each theorem above, with one switch of `Rule` turned (and, for
monotonicity, a decision recomputed at read time); each mutant's failure
is a checked statement here, so `lake build` fails if a mutant stops
failing. `contracts/site/src/market/promotion.rs` replays the same. -/
namespace Nucleus.ProofCommerce.Promotion.Mutants
open Nucleus.ProofCommerce.Market Nucleus.ProofCommerce.Promotion
open Nucleus.ProofCommerce.Promotion.Examples

/-- P1, against `admitted_only_first`: no first-settlement check. S0006
    settled before the start; the mutant matches the second settlement,
    of a statement already taken. -/
theorem mutant_grantsa_later_settlement :
    (grants { first := .none } P early).map (·.post) = [16] := by decide

/-- P2, against `never_twice`: first per post, not per statement. The
    second post of S0006 is matched too: two matches, one statement. -/
theorem mutant_grantstwice :
    (grants { first := .post } P secondPost).map (·.statement) = [s0006, s0006] := by decide

/-- P3, against `within_pool`: no pool clamp. 60 USDC paid from a 30 USDC pool. -/
theorem mutant_exceeds_pool :
    Psmall.pool < paid (grants { pool := false } Psmall three) := by decide

/-- P4, against `within_poster`: no per-poster clamp. 60 USDC to one poster
    whose cap is 40. -/
theorem mutant_exceeds_poster :
    P.perPoster < paidTo ladder (grants { perPoster := false } P onePoster) := by decide

/-- P5, against `within_fraction`: a flat per-statement match. 20 USDC on a
    10 USDC post. -/
theorem mutant_exceeds_fraction :
    (grants { fraction := false } P cheap).any (fun m => P.bps * m.price < m.amount * 10000) := by
  decide

/-- P6, against `paid_to_seller`: the match names the poster. -/
theorem mutant_pays_the_poster :
    (grants { toSeller := false } P s0006Trade).map (·.seller) = [ladder] ∧ ladder ≠ sellerKey := by
  decide

/-- P7, against `nothing_unlisted_or_early`: no list check. The
    self-dealing trade on the public bounty statement collects 20 USDC. -/
theorem mutant_pays_self_dealing :
    (grants { listed := false } P selfDeal).map (·.amount) = [usdc 20] := by decide

/-- P8, against `nothing_unlisted_or_early`: no start check. The
    settlement at block 90 is matched. -/
theorem mutant_pays_before_start :
    (grants { started := false } P early).map (·.block) = [90] := by decide

/-- P9, against `monotone`: the pool split at read time among every first
    settlement admitted without the pool clamp. One more settlement cuts an
    admitted match from 20 to 15 USDC. -/
def prorata (P : Params) (ms : List Match) : List Match :=
  ms.map fun m => { m with amount := min m.amount (P.pool / ms.length) }

def oneTrade : List Entry := trade 6 s0006 ladder (usdc 40) sellerKey 110 130
def twoTrades : List Entry := oneTrade ++ trade 7 sA stranger (usdc 40) sellerKey 110 131

theorem mutant_revokes :
    (prorata Psmall (grants { pool := false } Psmall oneTrade)).map (·.amount) = [usdc 20] ∧
    (prorata Psmall (grants { pool := false } Psmall twoTrades)).map (·.amount) = [usdc 15, usdc 15] := by
  decide

theorem model_keeps :
    (grants .model Psmall twoTrades).take 1 = grants .model Psmall oneTrade := by decide

end Nucleus.ProofCommerce.Promotion.Mutants

namespace Nucleus.ProofCommerce.Promotion
/-- info: 'Nucleus.ProofCommerce.Promotion.admitted_only_first' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms admitted_only_first
/-- info: 'Nucleus.ProofCommerce.Promotion.paid_to_seller' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms paid_to_seller
/-- info: 'Nucleus.ProofCommerce.Promotion.never_twice' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms never_twice
/-- info: 'Nucleus.ProofCommerce.Promotion.within_pool' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms within_pool
/-- info: 'Nucleus.ProofCommerce.Promotion.within_poster' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms within_poster
/-- info: 'Nucleus.ProofCommerce.Promotion.within_fraction' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms within_fraction
/-- info: 'Nucleus.ProofCommerce.Promotion.price_is_posts' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms price_is_posts
/-- info: 'Nucleus.ProofCommerce.Promotion.nothing_unlisted_or_early' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms nothing_unlisted_or_early
/-- info: 'Nucleus.ProofCommerce.Promotion.early_settlement_blocks' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms early_settlement_blocks
/-- info: 'Nucleus.ProofCommerce.Promotion.monotone' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms monotone
end Nucleus.ProofCommerce.Promotion
