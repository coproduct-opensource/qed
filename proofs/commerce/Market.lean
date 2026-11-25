import Std
set_option warningAsError true

/- The market index: every post on the board, ours and anyone's, joined to
   the vault orders that answer it, derived from chain events alone. A
   model of `contracts/site/src/market.rs`; it moves no funds.
   docs/rfcs/qed-market-index-2026-11-25.md.

   Events, in chain order:
   * the board's `Posted` and `Withdrawn`;
   * the vault's `Funded` (with the order's `context` and `policyHash`,
     decoded from the `fund` calldata, or from `settle`/`refund` when the
     fund call was not direct), `Settled`, `Refunded` and `Claimed`;
   * `tick`: the block time at which the index is read.

   The join rule: an order answers a post iff its context is
   `ctx post.id post.keyBinding` and its policy hash is the post's. `ctx`
   is keccak-256 over a tag, the ID and the key binding
   (`vault_wire::context`); here it is a parameter, and the one theorem
   that needs it injective says so. The vault does not check the board:
   nothing on chain makes one order per post, so a post's state is the
   furthest phase any joined order reached. -/
namespace Nucleus.ProofCommerce.Market

/-- What the index keeps of a post for the model. `member` (rounds) and
    the page read the rest. -/
structure Post where
  id : Nat
  keyBinding : Nat
  policy : Nat
  statement : Nat
  fundBy : Nat
  poster : Nat
  block : Nat
  deriving DecidableEq, Repr

inductive Phase where
  | funded
  | refunded
  | settled
  | claimed
  deriving DecidableEq, Repr

def Phase.rank : Phase → Nat
  | .funded => 3
  | .refunded => 4
  | .settled => 5
  | .claimed => 6

/-- One vault order. `payee` is the key a `Claimed` names for it: the
    seller and the asset (`payeeKey`, keccak-256 of the two addresses). -/
structure Order where
  digest : Nat
  context : Nat
  policy : Nat
  payee : Nat
  amount : Nat
  phase : Phase
  deriving DecidableEq, Repr

inductive Event where
  | posted (p : Post)
  | withdrawn (id : Nat)
  | funded (digest context policy payee amount : Nat)
  | settled (digest : Nat)
  | refunded (digest : Nat)
  | claimed (payee : Nat)
  | tick (now : Nat)
  deriving Repr

structure Market where
  posts : List Post
  withdrawn : List Nat
  orders : List Order
  now : Nat

def empty : Market := ⟨[], [], [], 0⟩

/-- `ctx id keyBinding`: the context an order answering that post carries. -/
abbrev Ctx := Nat → Nat → Nat

def joins (ctx : Ctx) (p : Post) (o : Order) : Bool :=
  o.context == ctx p.id p.keyBinding && o.policy == p.policy

def setPhase (d : Nat) (to : Phase) (o : Order) : Order :=
  if o.digest = d ∧ o.phase = .funded then { o with phase := to } else o

/-- A claim pays everything owed to the payee at that moment: every
    settled order of that payee, and no order settled later. -/
def claimOne (payee : Nat) (o : Order) : Order :=
  if o.payee = payee ∧ o.phase = .settled then { o with phase := .claimed } else o

/-- One event. The board refuses a second post with an ID it holds
    (`AlreadyPosted`) and the vault a second `fund` of a digest
    (`NotEmpty`); the index ignores both, as they cannot occur. -/
def apply (m : Market) : Event → Market
  | .posted p =>
      if m.posts.any (·.id == p.id) then m else { m with posts := m.posts ++ [p] }
  | .withdrawn id => { m with withdrawn := id :: m.withdrawn }
  | .funded d c pol pay amt =>
      if m.orders.any (·.digest == d) then m
      else { m with orders := m.orders ++ [⟨d, c, pol, pay, amt, .funded⟩] }
  | .settled d => { m with orders := m.orders.map (setPhase d .settled) }
  | .refunded d => { m with orders := m.orders.map (setPhase d .refunded) }
  | .claimed pay => { m with orders := m.orders.map (claimOne pay) }
  | .tick n => { m with now := max m.now n }

def replay (m : Market) (es : List Event) : Market := es.foldl apply m

/-! ## A post's state -/

inductive State where
  | listed
  | expired
  | withdrawn
  | funded
  | refunded
  | settled
  | claimed
  deriving DecidableEq, Repr

def State.rank : State → Nat
  | .listed => 0
  | .expired => 1
  | .withdrawn => 2
  | .funded => 3
  | .refunded => 4
  | .settled => 5
  | .claimed => 6

def ofRank : Nat → State
  | 0 => .listed
  | 1 => .expired
  | 2 => .withdrawn
  | 3 => .funded
  | 4 => .refunded
  | 5 => .settled
  | _ => .claimed

/-- Without a joined order: withdrawn, past its funding deadline, or listed. -/
def base (m : Market) (p : Post) : Nat :=
  if m.withdrawn.contains p.id then 2 else if p.fundBy < m.now then 1 else 0

/-- The furthest phase any joined order reached (0: none). -/
def top (ctx : Ctx) (p : Post) : List Order → Nat
  | [] => 0
  | o :: rest => if joins ctx p o then max o.phase.rank (top ctx p rest) else top ctx p rest

def rankOf (ctx : Ctx) (m : Market) (p : Post) : Nat := max (base m p) (top ctx p m.orders)

def state (ctx : Ctx) (m : Market) (p : Post) : State := ofRank (rankOf ctx m p)

/-- A statement is taken once an order joined to a post of it settled. -/
def taken (ctx : Ctx) (m : Market) (statement : Nat) : Bool :=
  m.posts.any fun p => p.statement == statement && 5 ≤ rankOf ctx m p

/-! ## Lemmas -/

theorem phase_rank_le (ph : Phase) : ph.rank ≤ 6 := by cases ph <;> decide

theorem top_le (ctx : Ctx) (p : Post) : ∀ l, top ctx p l ≤ 6
  | [] => by simp [top]
  | o :: rest => by
      have := top_le ctx p rest
      have := phase_rank_le o.phase
      simp only [top]; split <;> omega

theorem base_le (m : Market) (p : Post) : base m p ≤ 2 := by
  unfold base; split
  · omega
  · split <;> omega

theorem rankOf_le (ctx : Ctx) (m : Market) (p : Post) : rankOf ctx m p ≤ 6 := by
  have := top_le ctx p m.orders; have := base_le m p
  unfold rankOf; omega

theorem state_rank (ctx : Ctx) (m : Market) (p : Post) :
    (state ctx m p).rank = rankOf ctx m p := by
  have h := rankOf_le ctx m p
  unfold state
  generalize rankOf ctx m p = n at h ⊢
  match n, h with
  | 0, _ | 1, _ | 2, _ | 3, _ | 4, _ | 5, _ | 6, _ => rfl

theorem top_append (ctx : Ctx) (p : Post) (o : Order) :
    ∀ l, top ctx p l ≤ top ctx p (l ++ [o])
  | [] => by simp [top]
  | x :: rest => by
      have := top_append ctx p o rest
      simp only [List.cons_append, top]; split <;> omega

/-- A map that keeps each order's context and policy and moves its phase
    only forward keeps `top` or raises it. -/
theorem top_map (ctx : Ctx) (p : Post) (f : Order → Order)
    (ctx_ : ∀ o, (f o).context = o.context) (pol : ∀ o, (f o).policy = o.policy)
    (fwd : ∀ o, o.phase.rank ≤ (f o).phase.rank) :
    ∀ l, top ctx p l ≤ top ctx p (l.map f)
  | [] => by simp [top]
  | x :: rest => by
      have ih := top_map ctx p f ctx_ pol fwd rest
      have hj : joins ctx p (f x) = joins ctx p x := by simp [joins, ctx_, pol]
      have := fwd x
      simp only [List.map_cons, top, hj]; split <;> omega

theorem setPhase_context (d : Nat) (to : Phase) (o : Order) : (setPhase d to o).context = o.context := by
  unfold setPhase; split <;> rfl
theorem setPhase_policy (d : Nat) (to : Phase) (o : Order) : (setPhase d to o).policy = o.policy := by
  unfold setPhase; split <;> rfl
theorem claimOne_context (pay : Nat) (o : Order) : (claimOne pay o).context = o.context := by
  unfold claimOne; split <;> rfl
theorem claimOne_policy (pay : Nat) (o : Order) : (claimOne pay o).policy = o.policy := by
  unfold claimOne; split <;> rfl

theorem setPhase_fwd (d : Nat) (to : Phase) (hto : to ≠ .funded) (o : Order) :
    o.phase.rank ≤ (setPhase d to o).phase.rank := by
  unfold setPhase; split
  · rename_i h; rw [h.2]; cases to <;> simp [Phase.rank] at hto ⊢
  · omega
theorem claimOne_fwd (pay : Nat) (o : Order) : o.phase.rank ≤ (claimOne pay o).phase.rank := by
  unfold claimOne; split
  · rename_i h; simp [h.2, Phase.rank]
  · omega

/-- Every joined order is at most `top`. -/
theorem rank_le_top (ctx : Ctx) (p : Post) :
    ∀ l, ∀ o ∈ l, joins ctx p o = true → o.phase.rank ≤ top ctx p l
  | [], o, h, _ => by simp at h
  | x :: rest, o, h, hj => by
      have ih := rank_le_top ctx p rest
      simp only [List.mem_cons] at h
      simp only [top]
      rcases h with h | h
      · subst h; simp only [hj, ↓reduceIte]; exact Nat.le_max_left _ _
      · have := ih o h hj; split <;> omega

/-- A positive `top` is reached by a joined order. -/
theorem top_witness (ctx : Ctx) (p : Post) :
    ∀ l, ∀ k, 0 < k → k ≤ top ctx p l → ∃ o ∈ l, joins ctx p o = true ∧ k ≤ o.phase.rank
  | [], k, hk, h => by simp [top] at h; omega
  | x :: rest, k, hk, h => by
      have ih := top_witness ctx p rest k hk
      simp only [top] at h
      split at h
      · rename_i hj
        by_cases hx : k ≤ x.phase.rank
        · exact ⟨x, by simp, hj, hx⟩
        · obtain ⟨o, ho, j, r⟩ := ih (by omega)
          exact ⟨o, by simp [ho], j, r⟩
      · obtain ⟨o, ho, j, r⟩ := ih h
        exact ⟨o, by simp [ho], j, r⟩

theorem base_mono (m m' : Market) (p : Post)
    (hw : m.withdrawn.contains p.id = true → m'.withdrawn.contains p.id = true)
    (hn : m.now ≤ m'.now) : base m p ≤ base m' p := by
  unfold base
  cases ha : m.withdrawn.contains p.id <;> cases hb : m'.withdrawn.contains p.id
  · simp only [Bool.false_eq_true, ↓reduceIte]; split <;> split <;> omega
  · simp only [Bool.false_eq_true, ↓reduceIte]; split <;> omega
  · exact absurd ((hw ha).symm.trans hb) (by decide)
  · exact Nat.le_refl _

theorem base_fwd (m : Market) (e : Event) (p : Post) : base m p ≤ base (apply m e) p := by
  cases e with
  | withdrawn id =>
      apply base_mono
      · intro h; simp only [apply, List.contains_cons, h, Bool.or_true]
      · exact Nat.le_refl _
  | tick n =>
      apply base_mono
      · intro h; exact h
      · simp only [apply]; omega
  | posted q => simp only [apply]; split <;> exact Nat.le_refl _
  | funded => simp only [apply]; split <;> exact Nat.le_refl _
  | settled => exact Nat.le_refl _
  | refunded => exact Nat.le_refl _
  | claimed => exact Nat.le_refl _

theorem top_fwd (ctx : Ctx) (m : Market) (e : Event) (p : Post) :
    top ctx p m.orders ≤ top ctx p (apply m e).orders := by
  cases e with
  | funded d c pol pay amt =>
      simp only [apply]; split
      · exact Nat.le_refl _
      · exact top_append ctx p _ _
  | settled d =>
      exact top_map ctx p _ (setPhase_context d _) (setPhase_policy d _)
        (setPhase_fwd d _ (by decide)) _
  | refunded d =>
      exact top_map ctx p _ (setPhase_context d _) (setPhase_policy d _)
        (setPhase_fwd d _ (by decide)) _
  | claimed pay =>
      exact top_map ctx p _ (claimOne_context pay) (claimOne_policy pay) (claimOne_fwd pay) _
  | posted q => simp only [apply]; split <;> exact Nat.le_refl _
  | withdrawn => exact Nat.le_refl _
  | tick => exact Nat.le_refl _

/-! ## Theorems -/

/-- **States only move forward.** One event never moves a post back:
    listed < expired < withdrawn < funded < refunded < settled < claimed. -/
theorem state_forward (ctx : Ctx) (m : Market) (e : Event) (p : Post) :
    (state ctx m p).rank ≤ (state ctx (apply m e) p).rank := by
  rw [state_rank, state_rank]
  have := base_fwd m e p; have := top_fwd ctx m e p
  unfold rankOf; omega

/-- The same over any replay of events. -/
theorem state_forward_replay (ctx : Ctx) (p : Post) :
    ∀ (es : List Event) (m : Market), (state ctx m p).rank ≤ (state ctx (replay m es) p).rank
  | [], m => by simp [replay]
  | e :: es, m => by
      have h1 := state_forward ctx m e p
      have h2 := state_forward_replay ctx p es (apply m e)
      simp only [replay, List.foldl_cons] at h2 ⊢
      omega

/-- Settled (or claimed) shows only with a joined order settled. -/
theorem settled_has_joined_order (ctx : Ctx) (m : Market) (p : Post)
    (h : 5 ≤ (state ctx m p).rank) :
    ∃ o ∈ m.orders, joins ctx p o = true ∧ (o.phase = .settled ∨ o.phase = .claimed) := by
  rw [state_rank] at h
  have hb := base_le m p
  unfold rankOf at h
  obtain ⟨o, ho, j, r⟩ := top_witness ctx p m.orders 5 (by omega) (by omega)
  refine ⟨o, ho, j, ?_⟩
  cases hp : o.phase <;> simp [hp, Phase.rank] at r ⊢

/-- **A post becomes settled only by a `Settled` event whose order joins
    it**, and that order was funded. -/
theorem settles_only_by_joined_settled (ctx : Ctx) (m : Market) (e : Event) (p : Post)
    (before : (state ctx m p).rank < 5) (after : 5 ≤ (state ctx (apply m e) p).rank) :
    ∃ d, e = .settled d ∧ ∃ o ∈ m.orders, o.digest = d ∧ joins ctx p o = true ∧ o.phase = .funded := by
  rw [state_rank] at before after
  unfold rankOf at before after
  have hb := base_le (apply m e) p
  have topAfter : 5 ≤ top ctx p (apply m e).orders := by omega
  -- Every joined order is below settled before the event.
  have below : ∀ o ∈ m.orders, joins ctx p o = true → o.phase.rank < 5 := fun o ho j => by
    have := rank_le_top ctx p m.orders o ho j; omega
  obtain ⟨o', ho', j', r'⟩ := top_witness ctx p (apply m e).orders 5 (by omega) topAfter
  cases e with
  | settled d =>
      simp only [apply, List.mem_map] at ho'
      obtain ⟨o, ho, rfl⟩ := ho'
      have j : joins ctx p o = true := by
        simpa [joins, setPhase_context, setPhase_policy] using j'
      unfold setPhase at r'
      split at r'
      · rename_i hc; exact ⟨d, rfl, o, ho, hc.1, j, hc.2⟩
      · have := below o ho j; omega
  | refunded d =>
      simp only [apply, List.mem_map] at ho'
      obtain ⟨o, ho, rfl⟩ := ho'
      have j : joins ctx p o = true := by
        simpa [joins, setPhase_context, setPhase_policy] using j'
      have := below o ho j
      unfold setPhase at r'; split at r'
      · simp [Phase.rank] at r'
      · omega
  | claimed pay =>
      simp only [apply, List.mem_map] at ho'
      obtain ⟨o, ho, rfl⟩ := ho'
      have j : joins ctx p o = true := by
        simpa [joins, claimOne_context, claimOne_policy] using j'
      have := below o ho j
      unfold claimOne at r'; split at r'
      · rename_i hc; rw [hc.2] at this; simp [Phase.rank] at this
      · omega
  | funded d c pol pay amt =>
      simp only [apply] at ho'
      split at ho'
      · have := below o' ho' j'; omega
      · simp only [List.mem_append, List.mem_singleton] at ho'
        rcases ho' with ho' | rfl
        · have := below o' ho' j'; omega
        · simp [Phase.rank] at r'
  | posted q =>
      simp only [apply] at ho'; split at ho' <;> (have := below o' ho' j'; omega)
  | withdrawn id => have := below o' ho' j'; omega
  | tick n => have := below o' ho' j'; omega

/-- **An order joins at most one post**, when `ctx` is injective (keccak-256
    collision resistance, assumed) and post IDs are distinct. -/
theorem join_unique (ctx : Ctx) (inj : ∀ a b c d, ctx a b = ctx c d → a = c ∧ b = d)
    (p q : Post) (o : Order) (hp : joins ctx p o = true) (hq : joins ctx q o = true) :
    p.id = q.id := by
  simp only [joins, Bool.and_eq_true, beq_iff_eq] at hp hq
  exact (inj _ _ _ _ (hp.1.symm.trans hq.1)).1

/-- Post IDs in the index are distinct: two posts with one ID are one post. -/
def IdsDistinct (m : Market) : Prop := ∀ p ∈ m.posts, ∀ q ∈ m.posts, p.id = q.id → p = q

theorem ids_distinct_apply (m : Market) (e : Event) (h : IdsDistinct m) :
    IdsDistinct (apply m e) := by
  cases e with
  | posted n =>
      simp only [apply]; split
      · exact h
      · rename_i fresh
        intro p hp q hq hpq
        simp only [List.any_eq_true, beq_iff_eq, not_exists, not_and] at fresh
        simp only [List.mem_append, List.mem_singleton] at hp hq
        rcases hp with hp | rfl <;> rcases hq with hq | rfl
        · exact h p hp q hq hpq
        · exact absurd hpq (fresh p hp)
        · exact absurd hpq.symm (fresh q hq)
        · rfl
  | withdrawn => exact h
  | funded => simp only [apply]; split <;> exact h
  | settled => exact h
  | refunded => exact h
  | claimed => exact h
  | tick => exact h

theorem ids_distinct_replay : ∀ (es : List Event) (m : Market), IdsDistinct m → IdsDistinct (replay m es)
  | [], _, h => h
  | e :: es, m, h => ids_distinct_replay es (apply m e) (ids_distinct_apply m e h)

/-- **No order is counted against two posts** of a replayed index. -/
theorem order_joins_one_post (ctx : Ctx) (inj : ∀ a b c d, ctx a b = ctx c d → a = c ∧ b = d)
    (es : List Event) (p q : Post) (o : Order)
    (hp : p ∈ (replay empty es).posts) (hq : q ∈ (replay empty es).posts)
    (jp : joins ctx p o = true) (jq : joins ctx q o = true) : p = q :=
  ids_distinct_replay es empty (by intro p hp; simp [empty] at hp) p hp q hq
    (join_unique ctx inj p q o jp jq)

/-! ## Rounds -/

/-- A round: a budget, a task count, and which posts are its (the bounty
    buyer's, from the round's first post to the next round's). -/
structure Round where
  budget : Nat
  tasks : Nat
  member : Post → Bool

def inRound (ctx : Ctx) (m : Market) (r : Round) (o : Order) : Bool :=
  m.posts.any fun p => r.member p && joins ctx p o

def sumIf (f : Order → Bool) : List Order → Nat
  | [] => 0
  | o :: rest => (if f o then o.amount else 0) + sumIf f rest

def countIf (f : Order → Bool) : List Order → Nat
  | [] => 0
  | o :: rest => (if f o then 1 else 0) + countIf f rest

def isRefunded (o : Order) : Bool := o.phase == .refunded

/-- Funded into the round, and booked back to the buyer. Each order is
    one term of each sum: never counted twice. -/
def fundedAmt (ctx : Ctx) (m : Market) (r : Round) : Nat := sumIf (inRound ctx m r) m.orders
def refundAmt (ctx : Ctx) (m : Market) (r : Round) : Nat :=
  sumIf (fun o => inRound ctx m r o && isRefunded o) m.orders
def fundedTasks (ctx : Ctx) (m : Market) (r : Round) : Nat := countIf (inRound ctx m r) m.orders
def refundTasks (ctx : Ctx) (m : Market) (r : Round) : Nat :=
  countIf (fun o => inRound ctx m r o && isRefunded o) m.orders

def spent (ctx : Ctx) (m : Market) (r : Round) : Nat := fundedAmt ctx m r - refundAmt ctx m r
def remaining (ctx : Ctx) (m : Market) (r : Round) : Nat := r.budget - spent ctx m r
def used (ctx : Ctx) (m : Market) (r : Round) : Nat := fundedTasks ctx m r - refundTasks ctx m r
def remainingTasks (ctx : Ctx) (m : Market) (r : Round) : Nat := r.tasks - used ctx m r

theorem sumIf_and_le (f g : Order → Bool) : ∀ l, sumIf (fun o => f o && g o) l ≤ sumIf f l
  | [] => by simp [sumIf]
  | o :: rest => by
      have := sumIf_and_le f g rest
      simp only [sumIf]
      by_cases hf : f o = true <;> by_cases hg : g o = true <;> simp [hf, hg] <;> omega

theorem countIf_and_le (f g : Order → Bool) : ∀ l, countIf (fun o => f o && g o) l ≤ countIf f l
  | [] => by simp [countIf]
  | o :: rest => by
      have := countIf_and_le f g rest
      simp only [countIf]
      by_cases hf : f o = true <;> by_cases hg : g o = true <;> simp [hf, hg] <;> omega

/-- Refunds never exceed what was funded into the round. -/
theorem refunds_le_funded (ctx : Ctx) (m : Market) (r : Round) :
    refundAmt ctx m r ≤ fundedAmt ctx m r := sumIf_and_le _ _ _

/-- **Remaining = budget − (funded − refunded), never below zero** while
    the round keeps its commitment (it funds at most its budget, net of
    refunds): no truncation hides an overspend. -/
theorem remaining_exact (ctx : Ctx) (m : Market) (r : Round)
    (commitment : fundedAmt ctx m r ≤ r.budget + refundAmt ctx m r) :
    remaining ctx m r + (fundedAmt ctx m r - refundAmt ctx m r) = r.budget := by
  have := refunds_le_funded ctx m r
  unfold remaining spent; omega

theorem remaining_tasks_exact (ctx : Ctx) (m : Market) (r : Round)
    (commitment : fundedTasks ctx m r ≤ r.tasks + refundTasks ctx m r) :
    remainingTasks ctx m r + (fundedTasks ctx m r - refundTasks ctx m r) = r.tasks := by
  have := countIf_and_le (inRound ctx m r) isRefunded m.orders
  unfold remainingTasks used fundedTasks refundTasks at *; omega

/-- Two rounds with no post in common share no order. -/
theorem rounds_disjoint (ctx : Ctx) (inj : ∀ a b c d, ctx a b = ctx c d → a = c ∧ b = d)
    (es : List Event) (r s : Round) (apart : ∀ p, ¬ (r.member p = true ∧ s.member p = true))
    (o : Order) :
    ¬ (inRound ctx (replay empty es) r o = true ∧ inRound ctx (replay empty es) s o = true) := by
  intro ⟨hr, hs⟩
  simp only [inRound, List.any_eq_true, Bool.and_eq_true] at hr hs
  obtain ⟨p, hp, mp, jp⟩ := hr
  obtain ⟨q, hq, mq, jq⟩ := hs
  have := order_joins_one_post ctx inj es p q o hp hq jp jq
  subst this
  exact apart p ⟨mp, mq⟩

/-! ## Taken statements -/

/-- **Taken means settled**: a statement is taken exactly when some post of
    it has a joined order settled or claimed. -/
theorem taken_iff (ctx : Ctx) (m : Market) (s : Nat) :
    taken ctx m s = true ↔
      ∃ p ∈ m.posts, p.statement = s ∧
        ∃ o ∈ m.orders, joins ctx p o = true ∧ (o.phase = .settled ∨ o.phase = .claimed) := by
  constructor
  · intro h
    simp only [taken, List.any_eq_true, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at h
    obtain ⟨p, hp, hs, r⟩ := h
    have : 5 ≤ (state ctx m p).rank := by rw [state_rank]; exact r
    exact ⟨p, hp, hs, settled_has_joined_order ctx m p this⟩
  · intro ⟨p, hp, hs, o, ho, j, ph⟩
    simp only [taken, List.any_eq_true, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq]
    refine ⟨p, hp, hs, ?_⟩
    have := rank_le_top ctx p m.orders o ho j
    have : 5 ≤ o.phase.rank := by rcases ph with h | h <;> simp [h, Phase.rank]
    unfold rankOf; omega

theorem posts_grow (m : Market) (e : Event) : ∀ p ∈ m.posts, p ∈ (apply m e).posts := by
  intro p hp
  cases e with
  | posted n => simp only [apply]; split
                · exact hp
                · exact List.mem_append_left _ hp
  | _ => simp only [apply] <;> (try split) <;> exact hp

/-- **Once taken, always taken.** -/
theorem taken_stays (ctx : Ctx) (m : Market) (e : Event) (s : Nat)
    (h : taken ctx m s = true) : taken ctx (apply m e) s = true := by
  simp only [taken, List.any_eq_true, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at h ⊢
  obtain ⟨p, hp, hs, r⟩ := h
  refine ⟨p, posts_grow m e p hp, hs, ?_⟩
  have := state_forward ctx m e p
  rw [state_rank, state_rank] at this; omega

end Nucleus.ProofCommerce.Market

/-! ## Mutants

Each theorem above, with one rule of the model changed the way an indexer
could get it wrong; each mutant's failure is a checked statement here, so
`lake build` fails if a mutant stops failing. -/
namespace Nucleus.ProofCommerce.Market.Mutants
open Nucleus.ProofCommerce.Market

/-- A test context function: injective on the small numbers used here. -/
def tctx : Ctx := fun id kb => 1000 * id + kb

def p1 : Post := ⟨1, 7, 50, 900, 100, 0, 0⟩
def p2 : Post := ⟨2, 7, 50, 900, 100, 0, 0⟩

/-- M1, against `state_forward`: the post shows its *latest* joined
    order's phase. A refunded order then a new funded one moves the post
    from refunded back to funded. -/
def latest (ctx : Ctx) (m : Market) (p : Post) : Nat :=
  match (m.orders.filter (joins ctx p)).getLast? with
  | some o => o.phase.rank
  | none => base m p

def twoOrders : Market :=
  replay empty [.posted p1, .funded 11 (tctx 1 7) 50 3 10, .refunded 11]

theorem mutant_latest_moves_back :
    latest tctx (apply twoOrders (.funded 12 (tctx 1 7) 50 3 10)) p1
      < latest tctx twoOrders p1 := by decide

theorem model_does_not_move_back :
    (state tctx twoOrders p1).rank
      ≤ (state tctx (apply twoOrders (.funded 12 (tctx 1 7) 50 3 10)) p1).rank := by decide

/-- M2, against `settles_only_by_joined_settled`: join on the context
    alone. An order with the post's context and another policy settles,
    and the post shows settled though no order joins it by the rule. -/
def joinsNoPolicy (ctx : Ctx) (p : Post) (o : Order) : Bool := o.context == ctx p.id p.keyBinding

def topNoPolicy (ctx : Ctx) (p : Post) (l : List Order) : Nat :=
  l.foldr (fun o r => if joinsNoPolicy ctx p o then max o.phase.rank r else r) 0

def otherPolicy : Market :=
  replay empty [.posted p1, .funded 21 (tctx 1 7) 51 3 10, .settled 21]

theorem mutant_settled_without_join :
    5 ≤ topNoPolicy tctx p1 otherPolicy.orders ∧
      otherPolicy.orders.all (fun o => !joins tctx p1 o) := by decide

theorem model_not_settled_without_join : (state tctx otherPolicy p1).rank < 5 := by decide

/-- M3, against `join_unique` and `order_joins_one_post`: drop the
    injectivity of `ctx` (a context that ignores the post's ID). One order
    joins two posts. -/
def flat : Ctx := fun _ kb => kb

theorem mutant_one_order_two_posts :
    let o : Order := ⟨31, flat 1 7, 50, 3, 10, .funded⟩
    joins flat p1 o = true ∧ joins flat p2 o = true ∧ p1.id ≠ p2.id := by decide

/-- M4, against `remaining_exact`: remaining counted from Funded alone,
    without refunds. A round funds twice, one refunded: the mutant's
    remaining plus what it counts spent is not the budget. -/
def r1 : Round := ⟨15, 2, fun p => p.id == 1⟩

def refundedRound : Market :=
  replay empty [.posted p1, .funded 41 (tctx 1 7) 50 3 10, .refunded 41,
    .funded 42 (tctx 1 7) 50 3 10, .tick 200]

theorem mutant_remaining_without_refunds :
    (r1.budget - fundedAmt tctx refundedRound r1) + fundedAmt tctx refundedRound r1 ≠ r1.budget
      ∧ fundedAmt tctx refundedRound r1 ≤ r1.budget + refundAmt tctx refundedRound r1 := by
  decide

theorem model_remaining : remaining tctx refundedRound r1 = 5 ∧
    remainingTasks tctx refundedRound r1 = 1 := by decide

/-- M5, against `taken_iff`: "taken" once funded. A funded, unsettled post
    makes its statement taken with no settled order. -/
def takenFunded (ctx : Ctx) (m : Market) (s : Nat) : Bool :=
  m.posts.any fun p => p.statement == s && 3 ≤ rankOf ctx m p

def fundedOnly : Market := replay empty [.posted p1, .funded 51 (tctx 1 7) 50 3 10]

theorem mutant_taken_when_funded :
    takenFunded tctx fundedOnly 900 = true ∧
      fundedOnly.orders.all (fun o => o.phase == .funded) := by decide

theorem model_not_taken_when_funded : taken tctx fundedOnly 900 = false := by decide

/-- M6, against `settles_only_by_joined_settled` through claims: a claim
    that also marks orders the payee has not been paid for (funded ones)
    shows a post claimed without a settlement. -/
def claimAny (payee : Nat) (o : Order) : Order :=
  if o.payee = payee then { o with phase := .claimed } else o

theorem mutant_claimed_without_settled :
    let m := fundedOnly
    let after := { m with orders := m.orders.map (claimAny 3) }
    top tctx p1 m.orders < 5 ∧ 5 ≤ top tctx p1 after.orders := by decide

theorem model_claim_needs_settled :
    (state tctx (apply fundedOnly (.claimed 3)) p1).rank < 5 := by decide

end Nucleus.ProofCommerce.Market.Mutants

namespace Nucleus.ProofCommerce.Market
/-- info: 'Nucleus.ProofCommerce.Market.state_forward_replay' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms state_forward_replay
/-- info: 'Nucleus.ProofCommerce.Market.settles_only_by_joined_settled' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms settles_only_by_joined_settled
/-- info: 'Nucleus.ProofCommerce.Market.order_joins_one_post' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms order_joins_one_post
/-- info: 'Nucleus.ProofCommerce.Market.remaining_exact' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms remaining_exact
/-- info: 'Nucleus.ProofCommerce.Market.rounds_disjoint' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms rounds_disjoint
/-- info: 'Nucleus.ProofCommerce.Market.taken_iff' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms taken_iff
/-- info: 'Nucleus.ProofCommerce.Market.taken_stays' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms taken_stays
end Nucleus.ProofCommerce.Market

/-! ## The real events

Base (chain 8453), board `0xd968d5659b3c63cd74d7b4d09345ff3417711038`, vault
`0x952c31aa208dd129059f6065a26b57c930c6ab3c`, read by `nucleus-site
market-capture` to block 62256533 (2026-11-25 21:21 UTC) and replayed in
`contracts/site/tests/market.rs` against the same table. The subset: the
first bounty post (withdrawn), round 1's refunded order, the four
settlements by the seller outside the authors, and round r1's five posts.
`ctx` is the table of keccak-256 contexts the Rust test recomputes. -/
namespace Nucleus.ProofCommerce.Market.Real
open Nucleus.ProofCommerce.Market

def buyer : Nat := 0x133c25a80fb323de143e8ad5c6c620bf8713edfd
def statement : Nat := 0x9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c

/-- keccak256(keccak256("NucleusContextV1") ‖ id ‖ keyBinding), for each
    post here (one key binding, the bounty buyer's). -/
def table : List (Nat × Nat) := [
  (0x28daaf524e25938fc92d7c55cab97516f4e55b3cbd120b6de885e3e4cd2098dd, 0x59596d4ce2add9f61560384abf166e7074dfa13126b745180c7250ae8c155f54),
  (0x2ca29bcf72cfddc732019e72d64750a13f458590bd042804ec07e5ea66b48812, 0x5b6e8ee307d614489776fd8725a45c880f2cbe2e8c6ce79adb1841ebca91663f),
  (0xb454a434583caf2c899e4d48b18d4776951128bbe029fd73f5c57a4c31a3bf7e, 0xe822fb25d1e4cc66aecf2b928d9e6495a54051d8b2682baf956d4c42f3920f94),
  (0x7b746a3c85353e75d03acbf0b1bd22ea3be925b583808f6a059ad8a409f35eb7, 0xd0d7f94faa8419f9bc81831c54ddc9a04e9eac068c7cc14a41caac0f7b3cc4d5),
  (0xec8668825da64c8724ae06170db5d42226cf34524795fe3799f727caa8e51bba, 0xb24d0bba9ea90262ec441448c30c1c95056067e9ab3e16f8d250ffd45df98902),
  (0x625e31dab83ec36ff2b3babc3be3e61ca9f1ea7ab39d32fe85c42989c49cba6b, 0x08770b74dba1a800a78f85b235cb8d92b27bf51a9e80bf531f8afb0bfe630370),
  (0xafa53fb047f9618d58ddb6d173abf031ec741c40ed44d3ac815391b182394727, 0xa1c0369fd35a3f2efc5cce7182544495e07615e47a576f5568958e8de7dc3bd3),
  (0x41099437d91be57496eb2a6207f3c017a3b2a675768926cf36cd9782cc81e353, 0x991bac0166894d824c265792f3109ad18a3ee6188333b6802e04275bb2d53522),
  (0xa739b0af1703182ac734efed744237f62dc93c61b6a49a354ee5ffcd9722b299, 0x998e2b4a7d895f6cf37f517782cba19f767818b2487c634717f8fd51adee1d5b),
  (0x34f01e4c96f3a234590bfd6f157bfff002e29828c9c4f3733d4869ae727f761c, 0xaa6233c4a19742bdef130a47958e2a9a2465057f8c0e8de8b310f0d1f8a15171),
  (0x86fff8186702d87007c8383584af57dc88a512c17b03f136095b27c290459485, 0xec3f72259e9fad2ff626e866db3cbfc871a9e3a7326499b64771ffa8b93a96d1)]

def ctx : Ctx := fun id _ => ((table.find? (·.1 == id)).map (·.2)).getD 0

def events : List Event := [
  .posted ⟨0x28daaf524e25938fc92d7c55cab97516f4e55b3cbd120b6de885e3e4cd2098dd, 0x3a6e9e05ca618436d2df7c4e6a0cbd28878d45e3d040da75a867b9ce9676e9d8, 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e, 0x9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c, 1794698957, 0x133c25a80fb323de143e8ad5c6c620bf8713edfd, 57110912⟩,
  .withdrawn 0x28daaf524e25938fc92d7c55cab97516f4e55b3cbd120b6de885e3e4cd2098dd,
  .posted ⟨0x2ca29bcf72cfddc732019e72d64750a13f458590bd042804ec07e5ea66b48812, 0x3a6e9e05ca618436d2df7c4e6a0cbd28878d45e3d040da75a867b9ce9676e9d8, 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e, 0x9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c, 1795044835, 0x133c25a80fb323de143e8ad5c6c620bf8713edfd, 58840301⟩,
  .funded 0x70a767b953b1acb3c20d99a8709101d7ca9e0c4ed7b19a19b3067d2543dc3214
    0x5b6e8ee307d614489776fd8725a45c880f2cbe2e8c6ce79adb1841ebca91663f 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e
    0xb134f0487483dfb8a362e03036409b5701e69ea32d73fcf4f00616d445b1b7df 25000000,
  .refunded 0x70a767b953b1acb3c20d99a8709101d7ca9e0c4ed7b19a19b3067d2543dc3214,
  .claimed 0x20f1a8ba11cedece31fdf2522044cd0c325cb0aede99845aa3662fc57593ddf4,
  .posted ⟨0xb454a434583caf2c899e4d48b18d4776951128bbe029fd73f5c57a4c31a3bf7e, 0x3a6e9e05ca618436d2df7c4e6a0cbd28878d45e3d040da75a867b9ce9676e9d8, 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e, 0x9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c, 1795596145, 0x133c25a80fb323de143e8ad5c6c620bf8713edfd, 61596854⟩,
  .funded 0xcdea51489e4a4e03a07d63d5443a4f978e93b94a6ca1850ab242458fe8946c24
    0xe822fb25d1e4cc66aecf2b928d9e6495a54051d8b2682baf956d4c42f3920f94 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e
    0x391711497fd15f8052e6b4021f1567a9f51f2e19e799a87db1547080408c6ae8 25000000,
  .settled 0xcdea51489e4a4e03a07d63d5443a4f978e93b94a6ca1850ab242458fe8946c24,
  .claimed 0x391711497fd15f8052e6b4021f1567a9f51f2e19e799a87db1547080408c6ae8,
  .posted ⟨0x7b746a3c85353e75d03acbf0b1bd22ea3be925b583808f6a059ad8a409f35eb7, 0x3a6e9e05ca618436d2df7c4e6a0cbd28878d45e3d040da75a867b9ce9676e9d8, 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e, 0x9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c, 1795662587, 0x133c25a80fb323de143e8ad5c6c620bf8713edfd, 61929064⟩,
  .funded 0xb5c5bdf7feaeb0d2b93d188facfd17812fe78e0047ef458067ecf4e0fbf7859a
    0xd0d7f94faa8419f9bc81831c54ddc9a04e9eac068c7cc14a41caac0f7b3cc4d5 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e
    0x391711497fd15f8052e6b4021f1567a9f51f2e19e799a87db1547080408c6ae8 25000000,
  .settled 0xb5c5bdf7feaeb0d2b93d188facfd17812fe78e0047ef458067ecf4e0fbf7859a,
  .claimed 0x391711497fd15f8052e6b4021f1567a9f51f2e19e799a87db1547080408c6ae8,
  .posted ⟨0xec8668825da64c8724ae06170db5d42226cf34524795fe3799f727caa8e51bba, 0x3a6e9e05ca618436d2df7c4e6a0cbd28878d45e3d040da75a867b9ce9676e9d8, 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e, 0x9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c, 1795665703, 0x133c25a80fb323de143e8ad5c6c620bf8713edfd, 61944643⟩,
  .funded 0xf894cd7e822b16dfc96059edb16ef0226a4453fb7e9bcc3f91411d44d9f14881
    0xb24d0bba9ea90262ec441448c30c1c95056067e9ab3e16f8d250ffd45df98902 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e
    0x391711497fd15f8052e6b4021f1567a9f51f2e19e799a87db1547080408c6ae8 25000000,
  .settled 0xf894cd7e822b16dfc96059edb16ef0226a4453fb7e9bcc3f91411d44d9f14881,
  .claimed 0x391711497fd15f8052e6b4021f1567a9f51f2e19e799a87db1547080408c6ae8,
  .posted ⟨0x625e31dab83ec36ff2b3babc3be3e61ca9f1ea7ab39d32fe85c42989c49cba6b, 0x3a6e9e05ca618436d2df7c4e6a0cbd28878d45e3d040da75a867b9ce9676e9d8, 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e, 0x9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c, 1795667715, 0x133c25a80fb323de143e8ad5c6c620bf8713edfd, 61954704⟩,
  .funded 0x47e69316147efd3853a60912e499b84f8a9c42e6ff265bb85197c10d97906885
    0x08770b74dba1a800a78f85b235cb8d92b27bf51a9e80bf531f8afb0bfe630370 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e
    0x391711497fd15f8052e6b4021f1567a9f51f2e19e799a87db1547080408c6ae8 25000000,
  .settled 0x47e69316147efd3853a60912e499b84f8a9c42e6ff265bb85197c10d97906885,
  .claimed 0x391711497fd15f8052e6b4021f1567a9f51f2e19e799a87db1547080408c6ae8,
  .posted ⟨0xafa53fb047f9618d58ddb6d173abf031ec741c40ed44d3ac815391b182394727, 0x3a6e9e05ca618436d2df7c4e6a0cbd28878d45e3d040da75a867b9ce9676e9d8, 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e, 0x9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c, 1795677106, 0x133c25a80fb323de143e8ad5c6c620bf8713edfd, 62001659⟩,
  .funded 0xe8c1e899d062f838109deb4a798d5fb5e0c212384ba9c632d0a6c85a3cd5ec91
    0xa1c0369fd35a3f2efc5cce7182544495e07615e47a576f5568958e8de7dc3bd3 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e
    0xad239bb5e3f37554ffb48e70fe9c313e47fb6d0bc07d19f4de6a27d9a4ed4593 1000000,
  .settled 0xe8c1e899d062f838109deb4a798d5fb5e0c212384ba9c632d0a6c85a3cd5ec91,
  .claimed 0xad239bb5e3f37554ffb48e70fe9c313e47fb6d0bc07d19f4de6a27d9a4ed4593,
  .posted ⟨0x41099437d91be57496eb2a6207f3c017a3b2a675768926cf36cd9782cc81e353, 0x3a6e9e05ca618436d2df7c4e6a0cbd28878d45e3d040da75a867b9ce9676e9d8, 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e, 0x9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c, 1795684847, 0x133c25a80fb323de143e8ad5c6c620bf8713edfd, 62040362⟩,
  .funded 0x61e5e951e5cc7573f73b01465d898061a3cc288a3794a1cdb16a215b5fdb8035
    0x991bac0166894d824c265792f3109ad18a3ee6188333b6802e04275bb2d53522 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e
    0xad239bb5e3f37554ffb48e70fe9c313e47fb6d0bc07d19f4de6a27d9a4ed4593 1000000,
  .settled 0x61e5e951e5cc7573f73b01465d898061a3cc288a3794a1cdb16a215b5fdb8035,
  .claimed 0xad239bb5e3f37554ffb48e70fe9c313e47fb6d0bc07d19f4de6a27d9a4ed4593,
  .posted ⟨0xa739b0af1703182ac734efed744237f62dc93c61b6a49a354ee5ffcd9722b299, 0x3a6e9e05ca618436d2df7c4e6a0cbd28878d45e3d040da75a867b9ce9676e9d8, 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e, 0x9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c, 1795685421, 0x133c25a80fb323de143e8ad5c6c620bf8713edfd, 62043232⟩,
  .funded 0xf491d331c15faf758860004518209e592475d9cd5e2300a3116a5881d6daaf18
    0x998e2b4a7d895f6cf37f517782cba19f767818b2487c634717f8fd51adee1d5b 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e
    0xad239bb5e3f37554ffb48e70fe9c313e47fb6d0bc07d19f4de6a27d9a4ed4593 1000000,
  .settled 0xf491d331c15faf758860004518209e592475d9cd5e2300a3116a5881d6daaf18,
  .claimed 0xad239bb5e3f37554ffb48e70fe9c313e47fb6d0bc07d19f4de6a27d9a4ed4593,
  .posted ⟨0x34f01e4c96f3a234590bfd6f157bfff002e29828c9c4f3733d4869ae727f761c, 0x3a6e9e05ca618436d2df7c4e6a0cbd28878d45e3d040da75a867b9ce9676e9d8, 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e, 0x9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c, 1795685994, 0x133c25a80fb323de143e8ad5c6c620bf8713edfd, 62046100⟩,
  .funded 0x22bbc2209751d3de037e784a7766b9a02dbc97a09e855335eaf14de0b48ffcb1
    0xaa6233c4a19742bdef130a47958e2a9a2465057f8c0e8de8b310f0d1f8a15171 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e
    0xad239bb5e3f37554ffb48e70fe9c313e47fb6d0bc07d19f4de6a27d9a4ed4593 1000000,
  .settled 0x22bbc2209751d3de037e784a7766b9a02dbc97a09e855335eaf14de0b48ffcb1,
  .claimed 0xad239bb5e3f37554ffb48e70fe9c313e47fb6d0bc07d19f4de6a27d9a4ed4593,
  .posted ⟨0x86fff8186702d87007c8383584af57dc88a512c17b03f136095b27c290459485, 0x3a6e9e05ca618436d2df7c4e6a0cbd28878d45e3d040da75a867b9ce9676e9d8, 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e, 0x9480265e16ead4f5064949d07886c5ef9fdba6fa250ed235072bc2ce56f6dc1c, 1795686613, 0x133c25a80fb323de143e8ad5c6c620bf8713edfd, 62049193⟩,
  .funded 0xf1ca16808f625519faa0355253396cd7937ae676d30019c434187f1ca92848ec
    0xec3f72259e9fad2ff626e866db3cbfc871a9e3a7326499b64771ffa8b93a96d1 0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e
    0xad239bb5e3f37554ffb48e70fe9c313e47fb6d0bc07d19f4de6a27d9a4ed4593 1000000,
  .settled 0xf1ca16808f625519faa0355253396cd7937ae676d30019c434187f1ca92848ec,
  .claimed 0xad239bb5e3f37554ffb48e70fe9c313e47fb6d0bc07d19f4de6a27d9a4ed4593
]

def none_ : Post := ⟨0, 0, 0, 0, 0, 0, 0⟩
def post (id : Nat) (m : Market) : Post := (m.posts.find? (·.id == id)).getD none_

/-- Read at block 62256533, 2026-11-25 21:21:22 UTC. -/
def now : Nat := 1795641682
def atNow : Market := apply (replay empty events) (.tick now)

/-- r1 opened with its first post, block 62001659 (2026-11-25 07:11:47 UTC):
    the events before its first funding, and that block's time. -/
def atR1Open : Market := apply (replay empty (events.take 23)) (.tick 1795590707)

/-- Round 1: the bounty buyer's posts from its first (block 57110912) to
    r1's first (block 62001659). Round r1: from block 62001659. -/
def round1 : Round := ⟨100000000, 4, fun p => p.poster == buyer && 57110912 ≤ p.block && p.block < 62001659⟩
def roundR1 : Round := ⟨5000000, 5, fun p => p.poster == buyer && 62001659 ≤ p.block⟩

/-- The four outside settlements each join their own round-1 post, which
    shows claimed. -/
theorem outside_settlements_join_round1 :
    [0xb454a434583caf2c899e4d48b18d4776951128bbe029fd73f5c57a4c31a3bf7e,
     0x7b746a3c85353e75d03acbf0b1bd22ea3be925b583808f6a059ad8a409f35eb7,
     0xec8668825da64c8724ae06170db5d42226cf34524795fe3799f727caa8e51bba,
     0x625e31dab83ec36ff2b3babc3be3e61ca9f1ea7ab39d32fe85c42989c49cba6b].all
      (fun id => round1.member (post id atNow) && state ctx atNow (post id atNow) == .claimed)
    = true := by decide

theorem outside_settlement_orders :
    ((atNow.orders.filter (joins ctx (post 0xb454a434583caf2c899e4d48b18d4776951128bbe029fd73f5c57a4c31a3bf7e atNow))).map (·.digest))
      = [0xcdea51489e4a4e03a07d63d5443a4f978e93b94a6ca1850ab242458fe8946c24] := by decide

/-- The first bounty post was withdrawn; round 1's other funded post was
    refunded. -/
theorem withdrawn_and_refunded :
    state ctx atNow (post 0x28daaf524e25938fc92d7c55cab97516f4e55b3cbd120b6de885e3e4cd2098dd atNow) = .withdrawn ∧
    state ctx atNow (post 0x2ca29bcf72cfddc732019e72d64750a13f458590bd042804ec07e5ea66b48812 atNow) = .refunded := by
  decide

/-- Round 1: five orders funded (125 USDC), one refunded (25 USDC): 0 of 4
    tasks and 0 of 100 USDC remain, with no truncation. -/
theorem round1_spent :
    fundedAmt ctx atNow round1 = 125000000 ∧ refundAmt ctx atNow round1 = 25000000 ∧
    remaining ctx atNow round1 = 0 ∧ remainingTasks ctx atNow round1 = 0 ∧
    fundedAmt ctx atNow round1 ≤ round1.budget + refundAmt ctx atNow round1 := by decide

/-- r1 at its first post: the post is listed, 5 of 5 tasks and 5 of 5 USDC
    remain, and its statement is already taken by round 1's settlements. -/
theorem r1_at_open :
    state ctx atR1Open (post 0xafa53fb047f9618d58ddb6d173abf031ec741c40ed44d3ac815391b182394727 atR1Open) = .listed ∧
    remaining ctx atR1Open roundR1 = 5000000 ∧ remainingTasks ctx atR1Open roundR1 = 5 ∧
    taken ctx atR1Open statement = true := by decide

/-- r1 at block 62256533: its five posts each settled and claimed; 0 of 5
    tasks and 0 of 5 USDC remain. -/
theorem r1_now :
    remaining ctx atNow roundR1 = 0 ∧ remainingTasks ctx atNow roundR1 = 0 ∧
    fundedAmt ctx atNow roundR1 = 5000000 ∧
    state ctx atNow (post 0xafa53fb047f9618d58ddb6d173abf031ec741c40ed44d3ac815391b182394727 atNow) = .claimed := by
  decide

/-- No order here is counted in both rounds, and each joins exactly one post. -/
theorem each_order_one_post :
    atNow.orders.all (fun o => (atNow.posts.filter (fun p => joins ctx p o)).length == 1) = true ∧
    atNow.orders.all (fun o => !(inRound ctx atNow round1 o && inRound ctx atNow roundR1 o)) = true := by
  decide

/-- M4 on the real round 1: counting Funded without refunds says 125 USDC
    spent of a 100 USDC budget; remaining plus spent is not the budget. -/
theorem mutant_round1_without_refunds :
    (round1.budget - fundedAmt ctx atNow round1) + fundedAmt ctx atNow round1 ≠ round1.budget := by
  decide

end Nucleus.ProofCommerce.Market.Real
