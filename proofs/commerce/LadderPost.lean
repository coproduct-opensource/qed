import Std
set_option warningAsError true

/- One ladder post: `nucleus-buyer post-tasks` with one task file and one
   journal, and the two commands that finish what it leaves,
   `task-withdraw` and `task-refund`. A model; it moves no funds.
   docs/rfcs/qed-nucleus-merge-ladder-2026-11-14.md, section 10.

   The journal is the standing bounty's (contracts/agents/src/bounty.rs,
   `Ledger::apply`), run as a one-shot: at most one post, ever. `open_` and
   `posted` are the ledger's `open` and `posted`; every guard below is a
   guard of `Ledger::apply` or of `step`, and the one guard the bounty does
   not have, `posted = 0` on an intent, is `Limits::posts = Some 1`.

   What the model keeps that a process loses on a crash is the journal and
   the chain. What it loses is `fresh`: whether this process journaled the
   intent and has not yet sent the post. A restarted process never sends a
   post for an intent it finds in the journal; it asks the board, and the
   buyer's pending nonce, and records `posted` or `abandoned`. A transient
   error while posting is treated the same way as a crash.

   The board's ID is a function of the task, and the task carries a fresh
   salt, so a new intent's ID is not on the board (`fresh` premise of
   `intent`). One nonce lane per wallet: a post transaction in flight is
   mined or dropped, never both, and nothing is sent from the buyer while it
   is in flight (`inflight`). -/
namespace Nucleus.ProofCommerce.LadderPost

/-- What the journal has open (`bounty::Open`, with `none` for nothing). -/
inductive Open where
  | none
  | intent (id : Nat)
  | posted (id : Nat)
  | signed (id : Nat)
  deriving DecidableEq

/-- The vault's phase of the one order the desk signed for. -/
inductive Phase where
  | empty
  | funded
  | settled
  | refunded
  deriving DecidableEq

/-- Fixed by the task file and by the chain's price when the process starts. -/
structure Terms where
  /-- The post's price cap, in token units. -/
  cap : Nat
  /-- Wei the buyer must hold before posting: its own `post`, `withdraw`,
      `refund` and `claim` at the price read then (`tasks::LADDER_GAS`). -/
  gasNeed : Nat
  fundBy : Nat
  deliverBy : Nat

structure State where
  open_ : Open
  /-- `posted` lines in the journal (`Ledger::posted`). -/
  posted : Nat
  /-- This buyer's posts on the board: ID and whether withdrawn. -/
  board : List (Nat × Bool)
  /-- A post transaction sent and neither mined nor dropped. -/
  inflight : Option Nat
  /-- Lost on a crash: this process journaled the open intent and has not
      sent its post yet. -/
  fresh : Bool
  phase : Phase
  /-- What a refund booked to the buyer and no claim has paid. -/
  owed : Nat
  now : Nat
  usdc : Nat
  eth : Nat

def State.onBoard (s : State) (id : Nat) : Prop := ∃ w, (id, w) ∈ s.board

def withdrawIn (id : Nat) (board : List (Nat × Bool)) : List (Nat × Bool) :=
  board.map fun e => if e.1 = id then (e.1, true) else e

inductive Step (k : Terms) : State → State → Prop where
  /-- Journal the intent. The one-shot limit (`posted = 0`) and gap 3's
      wallet check (`Stop::Wallet`, `Stop::Gas`) are its guards. -/
  | intent (s : State) (id : Nat)
      (idle : s.open_ = .none) (first : s.posted = 0)
      (new : ¬ s.onBoard id)
      (tokens : k.cap ≤ s.usdc) (gas : k.gasNeed ≤ s.eth) :
      Step k s { s with open_ := .intent id, fresh := true }
  /-- Send the post, once, from the process that journaled the intent. -/
  | send (s : State) (id : Nat)
      (open_ : s.open_ = .intent id) (here : s.fresh = true) (quiet : s.inflight = none) :
      Step k s { s with inflight := some id, fresh := false }
  | mine (s : State) (id : Nat) (sent : s.inflight = some id) :
      Step k s { s with inflight := none, board := (id, false) :: s.board }
  | drop (s : State) (id : Nat) (sent : s.inflight = some id) :
      Step k s { s with inflight := none }
  /-- A crash, or a transient error while posting. -/
  | crash (s : State) : Step k s { s with fresh := false }
  /-- The board holds the intent's task: journal it posted. -/
  | found (s : State) (id : Nat)
      (open_ : s.open_ = .intent id) (there : (id, false) ∈ s.board) :
      Step k s { s with open_ := .posted id, posted := s.posted + 1 }
  /-- Not on the board and nothing pending from the buyer: the intent is
      dropped. Only a process that did not just journal it may decide so. -/
  | abandon (s : State) (id : Nat)
      (open_ : s.open_ = .intent id) (gone : ¬ s.onBoard id)
      (quiet : s.inflight = none) (restarted : s.fresh = false) :
      Step k s { s with open_ := .none }
  /-- `task-withdraw`, or the funding deadline with nothing signed. -/
  | withdraw (s : State) (id : Nat)
      (open_ : s.open_ = .posted id) (live : (id, false) ∈ s.board) :
      Step k s { s with open_ := .none, board := withdrawIn id s.board }
  /-- The desk signs the first passing offer (journaled before it leaves). -/
  | sign (s : State) (id : Nat) (open_ : s.open_ = .posted id) :
      Step k s { s with open_ := .signed id, phase := .empty }
  /-- The seller's `fund`: the deposit leaves the buyer's wallet. -/
  | fund (s : State) (empty : s.phase = .empty) (inTime : s.now ≤ k.fundBy)
      (covered : k.cap ≤ s.usdc) :
      Step k s { s with phase := .funded, usdc := s.usdc - k.cap }
  | settle (s : State) (funded : s.phase = .funded) (inTime : s.now ≤ k.deliverBy) :
      Step k s { s with phase := .settled }
  /-- `task-refund`, or `post-tasks` itself: open to the buyer only after the
      delivery deadline, on a funded order. -/
  | refund (s : State) (id : Nat) (open_ : s.open_ = .signed id)
      (funded : s.phase = .funded) (late : k.deliverBy < s.now) :
      Step k s { s with phase := .refunded, owed := s.owed + k.cap }
  | claim (s : State) :
      Step k s { s with owed := 0, usdc := s.usdc + s.owed }
  | settled (s : State) (id : Nat) (open_ : s.open_ = .signed id)
      (done : s.phase = .settled) :
      Step k s { s with open_ := .none }
  | refunded (s : State) (id : Nat) (open_ : s.open_ = .signed id)
      (done : s.phase = .refunded) (paid : s.owed = 0) :
      Step k s { s with open_ := .none }
  | lapsed (s : State) (id : Nat) (open_ : s.open_ = .signed id)
      (empty : s.phase = .empty) (late : k.fundBy < s.now) :
      Step k s { s with open_ := .none }
  | tick (s : State) : Step k s { s with now := s.now + 1 }

/-- A fresh journal: nothing open, nothing posted, nothing in flight. -/
def initial (usdc eth now : Nat) : State :=
  { open_ := .none, posted := 0, board := [], inflight := none, fresh := false,
    phase := .empty, owed := 0, now, usdc, eth }

inductive Reachable (k : Terms) (start : State) : State → Prop where
  | start : Reachable k start start
  | next {s t : State} : Reachable k start s → Step k s t → Reachable k start t

/-- What holds in every reachable state. -/
structure Inv (s : State) : Prop where
  /-- Posts on the board plus a post in flight: at most one. -/
  one : s.board.length + (if s.inflight.isSome then 1 else 0) ≤ 1
  /-- A post in flight belongs to the open intent. -/
  flight : ∀ id, s.inflight = some id → s.open_ = .intent id
  /-- A process holding a fresh intent has sent nothing and sees nothing. -/
  fresh : s.fresh = true → s.inflight = none ∧ s.board = [] ∧ ∃ id, s.open_ = .intent id
  /-- Before the first `posted` line, whatever the board holds is the open
      intent's. -/
  before : s.posted = 0 → ∀ e ∈ s.board, s.open_ = .intent e.1
  /-- An intent is open only before the first post. -/
  intentFirst : ∀ id, s.open_ = .intent id → s.posted = 0
  /-- Posted and signed come after the post. -/
  after : ∀ id, (s.open_ = .posted id ∨ s.open_ = .signed id) → 1 ≤ s.posted
  /-- A journaled, unsigned post is live on the board. -/
  live : ∀ id, s.open_ = .posted id → (id, false) ∈ s.board
  /-- The journal counts at most one post. -/
  atMostOne : s.posted ≤ 1

theorem initial_inv (usdc eth now : Nat) : Inv (initial usdc eth now) := by
  constructor <;> simp [initial]

theorem length_withdrawIn (id : Nat) (b : List (Nat × Bool)) :
    (withdrawIn id b).length = b.length := by
  simp [withdrawIn]

theorem step_inv {k : Terms} {s t : State} (h : Inv s) (step : Step k s t) : Inv t := by
  cases step with
  | intent id idle first new tokens gas =>
      have board : s.board = [] := by
        cases hb : s.board with
        | nil => rfl
        | cons e rest =>
            have := h.before first e (by simp [hb])
            rw [idle] at this; cases this
      have flight : s.inflight = none := by
        cases hf : s.inflight with
        | none => rfl
        | some x => have := h.flight x hf; rw [idle] at this; cases this
      constructor
      · simp [board, flight]
      · intro x hx; simp [flight] at hx
      · intro _; exact ⟨flight, board, id, rfl⟩
      · intro _ e he; simp [board] at he
      · intro _ _; exact first
      · intro x hx; simp at hx
      · intro x hx; simp at hx
      · simp [first]
  | send id open_ here quiet =>
      obtain ⟨_, board, _⟩ := h.fresh here
      constructor
      · simp [board]
      · intro x hx; simp at hx; subst hx; exact open_
      · intro hf; simp at hf
      · intro hp e he; simp [board] at he
      · intro x hx; exact h.intentFirst x hx
      · intro x hx; exact h.after x hx
      · intro x hx; exact h.live x hx
      · exact h.atMostOne
  | mine id sent =>
      have one := h.one
      simp [sent] at one
      have openI := h.flight id sent
      have notFresh : s.fresh = false := by
        cases hf : s.fresh with
        | false => rfl
        | true => have := (h.fresh hf).1; rw [sent] at this; cases this
      constructor
      · simp [one]
      · intro x hx; simp at hx
      · intro hf; simp [notFresh] at hf
      · intro _ e he
        simp [one] at he
        subst he; exact openI
      · intro x hx; exact h.intentFirst x hx
      · intro x hx; exact h.after x hx
      · intro x hx; rw [openI] at hx; cases hx
      · exact h.atMostOne
  | drop id sent =>
      have openI := h.flight id sent
      have notFresh : s.fresh = false := by
        cases hf : s.fresh with
        | false => rfl
        | true => have := (h.fresh hf).1; rw [sent] at this; cases this
      constructor
      · have := h.one; simp [sent] at this; simp [this]
      · intro x hx; simp at hx
      · intro hf; simp [notFresh] at hf
      · exact h.before
      · intro x hx; exact h.intentFirst x hx
      · intro x hx; exact h.after x hx
      · intro x hx; rw [openI] at hx; cases hx
      · exact h.atMostOne
  | crash =>
      constructor
      · exact h.one
      · exact h.flight
      · intro hf; simp at hf
      · exact h.before
      · exact h.intentFirst
      · exact h.after
      · exact h.live
      · exact h.atMostOne
  | found id open_ there =>
      have zero := h.intentFirst id open_
      have flight : s.inflight = none := by
        cases hf : s.inflight with
        | none => rfl
        | some x =>
            have one := h.one
            simp [hf] at one
            rw [one] at there; simp at there
      constructor
      · have := h.one; simp [flight] at this ⊢; exact this
      · intro x hx; simp [flight] at hx
      · intro hf
        have := (h.fresh hf).2.1
        rw [this] at there; simp at there
      · intro hp; simp at hp
      · intro x hx; simp at hx
      · intro x _; simp
      · intro x hx; simp at hx; subst hx; exact there
      · simp [zero]
  | abandon id open_ gone quiet restarted =>
      have zero := h.intentFirst id open_
      have board : s.board = [] := by
        cases hb : s.board with
        | nil => rfl
        | cons e rest =>
            have hi := h.before zero e (by simp [hb])
            rw [open_] at hi
            cases hi
            exact absurd ⟨e.2, by simp [hb]⟩ gone
      constructor
      · simp [board, quiet]
      · intro x hx; simp [quiet] at hx
      · intro hf; simp [restarted] at hf
      · intro _ e he; simp [board] at he
      · intro x hx; simp at hx
      · intro x hx; simp at hx
      · intro x hx; simp at hx
      · exact h.atMostOne
  | withdraw id open_ live =>
      have one := h.after id (Or.inl open_)
      have flight : s.inflight = none := by
        cases hf : s.inflight with
        | none => rfl
        | some x => have := h.flight x hf; rw [open_] at this; cases this
      constructor
      · have := h.one; simp [flight, length_withdrawIn] at this ⊢; exact this
      · intro x hx; simp [flight] at hx
      · intro hf
        have := h.fresh hf
        obtain ⟨_, _, y, hy⟩ := this
        rw [open_] at hy; cases hy
      · intro hp; exact absurd (show s.posted = 0 from hp) (by omega)
      · intro x hx; simp at hx
      · intro x hx; simp at hx
      · intro x hx; simp at hx
      · exact h.atMostOne
  | sign id open_ =>
      have one := h.after id (Or.inl open_)
      constructor
      · exact h.one
      · intro x hx; have := h.flight x hx; rw [open_] at this; cases this
      · intro hf
        obtain ⟨_, _, y, hy⟩ := h.fresh hf
        rw [open_] at hy; cases hy
      · intro hp; exact absurd (show s.posted = 0 from hp) (by omega)
      · intro x hx; simp at hx
      · intro x _; exact one
      · intro x hx; simp at hx
      · exact h.atMostOne
  | fund empty inTime covered =>
      exact ⟨h.one, h.flight, h.fresh, h.before, h.intentFirst, h.after, h.live, h.atMostOne⟩
  | settle funded inTime =>
      exact ⟨h.one, h.flight, h.fresh, h.before, h.intentFirst, h.after, h.live, h.atMostOne⟩
  | refund id open_ funded late =>
      exact ⟨h.one, h.flight, h.fresh, h.before, h.intentFirst, h.after, h.live, h.atMostOne⟩
  | claim =>
      exact ⟨h.one, h.flight, h.fresh, h.before, h.intentFirst, h.after, h.live, h.atMostOne⟩
  | tick =>
      exact ⟨h.one, h.flight, h.fresh, h.before, h.intentFirst, h.after, h.live, h.atMostOne⟩
  | settled id open_ done =>
      have one := h.after id (Or.inr open_)
      have flight : s.inflight = none := by
        cases hf : s.inflight with
        | none => rfl
        | some x => have := h.flight x hf; rw [open_] at this; cases this
      constructor
      · exact h.one
      · intro x hx; simp [flight] at hx
      · intro hf
        obtain ⟨_, _, y, hy⟩ := h.fresh hf
        rw [open_] at hy; cases hy
      · intro hp; exact absurd (show s.posted = 0 from hp) (by omega)
      · intro x hx; simp at hx
      · intro x hx; simp at hx
      · intro x hx; simp at hx
      · exact h.atMostOne
  | refunded id open_ done paid =>
      have one := h.after id (Or.inr open_)
      have flight : s.inflight = none := by
        cases hf : s.inflight with
        | none => rfl
        | some x => have := h.flight x hf; rw [open_] at this; cases this
      constructor
      · exact h.one
      · intro x hx; simp [flight] at hx
      · intro hf
        obtain ⟨_, _, y, hy⟩ := h.fresh hf
        rw [open_] at hy; cases hy
      · intro hp; exact absurd (show s.posted = 0 from hp) (by omega)
      · intro x hx; simp at hx
      · intro x hx; simp at hx
      · intro x hx; simp at hx
      · exact h.atMostOne
  | lapsed id open_ empty late =>
      have one := h.after id (Or.inr open_)
      have flight : s.inflight = none := by
        cases hf : s.inflight with
        | none => rfl
        | some x => have := h.flight x hf; rw [open_] at this; cases this
      constructor
      · exact h.one
      · intro x hx; simp [flight] at hx
      · intro hf
        obtain ⟨_, _, y, hy⟩ := h.fresh hf
        rw [open_] at hy; cases hy
      · intro hp; exact absurd (show s.posted = 0 from hp) (by omega)
      · intro x hx; simp at hx
      · intro x hx; simp at hx
      · intro x hx; simp at hx
      · exact h.atMostOne

theorem reachable_inv {k : Terms} {usdc eth now : Nat} {s : State}
    (r : Reachable k (initial usdc eth now) s) : Inv s := by
  induction r with
  | start => exact initial_inv usdc eth now
  | next _ step ih => exact step_inv ih step

/-- **No double post.** Whatever crashes, restarts, dropped transactions
    and resumptions happen, this buyer's board never holds two posts from
    one journal. -/
theorem at_most_one_post {k : Terms} {usdc eth now : Nat} {s : State}
    (r : Reachable k (initial usdc eth now) s) : s.board.length ≤ 1 := by
  have := (reachable_inv r).one
  omega

/-- The journal counts at most one post. -/
theorem posted_at_most_once {k : Terms} {usdc eth now : Nat} {s : State}
    (r : Reachable k (initial usdc eth now) s) : s.posted ≤ 1 :=
  (reachable_inv r).atMostOne

/-- **Gap 1: an orphaned post can be withdrawn.** A journaled post nobody
    has been signed for is live on the board, so `task-withdraw` is enabled,
    after any crash. -/
theorem journaled_post_is_withdrawable {k : Terms} {usdc eth now : Nat} {s : State}
    (r : Reachable k (initial usdc eth now) s) {id : Nat} (posted : s.open_ = .posted id) :
    ∃ t, Step k s t ∧ (id, true) ∈ t.board ∧ t.open_ = .none := by
  have live := (reachable_inv r).live id posted
  refine ⟨_, Step.withdraw s id posted live, ?_, rfl⟩
  simp only [withdrawIn, List.mem_map]
  exact ⟨(id, false), live, by simp⟩

/-- **Gap 2: a funded order past its delivery deadline can be refunded**, by
    the buyer alone, and only then. -/
theorem late_funded_order_is_refundable {k : Terms} {s : State} {id : Nat}
    (open_ : s.open_ = .signed id) (funded : s.phase = .funded) (late : k.deliverBy < s.now) :
    ∃ t, Step k s t ∧ t.phase = .refunded ∧ t.owed = s.owed + k.cap :=
  ⟨_, Step.refund s id open_ funded late, rfl, rfl⟩

theorem refund_only_late_and_funded {k : Terms} {s t : State} (step : Step k s t)
    (was : s.phase ≠ .refunded) (now_ : t.phase = .refunded) :
    s.phase = .funded ∧ k.deliverBy < s.now := by
  cases step with
  | refund _ _ funded late => exact ⟨funded, late⟩
  | sign => simp at now_
  | fund => simp at now_
  | settle => simp at now_
  | _ => exact absurd now_ was

/-- **Gap 3: nothing is posted from a wallet that cannot pay.** Every intent
    was journaled with the cap in tokens and the gas need in ether. -/
theorem intent_only_when_covered {k : Terms} {s t : State} (step : Step k s t) {id : Nat}
    (before : s.open_ ≠ .intent id) (after : t.open_ = .intent id) :
    k.cap ≤ s.usdc ∧ k.gasNeed ≤ s.eth := by
  cases step with
  | intent _ _ _ _ tokens gas => exact ⟨tokens, gas⟩
  | _ => first | exact absurd after before | simp at after | (simp at after; exact absurd after before)

end Nucleus.ProofCommerce.LadderPost

namespace Nucleus.ProofCommerce.LadderPost
/-- info: 'Nucleus.ProofCommerce.LadderPost.at_most_one_post' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms at_most_one_post
/-- info: 'Nucleus.ProofCommerce.LadderPost.posted_at_most_once' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms posted_at_most_once
/-- info: 'Nucleus.ProofCommerce.LadderPost.journaled_post_is_withdrawable' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms journaled_post_is_withdrawable
/-- info: 'Nucleus.ProofCommerce.LadderPost.late_funded_order_is_refundable' does not depend on any axioms -/
#guard_msgs in #print axioms late_funded_order_is_refundable
/-- info: 'Nucleus.ProofCommerce.LadderPost.refund_only_late_and_funded' depends on axioms: [propext] -/
#guard_msgs in #print axioms refund_only_late_and_funded
/-- info: 'Nucleus.ProofCommerce.LadderPost.intent_only_when_covered' depends on axioms: [propext] -/
#guard_msgs in #print axioms intent_only_when_covered
end Nucleus.ProofCommerce.LadderPost
