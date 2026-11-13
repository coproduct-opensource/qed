import Std
set_option warningAsError true

/- The task board. A model; it moves no funds.

   A notice board for one vault. A buyer posts a task: which statement it
   wants proved, under which policy, in which token, for at most how much, by
   when, judged by which verifier and program, and at which iroh node it can
   be reached. Sellers read the posts from the chain. Settlement is the
   vault's business, not the board's.

   What the board does NOT guarantee, by the owner's decision that posting
   costs gas only (decision 3 of 2026-11-12):

   * that the poster holds any funds, or will sign anything;
   * that the statement can be fetched, or is a well-formed Lean export, or
     has a proof;
   * that the poster is reachable at the node the post names;
   * that a task which is not withdrawn is still wanted.

   A post is a notice. A seller is protected by the vault alone: it works for
   pay only once the buyer's deposit is in the vault.

   There is no step here that moves a token. That is the whole content of
   "the board holds no funds": no theorem below says it, because there is
   nothing to prove about a step that does not exist. -/
namespace Nucleus.ProofCommerce.Board

/-- Fixed at deployment: the one vault this board's tasks settle through
    (decision 17). -/
structure Deployment where
  chain : Nat
  address : Nat
  vault : Nat

/-- What a poster says it wants. Opaque to the board beyond the few checks
    `Live` makes. -/
structure Task where
  statement : Nat
  policy : Nat
  asset : Nat
  maximumAmount : Nat
  verifier : Nat
  program : Nat
  fundBy : Nat
  deliverBy : Nat
  buyerNode : Nat
  buyerKeyBinding : Nat
  salt : Nat
  deriving DecidableEq

/-- A post the board will take at time `now`: nothing zero, a positive price
    cap, and deadlines in order and not already past. -/
structure Live (t : Task) (now : Nat) : Prop where
  amountPositive : 0 < t.maximumAmount
  fundingOpen : now ≤ t.fundBy
  deadlinesOrdered : t.fundBy < t.deliverBy

/-- A post as the board records and announces it. -/
structure Post where
  poster : Nat
  task : Task
  /-- The vault the post is for. Always the deployment's. -/
  vault : Nat
  withdrawn : Bool

/-- The board's whole state: what is recorded under each task ID. -/
structure State where
  posts : Nat → Option Post

def initial : State := ⟨fun _ => none⟩

def State.set (s : State) (id : Nat) (p : Post) : State :=
  ⟨fun x => if x = id then some p else s.posts x⟩

/-- One call. `identify` stands for the contract's hash of chain, board,
    poster and task; the model needs nothing of it but that it is a function. -/
inductive Step (d : Deployment) (identify : Nat → Task → Nat) : State → State → Prop where
  | post (s : State) (poster : Nat) (t : Task) (now : Nat)
      (live : Live t now)
      (fresh : s.posts (identify poster t) = none) :
      Step d identify s (s.set (identify poster t) ⟨poster, t, d.vault, false⟩)
  | withdraw (s : State) (caller id : Nat) (p : Post)
      (posted : s.posts id = some p)
      (mine : p.poster = caller)
      (open_ : p.withdrawn = false) :
      Step d identify s (s.set id { p with withdrawn := true })

inductive Reachable (d : Deployment) (identify : Nat → Task → Nat) : State → Prop where
  | start : Reachable d identify initial
  | next {s t : State} :
      Reachable d identify s → Step d identify s t → Reachable d identify t

variable {d : Deployment} {identify : Nat → Task → Nat}

/-- A recorded post is never replaced by a different poster or task: an ID is
    posted at most once. -/
theorem posted_once {s t : State} (step : Step d identify s t) (id : Nat) (p : Post)
    (was : s.posts id = some p) :
    ∃ q, t.posts id = some q ∧ q.poster = p.poster ∧ q.task = p.task ∧ q.vault = p.vault := by
  cases step with
  | post poster task now live fresh =>
      by_cases same : id = identify poster task
      · subst same; rw [was] at fresh; cases fresh
      · exact ⟨p, by simp [State.set, same, was], rfl, rfl, rfl⟩
  | withdraw caller i q posted mine open_ =>
      by_cases same : id = i
      · subst same
        rw [was] at posted
        cases posted
        exact ⟨{ p with withdrawn := true }, by simp [State.set], rfl, rfl, rfl⟩
      · exact ⟨p, by simp [State.set, same, was], rfl, rfl, rfl⟩

/-- Only a call that withdraws this very ID turns a post withdrawn, and the
    step's own premise is that the caller is its poster. Stated on the step:
    if a post goes from open to withdrawn, a `withdraw` by its poster did it. -/
theorem only_the_poster_withdraws {s t : State} (step : Step d identify s t) (id : Nat)
    (p q : Post) (was : s.posts id = some p) (open_ : p.withdrawn = false)
    (now_ : t.posts id = some q) (closed : q.withdrawn = true) :
    ∃ caller, caller = p.poster ∧ t = s.set id { p with withdrawn := true } := by
  cases step with
  | post poster task now live fresh =>
      by_cases same : id = identify poster task
      · subst same; rw [was] at fresh; cases fresh
      · simp [State.set, same, was] at now_
        subst now_
        rw [open_] at closed
        cases closed
  | withdraw caller i r posted mine open2 =>
      by_cases same : id = i
      · subst same
        rw [was] at posted
        cases posted
        exact ⟨caller, mine.symm, rfl⟩
      · simp [State.set, same, was] at now_
        subst now_
        rw [open_] at closed
        cases closed

/-- A withdrawn task stays withdrawn. -/
theorem withdrawn_stays_withdrawn {s t : State} (step : Step d identify s t) (id : Nat)
    (p : Post) (was : s.posts id = some p) (closed : p.withdrawn = true) :
    ∃ q, t.posts id = some q ∧ q.withdrawn = true := by
  cases step with
  | post poster task now live fresh =>
      by_cases same : id = identify poster task
      · subst same; rw [was] at fresh; cases fresh
      · exact ⟨p, by simp [State.set, same, was], closed⟩
  | withdraw caller i q posted mine open_ =>
      by_cases same : id = i
      · subst same
        rw [was] at posted
        cases posted
        rw [closed] at open_
        cases open_
      · exact ⟨p, by simp [State.set, same, was], closed⟩

/-- Every post on the board names the one vault fixed at deployment. -/
theorem every_post_names_the_vault {s : State} (reach : Reachable d identify s) (id : Nat)
    (p : Post) (here : s.posts id = some p) : p.vault = d.vault := by
  induction reach generalizing p with
  | start => simp [initial] at here
  | next _ step ih =>
      cases step with
      | post poster task now live fresh =>
          by_cases same : id = identify poster task
          · subst same
            simp [State.set] at here
            subst here
            rfl
          · simp [State.set, same] at here
            exact ih p here
      | withdraw caller i q posted mine open_ =>
          by_cases same : id = i
          · subst same
            simp [State.set] at here
            subst here
            exact ih q posted
          · simp [State.set, same] at here
            exact ih p here

/-- A recorded task was live when it was posted: every post on the board has a
    positive price cap and ordered deadlines. (That it was not yet past its
    funding deadline at posting time is a fact about that moment, not about
    now, and is not carried in the state.) -/
theorem every_post_was_well_formed {s : State} (reach : Reachable d identify s) (id : Nat)
    (p : Post) (here : s.posts id = some p) :
    0 < p.task.maximumAmount ∧ p.task.fundBy < p.task.deliverBy := by
  induction reach generalizing p with
  | start => simp [initial] at here
  | next _ step ih =>
      cases step with
      | post poster task now live fresh =>
          by_cases same : id = identify poster task
          · subst same
            simp [State.set] at here
            subst here
            exact ⟨live.amountPositive, live.deadlinesOrdered⟩
          · simp [State.set, same] at here
            exact ih p here
      | withdraw caller i q posted mine open_ =>
          by_cases same : id = i
          · subst same
            simp [State.set] at here
            subst here
            exact ih q posted
          · simp [State.set, same] at here
            exact ih p here

end Nucleus.ProofCommerce.Board

namespace Nucleus.ProofCommerce.Board
/-- info: 'Nucleus.ProofCommerce.Board.posted_once' depends on axioms: [propext] -/
#guard_msgs in #print axioms posted_once
/-- info: 'Nucleus.ProofCommerce.Board.only_the_poster_withdraws' depends on axioms: [propext] -/
#guard_msgs in #print axioms only_the_poster_withdraws
/-- info: 'Nucleus.ProofCommerce.Board.withdrawn_stays_withdrawn' depends on axioms: [propext] -/
#guard_msgs in #print axioms withdrawn_stays_withdrawn
/-- info: 'Nucleus.ProofCommerce.Board.every_post_names_the_vault' depends on axioms: [propext] -/
#guard_msgs in #print axioms every_post_names_the_vault
/-- info: 'Nucleus.ProofCommerce.Board.every_post_was_well_formed' depends on axioms: [propext] -/
#guard_msgs in #print axioms every_post_was_well_formed
end Nucleus.ProofCommerce.Board
