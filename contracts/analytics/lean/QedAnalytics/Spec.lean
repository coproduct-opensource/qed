/-
QED visit analytics: what the collector means, written before its code.

The collector (contracts/analytics) counts beacons from qed.coproduct.dev
per window, per site path and per "first visit that day" bit, and once a
window publishes every cell with discrete Laplace noise, suppressing a cell
when its count plus its noise is under `K`. Since 2026-11-18 the window is a
week starting Monday 00:00 UTC (`week`); until then it was a UTC day. Every
beacon is counted in exactly one cell of exactly one window
(`one_window`), so one beacon moves the whole publication by at most a
factor of 2 (`publication_dp`). Suppression reads only the noisy value, so
the differential-privacy theorems hold for every window with no condition on
the counts (`window_dp`, `visit_dp`). The rule before 2026-11-15
read the true count, and `History.lean` proves why it was replaced
(`TrueCount.threshold_breaks_dp`). This file is the meaning: a model of the state
machine and the publisher, and the theorems the site shows. The Rust core is
translated by Charon and Aeneas into `generated/`, and `Refines.lean` proves
that the translation computes these functions, so every theorem here holds
of the translated code.

What is a model and nothing more is said where it is defined: the noise is
modelled by its law (`lap`), and the claim that the running sampler draws
from that law is about code that reads the operating system's randomness,
which nothing here translates.
-/
import Mathlib.Analysis.SpecificLimits.Basic
import Mathlib.Topology.Algebra.InfiniteSum.NatInt
import Mathlib.Topology.Algebra.InfiniteSum.ENNReal

namespace QedAnalytics

open scoped ENNReal

/-! ## 1. Constants -/

/-- Site paths on the collector's allow-list (`contracts/analytics/src/paths.rs`). -/
def PATHS : ℕ := 16

/-- Cells per window: for each path, a cell for returning visits (`2 * path`)
and one for first visits that day (`2 * path + 1`); then one for malformed
beacons and one for beacons refused by the rate limit. -/
def CELLS : ℕ := 2 * PATHS + 2

def MALFORMED : ℕ := 2 * PATHS
def LIMITED : ℕ := 2 * PATHS + 1

/-- A cell whose count plus noise is under `K` is published as `suppressed`. -/
def K : ℕ := 10

/-- A count saturates at the largest `u32`. -/
def MAX : ℕ := 2 ^ 32 - 1

/-! ## 2. The state machine -/

/-- Everything the collector's shell holds about one beacon when it calls the
core. The path is already an index into the allow-list (any value from
`PATHS` up means the body was malformed), `day` is days since 1970-01-01 UTC
on the collector's clock, and the rest is what the shell could have read from
the connection: the TCP peer (Caddy, on loopback), the time within the day,
and the sizes of the request head and body. -/
structure Request where
  path : ℕ
  first : Bool
  day : ℕ
  secondOfDay : ℕ
  peer : List ℕ
  peerPort : ℕ
  headBytes : ℕ
  bodyBytes : ℕ

abbrev Counts := Fin CELLS → ℕ

/-- The window a day belongs to: weeks that start on Monday 00:00 UTC.
Day 0 (1970-01-01) was a Thursday, so day 4 (1970-01-05) was the first
Monday, and window `w ≥ 1` holds days `7 * w - 3` to `7 * w + 3` (`week_iff`).
Window 0 holds days 0 to 3. Until 2026-11-18 the window was the day itself. -/
def week (d : ℕ) : ℕ := (d + 3) / 7

/-- **The days of a window.** -/
theorem week_iff (d w : ℕ) : week d = w ↔ 7 * w ≤ d + 3 ∧ d + 3 < 7 * w + 7 := by
  unfold week; omega

/-- A window starts on day `7 * w + 4` (a Monday) and the day before it is
in the previous window. -/
theorem week_starts (w : ℕ) : week (7 * w + 4) = w + 1 ∧ week (7 * w + 3) = w := by
  unfold week; omega

/-- Windows never go back as days go forward. -/
theorem week_mono {d d' : ℕ} (h : d ≤ d') : week d ≤ week d' := by
  unfold week; omega

/-- The collector's whole state: the window being counted and its cells. -/
structure Window where
  window : ℕ
  cells : Counts

def cell (path : ℕ) (first : Bool) : ℕ :=
  if path < PATHS then (if first then 2 * path + 1 else 2 * path) else MALFORMED

theorem cell_lt (path : ℕ) (first : Bool) : cell path first < CELLS := by
  unfold cell CELLS MALFORMED PATHS
  split
  · split <;> omega
  · omega

def cellIdx (path : ℕ) (first : Bool) : Fin CELLS := ⟨cell path first, cell_lt path first⟩

def limitedIdx : Fin CELLS := ⟨LIMITED, by unfold LIMITED CELLS; omega⟩

def bump (c : ℕ) : ℕ := if c < MAX then c + 1 else c

def fresh (w : ℕ) : Window := ⟨w, fun _ => 0⟩

/-- Count one beacon in cell `i` in window `w`. A beacon of a window before
the one being counted (the clock went back) changes nothing; one of a later
window starts that window from zero. -/
def count (s : Window) (i : Fin CELLS) (w : ℕ) : Window :=
  if w < s.window then s
  else
    let t := if s.window < w then fresh w else s
    ⟨w, Function.update t.cells i (bump (t.cells i))⟩

/-- The only fields of a request the core may use. -/
def project (r : Request) : ℕ × Bool × ℕ := (r.path, r.first, r.day)

/-- A beacon dated `day` is counted in the window of that day. -/
def step (s : Window) (path : ℕ) (first : Bool) (day : ℕ) : Window :=
  count s (cellIdx path first) (week day)

/-- A beacon refused by the rate limit, counted in the window of `day`.
Whether a beacon is refused depends on the arrival times of all beacons,
never on its fields. -/
def limit (s : Window) (day : ℕ) : Window := count s limitedIdx (week day)

def handle (s : Window) (r : Request) : Window :=
  match project r with
  | (path, first, day) => step s path first day

/-! ## 3. (a) Noninterference -/

/-- The state after a request depends on the request only through
`(path, first, day)`. -/
theorem handle_eq_of_project_eq (s : Window) (r₁ r₂ : Request)
    (h : project r₁ = project r₂) : handle s r₁ = handle s r₂ := by
  unfold handle
  rw [h]

/-- In particular, the connection's peer, the time within the day and the
request's sizes change nothing. -/
theorem handle_ignores_connection (s : Window) (r : Request) (sec : ℕ) (peer : List ℕ)
    (port head body : ℕ) :
    handle s { r with secondOfDay := sec, peer := peer, peerPort := port,
                      headBytes := head, bodyBytes := body } = handle s r :=
  handle_eq_of_project_eq s _ r rfl

/-! ## 4. Sensitivity: one beacon moves one cell by at most one -/

/-- Count the beacons of one window, in arrival order, each given by its cell. -/
def run (s : Window) (w : ℕ) : List (Fin CELLS) → Window
  | [] => s
  | i :: es => run (count s i w) w es

/-- L1 distance between two windows' cells. -/
def dist (a b : Counts) : ℕ := ∑ j, ((a j - b j) + (b j - a j))

theorem run_cells_of_le (d : ℕ) (es : List (Fin CELLS)) (s : Window) (hd : s.window = d)
    (hle : ∀ j, s.cells j ≤ MAX) (j : Fin CELLS) :
    (run s d es).cells j = min (s.cells j + es.count j) MAX := by
  induction es generalizing s with
  | nil =>
    have := hle j
    simp [run]
    omega
  | cons i es ih =>
    simp only [run]
    have hc : count s i d = ⟨d, Function.update s.cells i (bump (s.cells i))⟩ := by
      unfold count
      simp [hd]
    rw [hc, ih]
    · by_cases hji : j = i
      · subst hji
        have := hle j
        simp [Function.update, bump]
        split <;> omega
      · simp [Function.update, hji, Ne.symm hji]
    · rfl
    · intro k
      by_cases hki : k = i
      · subst hki
        have := hle k
        simp [Function.update, bump]
        split <;> omega
      · simp [Function.update, hki, hle k]

/-- A window's cells, from its beacons: each cell is its number of beacons,
saturated. Order does not matter. -/
theorem run_fresh (d : ℕ) (es : List (Fin CELLS)) (j : Fin CELLS) :
    (run (fresh d) d es).cells j = min (es.count j) MAX := by
  rw [run_cells_of_le d es (fresh d) rfl (fun _ => by simp [fresh, MAX])]
  simp [fresh]

/-- **Sensitivity 1.** Two windows whose beacons differ by one beacon end with
cells at L1 distance at most one. -/
theorem sensitivity (d : ℕ) (es₁ es₂ : List (Fin CELLS)) (e : Fin CELLS) :
    dist (run (fresh d) d (es₁ ++ e :: es₂)).cells (run (fresh d) d (es₁ ++ es₂)).cells ≤ 1 := by
  unfold dist
  simp only [run_fresh]
  have hj : ∀ j : Fin CELLS,
      (min ((es₁ ++ e :: es₂).count j) MAX - min ((es₁ ++ es₂).count j) MAX)
        + (min ((es₁ ++ es₂).count j) MAX - min ((es₁ ++ e :: es₂).count j) MAX)
        ≤ if j = e then 1 else 0 := by
    intro j
    simp only [List.count_append, List.count_cons]
    by_cases h : j = e
    · subst h; simp; omega
    · simp [h, Ne.symm h]
  calc _ ≤ ∑ j : Fin CELLS, (if j = e then 1 else 0) := Finset.sum_le_sum (fun j _ => hj j)
    _ = 1 := by simp


/-! ## 4b. Every beacon is in exactly one window

The machine above counts one window at a time. The publication is every
window's cells, so a beacon must not reach two published cells: that is what
keeps the per-beacon bound at a factor of 2 for the whole publication
(`publication_dp`). Publishing daily and weekly cells side by side would
put each beacon in two cells and double it. -/

/-- A beacon as the publication sees it: its day and its cell. -/
abbrev Dated := ℕ × Fin CELLS

/-- The cells of the beacons dated in window `w`, in arrival order. -/
def inWindow (w : ℕ) (es : List Dated) : List (Fin CELLS) :=
  (es.filter (fun e => week e.1 = w)).map Prod.snd

/-- What window `w` publishes from: its own beacons, counted from zero. -/
def windowCounts (es : List Dated) (w : ℕ) : Counts :=
  (run (fresh w) w (inWindow w es)).cells

theorem dist_self (a : Counts) : dist a a = 0 := by
  simp [dist]

/-- **One beacon, one window.** Adding one beacon dated `e.1` moves window
`w`'s cells by at most one if `w` is that day's window, and not at all
otherwise. -/
theorem one_window (es₁ es₂ : List Dated) (e : Dated) (w : ℕ) :
    dist (windowCounts (es₁ ++ e :: es₂) w) (windowCounts (es₁ ++ es₂) w)
      ≤ if week e.1 = w then 1 else 0 := by
  unfold windowCounts inWindow
  by_cases h : week e.1 = w
  · simp only [List.filter_append, List.filter_cons, h, decide_true, if_true,
      List.map_append, List.map_cons]
    exact sensitivity w _ _ e.2
  · simp only [List.filter_append, List.filter_cons, h, decide_false, if_false,
      Bool.false_eq_true]
    rw [dist_self]

/-- In particular, every other window's cells are unchanged. -/
theorem other_windows (es₁ es₂ : List Dated) (e : Dated) (w : ℕ) (h : week e.1 ≠ w) :
    windowCounts (es₁ ++ e :: es₂) w = windowCounts (es₁ ++ es₂) w := by
  have hd := one_window es₁ es₂ e w
  simp only [h, if_false, Nat.le_zero] at hd
  funext j
  have hj : ∀ j, (windowCounts (es₁ ++ e :: es₂) w j - windowCounts (es₁ ++ es₂) w j)
      + (windowCounts (es₁ ++ es₂) w j - windowCounts (es₁ ++ e :: es₂) w j) = 0 :=
    fun j => (Finset.sum_eq_zero_iff.mp hd) j (Finset.mem_univ j)
  have := hj j
  omega

/-! ## 5. (b) The threshold, on the noisy count

Owner decision 2026-11-15 ("go on rec"): suppress on the noisy count, so
that suppression is a function of the published noisy value alone and the
privacy theorem needs no condition on the counts. Until then the publisher
suppressed on the true count; `History.lean` keeps that rule and
`TrueCount.threshold_breaks_dp`, the proof that it is not differentially
private between 9 and 10. -/

inductive Cell where
  | suppressed
  | count (v : ℤ)
  deriving DecidableEq

/-- One published cell: with true count `c` and noise `z`, suppressed when
`c + z` is under `K`, otherwise `c + z`. -/
def publish (c : ℕ) (z : ℤ) : Cell :=
  if (c : ℤ) + z < K then .suppressed else .count (c + z)

/-- What is published from a noisy value `v`, reading nothing else. -/
def post (v : ℤ) : Cell :=
  if v < K then .suppressed else .count v

/-- **The publisher reads only the noisy value.** -/
theorem publish_is_post (c : ℕ) (z : ℤ) : publish c z = post ((c : ℤ) + z) := rfl

/-- **The threshold.** A cell whose count plus noise is under `K` is
suppressed. -/
theorem publish_suppresses (c : ℕ) (z : ℤ) (h : (c : ℤ) + z < K) :
    publish c z = .suppressed := by
  simp [publish, h]

theorem publish_shows (c : ℕ) (z : ℤ) (h : (K : ℤ) ≤ c + z) :
    publish c z = .count (c + z) := by
  simp [publish, not_lt.mpr h]

/-- **No value under `K` is ever published.** -/
theorem publish_at_least_k (c : ℕ) (z v : ℤ) (h : publish c z = .count v) : (K : ℤ) ≤ v := by
  unfold publish at h
  split_ifs at h with hk
  · cases h; omega

/-! ## 6. (c) The noise and differential privacy -/

/-- The law of the noise: discrete Laplace with ratio 1/2,
`P(z) = 1/3 · 2^-|z|`. Every change of one in a cell changes the likelihood
of any output by a factor of at most 2, so `ε = ln 2`. -/
noncomputable def lap (z : ℤ) : ℝ≥0∞ := 3⁻¹ * 2⁻¹ ^ z.natAbs

/-- The noise's law sums to one. -/
theorem lap_total : ∑' z : ℤ, lap z = 1 := by
  have geo : ∑' n : ℕ, (2⁻¹ : ℝ≥0∞) ^ n = 2 := by
    rw [ENNReal.tsum_geometric, ENNReal.one_sub_inv_two, inv_inv]
  have hpos : HasSum (fun n : ℕ => lap n) (3⁻¹ * 2) := by
    rw [ENNReal.summable.hasSum_iff]
    simp only [lap, Int.natAbs_natCast]
    rw [ENNReal.tsum_mul_left, geo]
  have hneg : HasSum (fun n : ℕ => lap (-((n : ℤ) + 1))) (3⁻¹ * 1) := by
    rw [ENNReal.summable.hasSum_iff]
    have habs : ∀ n : ℕ, (-((n : ℤ) + 1)).natAbs = n + 1 := fun n => by omega
    simp only [lap, habs, pow_succ]
    rw [ENNReal.tsum_mul_left, ENNReal.tsum_mul_right, geo,
      ENNReal.mul_inv_cancel (by norm_num) (by norm_num)]
  have := hpos.of_nat_of_neg_add_one hneg
  rw [this.tsum_eq, ← mul_add]
  rw [show (2 : ℝ≥0∞) + 1 = 3 by norm_num]
  exact ENNReal.inv_mul_cancel (by norm_num) (by norm_num)

/-- The sampler, as a law: the number of heads a fair coin shows before its
first tail. The collector draws two such counts per cell from the operating
system's random bytes and publishes their difference as the noise
(`contracts/analytics/src/noise.rs`). That the bytes are fair and
independent, and that the count saturates only at `2^32 - 1` heads (an event
of probability `2^-(2^32)`), are claims about the running system, not
theorems here. -/
noncomputable def geom (g : ℕ) : ℝ≥0∞ := 2⁻¹ ^ (g + 1)

theorem quarter_sum : ∑' g : ℕ, (4⁻¹ : ℝ≥0∞) ^ (g + 1) = 3⁻¹ := by
  have hsub : (1 : ℝ≥0∞) - 4⁻¹ = 3 * 4⁻¹ := by
    apply ENNReal.sub_eq_of_eq_add (by simp)
    rw [← add_one_mul, show (3 : ℝ≥0∞) + 1 = 4 by norm_num,
      ENNReal.mul_inv_cancel (by norm_num) (by norm_num)]
  simp only [pow_succ]
  rw [ENNReal.tsum_mul_right, ENNReal.tsum_geometric, hsub,
    ENNReal.mul_inv (by simp) (by simp), inv_inv, mul_assoc,
    ENNReal.mul_inv_cancel (by norm_num) (by norm_num), mul_one]

/-- **The sampler's law is `lap`.** The difference `G₁ - G₂` of two
independent counts takes the value `n ≥ 0` with probability `lap n`, and the
value `-(n + 1)` with probability `lap (-(n + 1))`. -/
theorem difference_nonneg (n : ℕ) :
    ∑' g : ℕ, geom (g + n) * geom g = lap n := by
  have : ∀ g : ℕ, geom (g + n) * geom g = 2⁻¹ ^ n * (4⁻¹ : ℝ≥0∞) ^ (g + 1) := by
    intro g
    have h4 : (4⁻¹ : ℝ≥0∞) = 2⁻¹ * 2⁻¹ := by
      rw [← ENNReal.mul_inv (by simp) (by simp)]; norm_num
    rw [h4, mul_pow]
    unfold geom
    ring
  simp only [this]
  rw [ENNReal.tsum_mul_left, quarter_sum]
  simp [lap, mul_comm]

theorem difference_neg (n : ℕ) :
    ∑' g : ℕ, geom g * geom (g + n + 1) = lap (-((n : ℤ) + 1)) := by
  have : ∀ g : ℕ, geom g * geom (g + n + 1)
      = 2⁻¹ ^ (n + 1) * (4⁻¹ : ℝ≥0∞) ^ (g + 1) := by
    intro g
    have h4 : (4⁻¹ : ℝ≥0∞) = 2⁻¹ * 2⁻¹ := by
      rw [← ENNReal.mul_inv (by simp) (by simp)]; norm_num
    rw [h4, mul_pow]
    unfold geom
    ring
  simp only [this]
  rw [ENNReal.tsum_mul_left, quarter_sum]
  have habs : (-((n : ℤ) + 1)).natAbs = n + 1 := by omega
  rw [lap, habs, mul_comm]

theorem lap_shift (v c c' : ℤ) :
    lap (v - c) ≤ 2 ^ (c - c').natAbs * lap (v - c') := by
  unfold lap
  have htri : (v - c').natAbs ≤ (v - c).natAbs + (c - c').natAbs := by omega
  set a := (v - c).natAbs
  set b := (v - c').natAbs
  set m := (c - c').natAbs
  have h2 : (2 : ℝ≥0∞) ^ m * 2⁻¹ ^ m = 1 := by
    rw [← mul_pow, ENNReal.mul_inv_cancel (by norm_num) (by norm_num), one_pow]
  have hb : (2⁻¹ : ℝ≥0∞) ^ (a + m) ≤ 2⁻¹ ^ b :=
    pow_le_pow_right_of_le_one' (by norm_num) htri
  calc (3⁻¹ : ℝ≥0∞) * 2⁻¹ ^ a = 3⁻¹ * ((2 ^ m * 2⁻¹ ^ m) * 2⁻¹ ^ a) := by rw [h2, one_mul]
    _ = 2 ^ m * (3⁻¹ * 2⁻¹ ^ (a + m)) := by rw [pow_add]; ring
    _ ≤ 2 ^ m * (3⁻¹ * 2⁻¹ ^ b) := by gcongr

/-! ## 7. Post-processing

A law on `α` pushed through a function `f`. Whatever `f` does, it reads only
its argument, so a bound that holds for every set of arguments holds for
every set of results. -/

/-- The law of `f x` when `x` has law `p`. -/
noncomputable def push {α β : Type} [DecidableEq β] (f : α → β) (p : α → ℝ≥0∞) (y : β) : ℝ≥0∞ :=
  ∑' x, if f x = y then p x else 0

/-- The mass `push f p` gives a set is the mass `p` gives its preimage. -/
theorem push_mass {α β : Type} [DecidableEq β] (f : α → β) (p : α → ℝ≥0∞) (S : Set β) :
    ∑' y, S.indicator (push f p) y = ∑' x, (f ⁻¹' S).indicator p x := by
  have h : ∀ y, S.indicator (push f p) y
      = ∑' x, if f x = y then (f ⁻¹' S).indicator p x else 0 := by
    intro y
    unfold push
    by_cases hy : y ∈ S
    · rw [Set.indicator_of_mem hy]
      congr 1
      funext x
      by_cases hx : f x = y
      · have hm : x ∈ f ⁻¹' S := by simp [hx, hy]
        simp [hx, Set.indicator_of_mem hm]
      · simp [hx]
    · rw [Set.indicator_of_notMem hy]
      symm
      refine ENNReal.tsum_eq_zero.mpr fun x => ?_
      by_cases hx : f x = y
      · have hm : x ∉ f ⁻¹' S := by simp [hx, hy]
        simp [hx, Set.indicator_of_notMem hm]
      · simp [hx]
  simp only [h]
  rw [ENNReal.tsum_comm]
  congr 1
  funext x
  simp only [@eq_comm _ (f x)]
  exact tsum_ite_eq (f x) (fun _ => (f ⁻¹' S).indicator p x)

/-- **Post-processing.** If every set of arguments is at most `r` times as
likely under `p` as under `q`, every set of results of `f` is too. -/
theorem postprocess {α β : Type} [DecidableEq β] (f : α → β) (p q : α → ℝ≥0∞) (r : ℝ≥0∞)
    (h : ∀ T : Set α, ∑' x, T.indicator p x ≤ r * ∑' x, T.indicator q x) (S : Set β) :
    ∑' y, S.indicator (push f p) y ≤ r * ∑' y, S.indicator (push f q) y := by
  rw [push_mass, push_mass]
  exact h _

/-! ## 8. (c) Differential privacy of a published window -/

/-- A window's noisy values, one per cell. -/
abbrev Noisy := Fin CELLS → ℤ

/-- A published window: one value per cell. -/
abbrev Output := Fin CELLS → Cell

/-- The noise of a window: one draw per cell, independent, each of law `lap`. -/
noncomputable def noiseDensity (z : Noisy) : ℝ≥0∞ := ∏ j, lap (z j)

/-- The law of the noisy window: each cell's true count plus its noise. -/
noncomputable def noisyDensity (a : Counts) (v : Noisy) : ℝ≥0∞ := ∏ j, lap (v j - a j)

/-- The law of a published window with true counts `a`: the window's noise
pushed through `publish`, cell by cell. -/
noncomputable def windowDensity (a : Counts) (o : Output) : ℝ≥0∞ :=
  ∑' z : Noisy, if (fun j => publish (a j) (z j)) = o then noiseDensity z else 0

/-- Publishing a window from its noisy values. -/
def publishWindow (v : Noisy) : Output := fun j => post (v j)

/-- **The published window is a function of the noisy window.** Its law is
the noisy window's law pushed through `publishWindow`, which reads nothing
else. -/
theorem window_is_post (a : Counts) :
    windowDensity a = push publishWindow (noisyDensity a) := by
  funext o
  unfold windowDensity push
  let s : Noisy := fun j => (a j : ℤ)
  symm
  rw [← (Equiv.addRight s).tsum_eq]
  congr 1
  funext z
  have h1 : publishWindow (z + s) = fun j => publish (a j) (z j) := by
    funext j
    simp [publishWindow, publish_is_post, s, add_comm]
  have h2 : noisyDensity a (z + s) = noiseDensity z := by
    simp [noisyDensity, noiseDensity, s]
  simp only [Equiv.coe_addRight, h1, h2]

/-- The noisy window: the likelihood of any noisy value changes by at most
`2 ^ dist` between true counts `a` and `b` (group privacy). -/
theorem noisy_ratio (a b : Counts) (v : Noisy) :
    noisyDensity a v ≤ 2 ^ dist a b * noisyDensity b v := by
  unfold noisyDensity dist
  rw [Finset.prod_pow_eq_pow_sum .. |>.symm, ← Finset.prod_mul_distrib]
  refine Finset.prod_le_prod' fun j _ => ?_
  have := lap_shift (v j) (a j) (b j)
  have hm : ((a j : ℤ) - b j).natAbs = (a j - b j) + (b j - a j) := by omega
  simpa [hm] using this

/-- **The noisy window is ε = ln 2.** Two windows at distance at most one:
any set of noisy windows is at most twice as likely under one as under the
other. -/
theorem noisy_dp (a b : Counts) (hd : dist a b ≤ 1) (T : Set Noisy) :
    ∑' v, T.indicator (noisyDensity a) v ≤ 2 * ∑' v, T.indicator (noisyDensity b) v := by
  rw [← ENNReal.tsum_mul_left]
  refine ENNReal.tsum_le_tsum fun v => ?_
  by_cases hv : v ∈ T
  · simp only [Set.indicator_of_mem hv]
    calc noisyDensity a v ≤ 2 ^ dist a b * noisyDensity b v := noisy_ratio a b v
      _ ≤ 2 ^ 1 * noisyDensity b v := by gcongr; norm_num
      _ = 2 * noisyDensity b v := by ring
  · simp [Set.indicator_of_notMem hv]

/-- **A window, any counts.** The likelihood of any published window changes
by at most `2 ^ dist` between true counts `a` and `b`: `m` beacons,
`m · ln 2`. -/
theorem window_ratio (a b : Counts) (o : Output) :
    windowDensity a o ≤ 2 ^ dist a b * windowDensity b o := by
  rw [window_is_post, window_is_post]
  unfold push
  rw [← ENNReal.tsum_mul_left]
  refine ENNReal.tsum_le_tsum fun v => ?_
  split_ifs
  · exact noisy_ratio a b v
  · simp

/-- **ε = ln 2 per window, for any set of published windows, for any
counts.** Two windows at distance at most one: the probability of any set of
published windows changes by at most a factor of 2. By post-processing:
suppression reads only the noisy value. -/
theorem window_dp (a b : Counts) (hd : dist a b ≤ 1) (S : Set Output) :
    ∑' o, S.indicator (windowDensity a) o ≤ 2 * ∑' o, S.indicator (windowDensity b) o := by
  rw [window_is_post, window_is_post]
  exact postprocess publishWindow _ _ 2 (noisy_dp a b hd) S

/-- **One beacon, end to end, in its window.** Two windows whose beacons
differ by one beacon: any set of published windows is at most twice as
likely under one as under the other. -/
theorem visit_dp (w : ℕ) (es₁ es₂ : List (Fin CELLS)) (e : Fin CELLS) (S : Set Output) :
    ∑' o, S.indicator (windowDensity (run (fresh w) w (es₁ ++ e :: es₂)).cells) o
      ≤ 2 * ∑' o, S.indicator (windowDensity (run (fresh w) w (es₁ ++ es₂)).cells) o :=
  window_dp _ _ (sensitivity w es₁ es₂ e) S

/-! ## 8b. The whole publication: every window at once

The windows in `W` are published together, each with its own noise drawn
independently (the shell draws fresh coins per cell, §8 of the RFC: by test,
not proof). A beacon reaches one window (`one_window`), so the publication
of any finite set of windows moves by at most a factor of 2. -/

/-- The law of the publication of the windows in `W`, each from its counts
`a w`, with independent noise per window. -/
noncomputable def publicationDensity (W : Finset ℕ) (a : ℕ → Counts) (o : W → Output) :
    ℝ≥0∞ :=
  ∏ w : W, windowDensity (a w) (o w)

/-- A beacon's window is in `W` at most once. -/
theorem windows_moved (W : Finset ℕ) (es₁ es₂ : List Dated) (e : Dated) :
    ∑ w : W, dist (windowCounts (es₁ ++ e :: es₂) w) (windowCounts (es₁ ++ es₂) w) ≤ 1 := by
  calc ∑ w : W, dist (windowCounts (es₁ ++ e :: es₂) w) (windowCounts (es₁ ++ es₂) w)
      ≤ ∑ w : W, (if week e.1 = (w : ℕ) then 1 else 0) :=
        Finset.sum_le_sum fun w _ => one_window es₁ es₂ e w
    _ = ∑ w ∈ W, (if week e.1 = w then 1 else 0) :=
        Finset.sum_coe_sort W (fun w => if week e.1 = w then 1 else 0)
    _ ≤ 1 := by rw [Finset.sum_ite_eq]; split <;> simp

/-- **The publication, pointwise.** One beacon more changes the likelihood of
any publication of the windows in `W` by at most a factor of 2. -/
theorem publication_ratio (W : Finset ℕ) (es₁ es₂ : List Dated) (e : Dated) (o : W → Output) :
    publicationDensity W (windowCounts (es₁ ++ e :: es₂)) o
      ≤ 2 * publicationDensity W (windowCounts (es₁ ++ es₂)) o := by
  unfold publicationDensity
  set A := windowCounts (es₁ ++ e :: es₂)
  set B := windowCounts (es₁ ++ es₂)
  calc ∏ w : W, windowDensity (A w) (o w)
      ≤ ∏ w : W, (2 ^ dist (A w) (B w) * windowDensity (B w) (o w)) :=
        Finset.prod_le_prod' fun w _ => window_ratio _ _ _
    _ = 2 ^ (∑ w : W, dist (A w) (B w)) * ∏ w : W, windowDensity (B w) (o w) := by
        rw [Finset.prod_mul_distrib, Finset.prod_pow_eq_pow_sum]
    _ ≤ 2 ^ 1 * ∏ w : W, windowDensity (B w) (o w) := by
        gcongr
        · norm_num
        · exact windows_moved W es₁ es₂ e
    _ = 2 * ∏ w : W, windowDensity (B w) (o w) := by rw [pow_one]

/-- **ε = ln 2 per beacon for the whole publication.** For any finite set of
windows `W` and any set `S` of their publications, one beacon more makes `S`
at most twice as likely. -/
theorem publication_dp (W : Finset ℕ) (es₁ es₂ : List Dated) (e : Dated)
    (S : Set (W → Output)) :
    ∑' o, S.indicator (publicationDensity W (windowCounts (es₁ ++ e :: es₂))) o
      ≤ 2 * ∑' o, S.indicator (publicationDensity W (windowCounts (es₁ ++ es₂))) o := by
  rw [← ENNReal.tsum_mul_left]
  refine ENNReal.tsum_le_tsum fun o => ?_
  by_cases ho : o ∈ S
  · simp only [Set.indicator_of_mem ho]
    exact publication_ratio W es₁ es₂ e o
  · simp [Set.indicator_of_notMem ho]

/-! ## 9. What suppression no longer promises

Under the true-count rule a cell under `K` was never shown. Under the noisy
rule it is shown when its noise lifts it to `K`; these are the exact
probabilities. -/

/-- The probability that a cell with true count `c` is shown. -/
noncomputable def shown (c : ℕ) : ℝ≥0∞ :=
  ∑' z : ℤ, if publish c z = .suppressed then 0 else lap z

theorem geometric_half : ∑' n : ℕ, (2⁻¹ : ℝ≥0∞) ^ n = 2 := by
  rw [ENNReal.tsum_geometric, ENNReal.one_sub_inv_two, inv_inv]

/-- **A cell under `K` is shown with probability `1 / (3 · 2^(K - 1 - c))`.**
It is shown exactly when its noise is at least `K - c`. -/
theorem shown_below_k (c : ℕ) (h : c < K) : shown c = (3 * 2 ^ (K - 1 - c))⁻¹ := by
  obtain ⟨n, hn⟩ : ∃ n, K - c = n + 1 := ⟨K - c - 1, by omega⟩
  have hn' : K - 1 - c = n := by omega
  have hiff : ∀ z : ℤ, publish c z = .suppressed ↔ z < ((n + 1 : ℕ) : ℤ) := by
    intro z
    rw [← hn]
    unfold publish
    split_ifs with hk
    · simp only [true_iff]; omega
    · simp only [false_iff]; omega
  have hpos : HasSum (fun i : ℕ => if publish c i = .suppressed then 0 else lap i)
      (3⁻¹ * 2⁻¹ ^ (n + 1) * 2) := by
    rw [ENNReal.summable.hasSum_iff]
    rw [← Summable.sum_add_tsum_nat_add' (k := n + 1) ENNReal.summable]
    have hfin : ∑ i ∈ Finset.range (n + 1),
        (if publish c (i : ℤ) = .suppressed then 0 else lap i) = 0 := by
      refine Finset.sum_eq_zero fun i hi => ?_
      have : publish c (i : ℤ) = .suppressed := (hiff i).mpr (by simp at hi; omega)
      simp [this]
    have htail : ∀ i : ℕ,
        (if publish c ((i + (n + 1) : ℕ) : ℤ) = .suppressed then 0
          else lap ((i + (n + 1) : ℕ) : ℤ)) = 3⁻¹ * 2⁻¹ ^ (n + 1) * 2⁻¹ ^ i := by
      intro i
      have : ¬ publish c ((i + (n + 1) : ℕ) : ℤ) = .suppressed := by
        rw [hiff]; omega
      simp only [this, if_false, lap, Int.natAbs_natCast]
      rw [pow_add]
      ring
    rw [hfin, zero_add]
    simp only [htail]
    rw [ENNReal.tsum_mul_left, geometric_half]
  have hneg : HasSum (fun i : ℕ =>
      if publish c (-((i : ℤ) + 1)) = .suppressed then 0 else lap (-((i : ℤ) + 1))) 0 := by
    have : ∀ i : ℕ, publish c (-((i : ℤ) + 1)) = .suppressed := fun i => (hiff _).mpr (by omega)
    simp only [this, if_true]
    exact hasSum_zero
  have hall := HasSum.of_nat_of_neg_add_one
    (f := fun z : ℤ => if publish c z = .suppressed then 0 else lap z) hpos hneg
  rw [shown, hall.tsum_eq, add_zero, hn', pow_succ, ENNReal.mul_inv (by simp) (by simp),
    ENNReal.inv_pow]
  rw [mul_assoc, mul_assoc, ENNReal.inv_mul_cancel (by norm_num) (by norm_num), mul_one]

/-- **A cell with no visits is shown with probability 1/1536.** -/
theorem shown_zero : shown 0 = 1536⁻¹ := by
  rw [shown_below_k 0 (by unfold K; omega)]
  norm_num [K]

/-- **A cell with 9 visits is shown with probability 1/3.** -/
theorem shown_nine : shown 9 = 3⁻¹ := by
  rw [shown_below_k 9 (by unfold K; omega)]
  norm_num [K]

/-- **Every cell under `K` is shown with probability at most 1/3.** -/
theorem shown_below_k_le (c : ℕ) (h : c < K) : shown c ≤ 3⁻¹ := by
  rw [shown_below_k c h]
  refine ENNReal.inv_le_inv.mpr ?_
  calc (3 : ℝ≥0∞) = 3 * 1 := (mul_one 3).symm
    _ ≤ 3 * 2 ^ (K - 1 - c) := by gcongr; exact one_le_pow₀ (by norm_num)

end QedAnalytics
