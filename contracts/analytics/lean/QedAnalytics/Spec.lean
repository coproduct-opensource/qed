/-
QED visit analytics: what the collector means, written before its code.

The collector (contracts/analytics) counts beacons from qed.coproduct.dev
per day, per site path and per "first visit today" bit, and once a day
publishes every cell with discrete Laplace noise, suppressing cells whose
true count is under `K`. This file is the meaning: a model of the state
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

/-- Cells per day: for each path, a cell for returning visits (`2 * path`)
and one for first visits today (`2 * path + 1`); then one for malformed
beacons and one for beacons refused by the rate limit. -/
def CELLS : ℕ := 2 * PATHS + 2

def MALFORMED : ℕ := 2 * PATHS
def LIMITED : ℕ := 2 * PATHS + 1

/-- A cell whose true count is under `K` is published as `suppressed`. -/
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

/-- The collector's whole state: the day being counted and its cells. -/
structure Day where
  day : ℕ
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

def fresh (day : ℕ) : Day := ⟨day, fun _ => 0⟩

/-- Count one beacon in cell `i` on `day`. A beacon dated before the day being
counted (the clock went back) changes nothing; one dated later starts a new
day from zero. -/
def count (s : Day) (i : Fin CELLS) (day : ℕ) : Day :=
  if day < s.day then s
  else
    let t := if s.day < day then fresh day else s
    ⟨day, Function.update t.cells i (bump (t.cells i))⟩

/-- The only fields of a request the core may use. -/
def project (r : Request) : ℕ × Bool × ℕ := (r.path, r.first, r.day)

def step (s : Day) (path : ℕ) (first : Bool) (day : ℕ) : Day :=
  count s (cellIdx path first) day

/-- A beacon refused by the rate limit, counted on `day`. Whether a beacon is
refused depends on the arrival times of all beacons, never on its fields. -/
def limit (s : Day) (day : ℕ) : Day := count s limitedIdx day

def handle (s : Day) (r : Request) : Day :=
  match project r with
  | (path, first, day) => step s path first day

/-! ## 3. (a) Noninterference -/

/-- The state after a request depends on the request only through
`(path, first, day)`. -/
theorem handle_eq_of_project_eq (s : Day) (r₁ r₂ : Request)
    (h : project r₁ = project r₂) : handle s r₁ = handle s r₂ := by
  unfold handle
  rw [h]

/-- In particular, the connection's peer, the time within the day and the
request's sizes change nothing. -/
theorem handle_ignores_connection (s : Day) (r : Request) (sec : ℕ) (peer : List ℕ)
    (port head body : ℕ) :
    handle s { r with secondOfDay := sec, peer := peer, peerPort := port,
                      headBytes := head, bodyBytes := body } = handle s r :=
  handle_eq_of_project_eq s _ r rfl

/-! ## 4. Sensitivity: one beacon moves one cell by at most one -/

/-- Count the beacons of one day, in arrival order, each given by its cell. -/
def run (s : Day) (day : ℕ) : List (Fin CELLS) → Day
  | [] => s
  | i :: es => run (count s i day) day es

/-- L1 distance between two days' cells. -/
def dist (a b : Counts) : ℕ := ∑ j, ((a j - b j) + (b j - a j))

theorem run_cells_of_le (d : ℕ) (es : List (Fin CELLS)) (s : Day) (hd : s.day = d)
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

/-- A day's cells, from its beacons: each cell is its number of beacons,
saturated. Order does not matter. -/
theorem run_fresh (d : ℕ) (es : List (Fin CELLS)) (j : Fin CELLS) :
    (run (fresh d) d es).cells j = min (es.count j) MAX := by
  rw [run_cells_of_le d es (fresh d) rfl (fun _ => by simp [fresh, MAX])]
  simp [fresh]

/-- **Sensitivity 1.** Two days whose beacons differ by one beacon end with
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

/-! ## 5. (b) The threshold -/

inductive Cell where
  | suppressed
  | count (v : ℤ)
  deriving DecidableEq

/-- One published cell: suppressed under `K`, otherwise the true count plus
the noise `z`. -/
def publish (c : ℕ) (z : ℤ) : Cell :=
  if c < K then .suppressed else .count (c + z)

/-- **The threshold.** A cell whose true count is under `K` is suppressed,
whatever the noise. -/
theorem publish_suppresses (c : ℕ) (z : ℤ) (h : c < K) : publish c z = .suppressed := by
  simp [publish, h]

theorem publish_shows (c : ℕ) (z : ℤ) (h : K ≤ c) : publish c z = .count (c + z) := by
  simp [publish, Nat.not_lt.mpr h]

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

/-- The law of one published cell with true count `c`: the noise's law pushed
through `publish`. -/
noncomputable def cellDensity (c : ℕ) (o : Cell) : ℝ≥0∞ :=
  ∑' z : ℤ, if publish c z = o then lap z else 0

theorem cellDensity_below (c : ℕ) (h : c < K) (o : Cell) :
    cellDensity c o = if o = .suppressed then 1 else 0 := by
  unfold cellDensity
  simp only [publish_suppresses c _ h]
  by_cases ho : o = .suppressed
  · subst ho; simp [lap_total]
  · simp [ho, Ne.symm ho]

theorem cellDensity_above (c : ℕ) (h : K ≤ c) (o : Cell) :
    cellDensity c o = match o with
      | .suppressed => 0
      | .count v => lap (v - c) := by
  unfold cellDensity
  simp only [publish_shows c _ h]
  cases o with
  | suppressed => simp
  | count v =>
    simp only [Cell.count.injEq]
    rw [tsum_eq_single (v - c)]
    · simp
    · intro z hz
      have : (c : ℤ) + z ≠ v := by omega
      simp [this]

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

/-- **One cell.** For true counts on the same side of `K`, the likelihood of
any published value changes by at most `2 ^ |c - c'|`. -/
theorem cell_ratio (c c' : ℕ) (hside : c < K ↔ c' < K) (o : Cell) :
    cellDensity c o ≤ 2 ^ ((c - c') + (c' - c)) * cellDensity c' o := by
  by_cases hc : c < K
  · have hc' := hside.mp hc
    rw [cellDensity_below c hc, cellDensity_below c' hc']
    exact le_mul_of_one_le_left (zero_le) (one_le_pow₀ (by norm_num))
  · have hc' : ¬ c' < K := fun h => hc (hside.mpr h)
    rw [cellDensity_above c (Nat.not_lt.mp hc), cellDensity_above c' (Nat.not_lt.mp hc')]
    cases o with
    | suppressed => simp
    | count v =>
      have := lap_shift v c c'
      have hm : ((c : ℤ) - c').natAbs = (c - c') + (c' - c) := by omega
      simpa [hm] using this

/-- A published day: one value per cell. -/
abbrev Output := Fin CELLS → Cell

/-- The law of a published day: each cell's noise drawn independently. -/
noncomputable def dayDensity (a : Counts) (o : Output) : ℝ≥0∞ :=
  ∏ j, cellDensity (a j) (o j)

/-- Every cell of `a` is on the same side of `K` as the same cell of `b`. -/
def SameSide (a b : Counts) : Prop := ∀ j, (a j < K ↔ b j < K)

/-- **A day.** For days whose cells sit on the same sides of `K`, the
likelihood of any published day changes by at most `2 ^ dist`. -/
theorem day_ratio (a b : Counts) (h : SameSide a b) (o : Output) :
    dayDensity a o ≤ 2 ^ dist a b * dayDensity b o := by
  unfold dayDensity dist
  rw [Finset.prod_pow_eq_pow_sum .. |>.symm, ← Finset.prod_mul_distrib]
  exact Finset.prod_le_prod' (fun j _ => cell_ratio (a j) (b j) (h j) (o j))

/-- **ε = ln 2 per day, for any set of published days.** Two days at distance
at most one, cells on the same sides of `K`: the probability of any set of
outputs changes by at most a factor of 2. -/
theorem day_dp (a b : Counts) (h : SameSide a b) (hd : dist a b ≤ 1) (S : Set Output) :
    ∑' o, S.indicator (dayDensity a) o ≤ 2 * ∑' o, S.indicator (dayDensity b) o := by
  rw [← ENNReal.tsum_mul_left]
  refine ENNReal.tsum_le_tsum fun o => ?_
  by_cases ho : o ∈ S
  · simp only [Set.indicator_of_mem ho]
    calc dayDensity a o ≤ 2 ^ dist a b * dayDensity b o := day_ratio a b h o
      _ ≤ 2 ^ 1 * dayDensity b o := by gcongr; norm_num
      _ = 2 * dayDensity b o := by ring
  · simp [Set.indicator_of_notMem ho]

/-- **One beacon, end to end.** Two days whose beacons differ by one beacon,
with every cell on the same side of `K`: any set of published days is at most
twice as likely under one as under the other. -/
theorem visit_dp (d : ℕ) (es₁ es₂ : List (Fin CELLS)) (e : Fin CELLS)
    (h : SameSide (run (fresh d) d (es₁ ++ e :: es₂)).cells (run (fresh d) d (es₁ ++ es₂)).cells)
    (S : Set Output) :
    ∑' o, S.indicator (dayDensity (run (fresh d) d (es₁ ++ e :: es₂)).cells) o
      ≤ 2 * ∑' o, S.indicator (dayDensity (run (fresh d) d (es₁ ++ es₂)).cells) o :=
  day_dp _ _ h (sensitivity d es₁ es₂ e) S

/-- **Where the guarantee stops: the threshold.** A cell at `K - 1` is
suppressed with probability one, and at `K` never. Thresholding on the true
count is not differentially private for any ε, which is why `day_dp` and
`visit_dp` assume `SameSide`. -/
theorem threshold_breaks_dp :
    cellDensity (K - 1) .suppressed = 1 ∧ cellDensity K .suppressed = 0 := by
  constructor
  · rw [cellDensity_below _ (by unfold K; omega)]; simp
  · rw [cellDensity_above _ le_rfl]

end QedAnalytics
