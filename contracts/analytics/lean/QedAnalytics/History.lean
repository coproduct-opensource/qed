/-
The publisher's first rule, kept because it is why the rule changed.

From the first deploy (2026-11-15 01:44 UTC) the collector suppressed a cell
when its TRUE count was under `K`. `threshold_breaks_dp` proves what that
costs: a cell at 9 was suppressed with probability 1 and at 10 with
probability 0, so one beacon could change the probability of an output from
1 to 0, and no ε bounds that. The old `day_dp` and `visit_dp` held only for
days whose cells all stayed on one side of `K`.

Owner decision 2026-11-15 ("go on rec"): suppress on the NOISY count
(`Spec.lean`, `publish`). Suppression then reads only the noisy value, and
`day_dp` and `visit_dp` (since 2026-11-18 `window_dp` and `visit_dp`, over
weeks) hold for every window by post-processing. What that
gives up is stated there too: a cell under `K` is now shown with probability
`shown c` (`shown_zero`, `shown_nine`, `shown_below_k_le`).

No day was published under this rule: the first day, 2026-11-15, is
published after 00:00 UTC on 2026-11-16, by the collector built from the
noisy rule.
-/
import QedAnalytics.Spec

namespace QedAnalytics.TrueCount

open scoped ENNReal

/-- The rule until 2026-11-15: suppressed when the true count `c` is under
`K`, otherwise `c` plus the noise `z`. -/
def publish (c : ℕ) (z : ℤ) : Cell :=
  if c < K then .suppressed else .count (c + z)

/-- The law of one cell published under that rule. -/
noncomputable def cellDensity (c : ℕ) (o : Cell) : ℝ≥0∞ :=
  ∑' z : ℤ, if publish c z = o then lap z else 0

theorem cellDensity_below (c : ℕ) (h : c < K) (o : Cell) :
    cellDensity c o = if o = .suppressed then 1 else 0 := by
  unfold cellDensity
  simp only [publish, h, if_true]
  by_cases ho : o = .suppressed
  · subst ho; simp [lap_total]
  · simp [ho, Ne.symm ho]

theorem cellDensity_above_suppressed (c : ℕ) (h : K ≤ c) :
    cellDensity c .suppressed = 0 := by
  unfold cellDensity
  simp [publish, Nat.not_lt.mpr h]

/-- **Why the rule changed.** Under the true-count rule a cell at `K - 1` is
suppressed with probability one, and at `K` never: no ε bounds the change
one beacon makes. -/
theorem threshold_breaks_dp :
    cellDensity (K - 1) .suppressed = 1 ∧ cellDensity K .suppressed = 0 := by
  constructor
  · rw [cellDensity_below _ (by unfold K; omega)]; simp
  · exact cellDensity_above_suppressed _ le_rfl

end QedAnalytics.TrueCount
