/-
What /visits checks in the browser: the part of the privacy argument that is
finite. Lean core only. The full proofs (`../lean/QedAnalytics/Spec.lean`,
Mathlib) cover what this does not: that the noise's law sums to one, the
infinite sums over sets of outputs, the sampler's law, composition across
cells and windows, and that the Rust code computes these functions
(`Refines.lean`).

The noise added to a cell is `z` with probability `2^-|z| / 3`. A published
cell with true count `c` takes the noisy value `o = c + z` with probability
proportional to `w c o = 2^-|o - c|`. Without reals: `w c o ≤ 2 * w c' o` is
`2^|o - c'| ≤ 2 * 2^|o - c|`.
-/
namespace QedVisits

/-- A cell whose count plus noise is under `K` is suppressed. -/
def K : Int := 10

/-- What is published from a noisy value: `none` (suppressed) under `K`,
otherwise the value. It reads nothing else. -/
def post (v : Int) : Option Int := if v < K then none else some v

/-- What is published for true count `c` and noise `z`. -/
def publish (c : Nat) (z : Int) : Option Int := if (c : Int) + z < K then none else some (c + z)

/-- `2^(n - |v - c|)`: the likelihood of noisy value `v` under true count
`c`, times `3 · 2^n`, for values within `n` of `c`. -/
def scaled (n : Nat) (c v : Int) : Nat := 2 ^ (n - (v - c).natAbs)

/-- The claim:

1. **The ratio.** For true counts at most one apart (one beacon), every
   noisy value is at most twice as likely under one as under the other.
2. **Post-processing.** The published cell is a function of the noisy value
   alone.
3. **Any finite set of noisy values.** For true counts at most one apart,
   every finite list of noisy values, all within `n` of both counts, has at
   most twice the (scaled) mass under one as under the other.
4. **Any published value.** In particular, the noisy values in such a list
   that publish as any given `y`. -/
def claim : Prop :=
  (∀ c c' o : Int, (c - c').natAbs ≤ 1 → 2 ^ (o - c').natAbs ≤ 2 * 2 ^ (o - c).natAbs) ∧
  (∀ (c : Nat) (z : Int), publish c z = post ((c : Int) + z)) ∧
  (∀ (c c' : Int) (n : Nat) (S : List Int), (c - c').natAbs ≤ 1 →
    (∀ v ∈ S, (v - c).natAbs ≤ n ∧ (v - c').natAbs ≤ n) →
    (S.map (scaled n c)).sum ≤ 2 * (S.map (scaled n c')).sum) ∧
  (∀ (c c' : Int) (n : Nat) (S : List Int) (y : Option Int), (c - c').natAbs ≤ 1 →
    (∀ v ∈ S, (v - c).natAbs ≤ n ∧ (v - c').natAbs ≤ n) →
    ((S.filter (fun v => post v == y)).map (scaled n c)).sum
      ≤ 2 * ((S.filter (fun v => post v == y)).map (scaled n c')).sum)

end QedVisits
