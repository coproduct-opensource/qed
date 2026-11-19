/-
The proof of `QedVisits.claim` (`Statement.lean`), Lean core only. It avoids
`omega` on purpose: a first proof by `omega` over `Int` exported to 4.6 MB
of NDJSON; the triangle inequality and two `Nat` facts keep the artifact
small enough to check in a browser tab.
-/
import QedVisits.Statement

namespace QedVisits

theorem two_pow_le {a b : Nat} (h : b ≤ a + 1) : 2 ^ b ≤ 2 * 2 ^ a := by
  have : 2 ^ b ≤ 2 ^ (a + 1) := Nat.pow_le_pow_right (by decide) h
  rw [Nat.pow_succ, Nat.mul_comm] at this
  exact this

/-- One beacon moves a noisy value's distance to the count by at most one. -/
theorem dist_le (c c' o : Int) (h : (c - c').natAbs ≤ 1) :
    (o - c').natAbs ≤ (o - c).natAbs + 1 := by
  have e : o - c' = (o - c) + (c - c') := by
    rw [Int.sub_eq_add_neg, Int.sub_eq_add_neg, Int.sub_eq_add_neg, Int.add_assoc,
      Int.neg_add_cancel_left]
  rw [e]
  exact Nat.le_trans (Int.natAbs_add_le _ _) (Nat.add_le_add_left h _)

theorem ratio (c c' o : Int) (h : (c - c').natAbs ≤ 1) :
    2 ^ (o - c').natAbs ≤ 2 * 2 ^ (o - c).natAbs :=
  two_pow_le (dist_le c c' o h)

theorem sub_le_sub_add {n a b : Nat} (hb : b ≤ a + 1) : n - a ≤ (n - b) + 1 := by
  apply Nat.sub_le_iff_le_add.mpr
  have h1 : n ≤ n - b + b := Nat.sub_le_iff_le_add.mp (Nat.le_refl (n - b))
  have h2 : n - b + b ≤ n - b + (a + 1) := Nat.add_le_add_left hb _
  rw [Nat.add_comm a 1, ← Nat.add_assoc] at h2
  exact Nat.le_trans h1 h2

theorem scaled_le (n : Nat) (c c' v : Int) (h : (c - c').natAbs ≤ 1) :
    scaled n c v ≤ 2 * scaled n c' v :=
  two_pow_le (sub_le_sub_add (dist_le c c' v h))

theorem mass (c c' : Int) (n : Nat) (S : List Int) (h : (c - c').natAbs ≤ 1) :
    (S.map (scaled n c)).sum ≤ 2 * (S.map (scaled n c')).sum := by
  induction S with
  | nil => exact Nat.zero_le _
  | cons v S ih =>
    rw [List.map_cons, List.map_cons, List.sum_cons, List.sum_cons, Nat.mul_add]
    exact Nat.add_le_add (scaled_le n c c' v h) ih

theorem proof : claim :=
  ⟨ratio,
   fun _ _ => rfl,
   fun c c' n S h _ => mass c c' n S h,
   fun c c' n _ _ h _ => mass c c' n _ h⟩

end QedVisits
