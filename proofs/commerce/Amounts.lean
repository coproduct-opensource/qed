import Std
set_option warningAsError true

namespace Nucleus.ProofCommerce

/-- Decomposing BEFORE multiplication avoids a uint256 intermediate overflow.
    This proves the arithmetic identity, not the Rust implementation. -/
theorem ceil_fee_decomposition (amount rate : Nat) :
    (amount * rate + 9999) / 10000 =
    (amount / 10000) * rate + ((amount % 10000) * rate + 9999) / 10000 := by
  have h := Nat.div_add_mod amount 10000
  have expand : amount * rate + 9999 =
      10000 * ((amount / 10000) * rate) + (amount % 10000 * rate + 9999) := by
    calc
      _ = (10000 * (amount / 10000) + amount % 10000) * rate + 9999 := by rw [h]
      _ = _ := by simp [Nat.add_mul, Nat.mul_assoc, Nat.add_assoc]
  rw [expand, Nat.mul_add_div (by decide : 0 < 10000)]

/-- Every intermediate of the decomposed whole-unit multiplication is bounded.
    Residual multiplication has a separate small bound. -/
theorem whole_fee_bounded (amount rate : Nat) (bounded : rate ≤ 10000) :
    (amount / 10000) * rate ≤ amount := by
  have hm := Nat.mul_le_mul_left (amount / 10000) bounded
  have hd := Nat.div_add_mod amount 10000
  have commute := Nat.mul_comm (amount / 10000) 10000
  omega

theorem residual_fee_bounded (amount rate : Nat) (bounded : rate ≤ 10000) :
    amount % 10000 * rate + 9999 ≤ 9999 * 10000 + 9999 := by
  have hr : amount % 10000 ≤ 9999 := by have := Nat.mod_lt amount (by decide : 0 < 10000); omega
  exact Nat.add_le_add_right (Nat.mul_le_mul hr bounded) 9999

/-- info: 'Nucleus.ProofCommerce.ceil_fee_decomposition' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms ceil_fee_decomposition

end Nucleus.ProofCommerce
