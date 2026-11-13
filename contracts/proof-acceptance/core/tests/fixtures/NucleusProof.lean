import NucleusTask
/- Seller-authored proof. -/
theorem Nucleus.helper (n m : Nat) : n + Nat.succ m = Nat.succ (n + m) := Nat.add_succ n m
theorem Nucleus.proof : Nucleus.Claim := fun n m => Nucleus.helper n m
