/- Buyer-authored statement. -/
def Nucleus.Claim : Prop := ∀ n m : Nat, n + Nat.succ m = Nat.succ (n + m)
