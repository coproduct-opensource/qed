/-- A fixture claim with a small closure. -/
def Statements.S0001.claim : Prop := ∀ p q : Prop, p ∧ q → q ∧ p
