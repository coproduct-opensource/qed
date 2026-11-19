import Statements.S0001

theorem Statements.S0001.proof : Statements.S0001.claim :=
  fun _ _ h => ⟨h.2, h.1⟩
