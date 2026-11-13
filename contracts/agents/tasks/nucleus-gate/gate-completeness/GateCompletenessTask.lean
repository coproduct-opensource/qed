import PortcullisCoreDecide.Funs
/- Buyer-authored statement. Nucleus commit 5e8f7c85ab118279c9ad1b36238de4e87f2e577b.
   Subject: nucleus_ifc_kernel::exposure::should_gate, as Aeneas extracted it
   (crates/portcullis-core/lean/generated-decide). The extracted function
   gates an exfiltration operation that completes, or follows, the three-leg
   exposure state. Nucleus proves these two facts for a hand-written model
   (ExposureProofs.lean: should_gate_completing_uninhabitable,
   should_gate_all_exfil_when_uninhabitable); this asks for them of the
   extracted function. Toward tracking issue #3310 (Kernel::decide). -/
open Aeneas Aeneas.Std Result nucleus_ifc_kernel in
def Nucleus.Claim : Prop :=
  exposure.should_gate ⟨true, true, false⟩ ifc_ops.Operation.GitPush = ok true
  ∧ exposure.should_gate ⟨true, true, true⟩ ifc_ops.Operation.RunBash = ok true
  ∧ exposure.should_gate ⟨true, true, true⟩ ifc_ops.Operation.GitPush = ok true
  ∧ exposure.should_gate ⟨true, true, true⟩ ifc_ops.Operation.CreatePr = ok true
