import PortcullisCoreDecide.Funs
/- Buyer-authored statement. Nucleus commit 5e8f7c85ab118279c9ad1b36238de4e87f2e577b.
   Subject: nucleus_ifc_kernel::exposure::should_gate, as Aeneas extracted it
   (crates/portcullis-core/lean/generated-decide). Nucleus proves these facts
   for a hand-written model (ExposureProofs.lean: should_gate_empty,
   should_gate_non_exfil_never_gated); this asks for them of the extracted
   function. Toward tracking issue #3310 (Kernel::decide). -/
open Aeneas Aeneas.Std Result nucleus_ifc_kernel in
def Nucleus.Claim : Prop :=
  (∀ op : ifc_ops.Operation,
      exposure.should_gate ⟨false, false, false⟩ op = ok false)
  ∧ (∀ s : exposure.ExposureSet,
      exposure.should_gate s ifc_ops.Operation.ReadFiles = ok false
      ∧ exposure.should_gate s ifc_ops.Operation.WebFetch = ok false)
