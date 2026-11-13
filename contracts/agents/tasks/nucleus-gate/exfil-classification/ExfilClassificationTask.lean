import PortcullisCoreDecide.Funs
/- Buyer-authored statement. Nucleus commit 5e8f7c85ab118279c9ad1b36238de4e87f2e577b.
   Subjects: nucleus_ifc_kernel::ifc_ops::is_exfil_operation and
   nucleus_ifc_kernel::exposure::classify_operation, as Aeneas extracted them.
   The two classifications of an operation agree: an operation is an
   exfiltration operation exactly when its exposure label is the exfiltration
   leg, and neither function fails. The gate consults the first and the
   exposure projection the second; if they diverged, an operation could add
   the third leg without being gated. Toward #3310. -/
open Aeneas Aeneas.Std Result nucleus_ifc_kernel in
def Nucleus.Claim : Prop :=
  ∀ op : ifc_ops.Operation,
    ∃ b : Bool, ifc_ops.is_exfil_operation op = ok b
      ∧ (b = true ↔
          exposure.classify_operation op = ok (some exposure.ExposureLabel.ExfilVector))
