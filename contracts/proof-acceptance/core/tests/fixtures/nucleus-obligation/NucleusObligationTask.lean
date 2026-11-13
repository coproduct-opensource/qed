import PortcullisCoreCredential.Funs
/- Buyer-authored statement over the Aeneas-extracted credential relation:
   a credential is never deliverable to the guest, and the delivery decision
   never fails. -/
open Aeneas Aeneas.Std Result nucleus_ifc_kernel in
def Nucleus.Claim : Prop :=
  extracted.credential.credential_may_reach extracted.credential.CredSink.Guest = ok false
  ∧ ∀ (l : extracted.ifc_confidentiality.ConfLevel) (s : extracted.credential.CredSink),
      ∃ b : Bool, extracted.credential.cred_may_deliver l s = ok b
