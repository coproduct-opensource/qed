import NucleusObligationTask
import CredentialNoninterferenceExtracted
/- Seller-authored proof: the two theorems nucleus already carries. -/
theorem Nucleus.proof : Nucleus.Claim :=
  ⟨CredentialNoninterference.a_credential_never_reaches_the_guest,
   CredentialNoninterference.cred_may_deliver_never_fails⟩
