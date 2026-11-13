//! The QED acceptance rule for a browser.
//!
//! The same function the order program runs inside the proof
//! (`nucleus_proof_acceptance::accept_aborting`), compiled to
//! `wasm32-unknown-unknown`, behind a raw C ABI so a page needs no generated
//! glue:
//!
//! - `qed_alloc(len) -> ptr` and `qed_free(ptr, len)` manage buffers;
//! - `qed_check(policy, statement, artifact)` (three pointer/length pairs)
//!   returns `(ptr << 32) | len` of a verdict JSON the caller then frees.
//!
//! A kernel refusal panics, and on this target a panic aborts: the module
//! traps and returns nothing. The caller reports a trap as a refusal ("the
//! checker aborted"), exactly as a proof guest that aborts commits nothing.
//!
//! What a verdict does NOT say: whether a zero-knowledge proof exists,
//! whether a vault paid for these bytes, or anything about a chain.
use nucleus_proof_acceptance::{Accepted, Policy, Refusal, accept_aborting};
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn unhex32(text: &str) -> Option<[u8; 32]> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Parse the policy JSON the site serves:
/// `{statementSha256, claim, permittedAxioms, maximumArtifactBytes}`.
pub fn policy_from_json(bytes: &[u8]) -> Result<Policy, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|e| format!("policy JSON: {e}"))?;
    let statement_sha256 = value["statementSha256"]
        .as_str()
        .and_then(unhex32)
        .ok_or("policy: statementSha256")?;
    let claim = value["claim"].as_str().ok_or("policy: claim")?.to_owned();
    let permitted_axioms = value["permittedAxioms"]
        .as_array()
        .ok_or("policy: permittedAxioms")?
        .iter()
        .map(|a| a.as_str().map(str::to_owned).ok_or("policy: axiom"))
        .collect::<Result<Vec<_>, _>>()?;
    let maximum_artifact_bytes = value["maximumArtifactBytes"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or("policy: maximumArtifactBytes")?;
    Ok(Policy {
        statement_sha256,
        claim,
        permitted_axioms,
        maximum_artifact_bytes,
    })
}

/// The refusal's name, as the site and the parity test compare it.
pub fn refusal_kind(refusal: &Refusal) -> &'static str {
    match refusal {
        Refusal::StatementMismatch => "StatementMismatch",
        Refusal::StatementUnterminated => "StatementUnterminated",
        Refusal::StatementInvalid(_) => "StatementInvalid",
        Refusal::ClaimNotDeclared => "ClaimNotDeclared",
        Refusal::ArtifactEmpty => "ArtifactEmpty",
        Refusal::ArtifactTooLarge => "ArtifactTooLarge",
        Refusal::ExportInvalid(_) => "ExportInvalid",
        Refusal::KernelRefused => "KernelRefused",
        Refusal::StatementAltered => "StatementAltered",
        Refusal::ArtifactDeclaresAxiom(_) => "ArtifactDeclaresAxiom",
        Refusal::ClaimNotProved => "ClaimNotProved",
        Refusal::BaseMismatch => "BaseMismatch",
    }
}

/// The verdict JSON for a decided check.
pub fn verdict(policy: &Policy, artifact: &[u8], decided: &Result<Accepted, Refusal>) -> Value {
    let policy_hash = hex(&policy.hash());
    let artifact_keccak256 = hex(&Keccak256::digest(artifact));
    match decided {
        Ok(a) => json!({
            "verdict": "accepted",
            "proof": a.proof,
            "declarations": a.declarations,
            "policyHash": policy_hash,
            "artifactKeccak256": artifact_keccak256,
        }),
        Err(r) => json!({
            "verdict": "refused",
            "refusal": refusal_kind(r),
            "detail": format!("{r:?}"),
            "policyHash": policy_hash,
            "artifactKeccak256": artifact_keccak256,
        }),
    }
}

/// The whole check on byte inputs; used by the C ABI below and, natively, by
/// the parity test.
pub fn check(policy_json: &[u8], statement: &[u8], artifact: &[u8]) -> Value {
    let policy = match policy_from_json(policy_json) {
        Ok(p) => p,
        Err(e) => return json!({ "verdict": "refused", "refusal": "PolicyInvalid", "detail": e }),
    };
    let decided = accept_aborting(&policy, statement, artifact);
    verdict(&policy, artifact, &decided)
}

/// Allocate `len` bytes for the caller to fill. Never returns null for
/// `len > 0` (allocation failure aborts).
#[unsafe(no_mangle)]
pub extern "C" fn qed_alloc(len: u32) -> *mut u8 {
    let mut buffer = Vec::<u8>::with_capacity(len as usize);
    let ptr = buffer.as_mut_ptr();
    std::mem::forget(buffer);
    ptr
}

/// Free a buffer from `qed_alloc` or from a `qed_check` result.
///
/// # Safety
/// `ptr` and `len` must come from `qed_alloc(len)` or a `qed_check` result,
/// and be freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qed_free(ptr: *mut u8, len: u32) {
    // SAFETY: the caller's contract above.
    unsafe { drop(Vec::from_raw_parts(ptr, 0, len as usize)) }
}

/// Run the acceptance rule. Returns `(ptr << 32) | len` of the verdict JSON.
///
/// # Safety
/// Each pointer/length pair must describe `len` initialised bytes the caller
/// owns for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qed_check(
    policy_ptr: *const u8,
    policy_len: u32,
    statement_ptr: *const u8,
    statement_len: u32,
    artifact_ptr: *const u8,
    artifact_len: u32,
) -> u64 {
    // SAFETY: the caller's contract above.
    let (policy, statement, artifact) = unsafe {
        (
            std::slice::from_raw_parts(policy_ptr, policy_len as usize),
            std::slice::from_raw_parts(statement_ptr, statement_len as usize),
            std::slice::from_raw_parts(artifact_ptr, artifact_len as usize),
        )
    };
    let out = serde_json::to_vec(&check(policy, statement, artifact)).unwrap_or_default();
    let len = out.len();
    let mut out = out.into_boxed_slice();
    let ptr = out.as_mut_ptr();
    std::mem::forget(out);
    ((ptr as u64) << 32) | len as u64
}
