//! Acceptance of a delivered Lean proof against a buyer's pinned claim.
//!
//! The buyer authors a Lean export that ends with the declaration of the
//! claim: every definition the statement depends on, the statement itself, and
//! any axiom the buyer is willing to allow. The policy pins that export by
//! SHA-256 and names the claim. The seller delivers the bytes that continue
//! the export: further declarations ending in a term whose type is the claim.
//!
//! `accept` says yes only if the concatenation checks in the kernel checker,
//! the delivered part declares no axiom and no quotient primitive, and it
//! contains a theorem or definition whose type is exactly the pinned claim.
//! The buyer's part cannot be redefined: the checker refuses a second
//! declaration of any name, and the buyer's bytes are fixed by the hash.
//!
//! This function is the definition of "accepted". A proof guest runs it and
//! commits the result; it adds no authority of its own.
/// Export v2 (statement format v2): a statement, base or artifact may be
/// NDJSON or the binary form; `export_v2_from_ndjson` converts.
pub use nanoda_lib::acceptance::{
    EXPORT_V2_MAGIC, export_v2_decode_all, export_v2_from_ndjson, export_v2_round_trip,
};
use nanoda_lib::acceptance::{
    Entry, Kind, Marked, ends_at_a_record_end, inspect_after_segments, inspect_all_marked_segments,
};
use sha3::{Digest, Keccak256};

pub mod base;
pub mod vault_program;

pub type Hash = [u8; 32];

/// SHA-256. Inside a RISC Zero guest this is the machine's own accelerated
/// SHA-256; elsewhere the `sha2` crate. The same function either way.
pub(crate) fn sha256(bytes: &[u8]) -> Hash {
    #[cfg(target_os = "zkvm")]
    {
        use risc0_zkvm::sha::{Impl, Sha256 as _};
        let digest = Impl::hash_bytes(bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_bytes());
        out
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        use sha2::Digest as _;
        sha2::Sha256::digest(bytes).into()
    }
}

/// What the buyer fixes before funding. Its hash is `Order.policy_hash`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// SHA-256 of the buyer's export bytes.
    pub statement_sha256: Hash,
    /// Dotted name of the claim, declared in the buyer's export.
    pub claim: String,
    /// Axioms the checker may admit. They must be declared in the buyer's
    /// export; the seller's artifact may declare none.
    pub permitted_axioms: Vec<String>,
    pub maximum_artifact_bytes: u32,
}

pub(crate) fn field(hasher: &mut Keccak256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

impl Policy {
    /// Keccak-256 over a length-prefixed encoding of every field.
    pub fn hash(&self) -> Hash {
        let Policy {
            statement_sha256,
            claim,
            permitted_axioms,
            maximum_artifact_bytes,
        } = self;
        let mut hasher = Keccak256::new();
        field(&mut hasher, b"NucleusLeanClaimPolicyV1");
        field(&mut hasher, statement_sha256);
        field(&mut hasher, claim.as_bytes());
        hasher.update(
            u64::try_from(permitted_axioms.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for axiom in permitted_axioms {
            field(&mut hasher, axiom.as_bytes());
        }
        hasher.update(maximum_artifact_bytes.to_be_bytes());
        hasher.finalize().into()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The statement bytes are not the ones the policy pins.
    StatementMismatch,
    /// The statement does not end at a line boundary.
    StatementUnterminated,
    /// The statement does not parse, or declares an axiom outside the policy.
    StatementInvalid(String),
    /// The statement does not declare exactly one universe-monomorphic
    /// definition, opaque constant or inductive type with the claim's name.
    ClaimNotDeclared,
    ArtifactEmpty,
    ArtifactTooLarge,
    /// The concatenation does not parse, or the artifact declares an axiom
    /// the policy does not permit.
    ExportInvalid(String),
    /// The kernel checker refused a declaration.
    KernelRefused,
    /// Parsing the concatenation changed the buyer's declarations.
    StatementAltered,
    /// The artifact declares an axiom or a quotient primitive.
    ArtifactDeclaresAxiom(String),
    /// No delivered theorem or definition has the claim as its type.
    ClaimNotProved,
    /// The order names a base, and the statement does not begin with bytes
    /// that hash to it.
    BaseMismatch,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Accepted {
    pub policy_hash: Hash,
    /// Keccak-256 of the delivered bytes, as the escrow computes it.
    pub artifact_keccak256: Hash,
    /// Declarations the checker verified, buyer's and seller's together.
    pub declarations: usize,
    /// Rendered name of the delivered declaration that has the claim's type.
    pub proof: String,
}

fn claim_index(statement: &[Entry], claim: &str) -> Option<usize> {
    let mut matches = statement
        .iter()
        .enumerate()
        .filter(|(_, e)| e.name == claim);
    let (Some((index, entry)), None) = (matches.next(), matches.next()) else {
        return None;
    };
    (entry.universe_parameters == 0
        && matches!(
            entry.kind,
            Kind::Definition | Kind::Opaque | Kind::Inductive
        ))
    .then_some(index)
}

/// Decide acceptance. `run` parses the statement and artifact together once,
/// type-checks every declaration, and reports how many declarations the
/// statement's bytes made (`nanoda_lib::acceptance::inspect_all_marked_segments`
/// with one mark, the end of the statement); it returns `None` if the checker
/// refused by panicking. See `accept` and `accept_aborting` for the two ways
/// to run it.
///
/// Until statement format v2's optimization pass this parsed the statement
/// alone first and then the concatenation, and refused if the two disagreed
/// about the statement's declarations (`StatementAltered`). Parsing is a
/// function of the bytes read so far, so they cannot disagree; the one-parse
/// form takes the statement's declarations from the mark instead. A statement
/// that does not parse is now refused as `ExportInvalid`, not
/// `StatementInvalid`; the verdict is the same
/// (`docs/rfcs/proof-commerce-statement-format-v2-2026-11-13.md`).
fn decide(
    policy: &Policy,
    statement: &[u8],
    artifact: &[u8],
    run: impl Fn(&[&[u8]], &[String], [usize; 1]) -> Option<Result<Marked, String>>,
) -> Result<Accepted, Refusal> {
    if artifact.is_empty() {
        return Err(Refusal::ArtifactEmpty);
    }
    if u32::try_from(artifact.len()).map_or(true, |n| n > policy.maximum_artifact_bytes) {
        return Err(Refusal::ArtifactTooLarge);
    }
    if sha256(statement) != policy.statement_sha256 {
        return Err(Refusal::StatementMismatch);
    }
    if !ends_at_a_record_end(statement) {
        return Err(Refusal::StatementUnterminated);
    }
    let marked = run(
        &[statement, artifact],
        &policy.permitted_axioms,
        [statement.len()],
    )
    .ok_or(Refusal::KernelRefused)?
    .map_err(Refusal::ExportInvalid)?;
    // How many declarations the statement's bytes made, from the parser.
    let &[statement_count] = marked.counts.as_slice() else {
        return Err(Refusal::ExportInvalid("one mark expected".into()));
    };
    let entries = &marked.entries;
    let (buyers, sellers) = entries
        .split_at_checked(statement_count)
        .ok_or(Refusal::StatementAltered)?;
    let claim = claim_index(buyers, &policy.claim).ok_or(Refusal::ClaimNotDeclared)?;
    if let Some(axiom) = sellers
        .iter()
        .find(|e| matches!(e.kind, Kind::Axiom | Kind::Quot))
    {
        return Err(Refusal::ArtifactDeclaresAxiom(axiom.name.clone()));
    }
    let proof = sellers
        .iter()
        .find(|e| {
            matches!(e.kind, Kind::Theorem | Kind::Definition)
                && e.type_is_declaration == Some(claim)
        })
        .ok_or(Refusal::ClaimNotProved)?;
    Ok(Accepted {
        policy_hash: policy.hash(),
        artifact_keccak256: Keccak256::digest(artifact).into(),
        declarations: entries.len(),
        proof: proof.name.clone(),
    })
}

/// For a proof guest: a kernel refusal aborts the process, so no statement
/// about the artifact can be committed.
pub fn accept_aborting(
    policy: &Policy,
    statement: &[u8],
    artifact: &[u8],
) -> Result<Accepted, Refusal> {
    decide(policy, statement, artifact, |segments, axioms, marks| {
        Some(inspect_all_marked_segments(segments, axioms, &marks))
    })
}

/// For a host: the checker runs on its own thread with a deep stack, and a
/// kernel refusal is returned as `Refusal::KernelRefused`.
#[cfg(not(target_os = "zkvm"))]
pub fn accept(policy: &Policy, statement: &[u8], artifact: &[u8]) -> Result<Accepted, Refusal> {
    decide(policy, statement, artifact, |segments, axioms, marks| {
        let axioms = axioms.to_vec();
        let owned: Vec<Vec<u8>> = segments.iter().map(|s| s.to_vec()).collect();
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                let segments: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
                inspect_all_marked_segments(&segments, &axioms, &marks)
            })
            .ok()?
            .join()
            .ok()
    })
}

/// Decide acceptance for a statement that begins with a checked base.
///
/// The first `base_length` bytes of the statement must hash to `base`. The
/// export is parsed once; the declarations those bytes make are NOT
/// type-checked here, and every later declaration is. The caller must hold a
/// proof that those bytes checked on their own under `policy.permitted_axioms`
/// (`vault_program::journal_on_base` requires it before calling this).
///
/// `run` is `nanoda_lib::acceptance::inspect_after` with two marks: the end
/// of the base and the end of the statement.
fn decide_on_base(
    policy: &Policy,
    statement: &[u8],
    artifact: &[u8],
    base_length: usize,
    base: Hash,
    run: impl Fn(&[&[u8]], &[String], [usize; 2]) -> Option<Result<Marked, String>>,
) -> Result<Accepted, Refusal> {
    if artifact.is_empty() {
        return Err(Refusal::ArtifactEmpty);
    }
    if u32::try_from(artifact.len()).map_or(true, |n| n > policy.maximum_artifact_bytes) {
        return Err(Refusal::ArtifactTooLarge);
    }
    if sha256(statement) != policy.statement_sha256 {
        return Err(Refusal::StatementMismatch);
    }
    if !ends_at_a_record_end(statement) {
        return Err(Refusal::StatementUnterminated);
    }
    let prefix = statement
        .get(..base_length)
        .filter(|prefix| !prefix.is_empty())
        .ok_or(Refusal::BaseMismatch)?;
    if sha256(prefix) != base {
        return Err(Refusal::BaseMismatch);
    }
    let marked = run(
        &[statement, artifact],
        &policy.permitted_axioms,
        [base_length, statement.len()],
    )
    .ok_or(Refusal::KernelRefused)?
    .map_err(Refusal::ExportInvalid)?;
    // How many declarations the statement's bytes made, from the parser.
    let &[_, statement_count] = marked.counts.as_slice() else {
        return Err(Refusal::ExportInvalid("two marks expected".into()));
    };
    let (buyers, sellers) = marked
        .entries
        .split_at_checked(statement_count)
        .ok_or(Refusal::StatementAltered)?;
    let claim = claim_index(buyers, &policy.claim).ok_or(Refusal::ClaimNotDeclared)?;
    if let Some(axiom) = sellers
        .iter()
        .find(|e| matches!(e.kind, Kind::Axiom | Kind::Quot))
    {
        return Err(Refusal::ArtifactDeclaresAxiom(axiom.name.clone()));
    }
    let proof = sellers
        .iter()
        .find(|e| {
            matches!(e.kind, Kind::Theorem | Kind::Definition)
                && e.type_is_declaration == Some(claim)
        })
        .ok_or(Refusal::ClaimNotProved)?;
    Ok(Accepted {
        policy_hash: policy.hash(),
        artifact_keccak256: Keccak256::digest(artifact).into(),
        declarations: marked.entries.len(),
        proof: proof.name.clone(),
    })
}

/// For a proof guest: as `accept_aborting`, on a checked base.
pub fn accept_on_base_aborting(
    policy: &Policy,
    statement: &[u8],
    artifact: &[u8],
    base_length: usize,
    base: Hash,
) -> Result<Accepted, Refusal> {
    decide_on_base(
        policy,
        statement,
        artifact,
        base_length,
        base,
        |segments, axioms, marks| Some(inspect_after_segments(segments, axioms, &marks)),
    )
}

/// For a host: as `accept`, on a checked base. The caller answers for the
/// base having been checked; `base::check` is the native way to find out.
#[cfg(not(target_os = "zkvm"))]
pub fn accept_on_base(
    policy: &Policy,
    statement: &[u8],
    artifact: &[u8],
    base_length: usize,
    base: Hash,
) -> Result<Accepted, Refusal> {
    decide_on_base(
        policy,
        statement,
        artifact,
        base_length,
        base,
        |segments, axioms, marks| {
            let axioms = axioms.to_vec();
            let owned: Vec<Vec<u8>> = segments.iter().map(|s| s.to_vec()).collect();
            std::thread::Builder::new()
                .stack_size(64 * 1024 * 1024)
                .spawn(move || {
                    let segments: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
                    inspect_after_segments(&segments, &axioms, &marks)
                })
                .ok()?
                .join()
                .ok()
        },
    )
}
