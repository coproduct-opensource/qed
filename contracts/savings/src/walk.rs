//! Who authored the lemmas a settled proof reused: the provenance index of
//! proof-carrying savings (proofs/commerce/Savings.lean, `authorsOf` and
//! `newProv`; docs/rfcs/qed-proof-carrying-savings-2026-11-28.md). The
//! buyer's desk and the site both run this code, so a published
//! attribution is recomputed with what produced it.
//!
//! A settled artifact is accepted, then walked from its proof through every
//! constant reached (`nanoda_lib::acceptance::used_constants`). Each seller
//! side declaration is keyed by its name and the digests of its type and
//! value. The index maps a key to the payee of the first settlement whose
//! artifact carried it; the authors of a settlement are the payees the
//! index names for its keys, distinct, less its own seller.
//!
//! Never attributed (`Savings.excluded_never_earns`):
//! - kernel-reserved names (the walk leaves them out);
//! - the statement's own declarations;
//! - every declaration of the Lean 4.30.0 library (`library`): the
//!   committed key set of an export of `Init` with the exporter statements
//!   use. Without it the first seller to re-export `rfl` or `Nat.add_succ`
//!   would be credited with them;
//! - every key that appeared on the statement side of a statement read.
use crate::{Rule, authors_of, extend};
use nucleus_proof_acceptance::{Policy, accept};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub type Hash = [u8; 32];
/// A declaration's key: SHA-256 of a tag, its dotted name, and the digests
/// of its type and value (zero for none).
pub type Key = Hash;

/// The library exclusion set: sorted 32-byte keys of every declaration in
/// `lean4export Init` with Lean 4.30.0 and lean4export 3.1.0
/// (`library/README.md` has the export's SHA-256 and the command).
const LIBRARY: &[u8] = include_bytes!("../library/lean-4.30.0-init.keys");

/// Whether `key` is a declaration of the pinned Lean library.
pub fn is_library(key: &Key) -> bool {
    let n = LIBRARY.len() / 32;
    let at = |i: usize| -> &[u8] { LIBRARY.get(i * 32..i * 32 + 32).unwrap_or(&[]) };
    let (mut lo, mut hi) = (0usize, n);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        match at(mid).cmp(key.as_slice()) {
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
            std::cmp::Ordering::Equal => return true,
        }
    }
    false
}

/// How many keys the library set holds; 0 means it is absent, and author
/// shares are not paid (their 20 % stays with the buyer).
pub fn library_size() -> usize {
    LIBRARY.len() / 32
}

pub fn sha256(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

pub fn key(name: &str, ty: &Hash, value: &Option<Hash>) -> Key {
    let mut bytes = b"NucleusDeclarationV1".to_vec();
    bytes.extend_from_slice(&(name.len() as u64).to_be_bytes());
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(ty);
    bytes.extend_from_slice(&value.unwrap_or([0; 32]));
    sha256(&bytes)
}

/// The seller side and the statement side of one settled artifact, keyed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declarations {
    pub statement: Vec<Key>,
    pub seller: Vec<Key>,
    /// The seller-side names, in export order, for a page.
    pub names: Vec<String>,
}

impl Declarations {
    /// The seller-side keys that can earn a share: not in the library.
    pub fn attributable(&self) -> Vec<Key> {
        self.seller
            .iter()
            .filter(|k| !is_library(k))
            .copied()
            .collect()
    }
    /// The seller-side names the library set leaves out.
    pub fn excluded_names(&self) -> Vec<String> {
        self.seller
            .iter()
            .zip(&self.names)
            .filter(|(k, _)| is_library(k))
            .map(|(_, n)| n.clone())
            .collect()
    }
}

/// Run `f` on a thread with a deep stack, as the acceptance host runs the
/// checker.
fn deep<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(f)
        .map_err(|e| e.to_string())?
        .join()
        .map_err(|_| "the walk panicked".to_owned())
}

/// Accept `artifact` for `statement` under `policy`, then walk from its
/// proof. Refused artifacts have no declarations to attribute.
pub fn declarations(
    policy: &Policy,
    statement: &[u8],
    artifact: &[u8],
) -> Result<Declarations, String> {
    let proof = accept(policy, statement, artifact)
        .map_err(|refusal| format!("the artifact is not accepted: {refusal:?}"))?
        .proof;
    let axioms = policy.permitted_axioms.clone();
    let (statement, artifact) = (statement.to_vec(), artifact.to_vec());
    let walked = deep(move || {
        nanoda_lib::acceptance::used_constants(
            &[&statement, &artifact],
            &axioms,
            &[statement.len()],
            &proof,
            &mut |bytes| sha256(bytes),
        )
    })??;
    let count = walked
        .counts
        .first()
        .copied()
        .ok_or("no count for the mark")?;
    let mut out = Declarations {
        statement: vec![],
        seller: vec![],
        names: vec![],
    };
    for used in &walked.used {
        let k = key(&used.name, &used.ty, &used.value);
        if used.position < count {
            out.statement.push(k);
        } else {
            out.seller.push(k);
            out.names.push(used.name.clone());
        }
    }
    Ok(out)
}

/// Every declaration of a whole export, keyed, sorted and distinct: the
/// library exclusion set's bytes, built by `qed-library-keys`.
pub fn library_keys(export: Vec<u8>, permitted_axioms: Vec<String>) -> Result<Vec<Key>, String> {
    let used = deep(move || {
        nanoda_lib::acceptance::declaration_digests(&[&export], &permitted_axioms, &mut |b| {
            sha256(b)
        })
    })??;
    let mut keys: Vec<Key> = used.iter().map(|u| key(&u.name, &u.ty, &u.value)).collect();
    keys.sort_unstable();
    keys.dedup();
    Ok(keys)
}

/// The provenance index: each key's first payee, in settlement order, and
/// the keys any statement carried. `P` is a payee: the desk and the site
/// use the payee key the vault's `Claimed` names (seller and asset).
#[derive(Clone, Debug)]
pub struct Provenance<P> {
    pub first: Vec<(Key, P)>,
    pub statements: HashSet<Key>,
}

impl<P> Default for Provenance<P> {
    fn default() -> Self {
        Self {
            first: Vec::new(),
            statements: HashSet::new(),
        }
    }
}

impl<P: PartialEq + Clone> Provenance<P> {
    /// One settlement by `seller` with these declarations, in chain order:
    /// its authors (`Savings.authorsOf`), then the index extended with what
    /// it carried (`Savings.newProv`). Library keys and keys a statement
    /// carried are never attributed.
    pub fn settle(&mut self, d: &Declarations, seller: P) -> Vec<P> {
        self.statements.extend(d.statement.iter().copied());
        let decls: Vec<Key> = d
            .attributable()
            .into_iter()
            .filter(|k| !self.statements.contains(k))
            .collect();
        let first: Vec<(Key, P)> = self
            .first
            .iter()
            .filter(|(k, _)| !self.statements.contains(k))
            .cloned()
            .collect();
        // Without the exclusion set nobody is an author: the 20 % stays with
        // the buyer (owner decision, 2026-11-28).
        let authors = if library_size() == 0 {
            Vec::new()
        } else {
            authors_of(&Rule::MODEL, &first, &decls, &seller)
        };
        extend(&mut self.first, &decls, &seller);
        authors
    }
}

#[cfg(test)]
mod tests;
