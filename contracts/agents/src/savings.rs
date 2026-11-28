//! Who authored the lemmas a settled proof reused: the provenance index of
//! proof-carrying savings (proofs/commerce/Savings.lean, `authorsOf` and
//! `newProv`; docs/rfcs/qed-proof-carrying-savings-2026-11-28.md).
//!
//! A settled artifact is accepted, then walked from its proof through every
//! constant reached (`nanoda_lib::acceptance::used_constants`). Each seller
//! side declaration is keyed by its name and the digests of its type and
//! value. The index maps a key to the payee of the first settlement whose
//! artifact carried it; the authors of a settlement are the payees the
//! index names for its keys, distinct, less its own seller.
//!
//! Left out of attribution: kernel-reserved names (the walk), the
//! statement's own declarations, and every key that appeared on the
//! statement side of any statement this index has read (`library`). A Lean
//! library declaration that no statement carried is still attributed to
//! the first seller that re-exported it: the measured Nucleus fixture
//! re-exports `rfl` and `Nat.add_succ`. That is the v1 limit the RFC records.
use crate::prelude::*;
use nucleus_proof_acceptance::{Policy, accept};
use nucleus_proof_commerce::Hash;
use qed_savings::{Rule, authors_of, extend};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// A declaration's key: SHA-256 of a tag, its dotted name, and the digests
/// of its type and value (zero for none).
pub type Key = Hash;

/// The seller side and the statement side of one settled artifact, keyed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declarations {
    pub statement: Vec<Key>,
    pub seller: Vec<Key>,
    /// The seller-side names, in export order, for a page.
    pub names: Vec<String>,
}

fn sha256(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

fn key(name: &str, ty: &Hash, value: &Option<Hash>) -> Key {
    let mut bytes = b"NucleusDeclarationV1".to_vec();
    bytes.extend_from_slice(&(name.len() as u64).to_be_bytes());
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(ty);
    bytes.extend_from_slice(&value.unwrap_or([0; 32]));
    sha256(&bytes)
}

/// Accept `artifact` for `statement` under `policy`, then walk from its
/// proof. Refused artifacts have no declarations to attribute.
pub fn declarations(policy: &Policy, statement: &[u8], artifact: &[u8]) -> Res<Declarations> {
    let proof = accept(policy, statement, artifact)
        .map_err(|refusal| format!("the artifact is not accepted: {refusal:?}"))?
        .proof;
    let axioms = policy.permitted_axioms.clone();
    let (statement, artifact) = (statement.to_vec(), artifact.to_vec());
    // A deep stack, as the acceptance host runs the checker.
    let walked = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            nanoda_lib::acceptance::used_constants(
                &[&statement, &artifact],
                &axioms,
                &[statement.len()],
                &proof,
                &mut |bytes| sha256(bytes),
            )
        })?
        .join()
        .map_err(|_| "the walk panicked")??;
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

/// The provenance index: each key's first payee, in settlement order, and
/// the keys any statement carried.
#[derive(Clone, Debug, Default)]
pub struct Provenance {
    pub first: Vec<(Key, Address)>,
    pub library: HashSet<Key>,
}

impl Provenance {
    /// One settlement by `seller` with these declarations, in chain order:
    /// its authors (`Savings.authorsOf`), then the index extended with what
    /// it carried (`Savings.newProv`). A key some statement carried is
    /// never attributed, and a key first carried before it appeared in a
    /// statement stops being attributed from then on.
    pub fn settle(&mut self, d: &Declarations, seller: Address) -> Vec<Address> {
        self.library.extend(d.statement.iter().copied());
        let decls: Vec<Key> = d
            .seller
            .iter()
            .filter(|k| !self.library.contains(*k))
            .copied()
            .collect();
        let first: Vec<(Key, Address)> = self
            .first
            .iter()
            .filter(|(k, _)| !self.library.contains(k))
            .copied()
            .collect();
        let authors = authors_of(&Rule::MODEL, &first, &decls, &seller);
        extend(&mut self.first, &decls, &seller);
        authors
    }
}

#[cfg(test)]
mod tests;
