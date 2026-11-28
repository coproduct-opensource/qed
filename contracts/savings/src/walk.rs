//! Who authored the lemmas a settled proof reused: the provenance index of
//! proof-carrying savings (proofs/commerce/Savings.lean, `authorsOf` and
//! `newProv`; docs/rfcs/qed-proof-carrying-savings-2026-11-28.md). The
//! buyer's desk and the site both run this code, so a published
//! attribution is recomputed with what produced it.
//!
//! A settled artifact is accepted, then walked from its proof through every
//! constant reached (`walk::export::used_constants`). Each seller
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
pub mod export;

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
const LIBRARY: &[u8] = include_bytes!("../library/lean-4.30.0-init.exclude");

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
    let (statement, artifact) = (statement.to_vec(), artifact.to_vec());
    let (count, used) = deep(move || -> Result<(usize, Vec<export::Used>), String> {
        let mut x = export::Export::default();
        x.read(&statement)?;
        let count = x.declarations();
        x.read(&artifact)?;
        Ok((
            count,
            export::used_constants(&x, &proof, &mut |bytes| sha256(bytes))?,
        ))
    })??;
    let mut out = Declarations {
        statement: vec![],
        seller: vec![],
        names: vec![],
    };
    for used in &used {
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
pub fn library_keys(bytes: Vec<u8>, _permitted_axioms: Vec<String>) -> Result<Vec<Key>, String> {
    let used = deep(move || -> Result<Vec<export::Used>, String> {
        let mut x = export::Export::default();
        x.read(&bytes)?;
        export::all_declarations(&x, &mut |b| sha256(b))
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
    /// Keys of published proof files public by now: introduced by no one
    /// (`Savings.newProv`), though an earlier introducer keeps its credit.
    pub published: HashSet<Key>,
}

impl<P> Default for Provenance<P> {
    fn default() -> Self {
        Self {
            first: Vec::new(),
            statements: HashSet::new(),
            published: HashSet::new(),
        }
    }
}

impl<P: PartialEq + Clone> Provenance<P> {
    /// An index that treats `public` (every declaration of every statement
    /// export the reader holds) as public from the start.
    pub fn with_public(public: HashSet<Key>) -> Self {
        Self {
            first: Vec::new(),
            statements: public,
            published: HashSet::new(),
        }
    }
    /// One settlement by `seller`, paid for by `buyer`, with these
    /// declarations, in chain order: its authors (`Savings.authorsOf`), then
    /// the index extended with what it carried (`Savings.newProv`). Never
    /// attributed: library keys and keys any statement carried (public,
    /// `Savings.no_credit_for_public`), and the seller or the buyer
    /// (`Savings.no_self_credit`).
    pub fn settle(&mut self, d: &Declarations, seller: P, buyer: &P) -> Vec<P> {
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
                .into_iter()
                .filter(|a| a != buyer)
                .collect()
        };
        let introduced: Vec<Key> = decls
            .iter()
            .filter(|k| !self.published.contains(*k))
            .copied()
            .collect();
        extend(&mut self.first, &introduced, &seller);
        authors
    }
}

/// One settlement in chain order, as an attributor reads it: the order, its
/// payee, and its artifact's declarations when the reader has the artifact
/// and its statement.
#[derive(Clone, Debug)]
pub struct Settled<P> {
    pub order: Hash,
    /// The block it settled in: what was public "as of" it.
    pub block: u64,
    pub payee: P,
    /// The paying buyer as a payee (its address and the order's asset);
    /// `None` when the reader cannot see it (an elided address).
    pub buyer: Option<P>,
    pub declarations: Option<Declarations>,
}

/// What an attributor can say of one settlement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attributed<P> {
    Authors(Vec<P>),
    /// This artifact, or an earlier settlement's, could not be read: the
    /// first carrier of a key is not known.
    Unknown(Hash),
}

/// Attribute every settlement in chain order. `public` is the keys of every
/// statement export the reader holds (public at every block); `published`
/// is the keys of each published proof file with the first block it was
/// public at. A key is public for a settlement when it is in `public`, in
/// the library set, or in a published file public before that settlement's
/// block (`Savings.no_credit_for_public`). A settlement is attributed
/// only when every settlement before it was read; one whose buyer the
/// reader cannot see is unknown itself, and still extends the index.
pub fn attribute_all<P: PartialEq + Clone>(
    settled: &[Settled<P>],
    public: &HashSet<Key>,
    published: &[(u64, HashSet<Key>)],
) -> Vec<(Hash, Attributed<P>)> {
    let mut index = Provenance::with_public(public.clone());
    let mut missing: Option<Hash> = None;
    let mut out = Vec::with_capacity(settled.len());
    for s in settled {
        // Settlements come in chain order, so what is public only grows.
        for (from, keys) in published {
            if *from < s.block {
                index.published.extend(keys.iter().copied());
            }
        }
        let a = match (&missing, &s.declarations) {
            (Some(first), _) => Attributed::Unknown(*first),
            (None, None) => {
                missing = Some(s.order);
                Attributed::Unknown(s.order)
            }
            (None, Some(d)) => match &s.buyer {
                Some(buyer) => Attributed::Authors(index.settle(d, s.payee.clone(), buyer)),
                None => {
                    // The index still learns what this settlement carried.
                    let seller = s.payee.clone();
                    index.settle(d, seller.clone(), &seller);
                    Attributed::Unknown(s.order)
                }
            },
        };
        out.push((s.order, a));
    }
    out
}

/// The keys of every declaration of each statement export: what
/// `attribute_all` treats as public.
pub fn public_keys(statements: &[(Policy, Vec<u8>)]) -> HashSet<Key> {
    let mut out = HashSet::new();
    for (policy, bytes) in statements {
        if let Ok(keys) = library_keys(bytes.clone(), policy.permitted_axioms.clone()) {
            out.extend(keys);
        }
    }
    out
}

#[cfg(test)]
mod tests;

/// An acceptance policy from its `input/policies.json` entry (the site's
/// layout), kept only when it hashes to `hash`, the policy hash an order
/// commits to; with the entry's statement file name.
pub fn policy_from_json(hash: &str, p: &serde_json::Value) -> Option<(Policy, String)> {
    let sha = p["statementSha256"].as_str()?.trim_start_matches("0x");
    let mut statement_sha256 = [0u8; 32];
    for (i, b) in statement_sha256.iter_mut().enumerate() {
        *b = u8::from_str_radix(sha.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    let policy = Policy {
        statement_sha256,
        claim: p["claim"].as_str()?.to_owned(),
        permitted_axioms: p["permittedAxioms"]
            .as_array()?
            .iter()
            .filter_map(|a| a.as_str().map(str::to_owned))
            .collect(),
        maximum_artifact_bytes: u32::try_from(p["maximumArtifactBytes"].as_u64()?).ok()?,
    };
    let computed: String = policy.hash().iter().map(|b| format!("{b:02x}")).collect();
    if computed != hash.trim_start_matches("0x").to_ascii_lowercase() {
        return None;
    }
    Some((policy, p["statementFile"].as_str()?.to_owned()))
}

/// A policy and its statement bytes, by policy hash.
pub type PolicyOf<'a> = dyn Fn(&str) -> Option<(Policy, Vec<u8>)> + 'a;

/// The published proof files (`published.json`: `[{artifact, policy,
/// fromBlock}]`, the artifact's keccak-256 file name, the policy hash its
/// statement is under, and the first block it was public at), each as its
/// seller-side keys. An entry the reader cannot read is left out, and says
/// so by its absence from the result's count.
pub fn published_keys(
    entries: &[serde_json::Value],
    policy: &PolicyOf,
    artifact: &dyn Fn(&str) -> Option<Vec<u8>>,
) -> Vec<(u64, HashSet<Key>)> {
    entries
        .iter()
        .filter_map(|e| {
            let from = e["fromBlock"].as_u64()?;
            let (p, statement) = policy(e["policy"].as_str()?)?;
            let bytes = artifact(e["artifact"].as_str()?.trim_start_matches("0x"))?;
            let d = declarations(&p, &statement, &bytes).ok()?;
            Some((from, d.seller.into_iter().collect()))
        })
        .collect()
}
