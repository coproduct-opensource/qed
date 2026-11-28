//! The desk's side of proof-carrying savings attribution
//! (docs/rfcs/qed-proof-carrying-savings-2026-11-28.md): who authored the
//! lemmas a settled order's proof reused, computed with the code the site
//! checks it with (`qed_savings::walk`).
//!
//! The desk reads every `Settled` of its vault from `NUCLEUS_SAVINGS_FROM`
//! (a block) in chain order, takes each artifact and order from its
//! `settle` calldata, and the statements from `NUCLEUS_SAVINGS_LIBRARY`, a
//! directory in the site's input layout (`policies.json`, `statements/`).
//! Without the library the desk attributes nothing: no author is paid and
//! the 20 % stays with the buyer. A settlement it cannot read makes this
//! and every later attribution unknown, with the same result.
use crate::chain::Chain;
use crate::prelude::*;
use nucleus_proof_commerce::Hash;
use qed_savings::walk::{self, Attributed, Settled};
use std::path::PathBuf;

pub const LIBRARY_VARIABLE: &str = "NUCLEUS_SAVINGS_LIBRARY";
pub const FROM_VARIABLE: &str = "NUCLEUS_SAVINGS_FROM";

/// The policies and statements a desk attributes with.
pub struct Library {
    pub policies: serde_json::Map<String, Value>,
    pub statements: Vec<(String, Vec<u8>)>,
}

impl Library {
    /// `NUCLEUS_SAVINGS_LIBRARY`, read; `None` when unset.
    pub fn from_environment() -> Res<Option<Self>> {
        let Ok(dir) = std::env::var(LIBRARY_VARIABLE) else {
            return Ok(None);
        };
        Self::read(&PathBuf::from(dir)).map(Some)
    }
    pub fn read(dir: &std::path::Path) -> Res<Self> {
        let policies: serde_json::Map<String, Value> =
            serde_json::from_slice(&fs::read(dir.join("policies.json"))?)?;
        let mut statements = Vec::new();
        for p in policies.values() {
            let Some(file) = p["statementFile"].as_str() else {
                continue;
            };
            if let Ok(bytes) = fs::read(dir.join("statements").join(file)) {
                statements.push((file.to_owned(), bytes));
            }
        }
        Ok(Self {
            policies,
            statements,
        })
    }
    fn declarations(&self, policy_hash: &Hash, artifact: &[u8]) -> Option<walk::Declarations> {
        let hash = hex(policy_hash);
        let (policy, file) = walk::policy_from_json(&hash, self.policies.get(&hash)?)?;
        let (_, statement) = self.statements.iter().find(|(f, _)| *f == file)?;
        walk::declarations(&policy, statement, artifact).ok()
    }
}

/// One settlement as read from the chain.
#[derive(Clone, Debug)]
pub struct Read {
    pub order: Hash,
    pub payee_key: Hash,
    pub seller: Address,
    pub policy_hash: Hash,
    pub artifact: Option<Vec<u8>>,
}

/// The vault's settlements from `from`, in chain order, with what their
/// `settle` calldata carries (third form; anything else reads as unknown).
pub fn read_settlements(chain: &Chain, vault: Address, from: u64) -> Res<Vec<Read>> {
    let latest = u64::from_str_radix(
        chain
            .rpc("eth_blockNumber", json!([]))?
            .as_str()
            .ok_or("block number expected")?
            .trim_start_matches("0x"),
        16,
    )?;
    let topic = crate::world::settled_topic(vault::Form::Third);
    let logs = chain.logs(
        &json!({"address": hex(&vault), "topics": [hex(&topic)]}),
        from,
        latest,
    )?;
    let mut out = Vec::new();
    for log in logs {
        let order = log["topics"][1]
            .as_str()
            .and_then(|t| unhex(t).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or("a Settled log without its digest")?;
        let tx = log["transactionHash"]
            .as_str()
            .ok_or("no transaction hash")?;
        let sent = chain.rpc("eth_getTransactionByHash", json!([tx]))?;
        let input = unhex(sent["input"].as_str().unwrap_or("0x"))?;
        match crate::world::settled_order_in(&input) {
            Some((seller, asset, policy_hash, artifact)) => {
                let mut key = seller.to_vec();
                key.extend_from_slice(&asset);
                out.push(Read {
                    order,
                    payee_key: keccak(&key),
                    seller,
                    policy_hash,
                    artifact: Some(artifact),
                });
            }
            None => out.push(Read {
                order,
                payee_key: [0; 32],
                seller: [0; 20],
                policy_hash: [0; 32],
                artifact: None,
            }),
        }
    }
    Ok(out)
}

/// What the desk publishes and pays for one order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attributed1 {
    /// Each author's address, for the payout.
    pub authors: Vec<Address>,
    /// The line for the signed delivery record (payee keys only).
    pub published: qed_deliveries::Attribution,
}

/// Attribute `order` over `settled` (chain order, `order` among them).
/// `None` when it cannot be known.
pub fn attribute(settled: &[Read], library: &Library, order: &Hash) -> Option<Attributed1> {
    let declared: Vec<Option<walk::Declarations>> = settled
        .iter()
        .map(|s| {
            s.artifact
                .as_ref()
                .and_then(|a| library.declarations(&s.policy_hash, a))
        })
        .collect();
    let input: Vec<Settled<Hash>> = settled
        .iter()
        .zip(&declared)
        .map(|(s, d)| Settled {
            order: s.order,
            payee: s.payee_key,
            declarations: d.clone(),
        })
        .collect();
    let at = settled.iter().position(|s| s.order == *order)?;
    let (_, result) = walk::attribute_all(&input).into_iter().nth(at)?;
    let Attributed::Authors(keys) = result else {
        return None;
    };
    let authors = keys
        .iter()
        .map(|k| settled.iter().find(|s| s.payee_key == *k).map(|s| s.seller))
        .collect::<Option<Vec<Address>>>()?;
    let excluded = declared.get(at)?.as_ref()?.excluded_names();
    Some(Attributed1 {
        authors,
        published: qed_deliveries::Attribution {
            order: hex(order),
            authors: keys.iter().map(|k| hex(k)).collect(),
            excluded,
        },
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const ARTIFACT: &[u8] = include_bytes!(
        "../../site/input/artifacts/ec7444f56a0c81b741210d072b10c80a412c09873041b1c83cbad35d09b869a8.bin"
    );
    const POLICY: &str = "0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e";

    fn read(order: u8, seller: u8) -> Read {
        Read {
            order: [order; 32],
            payee_key: keccak(&[[seller; 20], [0x33; 20]].concat()),
            seller: [seller; 20],
            policy_hash: unhex(POLICY).unwrap().try_into().unwrap(),
            artifact: Some(ARTIFACT.to_vec()),
        }
    }

    /// The bounty proof settled by A, then by B: B's attribution names A
    /// (by payee key to publish, by address to pay) and excludes `rfl` and
    /// `Nat.add_succ`. A settlement it cannot read makes later ones unknown.
    #[test]
    fn the_second_carrier_attributes_to_the_first_and_an_unread_one_stops_it() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../site/input");
        let library = Library::read(&dir).unwrap();
        let settled = vec![read(1, 0xa1), read(2, 0xb1)];
        let b = attribute(&settled, &library, &[2; 32]).unwrap();
        assert_eq!(b.authors, vec![[0xa1; 20]]);
        assert_eq!(b.published.authors, vec![hex(&settled[0].payee_key)]);
        assert_eq!(b.published.excluded, ["rfl", "Nat.add_succ"]);
        assert!(
            attribute(&settled, &library, &[1; 32])
                .unwrap()
                .authors
                .is_empty()
        );
        let mut gap = settled.clone();
        gap[0].artifact = None;
        assert_eq!(attribute(&gap, &library, &[2; 32]), None);
    }
}
