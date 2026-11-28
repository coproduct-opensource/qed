//! The desk's side of proof-carrying savings attribution
//! (docs/rfcs/qed-proof-carrying-savings-2026-11-28.md): who authored the
//! lemmas a settled order's proof reused, computed with the code the site
//! checks it with (`qed_savings::walk`).
//!
//! The desk reads every `Settled` of the vaults in `NUCLEUS_SAVINGS_VAULTS`
//! (the site's indexed set) in chain order, takes each artifact and order from its
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
/// The vaults the desk reads, `ADDRESS:FORM:FROM_BLOCK` comma-separated
/// (`FORM` is `second` or `third`): the same set as the site's market input
/// (`mainnet.status.vaults`), which `install-ladder` checks before it sets
/// the library.
pub const VAULTS_VARIABLE: &str = "NUCLEUS_SAVINGS_VAULTS";

/// One vault the desk reads settlements from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    pub vault: Address,
    pub form: vault::Form,
    pub from: u64,
}

/// `NUCLEUS_SAVINGS_VAULTS`, parsed.
pub fn parse_scope(text: &str) -> Res<Vec<Scope>> {
    text.split(',')
        .filter(|p| !p.trim().is_empty())
        .map(|part| {
            let mut it = part.trim().split(':');
            let (Some(a), Some(f), Some(b), None) = (it.next(), it.next(), it.next(), it.next())
            else {
                return Err(
                    format!("{VAULTS_VARIABLE}: {part:?} is not ADDRESS:FORM:FROM_BLOCK").into(),
                );
            };
            let vault: Address = unhex(a)?
                .try_into()
                .map_err(|_| format!("{VAULTS_VARIABLE}: {a} is not an address"))?;
            let form = match f {
                "second" => vault::Form::Second,
                "third" => vault::Form::Third,
                other => return Err(format!("{VAULTS_VARIABLE}: unknown form {other}").into()),
            };
            Ok(Scope {
                vault,
                form,
                from: b.parse()?,
            })
        })
        .collect()
}

/// The policies and statements a desk attributes with.
pub struct Library {
    pub policies: serde_json::Map<String, Value>,
    pub statements: Vec<(String, Vec<u8>)>,
    /// `published.json` (proof files public from a block) with the
    /// artifacts it names, from `artifacts/<keccak>.bin`.
    pub published: Vec<Value>,
    pub artifacts: Vec<(String, Vec<u8>)>,
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
        let published: Vec<Value> = match fs::read(dir.join("published.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(_) => Vec::new(),
        };
        let mut artifacts = Vec::new();
        for e in &published {
            if let Some(k) = e["artifact"].as_str() {
                let k = k.trim_start_matches("0x").to_ascii_lowercase();
                if let Ok(bytes) = fs::read(dir.join("artifacts").join(format!("{k}.bin"))) {
                    artifacts.push((k, bytes));
                }
            }
        }
        Ok(Self {
            policies,
            statements,
            published,
            artifacts,
        })
    }
    /// Each published proof file's keys, with the block it was public from.
    pub fn published_keys(&self) -> Vec<(u64, std::collections::HashSet<walk::Key>)> {
        let policy = |hash: &str| {
            let (p, file) = walk::policy_from_json(hash, self.policies.get(hash)?)?;
            let (_, bytes) = self.statements.iter().find(|(f, _)| *f == file)?;
            Some((p, bytes.clone()))
        };
        let artifact = |k: &str| {
            self.artifacts
                .iter()
                .find(|(h, _)| h.eq_ignore_ascii_case(k))
                .map(|(_, b)| b.clone())
        };
        walk::published_keys(&self.published, &policy, &artifact)
    }
    /// The keys of every statement export the library holds: public.
    pub fn public(&self) -> std::collections::HashSet<walk::Key> {
        let held: Vec<_> = self
            .policies
            .iter()
            .filter_map(|(hash, p)| {
                let (policy, file) = walk::policy_from_json(hash, p)?;
                let (_, bytes) = self.statements.iter().find(|(f, _)| *f == file)?;
                Some((policy, bytes.clone()))
            })
            .collect();
        walk::public_keys(&held)
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
    /// The block it settled in, and its log's index there.
    pub block: u64,
    pub log_index: u64,
    pub payee_key: Hash,
    pub seller: Address,
    /// The paying buyer as a payee (its address and the order's asset).
    pub buyer_key: Option<Hash>,
    pub policy_hash: Hash,
    pub artifact: Option<Vec<u8>>,
}

/// Every scoped vault's settlements, merged in chain order (block, then log
/// index), with what their `settle` calldata carries.
pub fn read_scope(chain: &Chain, scope: &[Scope]) -> Res<Vec<Read>> {
    let mut all = Vec::new();
    for s in scope {
        all.extend(read_settlements(chain, s.vault, s.form, s.from)?);
    }
    all.sort_by_key(|r| (r.block, r.log_index));
    Ok(all)
}

/// One vault's settlements from `from`, in chain order, with what their
/// `settle` calldata carries (a call that is not a direct `settle` reads as
/// unknown).
pub fn read_settlements(
    chain: &Chain,
    vault: Address,
    form: vault::Form,
    from: u64,
) -> Res<Vec<Read>> {
    let latest = u64::from_str_radix(
        chain
            .rpc("eth_blockNumber", json!([]))?
            .as_str()
            .ok_or("block number expected")?
            .trim_start_matches("0x"),
        16,
    )?;
    let topic = crate::world::settled_topic(form);
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
        let block = log["blockNumber"]
            .as_str()
            .and_then(|b| u64::from_str_radix(b.trim_start_matches("0x"), 16).ok())
            .ok_or("a Settled log without its block")?;
        let log_index = log["logIndex"]
            .as_str()
            .and_then(|b| u64::from_str_radix(b.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        let tx = log["transactionHash"]
            .as_str()
            .ok_or("no transaction hash")?;
        let sent = chain.rpc("eth_getTransactionByHash", json!([tx]))?;
        let input = unhex(sent["input"].as_str().unwrap_or("0x"))?;
        match crate::world::settled_order_in(form, &input) {
            Some((buyer, seller, asset, policy_hash, artifact)) => {
                let key = |who: &Address| keccak(&[who.as_slice(), asset.as_slice()].concat());
                out.push(Read {
                    order,
                    block,
                    log_index,
                    payee_key: key(&seller),
                    buyer_key: Some(key(&buyer)),
                    seller,
                    policy_hash,
                    artifact: Some(artifact),
                });
            }
            None => out.push(Read {
                order,
                block,
                log_index,
                payee_key: [0; 32],
                buyer_key: None,
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
            block: s.block,
            payee: s.payee_key,
            buyer: s.buyer_key,
            declarations: d.clone(),
        })
        .collect();
    let at = settled.iter().position(|s| s.order == *order)?;
    let (_, result) = walk::attribute_all(&input, &library.public(), &library.published_keys())
        .into_iter()
        .nth(at)?;
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
            block: u64::from(order),
            log_index: 0,
            payee_key: keccak(&[[seller; 20], [0x33; 20]].concat()),
            buyer_key: Some(keccak(&[[0xbb; 20], [0x33; 20]].concat())),
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

#[cfg(test)]
mod agreement {
    //! The desk's attribution on the site's Base fixture, read as the desk
    //! reads settlements (order, block, payee and buyer keys, policy hash,
    //! artifact), against the same numbers the site's test asserts
    //! (`contracts/site/tests/market.rs`,
    //! `on_base_a_proof_published_before_its_first_settlement_earns_no_one_a_share`).
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    const FIXTURE: &str = include_str!("../../site/tests/fixtures/market-base.json");
    const FIRST: &str = "0xee7156cc71d1d5ae5309304c7ff3c9f1883bfd9832fda897b2f199c958ac8b2b";

    fn word(v: &Value) -> Option<Hash> {
        unhex(v.as_str()?).ok()?.try_into().ok()
    }
    fn reads(dir: &std::path::Path) -> Vec<Read> {
        let index: Value = serde_json::from_str(FIXTURE).unwrap();
        let events = index["events"].as_array().unwrap();
        let mut out = Vec::new();
        for e in events {
            if e["event"] != "Settled" {
                continue;
            }
            let funded = events
                .iter()
                .find(|f| f["event"] == "Funded" && f["digest"] == e["digest"])
                .unwrap();
            let address = |v: &Value| -> Option<Vec<u8>> {
                unhex(v.as_str()?).ok().filter(|b| b.len() == 20)
            };
            let buyer_key = match (address(&funded["buyer"]), address(&funded["asset"])) {
                (Some(b), Some(a)) => Some(keccak(&[b, a].concat())),
                _ => None,
            };
            let k = e["artifactHash"].as_str().unwrap().trim_start_matches("0x");
            out.push(Read {
                order: word(&e["digest"]).unwrap(),
                block: e["block"].as_u64().unwrap(),
                log_index: e["logIndex"].as_u64().unwrap(),
                payee_key: word(&funded["payeeKey"]).unwrap(),
                buyer_key,
                seller: [0; 20],
                policy_hash: word(&funded["terms"]["policyHash"]).unwrap_or([0; 32]),
                artifact: fs::read(dir.join("artifacts").join(format!("{k}.bin"))).ok(),
            });
        }
        out
    }

    #[test]
    fn the_desk_and_the_site_agree_on_the_base_fixture() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../site/input");
        let settled = reads(&dir);
        assert_eq!(settled.len(), 11);
        let mut library = Library::read(&dir).unwrap();
        let tally = |library: &Library| {
            let (mut unknown, mut first, mut nobody) = (0, 0, 0);
            for s in &settled {
                match attribute(&settled, library, &s.order) {
                    None => unknown += 1,
                    Some(a) if a.published.authors == [FIRST] => first += 1,
                    Some(a) if a.published.authors.is_empty() => nobody += 1,
                    Some(a) => panic!("{a:?}"),
                }
            }
            (unknown, first, nobody)
        };
        assert_eq!(tally(&library), (2, 9, 0));
        library.published = vec![json!({
            "artifact": "ec7444f56a0c81b741210d072b10c80a412c09873041b1c83cbad35d09b869a8",
            "policy": "0x91370b722911e754ab3a6673a697d1275ff6ad9fee7ec865ddac1d12757d625e",
            "fromBlock": 57_024_789u64,
        })];
        library.artifacts = vec![(
            "ec7444f56a0c81b741210d072b10c80a412c09873041b1c83cbad35d09b869a8".into(),
            fs::read(dir.join(
                "artifacts/ec7444f56a0c81b741210d072b10c80a412c09873041b1c83cbad35d09b869a8.bin",
            ))
            .unwrap(),
        )];
        assert_eq!(tally(&library), (2, 0, 9));
    }

    #[test]
    fn a_scope_reads_address_form_and_block() {
        let s = parse_scope(
            "0x952c31aa208dd129059f6065a26b57c930c6ab3c:second:56772992,0x8917c501755f966a5b5f20d6608e297e7066f13b:third:57100000",
        )
        .unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!((s[0].form, s[1].from), (vault::Form::Second, 57_100_000));
        assert!(parse_scope("0x12:third:1").is_err());
        assert!(parse_scope("0x952c31aa208dd129059f6065a26b57c930c6ab3c:first:1").is_err());
    }
}
