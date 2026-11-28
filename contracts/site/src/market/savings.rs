//! Proof-carrying savings over the market's events: which settlements
//! saved their buyer something, and who is owed a share. A mirror of the
//! event model of proofs/commerce/Savings.lean, whose examples and mutants
//! the tests below replay; the split itself is `qed_savings::split`.
//! docs/rfcs/qed-proof-carrying-savings-2026-11-28.md.
//!
//! A `Settled` event of a funded order joined to a post writes one record:
//! the post's price, the order's amount, the referrer bound when the order
//! was funded, the authors the provenance index names for the settled
//! artifact's declarations (less the seller), and the split. The settled
//! artifact's declarations then enter the index under the seller, unless
//! an earlier settlement carried them first.
use super::{Index, Market, ModelEvent, Phase, Word, word};
use qed_savings::{Rule, Split, authors_of, split};

/// One market event with its block and what the split reads from it: a
/// post's price, a funded order's checked referrer, a settlement's
/// declarations, and, for a mutant only, the authors a settlement claims.
#[derive(Clone, Debug)]
pub struct Entry {
    pub block: u64,
    pub event: ModelEvent,
    pub price: u128,
    pub referral: Option<String>,
    pub decls: Vec<Word>,
    pub claimed: Vec<Word>,
}

impl Entry {
    pub fn of(block: u64, event: ModelEvent) -> Entry {
        Entry {
            block,
            event,
            price: 0,
            referral: None,
            decls: Vec::new(),
            claimed: Vec::new(),
        }
    }
}

/// A settled order's saving and who is owed what (`Savings.Record`). The
/// buyer is the post's poster, the seller (and each author) a payee key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub digest: Word,
    pub post: Word,
    pub statement: Word,
    pub buyer: String,
    pub seller: Word,
    pub block: u64,
    pub cap: u128,
    pub amount: u128,
    pub referrer: Option<String>,
    pub authors: Vec<Word>,
    pub split: Split,
}

#[derive(Clone, Debug, Default)]
pub struct State {
    pub market: Market,
    pub prices: Vec<(Word, u128)>,
    pub refs: Vec<(Word, Option<String>)>,
    pub prov: Vec<(Word, Word)>,
    pub records: Vec<Record>,
}

impl State {
    fn price_of(&self, id: &Word) -> u128 {
        self.prices
            .iter()
            .find(|(k, _)| k == id)
            .map_or(0, |(_, p)| *p)
    }
    pub fn ref_of(&self, d: &Word) -> Option<String> {
        self.refs
            .iter()
            .find(|(k, _)| k == d)
            .and_then(|(_, r)| r.clone())
    }

    /// `Savings.candidate`.
    fn candidate(&self, r: &Rule, x: &Entry, d: &Word) -> Option<Record> {
        let o = self
            .market
            .orders
            .iter()
            .find(|o| o.digest == *d && (!r.phase || o.phase == Phase::Funded))?;
        let p = self.market.posts.iter().find(|p| Market::joins(p, o))?;
        let referrer = if r.bound_ref {
            self.ref_of(d)
        } else {
            x.referral.clone()
        };
        let authors = if r.from_artifact {
            authors_of(r, &self.prov, &x.decls, &o.payee)
        } else {
            x.claimed.clone()
        };
        let cap = self.price_of(&p.id);
        Some(Record {
            digest: *d,
            post: p.id,
            statement: p.statement,
            buyer: p.poster.clone(),
            seller: o.payee,
            block: x.block,
            cap,
            amount: o.amount,
            split: split(r, cap, o.amount, referrer.is_some(), authors.len() as u128),
            referrer,
            authors,
        })
    }

    /// `Savings.newRecord`.
    fn new_record(&self, r: &Rule, x: &Entry) -> Option<Record> {
        match &x.event {
            ModelEvent::Settled(d) => self.candidate(r, x, d),
            ModelEvent::Refunded(d) if !r.on_settle => self.candidate(r, x, d),
            _ => None,
        }
    }

    /// `Savings.step`.
    pub fn step(&mut self, r: &Rule, x: &Entry) {
        let new = self.new_record(r, x);
        match &x.event {
            ModelEvent::Posted(p) => self.prices.push((p.id, x.price)),
            ModelEvent::Funded { digest, .. }
                if !self.market.orders.iter().any(|o| o.digest == *digest) =>
            {
                self.refs.push((*digest, x.referral.clone()));
            }
            _ => {}
        }
        if let Some(m) = &new {
            self.prov.extend(x.decls.iter().map(|d| (*d, m.seller)));
        }
        self.market.apply(&x.event);
        self.records.extend(new);
    }
}

/// A referral the site input names for an order: the opening of its salt.
/// It counts only when `keccak256("NucleusReferralV1" ‖ referrer ‖ nonce)`
/// equals the salt of the order as decoded from its `fund`, `settle` or
/// `refund` call, so the input can add no referral the order did not bind.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReferralInput {
    pub order: String,
    pub referrer: String,
    pub nonce: String,
}

/// `referral::referral_salt` of the desk (`contracts/agents`), recomputed here.
pub fn referral_salt(referrer: &[u8], nonce: &[u8]) -> Word {
    let mut bytes = b"NucleusReferralV1".to_vec();
    bytes.extend_from_slice(referrer);
    bytes.extend_from_slice(nonce);
    alloy_primitives::keccak256(&bytes).0
}

/// The referrer an input referral opens for a funded order, if it does.
fn opened(l: &super::Logged, referrals: &[ReferralInput]) -> Option<String> {
    let super::Event::Funded { digest, terms, .. } = &l.event else {
        return None;
    };
    let salt = word(&terms.as_ref()?.salt);
    referrals.iter().find_map(|r| {
        let referrer = super::unhex(&r.referrer).ok().filter(|b| b.len() == 20)?;
        let nonce = super::unhex(&r.nonce).ok().filter(|b| b.len() == 32)?;
        (r.order.eq_ignore_ascii_case(digest) && referral_salt(&referrer, &nonce) == salt)
            .then(|| super::hx(&referrer))
    })
}

/// The index's events as entries: a post's price, and a funded order's
/// referrer when an input referral opens its salt. Settlements carry no
/// declarations here: this page does not walk artifacts, so its author
/// shares are 0 and their 20 % reads as the buyer's.
pub fn entries(index: &Index, referrals: &[ReferralInput]) -> Vec<Entry> {
    index
        .events
        .iter()
        .map(|l| Entry {
            price: match &l.event {
                super::Event::Posted { maximum_amount, .. } => maximum_amount.parse().unwrap_or(0),
                _ => 0,
            },
            referral: opened(l, referrals),
            ..Entry::of(l.block, super::model_event(l))
        })
        .collect()
}

/// The records the index admits.
pub fn decide(index: &Index, referrals: &[ReferralInput]) -> Vec<Record> {
    run(&Rule::MODEL, &entries(index, referrals)).records
}

/// `Savings.run` from the empty market.
pub fn run<'a>(r: &Rule, entries: impl IntoIterator<Item = &'a Entry>) -> State {
    let mut s = State::default();
    for x in entries {
        s.step(r, x);
    }
    s
}

#[cfg(test)]
#[path = "savings_tests.rs"]
mod tests;

// ---- Attribution, recomputed and checked against the desk's ----------------

/// What the site holds to recompute attribution: artifacts by keccak-256
/// (no 0x), policies by policy hash (`input/policies.json`), statements by
/// file name.
pub struct Library<'a> {
    pub artifacts: &'a [(String, Vec<u8>)],
    pub policies: &'a serde_json::Map<String, serde_json::Value>,
    pub statements: &'a [(String, Vec<u8>)],
    /// `published.json`'s entries: proof files public from a block.
    pub published: &'a [serde_json::Value],
}

impl Library<'_> {
    /// Each published proof file's keys, with the block it was public from.
    pub fn published_keys(&self) -> Vec<(u64, std::collections::HashSet<qed_savings::walk::Key>)> {
        let policy = |hash: &str| {
            let (p, file) = qed_savings::walk::policy_from_json(hash, self.policies.get(hash)?)?;
            let (_, bytes) = self.statements.iter().find(|(f, _)| *f == file)?;
            Some((p, bytes.clone()))
        };
        let artifact = |k: &str| {
            self.artifacts
                .iter()
                .find(|(h, _)| h.eq_ignore_ascii_case(k))
                .map(|(_, b)| b.clone())
        };
        qed_savings::walk::published_keys(self.published, &policy, &artifact)
    }
    /// The keys of every statement export the site holds: public.
    pub fn public(&self) -> std::collections::HashSet<qed_savings::walk::Key> {
        let held: Vec<(nucleus_proof_acceptance::Policy, Vec<u8>)> = self
            .policies
            .iter()
            .filter_map(|(hash, p)| {
                let (policy, file) = qed_savings::walk::policy_from_json(hash, p)?;
                let (_, bytes) = self.statements.iter().find(|(f, _)| *f == file)?;
                Some((policy, bytes.clone()))
            })
            .collect();
        qed_savings::walk::public_keys(&held)
    }
    fn policy(&self, hash: &str) -> Option<(nucleus_proof_acceptance::Policy, &[u8])> {
        let (policy, file) = qed_savings::walk::policy_from_json(hash, self.policies.get(hash)?)?;
        let (_, bytes) = self.statements.iter().find(|(f, _)| *f == file)?;
        Some((policy, bytes))
    }
}

/// Every settlement in chain order with its payee key and, when the site
/// holds its artifact, policy and statement, its declarations.
pub fn settlements(index: &Index, lib: &Library) -> Vec<qed_savings::walk::Settled<Word>> {
    let mut funded: Vec<(String, Word, Option<String>, Option<Word>)> = Vec::new();
    let mut out = Vec::new();
    for l in &index.events {
        match &l.event {
            super::Event::Funded {
                digest,
                payee_key,
                terms,
                buyer,
                asset,
                ..
            } => {
                // The buyer as a payee: its address and the order's asset.
                // An elided address cannot be compared, so it reads unknown.
                let buyer_key = match (super::unhex(buyer), super::unhex(asset)) {
                    (Ok(b), Ok(a)) if b.len() == 20 && a.len() == 20 => {
                        Some(super::payee_key(&b, &a))
                    }
                    _ => None,
                };
                funded.push((
                    digest.to_ascii_lowercase(),
                    word(payee_key),
                    terms.as_ref().map(|t| t.policy_hash.to_ascii_lowercase()),
                    buyer_key,
                ))
            }
            super::Event::Settled {
                digest,
                artifact_hash,
                ..
            } => {
                let Some((_, payee, policy, buyer)) =
                    funded.iter().find(|(d, ..)| d.eq_ignore_ascii_case(digest))
                else {
                    continue;
                };
                let artifact = lib
                    .artifacts
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(artifact_hash.trim_start_matches("0x")));
                let declarations = match (artifact, policy.as_deref().and_then(|p| lib.policy(p))) {
                    (Some((_, a)), Some((policy, statement))) => {
                        qed_savings::walk::declarations(&policy, statement, a).ok()
                    }
                    _ => None,
                };
                out.push(qed_savings::walk::Settled {
                    order: word(digest),
                    block: l.block,
                    payee: *payee,
                    buyer: *buyer,
                    declarations,
                });
            }
            _ => {}
        }
    }
    out
}

/// How a published attribution compares with the site's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Check {
    Agrees,
    /// The desk published other authors than the site recomputes.
    Mismatch {
        published: Vec<String>,
        recomputed: Vec<String>,
    },
    /// The site could not recompute it: this or an earlier artifact is not
    /// held, so the first carrier of a key is not known.
    NotRecomputed(String),
}

/// Check each published attribution against the site's recomputation.
pub fn check(
    index: &Index,
    lib: &Library,
    published: &[qed_deliveries::Attribution],
) -> Vec<(String, Check)> {
    let recomputed = qed_savings::walk::attribute_all(
        &settlements(index, lib),
        &lib.public(),
        &lib.published_keys(),
    );
    let sorted = |v: Vec<String>| {
        let mut v: Vec<String> = v.into_iter().map(|s| s.to_ascii_lowercase()).collect();
        v.sort();
        v
    };
    published
        .iter()
        .map(|a| {
            let order = word(&a.order);
            let c = match recomputed.iter().find(|(o, _)| *o == order) {
                None => Check::NotRecomputed("no settlement of this order in the index".into()),
                Some((_, qed_savings::walk::Attributed::Unknown(first))) => Check::NotRecomputed(
                    format!("the artifact of order {} is not held", super::hx(first)),
                ),
                Some((_, qed_savings::walk::Attributed::Authors(v))) => {
                    let recomputed = sorted(v.iter().map(|w| super::hx(w)).collect());
                    let published = sorted(a.authors.clone());
                    if recomputed == published {
                        Check::Agrees
                    } else {
                        Check::Mismatch {
                            published,
                            recomputed,
                        }
                    }
                }
            };
            (a.order.to_ascii_lowercase(), c)
        })
        .collect()
}
