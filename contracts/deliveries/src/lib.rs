//! The bounty buyer's record of delivery attempts, its summary, and the
//! summary signed with the buyer's possession key.
//!
//! A *delivery attempt* is what a seller sends the buyer's desk off chain: an
//! offer for a posted task (`POST /task/<id>/offer`) or a request to review
//! one without signing (`POST /task/<id>/review`). A refused attempt leaves
//! nothing on chain, so this record is the only trace of it.
//!
//! **The record** is append-only JSON lines. The first line opens it:
//!
//! ```text
//! {"record":"qed-deliveries/1","opened":1794700000,"buyer":"0x133c…"}
//! {"at":1794700100,"route":"offer","task":"0x28da…","outcome":"refused","reason":"over-limit","sellerKey":"0x…","party":"outside"}
//! ```
//!
//! - `outcome` is `accepted` (an authorization was signed), `reviewed` (a
//!   review passed; nothing signed) or `refused`, and only `refused` carries
//!   a `reason`, one of [`Reason`].
//! - `sellerKey` is the RFC 7638 thumbprint of the key the seller proved
//!   possession of (DPoP), or null when no proof was accepted.
//! - `party` says whether the address the offer named as its seller is in the
//!   buyer's list of the authors' own wallets (`ours`), is not (`outside`),
//!   or could not be read from the offer (`unnamed`). **The address itself is
//!   not recorded**: an offer's seller address is public only once an order
//!   is funded, and then the vault's `Funded` log carries it.
//!
//! **The summary** counts the record: outcomes, refusals by reason, first and
//! last time, distinct sellers (by key), and each seller not known to be the
//! authors' in the order it first appeared. A line that cannot be read is
//! counted as unreadable, never as nothing.
//!
//! **The signature** is a JWS (RFC 7515, ES256) over the summary, with the
//! public key in its header. A reader checks that key's RFC 7638 thumbprint
//! against the buyer's key binding, which every task the buyer posts carries
//! on chain (`buyerKeyBinding`). docs/rfcs/qed-deliveries-2026-11-14.md.
use base64::Engine as _;
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer as _, Verifier as _},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, HashMap};

pub const RECORD_FORMAT: &str = "qed-deliveries/1";
pub const SUMMARY_FORMAT: &str = "qed-deliveries-summary/1";
/// The JWS `typ` of a signed summary, so it is never taken for a DPoP proof
/// or an Agent Card signature made with the same key.
pub const JWS_TYP: &str = "qed-deliveries+jws";
/// Past this many lines the desk stops appending and counts what it could
/// not write as `unrecorded`: the record cannot fill the buyer's disk.
pub const MAXIMUM_LINES: usize = 100_000;

const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub type Hash = [u8; 32];

/// Which desk request the attempt was.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Route {
    Offer,
    Review,
}

/// Why the desk refused an attempt. Every refusal the desk can give maps to
/// exactly one of these (`contracts/agents/src/desk.rs`, `reason_of`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    /// No DPoP proof, or one the desk refused (wrong key, replay, expired,
    /// wrong method, URI or node).
    Unauthenticated,
    /// No task with this ID was posted from this desk.
    UnknownTask,
    /// The task is no longer open: signed for, withdrawn, or over.
    NotOpen,
    /// No `PAYMENT-REQUIRED` header, or one that does not decode to exactly
    /// one offer of the vault's scheme with matching requirements.
    Malformed,
    /// The offered order names another buyer wallet, token, policy (and so
    /// statement) or context than the post.
    TermsMismatch,
    /// A verifier or proof program the post did not name.
    UntrustedJudge,
    /// The price is above the post's cap.
    OverLimit,
    /// A funding or delivery deadline outside the post's.
    Deadline,
    /// A base library the buyer does not accept.
    UnsupportedBase,
    /// An order the vault would not admit.
    Inadmissible,
    /// The offer passed review, and the signature could not be written to
    /// the buyer's journal first, so none was released.
    NotRecorded,
    /// The offer was held in the offer window, and a lower offer (or an
    /// equal one that arrived first) was signed for at the close.
    Outbid,
    /// The offer named a referrer whose preimage does not hash to the
    /// order's `salt`.
    BadReferral,
}

impl Reason {
    pub const ALL: [Reason; 13] = [
        Self::Unauthenticated,
        Self::UnknownTask,
        Self::NotOpen,
        Self::Malformed,
        Self::TermsMismatch,
        Self::UntrustedJudge,
        Self::OverLimit,
        Self::Deadline,
        Self::UnsupportedBase,
        Self::Inadmissible,
        Self::NotRecorded,
        Self::Outbid,
        Self::BadReferral,
    ];
    /// A short phrase for a page.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Unauthenticated => "no valid proof of possession",
            Self::UnknownTask => "no such task",
            Self::NotOpen => "task no longer open",
            Self::Malformed => "malformed offer",
            Self::TermsMismatch => "another statement, policy, token or buyer",
            Self::UntrustedJudge => "another verifier or program",
            Self::OverLimit => "over the price cap",
            Self::Deadline => "deadline outside the post's",
            Self::UnsupportedBase => "base library not accepted",
            Self::Inadmissible => "order the vault would refuse",
            Self::NotRecorded => "could not be recorded, so not signed",
            Self::Outbid => "a lower offer won the window",
            Self::BadReferral => "referral does not match the order's salt",
        }
    }
}

/// How the desk answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// An authorization was signed for this seller's order.
    Accepted,
    /// A review passed; nothing was signed.
    Reviewed,
    Refused(Reason),
}

/// Whether the address an offer named as its seller is one of the authors'.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Party {
    Ours,
    Outside,
    /// No seller address could be read from the attempt.
    Unnamed,
}

/// One line of the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub at: u64,
    pub route: Route,
    /// The task the path named, when it named a well-formed ID.
    pub task: Option<Hash>,
    pub outcome: Outcome,
    /// RFC 7638 thumbprint of the key the seller proved possession of.
    pub seller_key: Option<Hash>,
    pub party: Party,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum OutcomeName {
    Accepted,
    Reviewed,
    Refused,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Line {
    at: u64,
    route: Route,
    task: Option<String>,
    outcome: OutcomeName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<Reason>,
    seller_key: Option<String>,
    party: Party,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    record: String,
    opened: u64,
    buyer: String,
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn unhex32(text: &str) -> Result<Hash, String> {
    let digits = text.strip_prefix("0x").ok_or("0x expected")?;
    if digits.len() != 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("32 bytes of hex expected".into());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in digits.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).map_err(|e| e.to_string())?, 16)
            .map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn is_address(text: &str) -> bool {
    text.len() == 42
        && text.starts_with("0x")
        && text[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The record's first line.
pub fn header_line(opened: u64, buyer: &str) -> String {
    serde_json::to_string(&Header {
        record: RECORD_FORMAT.into(),
        opened,
        buyer: buyer.to_ascii_lowercase(),
    })
    .expect("a header serializes")
}

impl Attempt {
    pub fn line(&self) -> String {
        let (outcome, reason) = match self.outcome {
            Outcome::Accepted => (OutcomeName::Accepted, None),
            Outcome::Reviewed => (OutcomeName::Reviewed, None),
            Outcome::Refused(reason) => (OutcomeName::Refused, Some(reason)),
        };
        serde_json::to_string(&Line {
            at: self.at,
            route: self.route,
            task: self.task.as_ref().map(|t| hex(t)),
            outcome,
            reason,
            seller_key: self.seller_key.as_ref().map(|k| hex(k)),
            party: self.party,
        })
        .expect("a line serializes")
    }

    /// One line back, or why it cannot be read. Nothing is guessed: an
    /// unknown field, outcome or reason is unreadable.
    pub fn parse(text: &str) -> Result<Self, String> {
        let line: Line = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let outcome = match (line.outcome, line.reason) {
            (OutcomeName::Accepted, None) => Outcome::Accepted,
            (OutcomeName::Reviewed, None) => Outcome::Reviewed,
            (OutcomeName::Refused, Some(reason)) => Outcome::Refused(reason),
            (OutcomeName::Refused, None) => return Err("a refusal without a reason".into()),
            (_, Some(_)) => return Err("a reason on an attempt that was not refused".into()),
        };
        Ok(Self {
            at: line.at,
            route: line.route,
            task: line.task.as_deref().map(unhex32).transpose()?,
            outcome,
            seller_key: line.seller_key.as_deref().map(unhex32).transpose()?,
            party: line.party,
        })
    }
}

/// Counts of distinct sellers, by the key each proved possession of.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Sellers {
    pub distinct: u64,
    /// Every attempt by the key named one of the authors' wallets.
    pub ours: u64,
    /// At least one attempt by the key did not.
    pub unknown: u64,
}

/// A seller not known to be the authors', at its first attempt that was not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UnknownSeller {
    /// 1, 2, …: the order in which unknown sellers appeared. Stable: the
    /// record is append-only, so a seller's number never changes.
    pub n: u64,
    pub first_at: u64,
    pub route: Route,
    /// `accepted`, `reviewed` or `refused`.
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
}

/// What the record says, as the desk signs it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Summary {
    pub format: String,
    /// The buyer's wallet: the poster of the tasks these attempts were for.
    pub buyer: String,
    /// When the record was opened.
    pub opened: u64,
    pub signed_at: u64,
    /// Lines read as attempts.
    pub records: u64,
    /// Lines that could not be read. Shown, never folded into zero.
    pub unreadable: u64,
    /// Attempts the desk saw and could not write (record full, write
    /// failed). Counted in memory since the desk started.
    pub unrecorded: u64,
    pub first: Option<u64>,
    pub last: Option<u64>,
    pub accepted: u64,
    pub reviewed: u64,
    pub refused: BTreeMap<Reason, u64>,
    pub sellers: Sellers,
    pub unknown_sellers: Vec<UnknownSeller>,
}

impl Summary {
    pub fn refused_total(&self) -> u64 {
        self.refused.values().sum()
    }
}

fn outcome_name(outcome: Outcome) -> (&'static str, Option<Reason>) {
    match outcome {
        Outcome::Accepted => ("accepted", None),
        Outcome::Reviewed => ("reviewed", None),
        Outcome::Refused(reason) => ("refused", Some(reason)),
    }
}

/// Summarize a record's text. Errors only when the first line is not the
/// record's header (then nothing in it can be attributed to this buyer).
pub fn summarize(text: &str, unrecorded: u64, signed_at: u64) -> Result<Summary, String> {
    let mut lines = text.lines();
    let header: Header = serde_json::from_str(lines.next().ok_or("the record is empty")?)
        .map_err(|e| format!("the record's first line is not its header: {e}"))?;
    if header.record != RECORD_FORMAT || !is_address(&header.buyer) {
        return Err(format!(
            "the record's header names {:?} for {:?}",
            header.record, header.buyer
        ));
    }
    let mut s = Summary {
        format: SUMMARY_FORMAT.into(),
        buyer: header.buyer,
        opened: header.opened,
        signed_at,
        records: 0,
        unreadable: 0,
        unrecorded,
        first: None,
        last: None,
        accepted: 0,
        reviewed: 0,
        refused: BTreeMap::new(),
        sellers: Sellers::default(),
        unknown_sellers: Vec::new(),
    };
    // Per key: whether every attempt so far named one of ours.
    let mut keys: HashMap<Hash, bool> = HashMap::new();
    for text in lines {
        let attempt = match Attempt::parse(text) {
            Ok(a) => a,
            Err(_) => {
                s.unreadable += 1;
                continue;
            }
        };
        s.records += 1;
        s.first = Some(s.first.map_or(attempt.at, |f| f.min(attempt.at)));
        s.last = Some(s.last.map_or(attempt.at, |l| l.max(attempt.at)));
        match attempt.outcome {
            Outcome::Accepted => s.accepted += 1,
            Outcome::Reviewed => s.reviewed += 1,
            Outcome::Refused(reason) => *s.refused.entry(reason).or_default() += 1,
        }
        let Some(key) = attempt.seller_key else {
            continue;
        };
        let ours_now = attempt.party == Party::Ours;
        let was_ours = keys.get(&key).copied();
        // A key becomes unknown at its first attempt that was not ours.
        if !ours_now && was_ours != Some(false) {
            let (outcome, reason) = outcome_name(attempt.outcome);
            s.unknown_sellers.push(UnknownSeller {
                n: s.unknown_sellers.len() as u64 + 1,
                first_at: attempt.at,
                route: attempt.route,
                outcome: outcome.into(),
                reason,
            });
        }
        keys.insert(key, was_ours.unwrap_or(true) && ours_now);
    }
    s.sellers = Sellers {
        distinct: keys.len() as u64,
        ours: keys.values().filter(|ours| **ours).count() as u64,
        unknown: keys.values().filter(|ours| !**ours).count() as u64,
    };
    Ok(s)
}

/// RFC 7638 thumbprint of a P-256 public key.
pub fn thumbprint(x: &[u8; 32], y: &[u8; 32]) -> Hash {
    let jwk = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        B64URL.encode(x),
        B64URL.encode(y)
    );
    Sha256::digest(jwk.as_bytes()).into()
}

fn coordinates(key: &VerifyingKey) -> ([u8; 32], [u8; 32]) {
    let point = key.to_sec1_point(false);
    let bytes = point.as_bytes();
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&bytes[1..33]);
    y.copy_from_slice(&bytes[33..65]);
    (x, y)
}

/// The summary as a compact JWS signed with `key`.
pub fn sign(summary: &Summary, key: &SigningKey) -> String {
    let (x, y) = coordinates(key.verifying_key());
    let header = serde_json::json!({
        "alg": "ES256", "typ": JWS_TYP,
        "jwk": {"kty": "EC", "crv": "P-256", "x": B64URL.encode(x), "y": B64URL.encode(y)},
    });
    let signing = format!(
        "{}.{}",
        B64URL.encode(serde_json::to_vec(&header).expect("header")),
        B64URL.encode(serde_json::to_vec(summary).expect("summary"))
    );
    let signature: Signature = key.sign(signing.as_bytes());
    format!("{signing}.{}", B64URL.encode(signature.to_bytes()))
}

/// Why a signed summary could not be read. Each is shown as "could not
/// read", never as a count of zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unreadable {
    /// Not three base64url parts of JSON, or not this format.
    Malformed(String),
    /// Signed by a key whose thumbprint is not the buyer's binding.
    AnotherKey { thumbprint: Hash },
    /// The signature does not verify.
    Signature,
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "not a signed summary: {why}"),
            Self::AnotherKey { thumbprint } => {
                write!(f, "signed by key {}, not the buyer's", hex(thumbprint))
            }
            Self::Signature => write!(f, "the signature does not verify"),
        }
    }
}

/// Check a signed summary against the buyer's key binding and return it.
pub fn verify(jws: &str, binding: &Hash) -> Result<Summary, Unreadable> {
    let malformed = |why: &str| Unreadable::Malformed(why.to_owned());
    let mut parts = jws.trim().split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(malformed("not three parts"));
    };
    let decode = |part: &str| B64URL.decode(part).map_err(|e| malformed(&e.to_string()));
    let header_json: serde_json::Value =
        serde_json::from_slice(&decode(header)?).map_err(|e| malformed(&e.to_string()))?;
    if header_json["alg"] != "ES256" || header_json["typ"] != JWS_TYP {
        return Err(malformed("not an ES256 summary signature"));
    }
    let jwk = &header_json["jwk"];
    if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
        return Err(malformed("not a P-256 key"));
    }
    let coordinate = |name: &str| -> Result<[u8; 32], Unreadable> {
        decode(
            jwk[name]
                .as_str()
                .ok_or_else(|| malformed("key coordinate"))?,
        )?
        .try_into()
        .map_err(|_| malformed("key coordinate length"))
    };
    let (x, y) = (coordinate("x")?, coordinate("y")?);
    let print = thumbprint(&x, &y);
    if print != *binding {
        return Err(Unreadable::AnotherKey { thumbprint: print });
    }
    let mut point = [4u8; 65];
    point[1..33].copy_from_slice(&x);
    point[33..].copy_from_slice(&y);
    let key = VerifyingKey::from_sec1_bytes(&point).map_err(|_| malformed("key"))?;
    let signature =
        Signature::from_slice(&decode(signature)?).map_err(|_| malformed("signature"))?;
    key.verify(format!("{header}.{payload}").as_bytes(), &signature)
        .map_err(|_| Unreadable::Signature)?;
    let summary: Summary =
        serde_json::from_slice(&decode(payload)?).map_err(|e| malformed(&e.to_string()))?;
    if summary.format != SUMMARY_FORMAT {
        return Err(malformed("another summary format"));
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUYER: &str = "0x00000000000000000000000000000000000000b0";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }
    fn binding(key: &SigningKey) -> Hash {
        let (x, y) = coordinates(key.verifying_key());
        thumbprint(&x, &y)
    }
    fn attempt(at: u64, outcome: Outcome, seller: Option<u8>, party: Party) -> Attempt {
        Attempt {
            at,
            route: Route::Offer,
            task: Some([0x28; 32]),
            outcome,
            seller_key: seller.map(|s| [s; 32]),
            party,
        }
    }
    fn record(attempts: &[Attempt]) -> String {
        let mut text = header_line(1_000, BUYER);
        text.push('\n');
        for a in attempts {
            text.push_str(&a.line());
            text.push('\n');
        }
        text
    }

    #[test]
    fn every_line_reads_back_as_it_was_written() {
        for reason in Reason::ALL {
            for route in [Route::Offer, Route::Review] {
                for party in [Party::Ours, Party::Outside, Party::Unnamed] {
                    let a = Attempt {
                        at: 7,
                        route,
                        task: None,
                        outcome: Outcome::Refused(reason),
                        seller_key: Some([3; 32]),
                        party,
                    };
                    assert_eq!(Attempt::parse(&a.line()).unwrap(), a);
                }
            }
        }
        let accepted = attempt(9, Outcome::Accepted, None, Party::Unnamed);
        assert_eq!(Attempt::parse(&accepted.line()).unwrap(), accepted);
        // The reason's name on the wire is typed: over-limit, not prose.
        let over = attempt(
            9,
            Outcome::Refused(Reason::OverLimit),
            Some(1),
            Party::Outside,
        );
        assert!(over.line().contains(r#""reason":"over-limit""#));
    }

    #[test]
    fn an_unknown_reason_or_field_is_unreadable_never_a_guess() {
        let good = attempt(
            9,
            Outcome::Refused(Reason::OverLimit),
            Some(1),
            Party::Outside,
        )
        .line();
        for bad in [
            good.replace("over-limit", "too-expensive"),
            good.replace(
                r#""party":"outside""#,
                r#""party":"outside","seller":"0x01""#,
            ),
            good.replace(r#","reason":"over-limit""#, ""),
            good.replace(r#""outcome":"refused""#, r#""outcome":"accepted""#),
            "not json".into(),
        ] {
            assert!(Attempt::parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_summary_counts_outcomes_reasons_times_and_sellers() {
        let text = record(&[
            attempt(
                1_010,
                Outcome::Refused(Reason::OverLimit),
                Some(1),
                Party::Outside,
            ),
            attempt(1_020, Outcome::Reviewed, Some(2), Party::Ours),
            attempt(1_030, Outcome::Accepted, Some(2), Party::Ours),
            attempt(
                1_040,
                Outcome::Refused(Reason::Unauthenticated),
                None,
                Party::Unnamed,
            ),
            attempt(
                1_050,
                Outcome::Refused(Reason::NotOpen),
                Some(1),
                Party::Outside,
            ),
        ]);
        let s = summarize(&text, 0, 2_000).unwrap();
        assert_eq!((s.records, s.unreadable, s.unrecorded), (5, 0, 0));
        assert_eq!((s.first, s.last), (Some(1_010), Some(1_050)));
        assert_eq!((s.accepted, s.reviewed, s.refused_total()), (1, 1, 3));
        assert_eq!(s.refused[&Reason::OverLimit], 1);
        assert_eq!(s.refused[&Reason::Unauthenticated], 1);
        assert_eq!(s.refused.get(&Reason::Malformed), None);
        assert_eq!(
            s.sellers,
            Sellers {
                distinct: 2,
                ours: 1,
                unknown: 1
            }
        );
        assert_eq!(s.unknown_sellers.len(), 1);
        let first = &s.unknown_sellers[0];
        assert_eq!((first.n, first.first_at), (1, 1_010));
        assert_eq!(
            (first.outcome.as_str(), first.reason),
            ("refused", Some(Reason::OverLimit))
        );
        assert_eq!((s.opened, s.buyer.as_str()), (1_000, BUYER));
    }

    #[test]
    fn a_seller_numbered_once_keeps_its_number_as_the_record_grows() {
        let early = vec![
            attempt(
                1_010,
                Outcome::Refused(Reason::OverLimit),
                Some(1),
                Party::Outside,
            ),
            attempt(1_020, Outcome::Reviewed, Some(2), Party::Ours),
        ];
        let mut later = early.clone();
        // The authors' key names an outside wallet: it is now unknown, second.
        later.push(attempt(
            1_030,
            Outcome::Refused(Reason::Malformed),
            Some(2),
            Party::Unnamed,
        ));
        later.push(attempt(
            1_040,
            Outcome::Refused(Reason::Malformed),
            Some(1),
            Party::Unnamed,
        ));
        let a = summarize(&record(&early), 0, 2_000).unwrap();
        let b = summarize(&record(&later), 0, 2_000).unwrap();
        assert_eq!(
            b.unknown_sellers[..a.unknown_sellers.len()],
            a.unknown_sellers[..]
        );
        assert_eq!(b.unknown_sellers.len(), 2);
        assert_eq!(
            (b.unknown_sellers[1].n, b.unknown_sellers[1].first_at),
            (2, 1_030)
        );
        assert_eq!((b.sellers.ours, b.sellers.unknown), (0, 2));
    }

    #[test]
    fn an_unreadable_line_is_counted_and_an_empty_record_says_nothing_happened() {
        let mut text = record(&[attempt(
            1_010,
            Outcome::Refused(Reason::OverLimit),
            Some(1),
            Party::Outside,
        )]);
        text.push_str("{\"at\":5,\"outcome\":\"mystery\"}\n");
        let s = summarize(&text, 3, 2_000).unwrap();
        assert_eq!((s.records, s.unreadable, s.unrecorded), (1, 1, 3));
        let empty = summarize(&record(&[]), 0, 2_000).unwrap();
        assert_eq!((empty.records, empty.first, empty.last), (0, None, None));
        // Without the header nothing can be attributed.
        assert!(summarize("", 0, 1).is_err());
        assert!(
            summarize(
                &attempt(1, Outcome::Accepted, None, Party::Ours).line(),
                0,
                1
            )
            .is_err()
        );
    }

    #[test]
    fn a_signed_summary_verifies_only_under_the_buyers_binding() {
        let s = summarize(
            &record(&[attempt(
                1_010,
                Outcome::Refused(Reason::Deadline),
                Some(1),
                Party::Outside,
            )]),
            0,
            2_000,
        )
        .unwrap();
        let buyer = key(5);
        let jws = sign(&s, &buyer);
        assert_eq!(verify(&jws, &binding(&buyer)).unwrap(), s);
        // Another key, even a valid signature by it.
        let other = sign(&s, &key(6));
        assert!(matches!(
            verify(&other, &binding(&buyer)),
            Err(Unreadable::AnotherKey { .. })
        ));
        // One count changed after signing.
        let mut parts: Vec<String> = jws.split('.').map(str::to_owned).collect();
        let mut changed = s.clone();
        changed.records = 0;
        parts[1] = B64URL.encode(serde_json::to_vec(&changed).unwrap());
        assert_eq!(
            verify(&parts.join("."), &binding(&buyer)),
            Err(Unreadable::Signature)
        );
        assert!(matches!(
            verify("a.b", &binding(&buyer)),
            Err(Unreadable::Malformed(_))
        ));
    }
}
