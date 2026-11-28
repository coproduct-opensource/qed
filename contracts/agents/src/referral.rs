//! A referrer bound into a vault order's salt (proof-carrying savings,
//! docs/rfcs/qed-proof-carrying-savings-2026-11-28.md):
//!
//! ```text
//! salt = keccak256("NucleusReferralV1" ‖ referrer (20 bytes) ‖ nonce (32 bytes))
//! ```
//!
//! A seller sends the opening as `accepts[i].extra.referral = {referrer,
//! nonce}` in its `PAYMENT-REQUIRED` header. The buyer's desk takes it out
//! before the vault's review (`split`), so the review and the payment it
//! signs are those of the plain requirements a seller recomputes from its
//! order, then opens the salt with it. The buyer signs the order's digest,
//! which covers the salt, so the referrer is fixed at funding
//! (`Savings.referral_bound_before_funding`).
//!
//! This lives here, not in `nucleus-proof-commerce`: that crate's sources
//! are built into the proof guests, and the published program image IDs must
//! not move. An unreferred header is byte for byte what it was before.
use crate::prelude::*;
use nucleus_proof_commerce::Hash;

/// The tag a referral salt starts with.
pub const REFERRAL_TAG: &[u8] = b"NucleusReferralV1";

/// `keccak256("NucleusReferralV1" ‖ referrer ‖ nonce)`.
pub fn referral_salt(referrer: &Address, nonce: &Hash) -> Hash {
    let mut bytes = Vec::with_capacity(69);
    bytes.extend_from_slice(REFERRAL_TAG);
    bytes.extend_from_slice(referrer);
    bytes.extend_from_slice(nonce);
    keccak(&bytes)
}

/// A nonce for a referred order, derived from the order's other terms so a
/// seller need not keep it: the context, the seller, the amount and both
/// deadlines.
pub fn referral_nonce(order: &vault::Order) -> Hash {
    let mut bytes = Vec::with_capacity(100);
    bytes.extend_from_slice(&order.context);
    bytes.extend_from_slice(&order.seller);
    bytes.extend_from_slice(&order.amount);
    bytes.extend_from_slice(&order.fund_by.to_be_bytes());
    bytes.extend_from_slice(&order.deliver_by.to_be_bytes());
    keccak(&bytes)
}

/// Bind `referrer` into `order`: its salt becomes the referral salt.
pub fn refer(order: &mut vault::Order, referrer: &Address) {
    order.salt = referral_salt(referrer, &referral_nonce(order));
}

/// The `referral` an offer of a referred `order` carries.
pub fn referral_of(order: &vault::Order, referrer: &Address) -> Value {
    json!({"referrer": hex(referrer), "nonce": hex(&referral_nonce(order))})
}

/// A `PAYMENT-REQUIRED` header with `referral` added to its one offer's
/// `extra`.
pub fn with_referral(header: &str, referral: Value) -> Res<String> {
    let mut v: Value = serde_json::from_slice(&B64.decode(header.trim())?)?;
    let accepts = v["accepts"].as_array_mut().ok_or("no accepts")?;
    let [one] = accepts.as_mut_slice() else {
        return Err("a referral goes on a header with one offer".into());
    };
    one["extra"]["referral"] = referral;
    Ok(B64.encode(serde_json::to_vec(&v)?))
}

/// Why a referral is refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Bad {
    /// Not one `{referrer, nonce}` of an address and 32 bytes.
    Malformed,
    /// It does not open the order's salt.
    Wrong,
}

/// Take a referral out of a header: the header without it (unchanged when
/// there is none) and the opening it carried.
pub fn split(header: &str) -> Result<(String, Option<(Address, Hash)>), Bad> {
    let Ok(bytes) = B64.decode(header.trim()) else {
        return Ok((header.to_owned(), None));
    };
    let Ok(mut v) = serde_json::from_slice::<Value>(&bytes) else {
        return Ok((header.to_owned(), None));
    };
    let mut found = None;
    for offer in v["accepts"].as_array_mut().into_iter().flatten() {
        let Some(extra) = offer.get_mut("extra").and_then(Value::as_object_mut) else {
            continue;
        };
        let Some(r) = extra.remove("referral") else {
            continue;
        };
        if found.is_some() {
            return Err(Bad::Malformed);
        }
        let o = r.as_object().ok_or(Bad::Malformed)?;
        if o.len() != 2 {
            return Err(Bad::Malformed);
        }
        let referrer: Address = o
            .get("referrer")
            .and_then(Value::as_str)
            .and_then(|t| unhex(t).ok())
            .and_then(|b| b.try_into().ok())
            .ok_or(Bad::Malformed)?;
        let nonce: Hash = o
            .get("nonce")
            .and_then(Value::as_str)
            .and_then(|t| unhex(t).ok())
            .and_then(|b| b.try_into().ok())
            .ok_or(Bad::Malformed)?;
        found = Some((referrer, nonce));
    }
    match found {
        None => Ok((header.to_owned(), None)),
        Some(r) => Ok((
            B64.encode(serde_json::to_vec(&v).map_err(|_| Bad::Malformed)?),
            Some(r),
        )),
    }
}

/// Check an opening against the reviewed order's salt.
pub fn opens(referral: &(Address, Hash), order: &vault::Order) -> Result<(), Bad> {
    if referral_salt(&referral.0, &referral.1) == order.salt {
        Ok(())
    } else {
        Err(Bad::Wrong)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn order() -> vault::Order {
        vault::Order {
            buyer: [1; 20],
            seller: [2; 20],
            asset: [4; 20],
            amount: [0; 32],
            verifier: [6; 20],
            program: [7; 32],
            policy_hash: [9; 32],
            base: [0; 32],
            fund_by: 1000,
            deliver_by: 2000,
            salt: [10; 32],
            context: [11; 32],
        }
    }
    fn header(o: &vault::Order) -> String {
        B64.encode(
            serde_json::to_vec(&json!({"x402Version": 2, "resource": {}, "accepts": [
                {"scheme": "nucleus-vault", "extra": {"order": {"salt": hex(&o.salt)}}}]}))
            .unwrap(),
        )
    }

    /// A referral opens the salt it was made for and no other; a header
    /// without one passes through unchanged. Driven red by skipping the
    /// salt comparison: the wrong nonce was accepted.
    #[test]
    fn a_referral_opens_its_own_salt_only() {
        let referrer = [0x5e; 20];
        let mut o = order();
        refer(&mut o, &referrer);
        let h = with_referral(&header(&o), referral_of(&o, &referrer)).unwrap();
        let (plain, r) = split(&h).unwrap();
        let r = r.unwrap();
        assert_eq!(r.0, referrer);
        assert_eq!(opens(&r, &o), Ok(()));
        assert!(
            !String::from_utf8(B64.decode(&plain).unwrap())
                .unwrap()
                .contains("referral")
        );
        assert_eq!(opens(&([0x5f; 20], r.1), &o), Err(Bad::Wrong));
        assert_eq!(opens(&(referrer, [1; 32]), &o), Err(Bad::Wrong));
        assert_eq!(opens(&r, &order()), Err(Bad::Wrong));
        let bad =
            with_referral(&header(&o), json!({"referrer": "0x12", "nonce": hex(&r.1)})).unwrap();
        assert_eq!(split(&bad), Err(Bad::Malformed));
        let unreferred = header(&order());
        assert_eq!(split(&unreferred).unwrap(), (unreferred.clone(), None));
    }
}
