//! x402 v2 wire form of the `nucleus-vault` scheme. Parsing and checks only.
//!
//! The seller's `PAYMENT-REQUIRED` carries a complete vault order. The buyer's
//! `PAYMENT-SIGNATURE` carries one thing of its own: its signature over the
//! token authorization that order fixes. Nobody else signs. A decoded header
//! becomes evidence only through `vault::admit_funding`.
use super::{Deployment, Funding, Order};
use crate::{
    Hash, WalletSignature,
    x402::{
        TokenDomain,
        wire::{Error, decimal_of, decode, encode, hex_of, undecimal, undecimal_u64, unhex},
    },
};
use serde::{Deserialize, Serialize};

pub const SCHEME: &str = "nucleus-vault";
pub const TRANSFER_METHOD: &str = "eip3009-receive";
pub const PAYMENT_FLOW: &str = "escrow";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireOrder {
    pub buyer: String,
    pub seller: String,
    pub asset: String,
    pub amount: String,
    pub verifier: String,
    pub program: String,
    pub policy_hash: String,
    /// Present only when the order names a base library. Absent means none,
    /// and a present all-zero value is refused, so one order has one encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    pub fund_by: u64,
    pub deliver_by: u64,
    pub salt: String,
    pub context: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Extra {
    pub asset_transfer_method: String,
    pub payment_flow: String,
    pub name: String,
    pub version: String,
    pub order: WireOrder,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Requirements {
    pub scheme: String,
    pub network: String,
    pub amount: String,
    pub asset: String,
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    pub extra: Extra,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireAuthorization {
    pub from: String,
    pub to: String,
    pub value: String,
    pub valid_after: String,
    pub valid_before: String,
    pub nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SchemePayload {
    pub signature: String,
    pub authorization: WireAuthorization,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PaymentPayload {
    pub x402_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<serde_json::Value>,
    pub accepted: Requirements,
    pub payload: SchemePayload,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PaymentRequired {
    pub x402_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub resource: serde_json::Value,
    pub accepts: Vec<Requirements>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

impl WireOrder {
    pub fn from_order(order: &Order) -> Self {
        let Order {
            buyer,
            seller,
            asset,
            amount,
            verifier,
            program,
            policy_hash,
            base,
            fund_by,
            deliver_by,
            salt,
            context,
        } = order;
        Self {
            buyer: hex_of(buyer),
            seller: hex_of(seller),
            asset: hex_of(asset),
            amount: decimal_of(*amount),
            verifier: hex_of(verifier),
            program: hex_of(program),
            policy_hash: hex_of(policy_hash),
            base: (*base != [0; 32]).then(|| hex_of(base)),
            fund_by: *fund_by,
            deliver_by: *deliver_by,
            salt: hex_of(salt),
            context: hex_of(context),
        }
    }
    pub fn to_order(&self) -> Result<Order, Error> {
        let Self {
            buyer,
            seller,
            asset,
            amount,
            verifier,
            program,
            policy_hash,
            base,
            fund_by,
            deliver_by,
            salt,
            context,
        } = self;
        let base = match base {
            None => [0; 32],
            Some(text) => {
                let named: Hash = unhex(text)?;
                if named == [0; 32] {
                    return Err(Error::Encoding);
                }
                named
            }
        };
        Ok(Order {
            buyer: unhex(buyer)?,
            seller: unhex(seller)?,
            asset: unhex(asset)?,
            amount: undecimal(amount)?,
            verifier: unhex(verifier)?,
            program: unhex(program)?,
            policy_hash: unhex(policy_hash)?,
            base,
            fund_by: *fund_by,
            deliver_by: *deliver_by,
            salt: unhex(salt)?,
            context: unhex(context)?,
        })
    }
}

/// The only requirements an order admits for this vault and token.
pub fn requirements(
    deployment: &Deployment,
    token: &TokenDomain,
    order: &Order,
    max_timeout_seconds: u64,
) -> Requirements {
    Requirements {
        scheme: SCHEME.into(),
        network: format!("eip155:{}", deployment.chain_id),
        amount: decimal_of(order.amount),
        asset: hex_of(&order.asset),
        pay_to: hex_of(&deployment.vault),
        max_timeout_seconds,
        extra: Extra {
            asset_transfer_method: TRANSFER_METHOD.into(),
            payment_flow: PAYMENT_FLOW.into(),
            name: token.name.clone(),
            version: token.version.clone(),
            order: WireOrder::from_order(order),
        },
    }
}

/// Value of the seller's PAYMENT-REQUIRED header for one order.
pub fn required_header(
    resource: serde_json::Value,
    accepted: Requirements,
) -> Result<String, Error> {
    encode(&PaymentRequired {
        x402_version: 2,
        error: None,
        resource,
        accepts: vec![accepted],
        extensions: None,
    })
}

/// What the buyer asked for and will accept. An offer is compared with this
/// before the buyer signs anything.
#[derive(Clone, Debug)]
pub struct Intent {
    pub wallet: [u8; 20],
    pub asset: [u8; 20],
    pub policy_hash: Hash,
    /// Digest of what was agreed off chain (the request, the parties' keys).
    pub context: Hash,
    pub maximum_amount: Hash,
    /// Verifier contracts and proof programs the buyer is willing to be judged by.
    pub verifiers: Vec<[u8; 20]>,
    pub programs: Vec<Hash>,
    pub fund_no_earlier_than: u64,
    pub deliver_no_later_than: u64,
    /// Base libraries the buyer accepts an order naming, each with the entry
    /// the buyer read from the vault's registry. An order naming any other
    /// base is refused; with none listed, only base-less orders pass.
    pub bases: Vec<(Hash, super::Entry)>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum OfferError {
    #[error(transparent)]
    Wire(#[from] Error),
    #[error(transparent)]
    Vault(#[from] super::Error),
    #[error("the offer does not contain exactly one entry of this scheme")]
    NoSingleOffer,
    #[error("the offered order names another wallet, token, policy or context")]
    NotMyOrder,
    #[error("the offered order names a verifier or proof program the buyer did not allow")]
    UntrustedJudge,
    #[error("the offered price exceeds the buyer's limit")]
    OverBudget,
    #[error("the offered deadlines fall outside the buyer's limits")]
    Deadline,
    #[error("the offered order names a base library the buyer did not list")]
    UnsupportedBase,
}

/// An offer the buyer has checked. The only way to build a payment header.
#[must_use]
#[derive(Debug)]
pub struct ReviewedOffer {
    accepted: Requirements,
    order: Order,
    signing_digest: Hash,
}
impl ReviewedOffer {
    pub fn order(&self) -> &Order {
        &self.order
    }
    /// The token-authorization digest the buyer's wallet signs.
    pub fn signing_digest(&self) -> Hash {
        self.signing_digest
    }
}

/// Buyer side. Refuse unless the offer is one entry of this scheme, for this
/// vault and token domain, admissible, and within the buyer's own intent,
/// including who and what will judge the work.
pub fn review_offer(
    deployment: &Deployment,
    token: &TokenDomain,
    header: &str,
    intent: &Intent,
    now: u64,
) -> Result<ReviewedOffer, OfferError> {
    let required: PaymentRequired = decode(header)?;
    if required.x402_version != 2 {
        return Err(Error::Version.into());
    }
    let mut offers = required
        .accepts
        .into_iter()
        .filter(|offer| offer.scheme == SCHEME);
    let (Some(accepted), None) = (offers.next(), offers.next()) else {
        return Err(OfferError::NoSingleOffer);
    };
    let order = accepted.extra.order.to_order()?;
    if accepted != requirements(deployment, token, &order, accepted.max_timeout_seconds) {
        return Err(Error::RequirementsMismatch.into());
    }
    // A base's royalty is priced from the entry the buyer read for it.
    let entry = if order.base == [0; 32] {
        None
    } else {
        let listed = intent.bases.iter().find(|(base, _)| *base == order.base);
        Some(&listed.ok_or(OfferError::UnsupportedBase)?.1)
    };
    super::admissible_with(deployment, &order, entry, now)?;
    if order.buyer != intent.wallet
        || order.asset != intent.asset
        || order.policy_hash != intent.policy_hash
        || order.context != intent.context
    {
        return Err(OfferError::NotMyOrder);
    }
    if !intent.verifiers.contains(&order.verifier) || !intent.programs.contains(&order.program) {
        return Err(OfferError::UntrustedJudge);
    }
    // Amounts are big-endian words of equal length, so byte order is numeric order.
    if order.amount > intent.maximum_amount {
        return Err(OfferError::OverBudget);
    }
    if order.fund_by < intent.fund_no_earlier_than
        || order.deliver_by > intent.deliver_no_later_than
    {
        return Err(OfferError::Deadline);
    }
    let signing_digest = super::authorization_digest(deployment, token, &order)?;
    Ok(ReviewedOffer {
        accepted,
        order,
        signing_digest,
    })
}

/// Value of the buyer's PAYMENT-SIGNATURE header.
pub fn signature_header(
    deployment: &Deployment,
    offer: ReviewedOffer,
    signature: &WalletSignature,
) -> Result<String, OfferError> {
    let authorization = super::authorization(deployment, &offer.order)?;
    Ok(encode(&PaymentPayload {
        x402_version: 2,
        resource: None,
        accepted: offer.accepted,
        payload: SchemePayload {
            signature: hex_of(&signature.0),
            authorization: WireAuthorization {
                from: hex_of(&authorization.from),
                to: hex_of(&authorization.to),
                value: decimal_of(authorization.value),
                valid_after: authorization.valid_after.to_string(),
                valid_before: authorization.valid_before.to_string(),
                nonce: hex_of(&authorization.nonce),
            },
        },
        extensions: None,
    })?)
}

/// Seller or relayer side. Decode a PAYMENT-SIGNATURE header and refuse unless
/// its requirements are the ones its order fixes, the authorization is the one
/// the order fixes, and the buyer signed it. Success is not a deposit.
pub fn admit_header(
    deployment: &Deployment,
    token: &TokenDomain,
    header: &str,
    max_timeout_seconds: u64,
    now: u64,
) -> Result<Funding, OfferError> {
    let payment: PaymentPayload = decode(header)?;
    if payment.x402_version != 2 {
        return Err(Error::Version.into());
    }
    let order = payment.accepted.extra.order.to_order()?;
    if payment.accepted != requirements(deployment, token, &order, max_timeout_seconds) {
        return Err(Error::RequirementsMismatch.into());
    }
    let expected = super::authorization(deployment, &order)?;
    let wire = &payment.payload.authorization;
    if unhex::<20>(&wire.from)? != expected.from
        || unhex::<20>(&wire.to)? != expected.to
        || undecimal(&wire.value)? != expected.value
        || undecimal_u64(&wire.valid_after)? != expected.valid_after
        || undecimal_u64(&wire.valid_before)? != expected.valid_before
        || unhex::<32>(&wire.nonce)? != expected.nonce
    {
        return Err(Error::Authorization(crate::x402::Error::NotBound).into());
    }
    let signature = WalletSignature(unhex(&payment.payload.signature)?);
    Ok(super::admit_funding(
        deployment, token, order, &signature, now,
    )?)
}

/// The `context` of an order made over HTTP: the request it answers and the
/// key that proved possession when asking. Both sides compute it; the vault
/// only carries it inside the digest.
pub fn context(request_hash: Hash, buyer_key_binding: Hash) -> Hash {
    crate::words([
        crate::hash(b"NucleusContextV1"),
        request_hash,
        buyer_key_binding,
    ])
}

#[cfg(test)]
mod tests;
