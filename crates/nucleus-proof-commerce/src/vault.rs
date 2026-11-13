//! Reference semantics of the vaults (models: proofs/commerce/Vault.lean for
//! the second form, proofs/commerce/Vault3.lean for the third). Data and
//! checks only: no network, no storage, no transfer.
//!
//! An order names its own token, verifier and proof program. The buyer commits
//! to every field by signing one EIP-3009 receive authorization whose nonce is
//! the order digest; nobody else signs anything. A vault's fee rate and
//! treasury are fixed at deployment and enter the digest through the vault's
//! address in the EIP-712 domain.
//!
//! Two contracts are in use and one module decides for both, so a fact about
//! an order is written once:
//!
//! - **Second** (`NucleusVault2`, live on Base): settlement pays the seller
//!   and books the fee; `sweep` pays the treasury.
//! - **Third** (`NucleusVault3`): nothing is paid inside fund, settle or
//!   refund; everything is booked and claimed. An order may name a base
//!   library, whose registered payee is owed a royalty inside the fee cap,
//!   and the delivery deadline is at most `maximum_term` after funding.
use crate::{
    Address, Hash, WalletSignature, address, amounts, hash,
    journals::Acceptance,
    recover, typed_digest, uint, words,
    x402::{Authorization, RECEIVE_TYPE, TokenDomain},
};

/// The second form's order type. It has no `base` field.
pub const ORDER_TYPE: &str = "Order(address buyer,address seller,address asset,uint256 amount,address verifier,bytes32 program,bytes32 policyHash,uint64 fundBy,uint64 deliverBy,bytes32 salt,bytes32 context)";
/// The third form's order type.
pub const ORDER_TYPE_3: &str = "Order(address buyer,address seller,address asset,uint256 amount,address verifier,bytes32 program,bytes32 policyHash,bytes32 base,uint64 fundBy,uint64 deliverBy,bytes32 salt,bytes32 context)";
pub const DOMAIN_NAME: &str = "NucleusVault";

/// Which vault contract an order is for. It decides the order's type string
/// and the EIP-712 domain version, and so the digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    Second,
    Third,
}
impl Form {
    pub fn domain_version(self) -> &'static str {
        match self {
            Form::Second => "1",
            Form::Third => "3",
        }
    }
}

/// What differs between the two contracts, fixed at deployment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rules {
    Second,
    Third {
        /// Longest time, in seconds, from funding to the delivery deadline.
        maximum_term: u64,
        /// Contract that says who is paid for a base library, and at what rate.
        registry: Address,
    },
}
impl Rules {
    pub fn form(&self) -> Form {
        match self {
            Rules::Second => Form::Second,
            Rules::Third { .. } => Form::Third,
        }
    }
}

/// One deployed vault. All of it is public and immutable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deployment {
    pub chain_id: u64,
    pub vault: Address,
    pub treasury: Address,
    pub fee_bps: u16,
    pub maximum_fee_bps: u16,
    pub rules: Rules,
}

/// What the buyer and seller agree. Untrusted until checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    pub buyer: Address,
    pub seller: Address,
    /// Token paid in. It must honour EIP-3009 receive authorizations.
    pub asset: Address,
    pub amount: Hash,
    /// Contract that checks the acceptance proof.
    pub verifier: Address,
    /// Identity of the proof program whose acceptance releases payment.
    pub program: Hash,
    pub policy_hash: Hash,
    /// The checked base library the statement builds on; zero for none. A
    /// second-form order has no such field and must leave it zero.
    pub base: Hash,
    pub fund_by: u64,
    pub deliver_by: u64,
    /// Makes otherwise equal orders distinct.
    pub salt: Hash,
    /// Digest of anything agreed off chain that the vault does not read.
    pub context: Hash,
}

/// What a registry says about a base library.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub payee: Address,
    pub bps: u16,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid vault deployment")]
    InvalidDeployment,
    #[error("invalid order fields or deadline ordering")]
    InvalidOrder,
    #[error("funding deadline passed")]
    Expired,
    #[error("the delivery deadline is further away than the vault's maximum term")]
    TermTooLong,
    #[error("rounded fee and royalty exceed the deployment's effective fee cap")]
    FeeExceedsCap,
    #[error("funding deadline leaves no representable authorization window")]
    Window,
    #[error("invalid or noncanonical authorization signature")]
    InvalidSignature,
    #[error("buyer did not sign the authorization this order fixes")]
    WrongSigner,
    #[error(transparent)]
    Allocation(#[from] amounts::Error),
}

fn domain(name: &str, version: &str, chain_id: u64, contract: Address) -> Hash {
    words([
        hash(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        hash(name.as_bytes()),
        hash(version.as_bytes()),
        uint(chain_id),
        address(contract),
    ])
}

/// EIP-712 digest of the order under this vault's domain. Every field is
/// destructured without `..`: a new field must be committed here to compile.
pub fn digest(deployment: &Deployment, order: &Order) -> Hash {
    digest_at(
        deployment.rules.form(),
        deployment.chain_id,
        deployment.vault,
        order,
    )
}

/// The digest needs only the contract's form, the chain and the vault's
/// address from a deployment. A proof program is given just those.
///
/// The second form's digest does not cover `base`, because that contract's
/// order has no such field; `admissible` refuses a second-form order whose
/// `base` is not zero, so two admitted orders never share a digest.
pub fn digest_at(form: Form, chain_id: u64, vault: Address, order: &Order) -> Hash {
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
    let message = match form {
        Form::Second => words([
            hash(ORDER_TYPE.as_bytes()),
            address(*buyer),
            address(*seller),
            address(*asset),
            *amount,
            address(*verifier),
            *program,
            *policy_hash,
            uint(*fund_by),
            uint(*deliver_by),
            *salt,
            *context,
        ]),
        Form::Third => words([
            hash(ORDER_TYPE_3.as_bytes()),
            address(*buyer),
            address(*seller),
            address(*asset),
            *amount,
            address(*verifier),
            *program,
            *policy_hash,
            *base,
            uint(*fund_by),
            uint(*deliver_by),
            *salt,
            *context,
        ]),
    };
    typed_digest(
        domain(DOMAIN_NAME, form.domain_version(), chain_id, vault),
        message,
    )
}

/// The royalty rate that applies to this order: the entry's rate when the
/// vault is of the third form, the order names a base, and the registry's
/// payee for it is a usable account; otherwise none.
fn royalty_rate(
    deployment: &Deployment,
    order: &Order,
    entry: Option<&Entry>,
) -> Option<(Address, u16)> {
    let Rules::Third { .. } = deployment.rules else {
        return None;
    };
    if order.base == [0; 32] {
        return None;
    }
    let entry = entry?;
    if entry.payee == [0; 20] || entry.payee == deployment.vault {
        return None;
    }
    Some((entry.payee, entry.bps))
}

/// `admissible_with` for an order whose base, if any, has no registry entry.
pub fn admissible(deployment: &Deployment, order: &Order, now: u64) -> Result<Hash, Error> {
    admissible_with(deployment, order, None, now)
}

/// The checks the vault makes on an order before taking a deposit, other than
/// the token's own check of the buyer's signature. `entry` is what the
/// vault's registry reports for `order.base` at funding. Returns the digest.
pub fn admissible_with(
    deployment: &Deployment,
    order: &Order,
    entry: Option<&Entry>,
    now: u64,
) -> Result<Hash, Error> {
    let Deployment {
        chain_id,
        vault,
        treasury,
        fee_bps,
        maximum_fee_bps,
        rules,
    } = deployment;
    if *chain_id == 0
        || *vault == [0; 20]
        || *treasury == [0; 20]
        || treasury == vault
        || *fee_bps == 0
        || fee_bps > maximum_fee_bps
        || *maximum_fee_bps > crate::BPS_SCALE
    {
        return Err(Error::InvalidDeployment);
    }
    match rules {
        Rules::Second => {}
        Rules::Third {
            maximum_term,
            registry,
        } => {
            if *maximum_term == 0 || *registry == [0; 20] || registry == vault {
                return Err(Error::InvalidDeployment);
            }
        }
    }
    if order.buyer == [0; 20]
        || order.seller == [0; 20]
        || order.asset == [0; 20]
        || order.verifier == [0; 20]
        || order.amount == [0; 32]
        || order.program == [0; 32]
        || order.policy_hash == [0; 32]
        || order.buyer == *vault
        || order.seller == *vault
        || order.fund_by >= order.deliver_by
    {
        return Err(Error::InvalidOrder);
    }
    // The second form's order has no base, and its digest does not cover one.
    if *rules == Rules::Second && order.base != [0; 32] {
        return Err(Error::InvalidOrder);
    }
    if now > order.fund_by {
        return Err(Error::Expired);
    }
    if let Rules::Third { maximum_term, .. } = rules {
        // A sum that does not fit in 64 bits is later than any deadline.
        if let Some(latest) = now.checked_add(*maximum_term) {
            if order.deliver_by > latest {
                return Err(Error::TermTooLong);
            }
        }
    }
    let royalty_bps = royalty_rate(deployment, order, entry).map_or(0, |(_, bps)| bps);
    if amounts::split(order.amount, *fee_bps, royalty_bps, *maximum_fee_bps)?.is_none() {
        return Err(Error::FeeExceedsCap);
    }
    Ok(digest(deployment, order))
}

/// The one token authorization that funds this order: payable to the vault,
/// for the exact amount, valid through `fund_by`, with the digest as nonce.
pub fn authorization(deployment: &Deployment, order: &Order) -> Result<Authorization, Error> {
    Ok(Authorization {
        from: order.buyer,
        to: deployment.vault,
        value: order.amount,
        valid_after: 0,
        valid_before: order.fund_by.checked_add(1).ok_or(Error::Window)?,
        nonce: digest(deployment, order),
    })
}

/// The digest the buyer's wallet signs for the token contract.
pub fn authorization_digest(
    deployment: &Deployment,
    token: &TokenDomain,
    order: &Order,
) -> Result<Hash, Error> {
    let Authorization {
        from,
        to,
        value,
        valid_after,
        valid_before,
        nonce,
    } = authorization(deployment, order)?;
    Ok(typed_digest(
        domain(
            &token.name,
            &token.version,
            deployment.chain_id,
            order.asset,
        ),
        words([
            hash(RECEIVE_TYPE.as_bytes()),
            address(from),
            address(to),
            value,
            uint(valid_after),
            uint(valid_before),
            nonce,
        ]),
    ))
}

/// Evidence that the order passes the vault's checks and that its buyer signed
/// the authorization it fixes. It is NOT a deposit: the token decides that.
///
/// ```compile_fail
/// use nucleus_proof_commerce::vault::{Funding, Order};
/// fn forge(order: Order) -> Funding {
///     Funding { order, digest: [0; 32], signature: [0; 65] }
/// }
/// ```
#[must_use]
#[derive(Debug)]
pub struct Funding {
    order: Order,
    digest: Hash,
    signature: [u8; 65],
}
impl Funding {
    pub fn order(&self) -> &Order {
        &self.order
    }
    pub fn digest(&self) -> Hash {
        self.digest
    }
    pub fn signature(&self) -> &[u8; 65] {
        &self.signature
    }
}

pub fn admit_funding(
    deployment: &Deployment,
    token: &TokenDomain,
    order: Order,
    signature: &WalletSignature,
    now: u64,
) -> Result<Funding, Error> {
    let digest = admissible(deployment, &order, now)?;
    let signer = recover(authorization_digest(deployment, token, &order)?, signature)
        .map_err(|_| Error::InvalidSignature)?;
    if signer != order.buyer {
        return Err(Error::WrongSigner);
    }
    Ok(Funding {
        order,
        digest,
        signature: signature.0,
    })
}

/// What a second-form settlement pays the seller and books for the treasury.
/// A refund returns `order.amount` to the buyer and nobody else.
pub fn payout(deployment: &Deployment, order: &Order) -> Result<amounts::Allocation, Error> {
    Ok(amounts::accepted(order.amount, deployment.fee_bps)?)
}

/// What a third-form settlement books, and for whom the royalty is. `entry`
/// is what the registry reported for `order.base` when the order was funded;
/// the vault stores that answer and never asks again.
pub fn split(
    deployment: &Deployment,
    order: &Order,
    entry: Option<&Entry>,
) -> Result<(amounts::Split, Option<Address>), Error> {
    let rate = royalty_rate(deployment, order, entry);
    let split = amounts::split(
        order.amount,
        deployment.fee_bps,
        rate.map_or(0, |(_, bps)| bps),
        deployment.maximum_fee_bps,
    )?
    .ok_or(Error::FeeExceedsCap)?;
    // A royalty that rounds to nothing is owed to nobody.
    let payee = rate
        .map(|(payee, _)| payee)
        .filter(|_| split.royalty != [0; 32]);
    Ok((split, payee))
}

/// The 160-byte statement an acceptance proof must commit for this order and
/// artifact. The vault hashes exactly these bytes with SHA-256.
pub fn acceptance_journal(
    deployment: &Deployment,
    order: &Order,
    artifact_hash: Hash,
) -> [u8; 160] {
    Acceptance {
        chain_id: deployment.chain_id,
        escrow: deployment.vault,
        order_digest: digest(deployment, order),
        artifact_hash,
    }
    .encode()
}

#[cfg(feature = "x402-wire")]
pub mod wire;

#[cfg(test)]
mod tests;
