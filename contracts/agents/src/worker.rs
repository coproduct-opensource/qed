//! What a seller does once a buyer has signed: relay `fund`, check that the
//! vault booked the terms it quoted and that there is time, prove, check the
//! time again, relay `settle`.
//!
//! Two things the signed order does not fix are checked here, after funding
//! and before any proving work
//! (docs/rfcs/proof-commerce-v3-review-2026-11-13.md, findings 3 and 4):
//!
//! - **The seller's share.** A third-form vault reads the base registry when
//!   an order is funded and books the royalty then. A base registered between
//!   the offer and `fund` lowers the seller's share. `clear_to_prove` compares
//!   the royalty the vault booked for this order with the royalty the seller
//!   quoted for, and refuses if it is larger.
//! - **The deadline.** `settle` carries the artifact in calldata. One that
//!   lands after `deliverBy` reverts, the artifact is public, and the buyer is
//!   refunded. `clear_to_prove` refuses to start unless the remaining time
//!   covers the expected proving time plus a margin; `clear_to_settle`
//!   refuses to submit inside the margin.
//!
//! Both are carried by types: `Sealer::seal` takes a `ClearToProve` and
//! `Venue::settle` takes a `ClearToSettle` by value, and only the two checks
//! here make them.
//!
//! When a check refuses, nothing more is sent. The buyer's deposit stays in
//! the vault until the delivery deadline and is then refundable to the buyer;
//! the seller has spent the gas of `fund`.
use crate::job::{Accepted, Step};
use crate::prelude::*;
use nucleus_proof_commerce::{Hash, vault};

/// How much time the seller keeps in hand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// `settle` is not submitted later than this many seconds before
    /// `deliverBy`.
    pub settle_margin: u64,
    /// How long the settlement proof is expected to take, in seconds.
    pub expected_proving: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            settle_margin: 120,
            expected_proving: 900,
        }
    }
}

/// Why a funded order is not proved or not settled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Held {
    /// The vault booked a larger royalty for this order than was quoted for.
    ShareReduced { quoted: U256, booked: U256 },
    /// Too little time to prove and still settle outside the margin.
    TooLateToProve { now: u64, deliver_by: u64 },
    /// The proof is ready and the margin before the deadline has begun.
    TooLateToSettle { now: u64, deliver_by: u64 },
}
impl std::fmt::Display for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShareReduced { quoted, booked } => write!(
                f,
                "the vault booked a royalty of {booked} for this order; it was quoted on {quoted}. Not proved; the deposit is refundable to the buyer after the delivery deadline"
            ),
            Self::TooLateToProve { now, deliver_by } => write!(
                f,
                "at {now} there is too little time to prove and settle before {deliver_by}. Not proved; the deposit is refundable to the buyer after the delivery deadline"
            ),
            Self::TooLateToSettle { now, deliver_by } => write!(
                f,
                "the proof was ready at {now}, inside the margin before {deliver_by}. Not submitted, so the artifact stays private; the deposit is refundable to the buyer after the delivery deadline"
            ),
        }
    }
}

/// Evidence that a funded order still pays what was quoted and leaves time
/// to prove. Only `clear_to_prove` makes one.
#[derive(Debug)]
pub struct ClearToProve(());

/// Evidence that `settle` can still be submitted outside the margin. Only
/// `clear_to_settle` makes one, and submitting consumes it.
#[derive(Debug)]
pub struct ClearToSettle(());

/// `quoted` is the royalty the seller priced the order on; `booked` what the
/// vault recorded for it at funding; `now` the chain's latest block time.
pub fn clear_to_prove(
    order: &vault::Order,
    quoted: U256,
    booked: U256,
    now: u64,
    limits: &Limits,
) -> Result<ClearToProve, Held> {
    if booked > quoted {
        return Err(Held::ShareReduced { quoted, booked });
    }
    let needed = limits.expected_proving.saturating_add(limits.settle_margin);
    if now.saturating_add(needed) > order.deliver_by {
        return Err(Held::TooLateToProve {
            now,
            deliver_by: order.deliver_by,
        });
    }
    Ok(ClearToProve(()))
}

/// `now` is the chain's latest block time, read after the proof was made.
pub fn clear_to_settle(
    order: &vault::Order,
    now: u64,
    limits: &Limits,
) -> Result<ClearToSettle, Held> {
    if now.saturating_add(limits.settle_margin) > order.deliver_by {
        return Err(Held::TooLateToSettle {
            now,
            deliver_by: order.deliver_by,
        });
    }
    Ok(ClearToSettle(()))
}

/// The vault as the worker uses it. The real one sends transactions; tests
/// substitute one that records.
pub trait Venue {
    /// Relay `fund`; returns the transaction.
    fn fund(&self, order: &vault::Order, signature: &[u8]) -> Res<String>;
    /// The royalty the vault recorded for a funded order (zero on a vault
    /// that has none).
    fn booked_royalty(&self, digest: Hash) -> Res<U256>;
    /// The latest block's timestamp.
    fn now(&self) -> Res<u64>;
    /// Relay `settle`; returns the transaction.
    fn settle(
        &self,
        clear: ClearToSettle,
        order: &vault::Order,
        artifact: &[u8],
        seal: Vec<u8>,
    ) -> Res<String>;
    /// After a settlement: collect the seller's share where the vault books
    /// it instead of paying it. A failure leaves the share booked.
    fn collect(&self, order: &vault::Order);
}

/// The zero-knowledge prover as the worker uses it.
pub trait Sealer {
    /// The settlement seal for an accepted job on a funded order.
    fn seal(&self, clear: &ClearToProve, id: &str, accepted: &Accepted) -> Res<Vec<u8>>;
}

/// What a finished job reports.
#[derive(Debug, PartialEq, Eq)]
pub struct Done {
    pub fund_transaction: String,
    pub settle_transaction: String,
}

/// Fund, check, prove, check, settle. `quoted_royalty` is the royalty this
/// seller priced the order on. `at` is told which step is beginning.
pub fn work(
    venue: &dyn Venue,
    sealer: &dyn Sealer,
    limits: &Limits,
    quoted_royalty: U256,
    id: &str,
    accepted: &Accepted,
    at: &dyn Fn(Step),
) -> Res<Done> {
    let order = accepted.funding.order();
    let fund_transaction = venue.fund(order, accepted.funding.signature())?;
    let booked = venue.booked_royalty(accepted.funding.digest())?;
    let clear = clear_to_prove(order, quoted_royalty, booked, venue.now()?, limits)
        .map_err(|held| held.to_string())?;
    at(Step::Proving);
    let seal = sealer.seal(&clear, id, accepted)?;
    let clear = clear_to_settle(order, venue.now()?, limits).map_err(|held| held.to_string())?;
    at(Step::Settling);
    let settle_transaction = venue.settle(clear, order, &accepted.artifact, seal)?;
    venue.collect(order);
    Ok(Done {
        fund_transaction,
        settle_transaction,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order(deliver_by: u64) -> vault::Order {
        vault::Order {
            buyer: [1; 20],
            seller: [2; 20],
            asset: [3; 20],
            amount: U256::from(1_000_000u64).to_be_bytes(),
            verifier: [4; 20],
            program: [5; 32],
            policy_hash: [6; 32],
            base: [0; 32],
            fund_by: 100,
            deliver_by,
            salt: [7; 32],
            context: [8; 32],
        }
    }
    const LIMITS: Limits = Limits {
        settle_margin: 120,
        expected_proving: 900,
    };

    #[test]
    fn a_larger_booked_royalty_than_quoted_stops_the_seller_before_proving() {
        let o = order(10_000);
        let (quoted, booked) = (U256::from(1_000u64), U256::from(1_001u64));
        assert_eq!(
            clear_to_prove(&o, quoted, booked, 1_000, &LIMITS).unwrap_err(),
            Held::ShareReduced { quoted, booked }
        );
        // Equal or smaller is what was quoted, or better.
        assert!(clear_to_prove(&o, quoted, quoted, 1_000, &LIMITS).is_ok());
        assert!(clear_to_prove(&o, quoted, U256::ZERO, 1_000, &LIMITS).is_ok());
    }

    #[test]
    fn proving_starts_only_with_the_proving_time_and_the_margin_in_hand() {
        let o = order(10_000);
        // 10,000 - 900 - 120 = 8,980 is the last moment.
        assert!(clear_to_prove(&o, U256::ZERO, U256::ZERO, 8_980, &LIMITS).is_ok());
        assert_eq!(
            clear_to_prove(&o, U256::ZERO, U256::ZERO, 8_981, &LIMITS).unwrap_err(),
            Held::TooLateToProve {
                now: 8_981,
                deliver_by: 10_000
            }
        );
    }

    #[test]
    fn settle_is_submitted_only_outside_the_margin() {
        let o = order(10_000);
        assert!(clear_to_settle(&o, 9_880, &LIMITS).is_ok());
        assert_eq!(
            clear_to_settle(&o, 9_881, &LIMITS).unwrap_err(),
            Held::TooLateToSettle {
                now: 9_881,
                deliver_by: 10_000
            }
        );
        // A clock at the far end does not wrap past the deadline.
        assert!(clear_to_settle(&o, u64::MAX, &LIMITS).is_err());
    }
}
