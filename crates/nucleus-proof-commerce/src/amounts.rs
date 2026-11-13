//! Atomic-unit allocation data only. No transfer authority or chain effects.
//! The decomposed ceil division corresponds to the identity proved in
//! proofs/commerce/Amounts.lean; implementation correspondence is not proved.
//!
//! Amounts are 256-bit. The only divisor is 10,000 and the only multipliers
//! are basis-point rates, so the arithmetic here is long division and
//! multiplication of four 64-bit limbs by one small number. A general
//! big-integer library is not linked: its division alone was the largest
//! function in the on-chain escrow after the entry point.
use crate::{BPS_SCALE, Hash};

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("positive price required")]
    ZeroPrice,
    #[error("positive fee rate at most10000bps required")]
    InvalidRate,
    #[error("allocation arithmetic refused")]
    Arithmetic,
}

/// Plain deterministic accounting data, never evidence of paid balances.
#[derive(Debug, PartialEq, Eq)]
pub struct Allocation {
    pub seller: Hash,
    pub protocol: Hash,
    pub buyer: Hash,
}

/// A 256-bit unsigned value as four 64-bit limbs, most significant first, so
/// array comparison is numeric comparison.
type Limbs = [u64; 4];

fn limbs(word: Hash) -> Limbs {
    let mut out = [0u64; 4];
    for (limb, chunk) in out.iter_mut().zip(word.chunks_exact(8)) {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        *limb = u64::from_be_bytes(bytes);
    }
    out
}
fn word(value: Limbs) -> Hash {
    let mut out = [0u8; 32];
    for (chunk, limb) in out.chunks_exact_mut(8).zip(value) {
        chunk.copy_from_slice(&limb.to_be_bytes());
    }
    out
}
/// Quotient and remainder by a nonzero divisor.
fn div_rem(value: Limbs, divisor: u64) -> Option<(Limbs, u64)> {
    let divisor = u128::from(divisor);
    let mut quotient = [0u64; 4];
    let mut remainder = 0u128;
    for (out, limb) in quotient.iter_mut().zip(value) {
        // remainder < divisor <= 2^64, so this fits in 128 bits.
        let current = (remainder << 64) | u128::from(limb);
        *out = u64::try_from(current.checked_div(divisor)?).ok()?;
        remainder = current.checked_rem(divisor)?;
    }
    Some((quotient, u64::try_from(remainder).ok()?))
}
/// Product with a small multiplier, or `None` if it does not fit in 256 bits.
fn mul(value: Limbs, multiplier: u64) -> Option<Limbs> {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    for (slot, limb) in out.iter_mut().zip(value).rev() {
        let product = u128::from(limb)
            .checked_mul(u128::from(multiplier))?
            .checked_add(carry)?;
        *slot = u64::try_from(product & u128::from(u64::MAX)).ok()?;
        carry = product >> 64;
    }
    (carry == 0).then_some(out)
}
fn add(a: Limbs, b: Limbs) -> Option<Limbs> {
    let mut out = [0u64; 4];
    let mut carry = false;
    for ((slot, x), y) in out.iter_mut().zip(a).zip(b).rev() {
        let (sum, first) = x.overflowing_add(y);
        let (sum, second) = sum.overflowing_add(u64::from(carry));
        *slot = sum;
        carry = first || second;
    }
    (!carry).then_some(out)
}
fn sub(a: Limbs, b: Limbs) -> Option<Limbs> {
    let mut out = [0u64; 4];
    let mut borrow = false;
    for ((slot, x), y) in out.iter_mut().zip(a).zip(b).rev() {
        let (difference, first) = x.overflowing_sub(y);
        let (difference, second) = difference.overflowing_sub(u64::from(borrow));
        *slot = difference;
        borrow = first || second;
    }
    (!borrow).then_some(out)
}
fn small(value: u64) -> Limbs {
    [0, 0, 0, value]
}

/// `floor(price * rate / 10000)` when `round_up` is false, the ceiling when
/// true, computed as `(price / 10000) * rate + f((price % 10000) * rate)` so
/// the full-width product is never formed.
fn scaled(price: Limbs, rate: u16, round_up: bool) -> Option<Limbs> {
    let scale = u64::from(BPS_SCALE);
    let (quotient, remainder) = div_rem(price, scale)?;
    let whole = mul(quotient, u64::from(rate))?;
    let rounding = if round_up { scale.checked_sub(1)? } else { 0 };
    let tail = remainder
        .checked_mul(u64::from(rate))?
        .checked_add(rounding)?
        .checked_div(scale)?;
    add(whole, small(tail))
}

/// Full uint256 ceil fee without overflowing amount*rate. Every intermediate
/// uses checked arithmetic; a refusal never emits an allocation.
pub fn accepted(amount: Hash, fee_bps: u16) -> Result<Allocation, Error> {
    if amount == [0; 32] {
        return Err(Error::ZeroPrice);
    }
    if fee_bps == 0 || fee_bps > BPS_SCALE {
        return Err(Error::InvalidRate);
    }
    let price = limbs(amount);
    let protocol = scaled(price, fee_bps, true).ok_or(Error::Arithmetic)?;
    let seller = sub(price, protocol).ok_or(Error::Arithmetic)?;
    Ok(Allocation {
        seller: word(seller),
        protocol: word(protocol),
        buyer: [0; 32],
    })
}

/// Non-delivery returns the full price; there is no protocol fee on refund.
pub fn refunded(amount: Hash) -> Result<Allocation, Error> {
    if amount == [0; 32] {
        return Err(Error::ZeroPrice);
    }
    Ok(Allocation {
        seller: [0; 32],
        protocol: [0; 32],
        buyer: amount,
    })
}

/// Enforce the agreed EFFECTIVE cap, including atomic-unit rounding, without
/// multiplying a full-width amount by10000. A tiny trade may be inadmissible.
pub fn within_cap(amount: Hash, fee_bps: u16, maximum_fee_bps: u16) -> Result<bool, Error> {
    if maximum_fee_bps < fee_bps || maximum_fee_bps > BPS_SCALE {
        return Err(Error::InvalidRate);
    }
    let fee = limbs(accepted(amount, fee_bps)?.protocol);
    let allowed = scaled(limbs(amount), maximum_fee_bps, false).ok_or(Error::Arithmetic)?;
    Ok(fee <= allowed)
}

/// What a third-vault settlement books: the seller's share, the protocol fee
/// and a base library's royalty. They add up to the price.
#[derive(Debug, PartialEq, Eq)]
pub struct Split {
    pub seller: Hash,
    pub protocol: Hash,
    pub royalty: Hash,
}

/// Fee rounded up, royalty rounded down, and the two together held to the
/// effective cap `floor(price * maximum / 10000)`. `Ok(None)` means the
/// charges exceed the cap, so the order is not admitted. Model:
/// `WithinCap` in proofs/commerce/Vault3.lean.
pub fn split(
    amount: Hash,
    fee_bps: u16,
    royalty_bps: u16,
    maximum_fee_bps: u16,
) -> Result<Option<Split>, Error> {
    if maximum_fee_bps < fee_bps || maximum_fee_bps > BPS_SCALE || royalty_bps > BPS_SCALE {
        return Err(Error::InvalidRate);
    }
    let price = limbs(amount);
    let protocol = limbs(accepted(amount, fee_bps)?.protocol);
    let royalty = scaled(price, royalty_bps, false).ok_or(Error::Arithmetic)?;
    let allowed = scaled(price, maximum_fee_bps, false).ok_or(Error::Arithmetic)?;
    // royalty <= allowed and protocol <= allowed - royalty, with no sum that
    // could wrap.
    let Some(room) = sub(allowed, royalty) else {
        return Ok(None);
    };
    if protocol > room {
        return Ok(None);
    }
    let charges = add(protocol, royalty).ok_or(Error::Arithmetic)?;
    let seller = sub(price, charges).ok_or(Error::Arithmetic)?;
    Ok(Some(Split {
        seller: word(seller),
        protocol: word(protocol),
        royalty: word(royalty),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruint::aliases::{U256, U512};
    use sha3::{Digest, Keccak256};
    #[test]
    fn full_width_allocations_match_an_independent_widened_formula() {
        let samples = [
            [0xff; 32],
            [1; 32],
            U256::ONE.to_be_bytes(),
            U256::from(9999).to_be_bytes(),
            U256::from(10000).to_be_bytes(),
            U256::from(10001).to_be_bytes(),
        ];
        for amount in samples
            .into_iter()
            .chain((0u64..128).map(|n| Keccak256::digest(n.to_be_bytes()).into()))
        {
            for rate in [1, 25, 100, 9999, 10000] {
                let allocation = accepted(amount, rate).unwrap();
                let mut wide = [0; 64];
                wide[32..].copy_from_slice(&amount);
                let expected = (U512::from_be_bytes(wide) * U512::from(rate) + U512::from(9999))
                    / U512::from(10000);
                let fee = U256::from_be_bytes(allocation.protocol);
                assert_eq!(
                    allocation.protocol.as_slice(),
                    &expected.to_be_bytes::<64>()[32..]
                );
                assert!(fee > U256::ZERO);
                assert_eq!(
                    U256::from_be_bytes(allocation.seller).checked_add(fee),
                    Some(U256::from_be_bytes(amount))
                );
                assert_eq!(allocation.buyer, [0; 32]);
                // The cap check against the same widened arithmetic: the fee is
                // within a cap exactly when fee * 10000 <= price * cap.
                for cap in [rate, 100, 9999, 10000] {
                    if cap >= rate {
                        let expected_within = U512::from(fee) * U512::from(10000)
                            <= U512::from_be_bytes(wide) * U512::from(cap);
                        assert_eq!(within_cap(amount, rate, cap), Ok(expected_within));
                    }
                }
            }
        }
    }
    #[test]
    fn a_split_matches_the_widened_formula_and_never_exceeds_the_cap() {
        let samples = [
            [0xff; 32],
            U256::ONE.to_be_bytes(),
            U256::from(100).to_be_bytes(),
            U256::from(9999).to_be_bytes(),
            U256::from(1_000_000).to_be_bytes(),
        ];
        for amount in samples
            .into_iter()
            .chain((0u64..64).map(|n| Keccak256::digest(n.to_be_bytes()).into()))
        {
            let mut wide = [0; 64];
            wide[32..].copy_from_slice(&amount);
            let price = U512::from_be_bytes(wide);
            for (fee, royalty, cap) in [
                (25, 0, 100),
                (25, 25, 100),
                (25, 75, 100),
                (25, 76, 100),
                (1, 9999, 10000),
                (100, 10000, 10000),
            ] {
                let fee_units = (price * U512::from(fee) + U512::from(9999)) / U512::from(10000);
                let royalty_units = price * U512::from(royalty) / U512::from(10000);
                let within =
                    (fee_units + royalty_units) * U512::from(10000) <= price * U512::from(cap);
                match split(amount, fee, royalty, cap).unwrap() {
                    None => assert!(!within, "{fee} {royalty} {cap}"),
                    Some(split) => {
                        assert!(within, "{fee} {royalty} {cap}");
                        assert_eq!(U512::from(U256::from_be_bytes(split.protocol)), fee_units);
                        assert_eq!(
                            U512::from(U256::from_be_bytes(split.royalty)),
                            royalty_units
                        );
                        assert_eq!(
                            U512::from(U256::from_be_bytes(split.seller))
                                + fee_units
                                + royalty_units,
                            price
                        );
                    }
                }
            }
        }
        assert_eq!(split([1; 32], 25, 10001, 100), Err(Error::InvalidRate));
        assert_eq!(split([1; 32], 25, 0, 24), Err(Error::InvalidRate));
        // No royalty: the same answer as the two-way allocation.
        let two = accepted(U256::from(1_000_000).to_be_bytes(), 25).unwrap();
        let three = split(U256::from(1_000_000).to_be_bytes(), 25, 0, 100)
            .unwrap()
            .unwrap();
        assert_eq!((three.seller, three.protocol), (two.seller, two.protocol));
        assert_eq!(three.royalty, [0; 32]);
    }

    #[test]
    fn rounding_and_refund_boundaries_are_explicit() {
        assert_eq!(accepted([0; 32], 25), Err(Error::ZeroPrice));
        assert_eq!(accepted([1; 32], 0), Err(Error::InvalidRate));
        assert_eq!(accepted([1; 32], 10001), Err(Error::InvalidRate));
        assert_eq!(
            accepted(U256::ONE.to_be_bytes(), 25).unwrap().protocol,
            U256::ONE.to_be_bytes()
        );
        assert_eq!(
            accepted(U256::from(10001).to_be_bytes(), 1)
                .unwrap()
                .protocol,
            U256::from(2).to_be_bytes()
        );
        let reverse = refunded([0xff; 32]).unwrap();
        assert_eq!(
            reverse,
            Allocation {
                seller: [0; 32],
                protocol: [0; 32],
                buyer: [0xff; 32]
            }
        );
        assert_eq!(refunded([0; 32]), Err(Error::ZeroPrice));
        assert!(!within_cap(U256::ONE.to_be_bytes(), 25, 100).unwrap());
        assert!(!within_cap(U256::from(99).to_be_bytes(), 25, 100).unwrap());
        assert!(within_cap(U256::from(100).to_be_bytes(), 25, 100).unwrap());
        assert!(within_cap([0xff; 32], 25, 100).unwrap());
    }
}
