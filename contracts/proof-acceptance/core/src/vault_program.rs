//! The proof program for the thin vault (proofs/commerce/Vault.lean), as an
//! ordinary function. It is the whole of what a settlement proof attests:
//!
//! - the policy presented is the one the order commits to;
//! - the delivered artifact satisfies that policy (`crate::accept`);
//! - and the statement names this chain, this vault, this order and exactly
//!   these artifact bytes.
//!
//! One proof per order. The buyer's consent is not re-proved here: the token
//! contract checks the buyer's signature over an authorization whose nonce is
//! the same order digest this program commits.
use crate::{Accepted, Policy, Refusal};
use nucleus_proof_commerce::{journals::Acceptance, vault};

/// Re-exported so a guest names the form without a second dependency.
pub use nucleus_proof_commerce::vault::Form;

/// `B` is the statement's and the artifact's bytes: owned (`Vec<u8>`, the
/// default) or borrowed from the input (`&[u8]`, what the order guest uses, so
/// neither is copied out of its input).
#[derive(Clone, Debug)]
pub struct Input<B = Vec<u8>> {
    /// Which vault contract the order is for. It fixes the input layout and
    /// the order digest; a guest program is built for exactly one form.
    pub form: vault::Form,
    pub chain_id: u64,
    pub vault: [u8; 20],
    pub order: vault::Order,
    pub policy: Policy,
    pub statement: B,
    pub artifact: B,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProgramRefusal {
    Malformed,
    PolicyNotInOrder,
    /// The order names a base library. This program has no way to check
    /// that the statement builds on a checked base, so it accepts none.
    UnsupportedBase,
    /// The order names a base and no commitment by the base program for that
    /// base under this policy's axioms was shown.
    BaseNotChecked,
    Acceptance(Refusal),
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProgramRefusal> {
        let (head, tail) = self
            .0
            .split_at_checked(n)
            .ok_or(ProgramRefusal::Malformed)?;
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProgramRefusal> {
        self.take(N)?
            .try_into()
            .map_err(|_| ProgramRefusal::Malformed)
    }
    fn u32(&mut self) -> Result<u32, ProgramRefusal> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, ProgramRefusal> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn slice(&mut self) -> Result<&'a [u8], ProgramRefusal> {
        let n = usize::try_from(self.u32()?).map_err(|_| ProgramRefusal::Malformed)?;
        self.take(n)
    }
    fn text(&mut self) -> Result<String, ProgramRefusal> {
        String::from_utf8(self.slice()?.to_vec()).map_err(|_| ProgramRefusal::Malformed)
    }
}
fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(bytes);
}

impl<B: AsRef<[u8]>> Input<B> {
    pub fn encode(&self) -> Vec<u8> {
        let Input {
            form,
            chain_id,
            vault,
            order,
            policy,
            statement,
            artifact,
        } = self;
        let vault::Order {
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
        let Policy {
            statement_sha256,
            claim,
            permitted_axioms,
            maximum_artifact_bytes,
        } = policy;
        let mut out = Vec::new();
        out.extend_from_slice(&chain_id.to_be_bytes());
        out.extend_from_slice(vault);
        out.extend_from_slice(buyer);
        out.extend_from_slice(seller);
        out.extend_from_slice(asset);
        out.extend_from_slice(amount);
        out.extend_from_slice(verifier);
        out.extend_from_slice(program);
        out.extend_from_slice(policy_hash);
        // The second form's layout has no base; it is the layout the
        // published second-form program reads.
        match form {
            vault::Form::Second => {}
            vault::Form::Third => out.extend_from_slice(base),
        }
        out.extend_from_slice(&fund_by.to_be_bytes());
        out.extend_from_slice(&deliver_by.to_be_bytes());
        out.extend_from_slice(salt);
        out.extend_from_slice(context);
        out.extend_from_slice(statement_sha256);
        put(&mut out, claim.as_bytes());
        out.extend_from_slice(
            &u32::try_from(permitted_axioms.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for axiom in permitted_axioms {
            put(&mut out, axiom.as_bytes());
        }
        out.extend_from_slice(&maximum_artifact_bytes.to_be_bytes());
        put(&mut out, statement.as_ref());
        put(&mut out, artifact.as_ref());
        out
    }
}

impl Input {
    pub fn decode(form: vault::Form, bytes: &[u8]) -> Result<Self, ProgramRefusal> {
        Ok(Input::decode_borrowed(form, bytes)?.to_owned_bytes())
    }
}

impl<'a> Input<&'a [u8]> {
    /// The same input with its statement and artifact copied out.
    pub fn to_owned_bytes(&self) -> Input {
        Input {
            form: self.form,
            chain_id: self.chain_id,
            vault: self.vault,
            order: self.order.clone(),
            policy: self.policy.clone(),
            statement: self.statement.to_vec(),
            artifact: self.artifact.to_vec(),
        }
    }

    /// As `Input::decode`, with the statement and artifact borrowed from
    /// `bytes`.
    pub fn decode_borrowed(form: vault::Form, bytes: &'a [u8]) -> Result<Self, ProgramRefusal> {
        let mut r = Reader(bytes);
        let chain_id = r.u64()?;
        let vault = r.array()?;
        let order = vault::Order {
            buyer: r.array()?,
            seller: r.array()?,
            asset: r.array()?,
            amount: r.array()?,
            verifier: r.array()?,
            program: r.array()?,
            policy_hash: r.array()?,
            base: match form {
                vault::Form::Second => [0; 32],
                vault::Form::Third => r.array()?,
            },
            fund_by: r.u64()?,
            deliver_by: r.u64()?,
            salt: r.array()?,
            context: r.array()?,
        };
        let statement_sha256 = r.array()?;
        let claim = r.text()?;
        let count = r.u32()?;
        let mut permitted_axioms = Vec::new();
        for _ in 0..count {
            permitted_axioms.push(r.text()?);
        }
        let policy = Policy {
            statement_sha256,
            claim,
            permitted_axioms,
            maximum_artifact_bytes: r.u32()?,
        };
        let statement = r.slice()?;
        let artifact = r.slice()?;
        if !r.0.is_empty() {
            return Err(ProgramRefusal::Malformed);
        }
        Ok(Input {
            form,
            chain_id,
            vault,
            order,
            policy,
            statement,
            artifact,
        })
    }
}

/// The 160-byte journal for an accepted delivery to this vault.
pub fn journal<B: AsRef<[u8]>>(
    input: &Input<B>,
    accept: impl FnOnce(&Policy, &[u8], &[u8]) -> Result<Accepted, Refusal>,
) -> Result<[u8; 160], ProgramRefusal> {
    if input.order.base != [0; 32] {
        return Err(ProgramRefusal::UnsupportedBase);
    }
    if input.order.policy_hash != input.policy.hash() {
        return Err(ProgramRefusal::PolicyNotInOrder);
    }
    let accepted = accept(
        &input.policy,
        input.statement.as_ref(),
        input.artifact.as_ref(),
    )
    .map_err(ProgramRefusal::Acceptance)?;
    Ok(Acceptance {
        chain_id: input.chain_id,
        escrow: input.vault,
        order_digest: vault::digest_at(input.form, input.chain_id, input.vault, &input.order),
        artifact_hash: accepted.artifact_keccak256,
    }
    .encode())
}

/// What a prover adds for an order that names a base: where the base ends in
/// the statement, and the payee and rate the base program committed. None of
/// it is trusted: the length must cut the statement at bytes that hash to
/// `order.base`, and payee and rate only select which base commitment is
/// verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseWitness {
    pub length: u32,
    pub payee: [u8; 20],
    pub bps: u16,
}

impl BaseWitness {
    pub const BYTES: usize = 26;

    pub fn encode(&self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        let (length, rest) = out.split_at_mut(4);
        length.copy_from_slice(&self.length.to_be_bytes());
        let (payee, bps) = rest.split_at_mut(20);
        payee.copy_from_slice(&self.payee);
        bps.copy_from_slice(&self.bps.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProgramRefusal> {
        let mut r = Reader(bytes);
        let witness = BaseWitness {
            length: r.u32()?,
            payee: r.array()?,
            bps: u16::from_be_bytes(r.array()?),
        };
        if !r.0.is_empty() {
            return Err(ProgramRefusal::Malformed);
        }
        Ok(witness)
    }
}

/// The bytes the base-aware third-form program reads: the third-form input,
/// then a witness exactly when the order names a base.
pub fn encode_with_base<B: AsRef<[u8]>>(
    input: &Input<B>,
    witness: Option<&BaseWitness>,
) -> Vec<u8> {
    let mut out = input.encode();
    if let Some(witness) = witness {
        out.extend_from_slice(&witness.encode());
    }
    out
}

/// Inverse of `encode_with_base`. A witness is required when the order names
/// a base and refused when it does not.
pub fn decode_with_base(bytes: &[u8]) -> Result<(Input, Option<BaseWitness>), ProgramRefusal> {
    let (input, witness) = decode_with_base_borrowed(bytes)?;
    Ok((input.to_owned_bytes(), witness))
}

/// As `decode_with_base`, with the statement and artifact borrowed from
/// `bytes`.
pub fn decode_with_base_borrowed(
    bytes: &[u8],
) -> Result<(Input<&[u8]>, Option<BaseWitness>), ProgramRefusal> {
    // An order names a base or not; try the layout without a witness first.
    if let Ok(input) = Input::decode_borrowed(vault::Form::Third, bytes) {
        return if input.order.base == [0; 32] {
            Ok((input, None))
        } else {
            Err(ProgramRefusal::Malformed)
        };
    }
    let cut = bytes
        .len()
        .checked_sub(BaseWitness::BYTES)
        .ok_or(ProgramRefusal::Malformed)?;
    let (head, tail) = bytes
        .split_at_checked(cut)
        .ok_or(ProgramRefusal::Malformed)?;
    let input = Input::decode_borrowed(vault::Form::Third, head)?;
    if input.order.base == [0; 32] {
        return Err(ProgramRefusal::Malformed);
    }
    Ok((input, Some(BaseWitness::decode(tail)?)))
}

/// The 160-byte journal for an accepted delivery to a third-form vault, for
/// orders with or without a base.
///
/// With a base: `base_checked` must say whether the base program committed
/// the given journal (in a guest, by `env::verify` against the base program's
/// image ID). Only then are the base's declarations left unchecked, by
/// `accept_on_base`.
pub fn journal_on_base<B: AsRef<[u8]>>(
    input: &Input<B>,
    witness: Option<&BaseWitness>,
    accept: impl FnOnce(&Policy, &[u8], &[u8]) -> Result<Accepted, Refusal>,
    accept_on_base: impl FnOnce(&Policy, &[u8], &[u8], usize, crate::Hash) -> Result<Accepted, Refusal>,
    base_checked: impl FnOnce(&[u8; 160]) -> bool,
) -> Result<[u8; 160], ProgramRefusal> {
    if input.form != vault::Form::Third {
        return Err(ProgramRefusal::Malformed);
    }
    if input.order.policy_hash != input.policy.hash() {
        return Err(ProgramRefusal::PolicyNotInOrder);
    }
    let accepted = match (input.order.base, witness) {
        (base, None) if base == [0; 32] => accept(
            &input.policy,
            input.statement.as_ref(),
            input.artifact.as_ref(),
        ),
        (base, Some(witness)) if base != [0; 32] => {
            let committed = crate::base::journal(
                base,
                crate::base::axioms_hash(&input.policy.permitted_axioms),
                witness.payee,
                witness.bps,
            );
            if !base_checked(&committed) {
                return Err(ProgramRefusal::BaseNotChecked);
            }
            let length = usize::try_from(witness.length).map_err(|_| ProgramRefusal::Malformed)?;
            accept_on_base(
                &input.policy,
                input.statement.as_ref(),
                input.artifact.as_ref(),
                length,
                base,
            )
        }
        _ => return Err(ProgramRefusal::Malformed),
    }
    .map_err(ProgramRefusal::Acceptance)?;
    Ok(Acceptance {
        chain_id: input.chain_id,
        escrow: input.vault,
        order_digest: vault::digest_at(input.form, input.chain_id, input.vault, &input.order),
        artifact_hash: accepted.artifact_keccak256,
    }
    .encode())
}
