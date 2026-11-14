//! Relayed EIP-3009 transfers: a seller with no ETH sweeps what a vault paid
//! it (docs/rfcs/qed-relayer-2026-11-13.md §15, rules T-1 to T-9).
//!
//! The relayer sends exactly one more call: USDC's
//! `transferWithAuthorization` (v, r, s form), signed by the seller. What it
//! may send is decided here, by `admit`, and only an `Admitted` value, which
//! nothing else can construct, reaches `Lane::send_transfer`.
use super::{Lane, Refusal, chain_refusal};
use crate::prelude::*;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

sol! {
    function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s);
    function authorizationState(address authorizer, bytes32 nonce) returns (bool);
    function DOMAIN_SEPARATOR() returns (bytes32);
}

/// T-4: an authorization must stay valid at least this long after the latest
/// block, so that it can still land.
pub const LANDING_MARGIN: u64 = 60;
/// T-6: the most claim hashes one request may name.
pub const MAXIMUM_CLAIMS: usize = 16;

/// `secp256k1`'s group order halved: a canonical signature has `s` at most
/// this, as FiatToken's `ECRecover` requires.
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// The lane's transfer configuration (T-1, T-8).
#[derive(Clone, Debug)]
pub struct TransferConfig {
    /// The one token whose `transferWithAuthorization` is relayed.
    pub token: Address,
    /// Its EIP-712 domain separator, computed from its name, version, chain
    /// and address and checked against the token at start.
    pub domain: [u8; 32],
    /// Relayed transfers per `from` in any 24 hours.
    pub per_address_per_day: usize,
    /// Relayed transfers in all, in any 24 hours.
    pub per_day: usize,
}

/// The EIP-712 domain separator of a token.
pub fn domain_separator(name: &str, version: &str, chain_id: u64, token: Address) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(&keccak(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    ));
    bytes.extend_from_slice(&keccak(name.as_bytes()));
    bytes.extend_from_slice(&keccak(version.as_bytes()));
    bytes.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    bytes.extend_from_slice(&[0; 12]);
    bytes.extend_from_slice(&token);
    keccak(&bytes)
}

/// The token's own `DOMAIN_SEPARATOR()`.
pub fn domain_on_chain(chain: &Chain, token: Address) -> Res<[u8; 32]> {
    chain
        .call([0; 20], token, &DOMAIN_SEPARATORCall {}.abi_encode())?
        .try_into()
        .map_err(|_| "DOMAIN_SEPARATOR reply is not one word".into())
}

/// One EIP-3009 transfer authorization, as signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    pub from: Address,
    pub to: Address,
    pub value: u128,
    pub valid_after: u64,
    pub valid_before: u64,
    pub nonce: [u8; 32],
}
impl Authorization {
    /// The EIP-712 digest the token checks the signature against.
    pub fn digest(&self, domain: &[u8; 32]) -> [u8; 32] {
        let Self {
            from,
            to,
            value,
            valid_after,
            valid_before,
            nonce,
        } = self;
        let mut message = Vec::with_capacity(224);
        message.extend_from_slice(&keccak(x402::TRANSFER_TYPE.as_bytes()));
        for address in [from, to] {
            message.extend_from_slice(&[0; 12]);
            message.extend_from_slice(address);
        }
        message.extend_from_slice(&U256::from(*value).to_be_bytes::<32>());
        message.extend_from_slice(&U256::from(*valid_after).to_be_bytes::<32>());
        message.extend_from_slice(&U256::from(*valid_before).to_be_bytes::<32>());
        message.extend_from_slice(nonce);
        let mut bytes = Vec::with_capacity(66);
        bytes.extend_from_slice(&[0x19, 0x01]);
        bytes.extend_from_slice(domain);
        bytes.extend_from_slice(&keccak(&message));
        keccak(&bytes)
    }
    /// Sign with `from`'s wallet key; the calldata the token takes.
    pub fn sign(&self, key: &SigningKey, domain: &[u8; 32]) -> Signed {
        let WalletSignature(signature) = crate::sign(key, self.digest(domain));
        let mut r = [0; 32];
        let mut s = [0; 32];
        r.copy_from_slice(&signature[..32]);
        s.copy_from_slice(&signature[32..64]);
        Signed {
            authorization: self.clone(),
            v: signature[64],
            r,
            s,
        }
    }
}

/// An authorization with its signature, as it travels in calldata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    pub authorization: Authorization,
    pub v: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
}
impl Signed {
    pub fn calldata(&self) -> Vec<u8> {
        let a = &self.authorization;
        transferWithAuthorizationCall {
            from: A::from(a.from),
            to: A::from(a.to),
            value: U256::from(a.value),
            validAfter: U256::from(a.valid_after),
            validBefore: U256::from(a.valid_before),
            nonce: a.nonce.into(),
            v: self.v,
            r: self.r.into(),
            s: self.s.into(),
        }
        .abi_encode()
    }
    /// T-3: the address the signature recovers to under `domain`, if it is
    /// in the one form the token accepts (v 27 or 28, low s, r and s not 0).
    pub fn signer(&self, domain: &[u8; 32]) -> Option<Address> {
        let recovery = self.v.checked_sub(27).filter(|v| *v <= 1)?;
        if self.r == [0; 32] || self.s == [0; 32] || self.s > HALF_ORDER {
            return None;
        }
        let mut rs = [0; 64];
        rs[..32].copy_from_slice(&self.r);
        rs[32..].copy_from_slice(&self.s);
        let signature = Signature::from_slice(&rs).ok()?;
        let key = VerifyingKey::recover_from_prehash(
            &self.authorization.digest(domain),
            &signature,
            RecoveryId::try_from(recovery).ok()?,
        )
        .ok()?;
        let point = key.to_sec1_point(false);
        keccak(&point.as_bytes()[1..])[12..].try_into().ok()
    }
}

/// T-2: the calldata is exactly `transferWithAuthorization` (v, r, s), in the
/// encoding the relayer itself produces.
pub fn parse(data: &[u8]) -> Result<Signed, &'static str> {
    if data.get(..4) != Some(transferWithAuthorizationCall::SELECTOR.as_slice()) {
        return Err("only transferWithAuthorization is relayed to the token");
    }
    let call = transferWithAuthorizationCall::abi_decode(data)
        .map_err(|_| "transferWithAuthorization calldata does not decode")?;
    if call.abi_encode() != data {
        return Err("calldata is not the canonical encoding of its call");
    }
    let small = |value: U256, what: &'static str| -> Result<u64, &'static str> {
        u64::try_from(value).map_err(|_| what)
    };
    Ok(Signed {
        authorization: Authorization {
            from: call.from.into_array(),
            to: call.to.into_array(),
            value: u128::try_from(call.value).map_err(|_| "value out of range")?,
            valid_after: small(call.validAfter, "validAfter out of range")?,
            valid_before: small(call.validBefore, "validBefore out of range")?,
            nonce: call.nonce.0,
        },
        v: call.v,
        r: call.r.0,
        s: call.s.0,
    })
}

pub fn claimed_topic() -> [u8; 32] {
    keccak(b"Claimed(address,address,uint256)")
}
pub fn transfer_topic() -> [u8; 32] {
    keccak(b"Transfer(address,address,uint256)")
}
fn word_of(address: Address) -> [u8; 32] {
    let mut word = [0; 32];
    word[12..].copy_from_slice(&address);
    word
}
fn same_word(log_topic: &Value, word: &[u8; 32]) -> bool {
    log_topic
        .as_str()
        .and_then(|text| unhex(text).ok())
        .is_some_and(|bytes| bytes == word)
}
fn amount_of(log: &Value) -> Res<u128> {
    let data = unhex(log["data"].as_str().ok_or("log data expected")?)?;
    u128::try_from(U256::try_from_be_slice(&data).ok_or("log data is not one word")?)
        .map_err(|_| "log amount out of range".into())
}
fn number(value: &Value) -> Res<u64> {
    Ok(u64::from_str_radix(
        value
            .as_str()
            .ok_or("quantity expected")?
            .trim_start_matches("0x"),
        16,
    )?)
}

/// T-6, as read from the chain for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Paid {
    /// C: what the named claims paid `from` in the token, from allow-listed
    /// vaults only.
    pub claimed: u128,
    /// b0: the lowest block among the named claims.
    pub since: u64,
    /// The head the scan ran to.
    pub head: u64,
    /// O: every token transfer out of `from` in `since..=head`.
    pub out: u128,
}
impl Paid {
    /// The most a relayed transfer may move: C − O.
    pub fn bound(&self) -> u128 {
        bound(self.claimed, self.out)
    }
}
/// T-6's arithmetic: C − O, and 0 when O ≥ C.
pub fn bound(claimed: u128, out: u128) -> u128 {
    claimed.saturating_sub(out)
}

/// T-6: read C, b0 and O from the chain, cache-free. `Err` is a refusal: 400
/// for a malformed list, 403 for a claim that is not one, 503 when the chain
/// cannot answer.
pub fn paid(
    chain: &Chain,
    vaults: &[Address],
    token: Address,
    from: Address,
    claims: &[String],
) -> Result<Paid, Refusal> {
    let unavailable =
        |e: Box<dyn std::error::Error>| (503, format!("chain answered malformed: {e}"));
    if claims.is_empty() || claims.len() > MAXIMUM_CLAIMS {
        return Err((
            400,
            format!("name 1 to {MAXIMUM_CLAIMS} claim transactions that paid from"),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    let (claimed_topic, from_word, token_word) = (claimed_topic(), word_of(from), word_of(token));
    let mut claimed: u128 = 0;
    let mut since = u64::MAX;
    for hash in claims {
        let bytes = unhex(hash).map_err(|_| (400, "claim hash malformed".to_owned()))?;
        if bytes.len() != 32 || !seen.insert(bytes) {
            return Err((400, "claim hashes must be distinct 32-byte hashes".into()));
        }
        let receipt = chain
            .rpc("eth_getTransactionReceipt", json!([hash]))
            .map_err(|e| chain_refusal(e.as_ref(), "receipt"))?;
        if receipt.is_null() {
            return Err((403, format!("claim {hash} is not on chain")));
        }
        if number(&receipt["status"]).map_err(unavailable)? != 1 {
            return Err((403, format!("claim {hash} reverted")));
        }
        let mut here: u128 = 0;
        for log in receipt["logs"].as_array().into_iter().flatten() {
            let emitter: Option<Address> = log["address"]
                .as_str()
                .and_then(|text| unhex(text).ok())
                .and_then(|bytes| bytes.try_into().ok());
            let topics = log["topics"].as_array();
            let matches = emitter.is_some_and(|e| vaults.contains(&e))
                && topics.is_some_and(|t| {
                    t.len() == 3
                        && same_word(&t[0], &claimed_topic)
                        && same_word(&t[1], &from_word)
                        && same_word(&t[2], &token_word)
                });
            if matches {
                here = here.saturating_add(amount_of(log).map_err(unavailable)?);
            }
        }
        if here == 0 {
            return Err((
                403,
                format!("{hash} pays from nothing in this token from an allow-listed vault"),
            ));
        }
        claimed = claimed.saturating_add(here);
        since = since.min(number(&receipt["blockNumber"]).map_err(unavailable)?);
    }
    let head = number(
        &chain
            .rpc("eth_blockNumber", json!([]))
            .map_err(|e| chain_refusal(e.as_ref(), "head"))?,
    )
    .map_err(unavailable)?;
    let outgoing = chain
        .logs(
            &json!({"address": hex(&token), "topics": [hex(&transfer_topic()), hex(&from_word)]}),
            since,
            head,
        )
        .map_err(|e| chain_refusal(e.as_ref(), "transfer logs"))?;
    let mut out: u128 = 0;
    for log in &outgoing {
        out = out.saturating_add(amount_of(log).map_err(unavailable)?);
    }
    Ok(Paid {
        claimed,
        since,
        head,
        out,
    })
}

/// Whether `from` has used `nonce` with the token.
pub fn nonce_used(chain: &Chain, token: Address, from: Address, nonce: [u8; 32]) -> Res<bool> {
    let word = chain.call(
        [0; 20],
        token,
        &authorizationStateCall {
            authorizer: A::from(from),
            nonce: nonce.into(),
        }
        .abi_encode(),
    )?;
    Ok(word.last().is_some_and(|b| *b == 1))
}

/// Evidence that one transfer passed T-1 to T-6. Only `admit` makes one, and
/// `Lane::send_transfer` takes it by value, so one admission sends at most
/// one transaction (ADR 0007 C-1, C-4).
#[must_use]
#[derive(Debug)]
pub struct Admitted {
    token: Address,
    data: Vec<u8>,
    from: Address,
    value: u128,
    paid: Paid,
}
impl Admitted {
    pub fn from(&self) -> Address {
        self.from
    }
    pub fn value(&self) -> u128 {
        self.value
    }
    pub fn paid(&self) -> Paid {
        self.paid
    }
    pub(super) fn into_call(self) -> (Address, Vec<u8>, Address) {
        (self.token, self.data, self.from)
    }
}

/// The checks that need no chain: T-2 and T-3. The authorization, for the
/// rate limits, which count before any chain work is done.
pub fn check_offline(config: &TransferConfig, data: &[u8]) -> Result<Signed, Refusal> {
    let signed = parse(data).map_err(|why| (422, why.to_owned()))?;
    let a = &signed.authorization;
    if a.value == 0 {
        return Err((422, "value must be more than 0".into()));
    }
    if a.to == a.from || a.to == [0; 20] {
        return Err((422, "to must be another, non-zero address".into()));
    }
    if signed.signer(&config.domain) != Some(a.from) {
        return Err((
            422,
            "the signature is not from's over this authorization".into(),
        ));
    }
    Ok(signed)
}

/// T-4 to T-6, read from the chain for this request.
pub fn admit(
    lane: &Lane,
    config: &TransferConfig,
    signed: Signed,
    claims: &[String],
) -> Result<Admitted, Refusal> {
    let a = &signed.authorization;
    let now = lane
        .chain
        .timestamp()
        .map_err(|e| chain_refusal(e.as_ref(), "time"))?;
    if a.valid_after >= now {
        return Err((422, "the authorization is not valid yet".into()));
    }
    if a.valid_before < now.saturating_add(LANDING_MARGIN) {
        return Err((
            422,
            format!("the authorization expires within {LANDING_MARGIN} s"),
        ));
    }
    if nonce_used(&lane.chain, config.token, a.from, a.nonce)
        .map_err(|e| chain_refusal(e.as_ref(), "authorizationState"))?
    {
        return Err((422, "the authorization's nonce is already used".into()));
    }
    let paid = paid(
        &lane.chain,
        &lane.config.vaults,
        config.token,
        a.from,
        claims,
    )?;
    if a.value > paid.bound() {
        return Err((
            422,
            format!(
                "value {} is above the bound {}: claimed {} less {} moved out since block {}",
                a.value,
                paid.bound(),
                paid.claimed,
                paid.out,
                paid.since
            ),
        ));
    }
    Ok(Admitted {
        token: config.token,
        data: signed.calldata(),
        from: a.from,
        value: a.value,
        paid,
    })
}
