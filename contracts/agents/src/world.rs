//! The deployed vault as the agents see it: the contract's calls, the order's
//! ABI form, and a deployment file read back against the chain.
use crate::balanceOfCall;
use crate::prelude::*;

sol! {
    struct VaultOrder { address buyer; address seller; address asset; uint256 amount; address verifier; bytes32 program; bytes32 policyHash; uint64 fundBy; uint64 deliverBy; bytes32 salt; bytes32 context; }
    function fund(VaultOrder o, bytes authorization) returns (bytes32);
    function settle(VaultOrder o, bytes artifact, bytes seal);
    function refund(VaultOrder o);
    function phase(bytes32 d) returns (uint8);
    function artifactOf(bytes32 d) returns (bytes32);
    function treasury() returns (address);
    function feeBps() returns (uint16);
    function maximumFeeBps() returns (uint16);
}

/// The third vault's calls. Its order has a `base` field, so its `fund` and
/// `settle` have different selectors from the second form's.
pub(crate) mod third {
    use crate::prelude::*;
    sol! {
        struct VaultOrder { address buyer; address seller; address asset; uint256 amount; address verifier; bytes32 program; bytes32 policyHash; bytes32 base; uint64 fundBy; uint64 deliverBy; bytes32 salt; bytes32 context; }
        function fund(VaultOrder o, bytes authorization) returns (bytes32);
        function settle(VaultOrder o, bytes artifact, bytes seal);
        function refund(VaultOrder o);
        function claim(address payee, address asset);
        function owed(address payee, address asset) returns (uint256);
        function royaltyOf(bytes32 d) returns (address payee, uint256 amount);

        function maximumTerm() returns (uint64);
        function registry() returns (address);
    }
    pub(crate) fn abi(o: &vault::Order) -> VaultOrder {
        VaultOrder {
            buyer: A::from(o.buyer),
            seller: A::from(o.seller),
            asset: A::from(o.asset),
            amount: U256::from_be_bytes(o.amount),
            verifier: A::from(o.verifier),
            program: o.program.into(),
            policyHash: o.policy_hash.into(),
            base: o.base.into(),
            fundBy: o.fund_by,
            deliverBy: o.deliver_by,
            salt: o.salt.into(),
            context: o.context.into(),
        }
    }
}

/// Calldata for `fund` on a vault of this form.
pub(crate) fn fund_data(form: vault::Form, order: &vault::Order, authorization: &[u8]) -> Vec<u8> {
    let authorization = Bytes::copy_from_slice(authorization);
    match form {
        vault::Form::Second => fundCall {
            o: abi(order),
            authorization,
        }
        .abi_encode(),
        vault::Form::Third => third::fundCall {
            o: third::abi(order),
            authorization,
        }
        .abi_encode(),
    }
}
/// Calldata for `settle` on a vault of this form.
pub(crate) fn settle_data(
    form: vault::Form,
    order: &vault::Order,
    artifact: &[u8],
    seal: Vec<u8>,
) -> Vec<u8> {
    let artifact = Bytes::copy_from_slice(artifact);
    match form {
        vault::Form::Second => settleCall {
            o: abi(order),
            artifact,
            seal: seal.into(),
        }
        .abi_encode(),
        vault::Form::Third => third::settleCall {
            o: third::abi(order),
            artifact,
            seal: seal.into(),
        }
        .abi_encode(),
    }
}
/// Calldata for `refund` on a vault of this form.
pub(crate) fn refund_data(form: vault::Form, order: &vault::Order) -> Vec<u8> {
    match form {
        vault::Form::Second => refundCall { o: abi(order) }.abi_encode(),
        vault::Form::Third => third::refundCall {
            o: third::abi(order),
        }
        .abi_encode(),
    }
}
/// Topic of the `Funded` event; both forms emit the same one.
pub(crate) fn funded_topic() -> [u8; 32] {
    keccak(b"Funded(bytes32,address,address,address,uint256)")
}
/// The artifact carried by calldata that is a direct call to `settle`.
pub(crate) fn artifact_in(form: vault::Form, calldata: &[u8]) -> Option<Vec<u8>> {
    match form {
        vault::Form::Second => settleCall::abi_decode(calldata)
            .ok()
            .map(|call| call.artifact.to_vec()),
        vault::Form::Third => third::settleCall::abi_decode(calldata)
            .ok()
            .map(|call| call.artifact.to_vec()),
    }
}
/// Topic of the `Settled` event a vault of this form emits.
pub(crate) fn settled_topic(form: vault::Form) -> [u8; 32] {
    keccak(match form {
        vault::Form::Second => b"Settled(bytes32,bytes32,uint256,uint256)".as_slice(),
        vault::Form::Third => {
            b"Settled(bytes32,bytes32,uint256,uint256,address,uint256)".as_slice()
        }
    })
}

pub(crate) const FEE_BPS: u16 = 25;
pub(crate) const MAXIMUM_FEE_BPS: u16 = 100;

pub(crate) fn abi(o: &vault::Order) -> VaultOrder {
    VaultOrder {
        buyer: A::from(o.buyer),
        seller: A::from(o.seller),
        asset: A::from(o.asset),
        amount: U256::from_be_bytes(o.amount),
        verifier: A::from(o.verifier),
        program: o.program.into(),
        policyHash: o.policy_hash.into(),
        fundBy: o.fund_by,
        deliverBy: o.deliver_by,
        salt: o.salt.into(),
        context: o.context.into(),
    }
}
/// An ABI-encoded `string` return value.
pub(crate) fn abi_string(bytes: &[u8]) -> Res<String> {
    let word = |at: usize| -> Res<usize> {
        let w = bytes.get(at..at + 32).ok_or("short string reply")?;
        if w[..24].iter().any(|b| *b != 0) {
            return Err("string reply out of range".into());
        }
        Ok(usize::try_from(u64::from_be_bytes(
            w[24..].try_into().map_err(|_| "word")?,
        ))?)
    };
    let start = word(0)?;
    let length = word(start)?;
    let text = bytes
        .get(start + 32..start + 32 + length)
        .ok_or("short string reply")?;
    Ok(String::from_utf8(text.to_vec())?)
}
/// The token's EIP-712 signing domain, as the token itself reports it. Real
/// USDC signs as "USD Coin"; assuming a name makes every authorization fail.
pub(crate) fn token_domain(chain: &Chain, token: Address) -> Res<x402::TokenDomain> {
    Ok(x402::TokenDomain {
        name: abi_string(&chain.call([0; 20], token, &[0x06, 0xfd, 0xde, 0x03])?)?,
        version: abi_string(&chain.call([0; 20], token, &[0x54, 0xfd, 0x4d, 0x50])?)?,
    })
}
/// Price of the one task these agents trade, in the token's smallest unit.
/// Seller and buyer each read `NUCLEUS_TASK_PRICE`; unset, it is 1,000,000
/// (one USDC). The buyer treats its value as the most it will pay.
pub fn wall_clock() -> Res<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}
pub(crate) fn address_arg(text: &str) -> Res<Address> {
    unhex(text)?.try_into().map_err(|_| "address length".into())
}

/// A deployed vault and the token and verifier its orders will use here.
pub(crate) struct World {
    pub(crate) chain: Chain,
    pub(crate) deployment: vault::Deployment,
    pub(crate) token: Address,
    pub(crate) domain: x402::TokenDomain,
    pub(crate) verifier: Address,
    /// Base libraries the deployment file lists (`"bases": ["0x..."]`), each
    /// with the entry the vault's registry reports now. A base the registry
    /// does not know is left out. A buyer accepts orders naming these only.
    pub(crate) bases: Vec<([u8; 32], vault::Entry)>,
}
impl World {
    /// Read the file, then take the vault's own parameters from the chain.
    pub(crate) fn read(path: &str) -> Res<Self> {
        let value: Value = serde_json::from_slice(&fs::read(path)?)?;
        let field = |name: &str| -> Res<Address> {
            address_arg(value[name].as_str().ok_or("deployment field missing")?)
        };
        let rpc = value["rpc"].as_str().ok_or("rpc missing")?.to_owned();
        let chain = Chain::connect(&rpc)?;
        let vault = field("vault")?;
        let word = |data: Vec<u8>| -> Res<Vec<u8>> { chain.call([0; 20], vault, &data) };
        let treasury: Address = word(treasuryCall {}.abi_encode())?[12..]
            .try_into()
            .map_err(|_| "treasury")?;
        let small = |bytes: Vec<u8>| -> Res<u16> {
            Ok(u16::from_be_bytes(
                bytes[30..].try_into().map_err(|_| "u16")?,
            ))
        };
        // Which contract this is comes from the file; what it was deployed
        // with comes from the chain. A file without `kind` is a second-form
        // vault, as every file written before the third form is.
        let rules = match value["kind"].as_str() {
            None | Some("vault2") => vault::Rules::Second,
            Some("vault3") => vault::Rules::Third {
                maximum_term: u64::from_be_bytes(
                    word(third::maximumTermCall {}.abi_encode())?
                        .get(24..32)
                        .ok_or("maximumTerm reply")?
                        .try_into()
                        .map_err(|_| "maximumTerm")?,
                ),
                registry: word(third::registryCall {}.abi_encode())?
                    .get(12..32)
                    .ok_or("registry reply")?
                    .try_into()
                    .map_err(|_| "registry")?,
            },
            Some(other) => return Err(format!("unknown vault kind {other:?}").into()),
        };
        let deployment = vault::Deployment {
            chain_id: chain.id,
            vault,
            treasury,
            fee_bps: small(word(feeBpsCall {}.abi_encode())?)?,
            maximum_fee_bps: small(word(maximumFeeBpsCall {}.abi_encode())?)?,
            rules,
        };
        let token = field("token")?;
        let domain = token_domain(&chain, token)?;
        let mut bases = Vec::new();
        if let (Some(listed), vault::Rules::Third { registry, .. }) =
            (value["bases"].as_array(), &deployment.rules)
        {
            for base in listed {
                let id: [u8; 32] = unhex(base.as_str().ok_or("base id")?)?
                    .try_into()
                    .map_err(|_| "base id length")?;
                if let Some(entry) = registry_entry(&chain, *registry, id)? {
                    bases.push((id, entry));
                }
            }
        }
        Ok(Self {
            chain,
            deployment,
            token,
            domain,
            verifier: field("verifier")?,
            bases,
        })
    }
    /// What a third-form vault has booked for `payee` in the deployment's
    /// token and not yet paid.
    pub(crate) fn owed(&self, payee: Address) -> Res<U256> {
        Ok(U256::from_be_slice(
            &self.chain.call(
                [0; 20],
                self.deployment.vault,
                &third::owedCall {
                    payee: A::from(payee),
                    asset: A::from(self.token),
                }
                .abi_encode(),
            )?,
        ))
    }
    pub(crate) fn balance(&self, owner: Address) -> Res<U256> {
        Ok(U256::from_be_slice(
            &self.chain.call(
                owner,
                self.token,
                &balanceOfCall {
                    account: A::from(owner),
                }
                .abi_encode(),
            )?,
        ))
    }
}

/// What a base registry reports for a base: `None` for a base it does not
/// know. `entryOf(bytes32) returns (address payee, uint16 bps)`.
pub(crate) fn registry_entry(
    chain: &Chain,
    registry: Address,
    base: [u8; 32],
) -> Res<Option<vault::Entry>> {
    let selector = crate::chain::keccak(b"entryOf(bytes32)");
    let data = [&selector[..4], &base[..]].concat();
    let reply = chain.call([0; 20], registry, &data)?;
    let payee: Address = reply
        .get(12..32)
        .ok_or("registry reply")?
        .try_into()
        .map_err(|_| "registry payee")?;
    let bps = u16::from_be_bytes(
        reply
            .get(62..64)
            .ok_or("registry reply")?
            .try_into()
            .map_err(|_| "registry rate")?,
    );
    Ok((payee != [0; 20]).then_some(vault::Entry { payee, bps }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order() -> vault::Order {
        vault::Order {
            buyer: [1; 20],
            seller: [2; 20],
            asset: [4; 20],
            amount: U256::from(1_000_000u64).to_be_bytes(),
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

    /// Calldata built for one form of vault is not a call the other accepts,
    /// and each form's settle calldata gives back its artifact.
    #[test]
    fn each_form_has_its_own_calls_and_event() {
        let (second, third) = (vault::Form::Second, vault::Form::Third);
        let fund = |form| fund_data(form, &order(), &[7; 65]);
        assert_ne!(fund(second)[..4], fund(third)[..4]);
        assert_eq!(fund(third).len(), fund(second).len() + 32);
        let settle = |form| settle_data(form, &order(), b"artifact", vec![1, 2, 3]);
        assert_ne!(settle(second)[..4], settle(third)[..4]);
        for form in [second, third] {
            assert_eq!(artifact_in(form, &settle(form)), Some(b"artifact".to_vec()));
            assert_eq!(artifact_in(form, &fund(form)), None);
        }
        assert_eq!(artifact_in(second, &settle(third)), None);
        assert_eq!(artifact_in(third, &settle(second)), None);
        assert_ne!(settled_topic(second), settled_topic(third));
        // The selectors the compiled contracts answer to.
        let selector = |signature: &str| keccak(signature.as_bytes())[..4].to_vec();
        let order3 = "(address,address,address,uint256,address,bytes32,bytes32,bytes32,uint64,uint64,bytes32,bytes32)";
        assert_eq!(fund(third)[..4], selector(&format!("fund({order3},bytes)")));
        assert_eq!(
            settle(third)[..4],
            selector(&format!("settle({order3},bytes,bytes)"))
        );
    }
}
