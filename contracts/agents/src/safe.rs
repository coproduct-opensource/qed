//! Create a Safe (v1.4.1) through the canonical proxy factory, to hold a
//! vault's treasury, and read it back.
//!
//!   safe-create RPC KEYFILE OWNER_ADDRESS SALT_NONCE [--dry-run]
//!
//! The singleton, factory and fallback handler are Safe's own v1.4.1
//! deployments, as recorded in github.com/safe-global/safe-deployments
//! (src/assets/v1.4.1/{safe_l2,safe_proxy_factory,compatibility_fallback_handler}.json,
//! "canonical" entries). Their code hashes are checked on the chain before
//! anything is sent. The Safe's address is predicted (CREATE2) before the
//! transaction and must equal the deployed one.
use crate::prelude::*;

mod abi {
    alloy_sol_types::sol! {
        function setup(address[] _owners, uint256 _threshold, address to, bytes data, address fallbackHandler, address paymentToken, uint256 payment, address paymentReceiver);
        function createProxyWithNonce(address _singleton, bytes initializer, uint256 saltNonce) returns (address proxy);
        function proxyCreationCode() returns (bytes);
        function getOwners() returns (address[]);
        function getThreshold() returns (uint256);
        function VERSION() returns (string);
    }
}

/// (address, keccak-256 of runtime code) from safe-deployments v1.4.1, canonical.
const SINGLETON_L2: (&str, &str) = (
    "0x29fcb43b46531bca003ddc8fcb67ffe91900c762",
    "0xb1f926978a0f44a2c0ec8fe822418ae969bd8c3f18d61e5103100339894f81ff",
);
const FACTORY: (&str, &str) = (
    "0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67",
    "0x50c3cdc4074750a7a974204a716c999edd37482f907608d960b2b025ee0b3317",
);
const FALLBACK_HANDLER: (&str, &str) = (
    "0xfd0732dc9e303f09fcef3a7388ad10a83459ec99",
    "0x7c6007a5d711cea8dfd5d91f5940ec29c7f200fe511eb1fc1397b367af3c42f9",
);
/// keccak256("fallback_manager.handler.address"), where a Safe keeps its handler.
const FALLBACK_HANDLER_SLOT: &str =
    "0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5";

fn address(text: &str) -> Res<Address> {
    unhex(text)?.try_into().map_err(|_| "address length".into())
}
fn word(text: &str) -> Res<[u8; 32]> {
    unhex(text)?.try_into().map_err(|_| "word length".into())
}

/// Check that `contract` holds code with the recorded hash.
fn known(chain: &Chain, (at, hash): (&str, &str), what: &str) -> Res<Address> {
    let at = address(at)?;
    let code = chain.code(at)?;
    if code.is_empty() {
        return Err(format!("no {what} at {}", hex(&at)).into());
    }
    if keccak(&code) != word(hash)? {
        return Err(format!("{what} at {} has unexpected code", hex(&at)).into());
    }
    println!(
        "  ok   {what} {}: {} bytes, code hash matches safe-deployments v1.4.1",
        hex(&at),
        code.len()
    );
    Ok(at)
}

/// The initializer a one-owner Safe is set up with.
pub fn initializer(owner: Address, fallback: Address) -> Vec<u8> {
    abi::setupCall {
        _owners: vec![A::from(owner)],
        _threshold: U256::from(1u8),
        to: A::ZERO,
        data: Bytes::new(),
        fallbackHandler: A::from(fallback),
        paymentToken: A::ZERO,
        payment: U256::ZERO,
        paymentReceiver: A::ZERO,
    }
    .abi_encode()
}

/// CREATE2 address of `createProxyWithNonce(singleton, initializer, nonce)`
/// (SafeProxyFactory 1.4.1: salt = keccak(keccak(initializer) ++ nonce),
/// init code = proxyCreationCode ++ uint256(singleton)).
pub fn predicted(
    factory: Address,
    creation_code: &[u8],
    singleton: Address,
    initializer: &[u8],
    salt_nonce: U256,
) -> Address {
    let salt = keccak(
        &[
            &keccak(initializer)[..],
            &salt_nonce.to_be_bytes::<32>()[..],
        ]
        .concat(),
    );
    let mut singleton_word = [0u8; 32];
    singleton_word[12..].copy_from_slice(&singleton);
    let init = keccak(&[creation_code, &singleton_word[..]].concat());
    let mut out = [0; 20];
    out.copy_from_slice(
        &keccak(&[&[0xffu8][..], &factory[..], &salt[..], &init[..]].concat())[12..],
    );
    out
}

pub fn safe_create(args: &[String]) -> Res<()> {
    let (args, dry) = match args {
        [rest @ .., flag] if flag == "--dry-run" => (rest, true),
        _ => (args, false),
    };
    let [rpc, keyfile, owner, salt_nonce] = args else {
        return Err("usage: safe-create RPC KEYFILE OWNER_ADDRESS SALT_NONCE [--dry-run]".into());
    };
    if !Path::new(keyfile).exists() {
        return Err("key file does not exist".into());
    }
    let chain = Chain::connect(rpc)?;
    let payer = Keys::load_or_create(keyfile)?.wallet.clone();
    let owner = address(owner)?;
    let salt_nonce: U256 = U256::from_str_radix(salt_nonce, 10).map_err(|_| "salt nonce")?;
    let singleton = known(&chain, SINGLETON_L2, "SafeL2 singleton")?;
    let factory = known(&chain, FACTORY, "SafeProxyFactory")?;
    let fallback = known(&chain, FALLBACK_HANDLER, "CompatibilityFallbackHandler")?;
    let creation = abi::proxyCreationCodeCall::abi_decode_returns(&chain.call(
        [0; 20],
        factory,
        &abi::proxyCreationCodeCall {}.abi_encode(),
    )?)?;
    let init = initializer(owner, fallback);
    let safe = predicted(factory, &creation, singleton, &init, salt_nonce);
    println!(
        "chain {} owner {} threshold 1; salt nonce {salt_nonce}; initializer {}",
        chain.id,
        hex(&owner),
        hex(&init)
    );
    println!("  predicted Safe address {}", hex(&safe));
    if !chain.code(safe)?.is_empty() {
        return Err("a contract already exists at the predicted address".into());
    }
    let call = abi::createProxyWithNonceCall {
        _singleton: A::from(singleton),
        initializer: Bytes::from(init),
        saltNonce: salt_nonce,
    }
    .abi_encode();
    println!("  calldata to factory {}: {}", hex(&factory), hex(&call));
    let chain = if dry { chain.dry() } else { chain };
    let before = chain.balance(address_of(&payer))?;
    let receipt = chain.send(&payer, Some(factory), 0, &call)?;
    if !receipt.success {
        return Err(format!("Safe creation failed in tx {}", receipt.transaction).into());
    }
    println!(
        "  ok   Safe creation tx {} gas {}; payer spent {} wei",
        receipt.transaction,
        receipt.gas_used,
        before.saturating_sub(chain.balance(address_of(&payer))?)
    );
    read_back(&chain, safe, owner, singleton, fallback)
}

/// Read a one-owner Safe back from the chain and compare with what was asked.
pub fn read_back(
    chain: &Chain,
    safe: Address,
    owner: Address,
    singleton: Address,
    fallback: Address,
) -> Res<()> {
    let code = chain.code(safe)?;
    if code.is_empty() {
        return Err("no contract at the predicted Safe address".into());
    }
    let owners = abi::getOwnersCall::abi_decode_returns(&chain.call(
        [0; 20],
        safe,
        &abi::getOwnersCall {}.abi_encode(),
    )?)?;
    let threshold = abi::getThresholdCall::abi_decode_returns(&chain.call(
        [0; 20],
        safe,
        &abi::getThresholdCall {}.abi_encode(),
    )?)?;
    let version = abi::VERSIONCall::abi_decode_returns(&chain.call(
        [0; 20],
        safe,
        &abi::VERSIONCall {}.abi_encode(),
    )?)?;
    let singleton_slot = chain.storage(safe, [0; 32])?;
    let handler_slot = chain.storage(safe, word(FALLBACK_HANDLER_SLOT)?)?;
    let owners: Vec<Address> = owners.iter().map(|a| a.into_array()).collect();
    println!(
        "  read Safe {}: owners [{}], threshold {threshold}, version {version}, singleton {}, fallback handler {}, proxy {} bytes",
        hex(&safe),
        owners.iter().map(|a| hex(a)).collect::<Vec<_>>().join(", "),
        hex(&singleton_slot[12..]),
        hex(&handler_slot[12..]),
        code.len()
    );
    if owners != vec![owner]
        || threshold != U256::from(1u8)
        || version != "1.4.1"
        || singleton_slot[12..] != singleton
        || handler_slot[12..] != fallback
    {
        return Err("the Safe does not report what it was set up with".into());
    }
    println!("  ok   Safe matches: one owner, threshold 1, v1.4.1, recorded singleton and handler");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every input moves the prediction. Agreement with the real factory is
    /// checked at run time: `safe-create` refuses unless the deployed address
    /// equals the prediction.
    #[test]
    fn the_prediction_changes_with_every_input_and_is_stable() {
        let factory = [0x11; 20];
        let creation = [0x60, 0x80, 0x60, 0x40];
        let singleton = [0x22; 20];
        let init = initializer([0x33; 20], [0x44; 20]);
        let a = predicted(factory, &creation, singleton, &init, U256::from(1u8));
        assert_eq!(
            a,
            predicted(factory, &creation, singleton, &init, U256::from(1u8))
        );
        assert_ne!(
            a,
            predicted(factory, &creation, singleton, &init, U256::from(2u8))
        );
        assert_ne!(
            a,
            predicted([0x12; 20], &creation, singleton, &init, U256::from(1u8))
        );
        assert_ne!(
            a,
            predicted(factory, &creation, [0x23; 20], &init, U256::from(1u8))
        );
        let other = initializer([0x34; 20], [0x44; 20]);
        assert_ne!(
            a,
            predicted(factory, &creation, singleton, &other, U256::from(1u8))
        );
    }

    #[test]
    fn the_initializer_names_one_owner_threshold_one_and_the_handler() {
        let init = initializer([0x33; 20], [0x44; 20]);
        let decoded = abi::setupCall::abi_decode(&init).unwrap();
        assert_eq!(decoded._owners, vec![A::from([0x33; 20])]);
        assert_eq!(decoded._threshold, U256::from(1u8));
        assert_eq!(decoded.fallbackHandler, A::from([0x44; 20]));
        assert_eq!(decoded.to, A::ZERO);
        assert!(decoded.data.is_empty());
        assert_eq!(decoded.paymentToken, A::ZERO);
        assert_eq!(decoded.payment, U256::ZERO);
    }

    #[test]
    fn create_addresses_follow_the_rlp_rule() {
        // The widely cited example: sender 0x6ac7…dbf0, nonces 0 and 1.
        let sender: Address = unhex("0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            hex(&crate::chain::create_address(sender, 0)),
            "0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d"
        );
        assert_eq!(
            hex(&crate::chain::create_address(sender, 1)),
            "0x343c43a37d37dff08ae8c4a11544c718abb4fcf8"
        );
    }
}
