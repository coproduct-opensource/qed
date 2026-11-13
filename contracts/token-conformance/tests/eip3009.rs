//! The vault's x402 funding authorization, run against real token bytecode.
//!
//! The token is the FiatToken implementation behind Base Sepolia USDC
//! (proxy 0x036CbD53842c5426634e7929541eC2318f3dCF7e, implementation
//! 0xd74cc5d436923b8ba2c179b4bca2841d8a52c5b5), runtime code read with
//! eth_getCode on 2026-11-11 and pinned by Keccak-256 below. It runs in a
//! local EVM with fresh storage, initialised through its own public methods.
//!
//! This exercises the token half only. The vault itself runs in
//! contracts/vault-conformance; here an externally owned address stands in as
//! the payee.
use alloy_sol_types::{SolCall, sol};
use k256::ecdsa::SigningKey;
use nucleus_proof_commerce::{
    WalletSignature,
    vault::{self, Deployment, Order},
    x402,
};
use revm::{
    Context, ExecuteCommitEvm, MainBuilder, MainContext,
    context::TxEnv,
    context_interface::result::{ExecutionResult, Output},
    database::{CacheDB, EmptyDB},
    primitives::{Address, B256, Bytes, TxKind, U256, keccak256},
    state::{AccountInfo, Bytecode},
};

sol! {
    function initialize(string tokenName, string tokenSymbol, string tokenCurrency, uint8 tokenDecimals, address newMasterMinter, address newPauser, address newBlacklister, address newOwner);
    function initializeV2(string newName);
    function initializeV2_1(address lostAndFound);
    function initializeV2_2(address[] accountsToBlacklist, string newSymbol);
    function configureMinter(address minter, uint256 minterAllowedAmount) returns (bool);
    function mint(address to, uint256 amount) returns (bool);
    function balanceOf(address account) returns (uint256);
    function authorizationState(address authorizer, bytes32 nonce) returns (bool);
    function receiveWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s);
    function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s);
}

const CHAIN: u64 = 84532;
const TOKEN: Address = Address::new([0x70; 20]);
const ESCROW: Address = Address::new([0xe5; 20]);
const ADMIN: Address = Address::new([0xad; 20]);
const RELAYER: Address = Address::new([0x4e; 20]);
const PRICE: u64 = 1_000_000;
const DEADLINE: u64 = 1_000;
const CODE_KECCAK: &str = "1254951e5483b882fd5def9452f58fe786eb3380c0bf9bb2744fa21a0a97a16c";
/// The token delegates signature checks to this separately deployed library.
const LIBRARY: Address = Address::new([
    0xba, 0x3b, 0x60, 0xc2, 0x1e, 0x28, 0xc4, 0x1d, 0xf4, 0xba, 0xbd, 0x90, 0xf2, 0x28, 0xe1, 0xd3,
    0x68, 0x62, 0x7d, 0xa6,
]);
const LIBRARY_KECCAK: &str = "0855e691adf48a1a47437ec347119ebfea7d3997af9a17f253178569753665c0";

type Db = CacheDB<EmptyDB>;
struct Chain {
    db: Db,
}
enum Outcome {
    Returned(Bytes),
    Reverted(String),
}

impl Chain {
    fn new() -> Self {
        let mut db = Db::default();
        for (address, hex, pinned) in [
            (
                TOKEN,
                include_str!("../fixtures/fiat-token-impl.runtime.hex"),
                CODE_KECCAK,
            ),
            (
                LIBRARY,
                include_str!("../fixtures/signature-checker.runtime.hex"),
                LIBRARY_KECCAK,
            ),
        ] {
            let hex = hex.trim();
            let code: Vec<u8> = (2..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(format!("{:x}", keccak256(&code)), pinned);
            db.insert_account_info(
                address,
                AccountInfo::default().with_code(Bytecode::new_raw(code.into())),
            );
        }
        let mut chain = Self { db };
        for call in [
            initializeCall {
                tokenName: "USDC".into(),
                tokenSymbol: "USDC".into(),
                tokenCurrency: "USD".into(),
                tokenDecimals: 6,
                newMasterMinter: ADMIN,
                newPauser: ADMIN,
                newBlacklister: ADMIN,
                newOwner: ADMIN,
            }
            .abi_encode(),
            initializeV2Call {
                newName: "USDC".into(),
            }
            .abi_encode(),
            initializeV2_1Call {
                lostAndFound: ADMIN,
            }
            .abi_encode(),
            initializeV2_2Call {
                accountsToBlacklist: vec![],
                newSymbol: "USDC".into(),
            }
            .abi_encode(),
            configureMinterCall {
                minter: ADMIN,
                minterAllowedAmount: U256::from(u64::MAX),
            }
            .abi_encode(),
        ] {
            chain.must(ADMIN, 1, call);
        }
        chain
    }
    fn call(&mut self, from: Address, timestamp: u64, data: Vec<u8>) -> Outcome {
        let db = std::mem::take(&mut self.db);
        let mut evm = Context::mainnet()
            .with_db(db)
            .modify_cfg_chained(|cfg| {
                cfg.chain_id = CHAIN;
                cfg.disable_nonce_check = true;
            })
            .modify_block_chained(|block| block.timestamp = U256::from(timestamp))
            .build_mainnet();
        let result = evm
            .transact_commit(
                TxEnv::builder()
                    .caller(from)
                    .kind(TxKind::Call(TOKEN))
                    .data(data.into())
                    .gas_limit(5_000_000)
                    .chain_id(Some(CHAIN))
                    .build()
                    .unwrap(),
            )
            .unwrap();
        self.db = evm.ctx.journaled_state.database;
        match result {
            ExecutionResult::Success {
                output: Output::Call(bytes),
                ..
            } => Outcome::Returned(bytes),
            ExecutionResult::Revert { output, .. } => {
                // Error(string): selector, offset, length, text.
                let text = output
                    .get(68..)
                    .map(|t| {
                        String::from_utf8_lossy(t)
                            .trim_end_matches('\0')
                            .to_string()
                    })
                    .unwrap_or_default();
                Outcome::Reverted(text)
            }
            other => panic!("unexpected EVM outcome: {other:?}"),
        }
    }
    fn must(&mut self, from: Address, timestamp: u64, data: Vec<u8>) -> Bytes {
        match self.call(from, timestamp, data) {
            Outcome::Returned(bytes) => bytes,
            Outcome::Reverted(reason) => panic!("reverted: {reason}"),
        }
    }
    fn refused(&mut self, from: Address, timestamp: u64, data: Vec<u8>) -> String {
        match self.call(from, timestamp, data) {
            Outcome::Returned(_) => panic!("the token accepted a call it must refuse"),
            Outcome::Reverted(reason) => reason,
        }
    }
    fn balance(&mut self, owner: Address) -> U256 {
        let out = self.must(RELAYER, 1, balanceOfCall { account: owner }.abi_encode());
        U256::from_be_slice(&out)
    }
    fn used(&mut self, authorizer: Address, nonce: B256) -> bool {
        let out = self.must(
            RELAYER,
            1,
            authorizationStateCall { authorizer, nonce }.abi_encode(),
        );
        U256::from_be_slice(&out) == U256::from(1)
    }
}

fn wallet(key: &SigningKey) -> [u8; 20] {
    let point = key.verifying_key().to_sec1_point(false);
    keccak256(&point.as_bytes()[1..])[12..].try_into().unwrap()
}
fn sign(key: &SigningKey, digest: [u8; 32]) -> WalletSignature {
    let (signature, recovery) = key.sign_prehash_recoverable(&digest);
    let mut bytes = [0; 65];
    bytes[..64].copy_from_slice(&signature.to_bytes());
    bytes[64] = recovery.to_byte() + 27;
    WalletSignature(bytes)
}
fn token_domain() -> x402::TokenDomain {
    x402::TokenDomain {
        name: "USDC".into(),
        version: "2".into(),
    }
}
/// An order's digest, the one authorization it fixes and the buyer's signature
/// over it, produced only by the commerce crate.
struct Funded {
    digest: [u8; 32],
    authorization: x402::Authorization,
    signature: [u8; 65],
}
fn funded_order(salt: u8) -> (Funded, SigningKey) {
    let buyer = SigningKey::from_slice(&[1; 32]).unwrap();
    let deployment = Deployment {
        chain_id: CHAIN,
        vault: ESCROW.into_array(),
        treasury: [5; 20],
        fee_bps: 25,
        maximum_fee_bps: 100,
        rules: nucleus_proof_commerce::vault::Rules::Second,
    };
    let order = Order {
        buyer: wallet(&buyer),
        seller: [2; 20],
        asset: TOKEN.into_array(),
        amount: U256::from(PRICE).to_be_bytes(),
        verifier: [6; 20],
        program: [7; 32],
        policy_hash: [9; 32],
        base: [0; 32],
        fund_by: DEADLINE,
        deliver_by: 2 * DEADLINE,
        salt: [salt; 32],
        context: [11; 32],
    };
    let authorization = vault::authorization(&deployment, &order).unwrap();
    let signature = sign(
        &buyer,
        vault::authorization_digest(&deployment, &token_domain(), &order).unwrap(),
    );
    let funding = vault::admit_funding(&deployment, &token_domain(), order, &signature, 1).unwrap();
    (
        Funded {
            digest: funding.digest(),
            authorization,
            signature: *funding.signature(),
        },
        buyer,
    )
}
fn receive(funding: &Funded) -> Vec<u8> {
    let a = &funding.authorization;
    let s = &funding.signature;
    receiveWithAuthorizationCall {
        from: a.from.into(),
        to: a.to.into(),
        value: U256::from_be_bytes(a.value),
        validAfter: U256::from(a.valid_after),
        validBefore: U256::from(a.valid_before),
        nonce: a.nonce.into(),
        v: s[64],
        r: B256::from_slice(&s[..32]),
        s: B256::from_slice(&s[32..64]),
    }
    .abi_encode()
}
fn transfer(funding: &Funded) -> Vec<u8> {
    let mut data = receive(funding);
    data[..4].copy_from_slice(&transferWithAuthorizationCall::SELECTOR);
    data
}
fn chain_with_buyer_balance(buyer: &SigningKey) -> Chain {
    let mut chain = Chain::new();
    chain.must(
        ADMIN,
        1,
        mintCall {
            to: wallet(buyer).into(),
            amount: U256::from(PRICE),
        }
        .abi_encode(),
    );
    chain
}

#[test]
fn the_vault_redeems_the_bound_authorization_exactly_once() {
    let (funding, buyer) = funded_order(7);
    let mut chain = chain_with_buyer_balance(&buyer);
    let buyer_address = Address::from(wallet(&buyer));
    assert!(!chain.used(buyer_address, funding.digest.into()));

    chain.must(ESCROW, DEADLINE, receive(&funding));

    assert_eq!(chain.balance(ESCROW), U256::from(PRICE));
    assert_eq!(chain.balance(buyer_address), U256::ZERO);
    // The token's replay key is the order's digest.
    assert!(chain.used(buyer_address, funding.digest.into()));

    chain.must(
        ADMIN,
        1,
        mintCall {
            to: buyer_address,
            amount: U256::from(PRICE),
        }
        .abi_encode(),
    );
    let reason = chain.refused(ESCROW, DEADLINE, receive(&funding));
    assert!(reason.contains("authorization is used"), "{reason}");
    assert_eq!(chain.balance(ESCROW), U256::from(PRICE));
}

#[test]
fn a_relayer_cannot_redeem_and_cannot_strand_the_deposit() {
    let (funding, buyer) = funded_order(7);
    let mut chain = chain_with_buyer_balance(&buyer);
    let reason = chain.refused(RELAYER, DEADLINE, receive(&funding));
    assert!(reason.contains("caller must be the payee"), "{reason}");
    assert_eq!(chain.balance(ESCROW), U256::ZERO);
    assert_eq!(chain.balance(wallet(&buyer).into()), U256::from(PRICE));
}

#[test]
fn a_standard_exact_facilitator_has_no_valid_message() {
    let (funding, buyer) = funded_order(7);
    let mut chain = chain_with_buyer_balance(&buyer);
    // Same fields and signature through transferWithAuthorization, from anyone.
    for caller in [RELAYER, ESCROW] {
        let reason = chain.refused(caller, DEADLINE, transfer(&funding));
        assert!(reason.contains("invalid signature"), "{reason}");
    }
    assert_eq!(chain.balance(ESCROW), U256::ZERO);
}

#[test]
fn the_window_ends_with_the_funding_deadline() {
    let (funding, buyer) = funded_order(7);
    let mut chain = chain_with_buyer_balance(&buyer);
    let reason = chain.refused(ESCROW, DEADLINE + 1, receive(&funding));
    assert!(reason.contains("authorization is expired"), "{reason}");
    assert_eq!(chain.balance(ESCROW), U256::ZERO);
    chain.must(ESCROW, DEADLINE, receive(&funding));
    assert_eq!(chain.balance(ESCROW), U256::from(PRICE));
}

#[test]
fn an_authorization_altered_after_signing_is_refused_by_the_token() {
    let (funding, buyer) = funded_order(7);
    let mut chain = chain_with_buyer_balance(&buyer);
    // Byte offsets into the call data: selector, then nine 32-byte words.
    for word in [1, 2, 4, 5] {
        let mut data = receive(&funding);
        data[4 + 32 * word + 31] ^= 1;
        let caller = if word == 1 {
            Address::from_slice(&data[4 + 32 + 12..4 + 64])
        } else {
            ESCROW
        };
        let reason = chain.refused(caller, 500, data);
        assert!(
            reason.contains("invalid signature"),
            "word {word}: {reason}"
        );
    }
    assert_eq!(chain.balance(ESCROW), U256::ZERO);
}
