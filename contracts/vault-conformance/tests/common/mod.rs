//! Shared harness: a local EVM with real FiatToken bytecode, the compiled vault
//! and the TEST verifier, plus order and call builders.
#![allow(dead_code)]
use alloy_sol_types::{SolCall, SolValue, sol};
use k256::ecdsa::SigningKey;
use nucleus_proof_commerce::{WalletSignature, vault, x402::TokenDomain};
use revm::{
    Context, ExecuteCommitEvm, MainBuilder, MainContext,
    context::TxEnv,
    context_interface::result::{ExecutionResult, Output},
    database::{CacheDB, EmptyDB},
    primitives::{Address, B256, Bytes, TxKind, U256, keccak256},
    state::{AccountInfo, Bytecode},
};
use sha2::{Digest, Sha256};

sol! {
    struct Order { address buyer; address seller; address asset; uint256 amount; address verifier; bytes32 program; bytes32 policyHash; uint64 fundBy; uint64 deliverBy; bytes32 salt; bytes32 context; }
    function digest(Order o) returns (bytes32);
    function feeOf(uint256 amount) returns (uint256);
    function fund(Order o, bytes authorization) returns (bytes32);
    function settle(Order o, bytes artifact, bytes seal);
    function refund(Order o);
    function phase(bytes32 d) returns (uint8);
    function artifactOf(bytes32 d) returns (bytes32);
    function initialize(string tokenName, string tokenSymbol, string tokenCurrency, uint8 tokenDecimals, address newMasterMinter, address newPauser, address newBlacklister, address newOwner);
    function initializeV2(string newName);
    function initializeV2_1(address lostAndFound);
    function initializeV2_2(address[] accountsToBlacklist, string newSymbol);
    function configureMinter(address minter, uint256 minterAllowedAmount) returns (bool);
    function mint(address to, uint256 amount) returns (bool);
    function balanceOf(address account) returns (uint256);
    function sweep(address asset);
    function accrued(address asset) returns (uint256);
    function blacklist(address account);
    function unBlacklist(address account);
}

/// The vault under test: NucleusVault2, which books fees and sweeps them
/// (model: proofs/commerce/Vault.lean).
pub const VAULT_BIN: &str = include_str!("../../../vault/out/NucleusVault2.bin");

pub const CHAIN: u64 = 84532;
pub const TOKEN: Address = Address::new([0x70; 20]);
pub const LIBRARY: Address = Address::new([
    0xba, 0x3b, 0x60, 0xc2, 0x1e, 0x28, 0xc4, 0x1d, 0xf4, 0xba, 0xbd, 0x90, 0xf2, 0x28, 0xe1, 0xd3,
    0x68, 0x62, 0x7d, 0xa6,
]);
pub const ADMIN: Address = Address::new([0xad; 20]);
pub const RELAYER: Address = Address::new([0x4e; 20]);
pub const TREASURY: Address = Address::new([0x7e; 20]);
pub const SELLER: Address = Address::new([0x5e; 20]);
pub const PROGRAM: [u8; 32] = [0x77; 32];
pub const PRICE: u64 = 1_000_000;

pub fn unhex(text: &str) -> Vec<u8> {
    let text = text.trim().trim_start_matches("0x");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
pub enum Outcome {
    Returned(Bytes),
    Reverted(Bytes),
}
pub struct Chain {
    pub db: CacheDB<EmptyDB>,
    pub vault: Address,
    pub verifier: Address,
}
impl Chain {
    pub fn new() -> Self {
        let mut db = CacheDB::<EmptyDB>::default();
        for (address, hex) in [
            (
                TOKEN,
                include_str!("../../../token-conformance/fixtures/fiat-token-impl.runtime.hex"),
            ),
            (
                LIBRARY,
                include_str!("../../../token-conformance/fixtures/signature-checker.runtime.hex"),
            ),
        ] {
            db.insert_account_info(
                address,
                AccountInfo::default().with_code(Bytecode::new_raw(unhex(hex).into())),
            );
        }
        let mut chain = Self {
            db,
            vault: Address::ZERO,
            verifier: Address::ZERO,
        };
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
            chain.must(ADMIN, TOKEN, 1, call);
        }
        chain.verifier = chain.create(unhex(include_str!("../../../vault/out/TestVerifier.bin")));
        let constructor = (TREASURY, 25u16, 100u16).abi_encode();
        chain.vault = chain.create([unhex(VAULT_BIN), constructor].concat());
        chain
    }
    pub fn transact(
        &mut self,
        from: Address,
        kind: TxKind,
        timestamp: u64,
        data: Vec<u8>,
    ) -> ExecutionResult {
        self.transact_with_value(from, kind, timestamp, data, U256::ZERO)
    }
    /// As `transact`, sending `value` wei with the call.
    pub fn transact_with_value(
        &mut self,
        from: Address,
        kind: TxKind,
        timestamp: u64,
        data: Vec<u8>,
        value: U256,
    ) -> ExecutionResult {
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
                    .kind(kind)
                    .data(data.into())
                    .value(value)
                    .gas_limit(8_000_000)
                    .chain_id(Some(CHAIN))
                    .build()
                    .unwrap(),
            )
            .unwrap();
        self.db = evm.ctx.journaled_state.database;
        result
    }
    pub fn create(&mut self, code: Vec<u8>) -> Address {
        match self.transact(ADMIN, TxKind::Create, 1, code) {
            ExecutionResult::Success {
                output: Output::Create(_, Some(address)),
                ..
            } => address,
            other => panic!("deployment failed: {other:?}"),
        }
    }
    fn call(&mut self, from: Address, to: Address, timestamp: u64, data: Vec<u8>) -> Outcome {
        match self.transact(from, TxKind::Call(to), timestamp, data) {
            ExecutionResult::Success {
                output: Output::Call(bytes),
                ..
            } => Outcome::Returned(bytes),
            ExecutionResult::Revert { output, .. } => Outcome::Reverted(output),
            other => panic!("unexpected EVM outcome: {other:?}"),
        }
    }
    pub fn must(&mut self, from: Address, to: Address, timestamp: u64, data: Vec<u8>) -> Bytes {
        match self.call(from, to, timestamp, data) {
            Outcome::Returned(bytes) => bytes,
            Outcome::Reverted(data) => {
                panic!("reverted: {data:x} {:?}", String::from_utf8_lossy(&data))
            }
        }
    }
    /// The call must revert; returns the 4-byte custom error selector, or the
    /// revert string for a token-level refusal.
    pub fn refused(&mut self, from: Address, to: Address, timestamp: u64, data: Vec<u8>) -> String {
        match self.call(from, to, timestamp, data) {
            Outcome::Returned(_) => panic!("accepted a call that must be refused"),
            Outcome::Reverted(data) if data.len() == 4 => error_name(&data),
            Outcome::Reverted(data) => String::from_utf8_lossy(data.get(68..).unwrap_or(&[]))
                .trim_end_matches('\0')
                .to_string(),
        }
    }
    pub fn balance(&mut self, owner: Address) -> U256 {
        U256::from_be_slice(&self.must(
            RELAYER,
            TOKEN,
            1,
            balanceOfCall { account: owner }.abi_encode(),
        ))
    }
    pub fn mint(&mut self, to: Address, amount: u64) {
        self.must(
            ADMIN,
            TOKEN,
            1,
            mintCall {
                to,
                amount: U256::from(amount),
            }
            .abi_encode(),
        );
    }
    /// Sweep the fees booked in `token` to the treasury.
    pub fn collect(&mut self, token: Address) {
        let vault = self.vault;
        self.must(RELAYER, vault, 1, sweepCall { asset: token }.abi_encode());
    }
    pub fn phase(&mut self, digest: [u8; 32]) -> u8 {
        let vault = self.vault;
        self.must(
            RELAYER,
            vault,
            1,
            phaseCall { d: digest.into() }.abi_encode(),
        )[31]
    }
    pub fn deployment(&self) -> vault::Deployment {
        vault::Deployment {
            chain_id: CHAIN,
            vault: self.vault.into_array(),
            treasury: TREASURY.into_array(),
            fee_bps: 25,
            maximum_fee_bps: 100,
            rules: vault::Rules::Second,
        }
    }
}
pub fn error_name(selector: &[u8]) -> String {
    for name in [
        "InvalidDeployment()",
        "InvalidOrder()",
        "FundingExpired()",
        "FeeExceedsCap()",
        "NotEmpty()",
        "NotFunded()",
        "BadSignatureLength()",
        "InexactDeposit()",
        "DeliveryExpired()",
        "DeadlineNotReached()",
        "InexactPayout()",
        "Reentered()",
        "NothingAccrued()",
        "TermTooLong()",
        "RegistryFailed()",
        "NothingOwed()",
        "Refused()",
        "InvalidEntry()",
        "AlreadyRegistered()",
    ] {
        if keccak256(name.as_bytes())[..4] == *selector {
            return name.trim_end_matches("()").to_string();
        }
    }
    format!("unknown error {selector:x?}")
}

pub fn wallet(key: &SigningKey) -> [u8; 20] {
    let point = key.verifying_key().to_sec1_point(false);
    keccak256(&point.as_bytes()[1..])[12..].try_into().unwrap()
}
pub fn sign(key: &SigningKey, digest: [u8; 32]) -> WalletSignature {
    let (signature, recovery) = key.sign_prehash_recoverable(&digest);
    let mut bytes = [0; 65];
    bytes[..64].copy_from_slice(&signature.to_bytes());
    bytes[64] = recovery.to_byte() + 27;
    WalletSignature(bytes)
}
pub fn token_domain() -> TokenDomain {
    TokenDomain {
        name: "USDC".into(),
        version: "2".into(),
    }
}
pub fn buyer() -> SigningKey {
    SigningKey::from_slice(&[1; 32]).unwrap()
}
pub fn order(chain: &Chain, salt: u8) -> vault::Order {
    vault::Order {
        buyer: wallet(&buyer()),
        seller: SELLER.into_array(),
        asset: TOKEN.into_array(),
        amount: U256::from(PRICE).to_be_bytes(),
        verifier: chain.verifier.into_array(),
        program: PROGRAM,
        policy_hash: [9; 32],
        base: [0; 32],
        fund_by: 1000,
        deliver_by: 2000,
        salt: [salt; 32],
        context: [11; 32],
    }
}
pub fn abi(o: &vault::Order) -> Order {
    Order {
        buyer: o.buyer.into(),
        seller: o.seller.into(),
        asset: o.asset.into(),
        amount: U256::from_be_bytes(o.amount),
        verifier: o.verifier.into(),
        program: o.program.into(),
        policyHash: o.policy_hash.into(),
        fundBy: o.fund_by,
        deliverBy: o.deliver_by,
        salt: o.salt.into(),
        context: o.context.into(),
    }
}
pub fn fund_call(chain: &Chain, o: &vault::Order, signer: &SigningKey) -> Vec<u8> {
    let signature = sign(
        signer,
        vault::authorization_digest(&chain.deployment(), &token_domain(), o).unwrap(),
    );
    fundCall {
        o: abi(o),
        authorization: Bytes::copy_from_slice(&signature.0),
    }
    .abi_encode()
}
/// The TEST verifier's accepted value for this order and artifact.
pub fn test_seal(chain: &Chain, o: &vault::Order, artifact: &[u8]) -> Vec<u8> {
    let journal = vault::acceptance_journal(&chain.deployment(), o, keccak256(artifact).0);
    let journal_digest: [u8; 32] = Sha256::digest(journal).into();
    keccak256((B256::from(o.program), B256::from(journal_digest)).abi_encode()).to_vec()
}
pub fn settle_call(o: &vault::Order, artifact: &[u8], seal: Vec<u8>) -> Vec<u8> {
    settleCall {
        o: abi(o),
        artifact: Bytes::copy_from_slice(artifact),
        seal: seal.into(),
    }
    .abi_encode()
}
pub fn funded(salt: u8) -> (Chain, vault::Order) {
    let mut chain = Chain::new();
    let o = order(&chain, salt);
    chain.mint(o.buyer.into(), PRICE);
    let (vault, call) = (chain.vault, fund_call(&chain, &o, &buyer()));
    chain.must(RELAYER, vault, 500, call);
    (chain, o)
}

pub mod third;
