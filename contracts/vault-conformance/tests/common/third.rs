//! Harness for the third vault (NucleusVault3; model proofs/commerce/Vault3.lean):
//! the same local EVM and real FiatToken, plus a TEST registry whose entries
//! the tests set, and the vault deployed against it.
use super::{
    ADMIN, CHAIN, Chain, PRICE, PROGRAM, RELAYER, SELLER, TOKEN, TREASURY, buyer, sign,
    token_domain, unhex, wallet,
};
use alloy_sol_types::{SolCall, SolValue, sol};
use k256::ecdsa::SigningKey;
use nucleus_proof_commerce::vault;
use revm::primitives::{Address, B256, Bytes, U256, keccak256};
use sha2::{Digest, Sha256};

sol! {
    struct Order3 { address buyer; address seller; address asset; uint256 amount; address verifier; bytes32 program; bytes32 policyHash; bytes32 base; uint64 fundBy; uint64 deliverBy; bytes32 salt; bytes32 context; }
    function digest(Order3 o) returns (bytes32);
    function fund(Order3 o, bytes authorization) returns (bytes32);
    function settle(Order3 o, bytes artifact, bytes seal);
    function refund(Order3 o);
    function claim(address payee, address asset);
    function owed(address payee, address asset) returns (uint256);
    function royaltyOf(bytes32 d) returns (address payee, uint256 amount);
    function set(bytes32 base, address payee, uint16 bps);
    function setMode(uint8 mode);
}

pub const VAULT3_BIN: &str = include_str!("../../../vault/out/NucleusVault3.bin");
pub const REGISTRY_BIN: &str = include_str!("../../../vault/out/TestRegistry.bin");
/// Longest term of the vault under test, in seconds.
pub const TERM: u64 = 5000;
pub const BASE: [u8; 32] = [0xba; 32];
pub const BASE_PAYEE: Address = Address::new([0xb5; 20]);

pub struct World {
    pub chain: Chain,
    pub vault: Address,
    pub registry: Address,
}
impl World {
    pub fn new() -> Self {
        let mut chain = Chain::new();
        let registry = chain.create(unhex(REGISTRY_BIN));
        let constructor = (TREASURY, 25u16, 100u16, TERM, registry).abi_encode();
        let vault = chain.create([unhex(VAULT3_BIN), constructor].concat());
        Self {
            chain,
            vault,
            registry,
        }
    }
    /// A world whose vault names a registry already deployed on `chain`.
    pub fn with_registry(mut chain: Chain, registry: Address) -> Self {
        let constructor = (TREASURY, 25u16, 100u16, TERM, registry).abi_encode();
        let vault = chain.create([unhex(VAULT3_BIN), constructor].concat());
        Self {
            chain,
            vault,
            registry,
        }
    }
    pub fn deployment(&self) -> vault::Deployment {
        vault::Deployment {
            chain_id: CHAIN,
            vault: self.vault.into_array(),
            treasury: TREASURY.into_array(),
            fee_bps: 25,
            maximum_fee_bps: 100,
            rules: vault::Rules::Third {
                maximum_term: TERM,
                registry: self.registry.into_array(),
            },
        }
    }
    pub fn order(&self, salt: u8) -> vault::Order {
        vault::Order {
            buyer: wallet(&buyer()),
            seller: SELLER.into_array(),
            asset: TOKEN.into_array(),
            amount: U256::from(PRICE).to_be_bytes(),
            verifier: self.chain.verifier.into_array(),
            program: PROGRAM,
            policy_hash: [9; 32],
            base: [0; 32],
            fund_by: 1000,
            deliver_by: 2000,
            salt: [salt; 32],
            context: [11; 32],
        }
    }
    pub fn must(&mut self, at: u64, data: Vec<u8>) -> Bytes {
        let vault = self.vault;
        self.chain.must(RELAYER, vault, at, data)
    }
    pub fn refused(&mut self, at: u64, data: Vec<u8>) -> String {
        let vault = self.vault;
        self.chain.refused(RELAYER, vault, at, data)
    }
    pub fn fund_call(&self, o: &vault::Order, signer: &SigningKey) -> Vec<u8> {
        let signature = sign(
            signer,
            vault::authorization_digest(&self.deployment(), &token_domain(), o).unwrap(),
        );
        fundCall {
            o: abi(o),
            authorization: Bytes::copy_from_slice(&signature.0),
        }
        .abi_encode()
    }
    /// The TEST verifier's accepted value for this order and artifact.
    pub fn test_seal(&self, o: &vault::Order, artifact: &[u8]) -> Vec<u8> {
        let journal = vault::acceptance_journal(&self.deployment(), o, keccak256(artifact).0);
        let journal_digest: [u8; 32] = Sha256::digest(journal).into();
        keccak256((B256::from(o.program), B256::from(journal_digest)).abi_encode()).to_vec()
    }
    pub fn settle_call(&self, o: &vault::Order, artifact: &[u8]) -> Vec<u8> {
        settle_with(o, artifact, self.test_seal(o, artifact))
    }
    pub fn phase(&mut self, digest: [u8; 32]) -> u8 {
        self.must(1, super::phaseCall { d: digest.into() }.abi_encode())[31]
    }
    pub fn owed(&mut self, payee: Address, asset: Address) -> U256 {
        U256::from_be_slice(&self.must(1, owedCall { payee, asset }.abi_encode()))
    }
    pub fn claim(&mut self, at: u64, payee: Address) -> Bytes {
        self.must(
            at,
            claimCall {
                payee,
                asset: TOKEN,
            }
            .abi_encode(),
        )
    }
    pub fn set_entry(&mut self, base: [u8; 32], payee: Address, bps: u16) {
        let registry = self.registry;
        let call = setCall {
            base: base.into(),
            payee,
            bps,
        }
        .abi_encode();
        self.chain.must(ADMIN, registry, 1, call);
    }
    pub fn set_mode(&mut self, mode: u8) {
        let registry = self.registry;
        self.chain
            .must(ADMIN, registry, 1, setModeCall { mode }.abi_encode());
    }
    /// A fresh world with one order funded at time 500.
    pub fn funded(salt: u8) -> (Self, vault::Order) {
        let mut world = Self::new();
        let o = world.order(salt);
        world.chain.mint(o.buyer.into(), PRICE);
        let call = world.fund_call(&o, &buyer());
        world.must(500, call);
        (world, o)
    }
}

pub fn abi(o: &vault::Order) -> Order3 {
    Order3 {
        buyer: o.buyer.into(),
        seller: o.seller.into(),
        asset: o.asset.into(),
        amount: U256::from_be_bytes(o.amount),
        verifier: o.verifier.into(),
        program: o.program.into(),
        policyHash: o.policy_hash.into(),
        base: o.base.into(),
        fundBy: o.fund_by,
        deliverBy: o.deliver_by,
        salt: o.salt.into(),
        context: o.context.into(),
    }
}
pub fn settle_with(o: &vault::Order, artifact: &[u8], seal: Vec<u8>) -> Vec<u8> {
    settleCall {
        o: abi(o),
        artifact: Bytes::copy_from_slice(artifact),
        seal: seal.into(),
    }
    .abi_encode()
}
pub fn refund_call(o: &vault::Order) -> Vec<u8> {
    refundCall { o: abi(o) }.abi_encode()
}
