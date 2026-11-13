//! The vault against a payment token that misbehaves (contracts/vault/src/
//! HostileToken.sol, TEST ONLY). Each test drives one of the vault's own
//! defences red: an order that names a hostile token must harm nobody but
//! itself, and must not move an honest token's deposit.
mod common;
use alloy_sol_types::{SolCall, sol};
use common::*;
use nucleus_proof_commerce::vault;
use revm::primitives::{Address, Bytes, U256};

sol! {
    function set(uint8 mode, bytes callback);
    function mintTo(address to, uint256 amount);
}
const HONEST: u8 = 0;
const SKIM_DEPOSIT: u8 = 1;
const REENTER_ON_DEPOSIT: u8 = 2;
const FALSE_ON_TRANSFER: u8 = 3;
const SILENT_ON_TRANSFER: u8 = 4;
const REENTER_ON_TRANSFER: u8 = 5;

struct World {
    chain: Chain,
    hostile: Address,
    /// An order paid in the hostile token.
    order: vault::Order,
}
impl World {
    fn new() -> Self {
        let mut chain = Chain::new();
        let hostile = chain.create(unhex(include_str!("../../vault/out/HostileToken.bin")));
        let mut order = order(&chain, 7);
        order.asset = hostile.into_array();
        // mint(address,uint256) on the hostile token has no access control.
        let mint = common::mintCall {
            to: order.buyer.into(),
            amount: U256::from(PRICE),
        }
        .abi_encode();
        chain.must(RELAYER, hostile, 1, mint);
        Self {
            chain,
            hostile,
            order,
        }
    }
    fn set(&mut self, mode: u8, callback: Vec<u8>) {
        let call = setCall {
            mode,
            callback: Bytes::from(callback),
        }
        .abi_encode();
        self.chain.must(RELAYER, self.hostile, 1, call);
    }
    fn fund(&self) -> Vec<u8> {
        fund_call(&self.chain, &self.order, &buyer())
    }
    fn held(&mut self, token: Address, owner: Address) -> U256 {
        let call = common::balanceOfCall { account: owner }.abi_encode();
        U256::from_be_slice(&self.chain.must(RELAYER, token, 1, call))
    }
    fn settle(&self) -> Vec<u8> {
        let seal = test_seal(&self.chain, &self.order, b"work");
        settle_call(&self.order, b"work", seal)
    }
}

#[test]
fn a_token_that_credits_less_than_the_amount_cannot_fund() {
    let mut w = World::new();
    let vault = w.chain.vault;
    w.set(SKIM_DEPOSIT, vec![]);
    assert_eq!(
        w.chain.refused(RELAYER, vault, 500, w.fund()),
        "InexactDeposit"
    );
    let digest = vault::digest(&w.chain.deployment(), &w.order);
    assert_eq!(w.chain.phase(digest), 0);
    // The same order funds once the token behaves.
    w.set(HONEST, vec![]);
    w.chain.must(RELAYER, vault, 500, w.fund());
    assert_eq!(w.chain.phase(digest), 1);
}

#[test]
fn a_token_cannot_call_back_into_the_vault_during_a_deposit() {
    let mut w = World::new();
    let vault = w.chain.vault;
    // An honest-token order is already funded and past its deadline: the
    // prize a re-entering token would go for.
    let honest = order(&w.chain, 1);
    w.chain.mint(honest.buyer.into(), PRICE);
    let call = fund_call(&w.chain, &honest, &buyer());
    w.chain.must(RELAYER, vault, 500, call);
    for callback in [
        refundCall { o: abi(&honest) }.abi_encode(),
        w.fund(),
        w.settle(),
    ] {
        w.set(REENTER_ON_DEPOSIT, callback);
        assert_eq!(w.chain.refused(RELAYER, vault, 500, w.fund()), "Reentered");
    }
    assert_eq!(w.held(TOKEN, vault), U256::from(PRICE));
    assert_eq!(
        w.chain.phase(vault::digest(&w.chain.deployment(), &honest)),
        1
    );
}

#[test]
fn a_payout_that_does_not_arrive_exactly_reverts_and_the_order_stays_funded() {
    for mode in [FALSE_ON_TRANSFER, SILENT_ON_TRANSFER] {
        let mut w = World::new();
        let vault = w.chain.vault;
        w.chain.must(RELAYER, vault, 500, w.fund());
        w.set(mode, vec![]);
        let digest = vault::digest(&w.chain.deployment(), &w.order);
        assert_eq!(
            w.chain.refused(RELAYER, vault, 600, w.settle()),
            "InexactPayout"
        );
        assert_eq!(
            w.chain.refused(
                RELAYER,
                vault,
                2001,
                refundCall { o: abi(&w.order) }.abi_encode()
            ),
            "InexactPayout"
        );
        assert_eq!(w.chain.phase(digest), 1);
        // Nothing was lost: the order settles once the token behaves.
        w.set(HONEST, vec![]);
        w.chain.must(RELAYER, vault, 600, w.settle());
        assert_eq!(w.chain.phase(digest), 2);
        assert_eq!(w.held(w.hostile, SELLER), U256::from(PRICE - 2500));
        let hostile = w.hostile;
        w.chain.collect(hostile);
        assert_eq!(w.held(w.hostile, TREASURY), U256::from(2500u64));
    }
}

#[test]
fn a_token_cannot_call_back_into_the_vault_during_a_payout() {
    let mut w = World::new();
    let vault = w.chain.vault;
    // The honest order is past its own deadline when the hostile order
    // settles. NOTE: this test also passes with the lock removed, because the
    // vault writes the phase before it pays; it shows that nothing moves, not
    // that the lock is what stops it. Only the deposit test fails without
    // the lock.
    let mut honest = order(&w.chain, 1);
    honest.deliver_by = 1500;
    w.chain.mint(honest.buyer.into(), PRICE);
    let call = fund_call(&w.chain, &honest, &buyer());
    w.chain.must(RELAYER, vault, 500, call);
    w.chain.must(RELAYER, vault, 500, w.fund());
    // During its own settlement the hostile token tries to settle again and
    // to refund the honest order.
    for (callback, at) in [
        (w.settle(), 600),
        (refundCall { o: abi(&honest) }.abi_encode(), 1600),
        (refundCall { o: abi(&w.order) }.abi_encode(), 600),
    ] {
        w.set(REENTER_ON_TRANSFER, callback);
        // The inner call is refused with `Reentered`; the vault makes payouts
        // by low-level call, so the outer settlement reports the failed
        // transfer as `InexactPayout`. Either way nothing moves.
        assert_eq!(
            w.chain.refused(RELAYER, vault, at, w.settle()),
            "InexactPayout"
        );
    }
    assert_eq!(w.held(TOKEN, vault), U256::from(PRICE));
    assert_eq!(w.held(w.hostile, vault), U256::from(PRICE));
    let d = w.chain.deployment();
    assert_eq!(w.chain.phase(vault::digest(&d, &honest)), 1);
    assert_eq!(w.chain.phase(vault::digest(&d, &w.order)), 1);
}

#[test]
fn an_order_whose_buyer_is_the_vault_is_refused() {
    let w = World::new();
    let mut chain = w.chain;
    let vault = chain.vault;
    let mut bad = order(&chain, 3);
    bad.buyer = vault.into_array();
    assert!(vault::admissible(&chain.deployment(), &bad, 500).is_err());
    let call = fundCall {
        o: abi(&bad),
        authorization: Bytes::from(vec![0u8; 65]),
    }
    .abi_encode();
    assert_eq!(chain.refused(RELAYER, vault, 500, call), "InvalidOrder");
}
