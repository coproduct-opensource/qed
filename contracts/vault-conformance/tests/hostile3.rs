//! NucleusVault3 against a payment token that misbehaves (contracts/vault/src/
//! HostileToken.sol, TEST ONLY). An order that names a hostile token must harm
//! nobody but itself and must not move an honest token's deposit.
mod common;
use alloy_sol_types::{SolCall, sol};
use common::third::*;
use common::{PRICE, RELAYER, SELLER, TOKEN, TREASURY, buyer, unhex};
use nucleus_proof_commerce::vault;
use revm::primitives::{Address, Bytes, U256};

sol! {
    function set(uint8 mode, bytes callback);
}
const HONEST: u8 = 0;
const SKIM_DEPOSIT: u8 = 1;
const REENTER_ON_DEPOSIT: u8 = 2;
const FALSE_ON_TRANSFER: u8 = 3;
const SILENT_ON_TRANSFER: u8 = 4;
const REENTER_ON_TRANSFER: u8 = 5;
const FALSE_AFTER_MOVING: u8 = 6;

struct Hostile {
    w: World,
    token: Address,
    /// An order paid in the hostile token.
    order: vault::Order,
    /// An order paid in the honest token, already funded.
    honest: vault::Order,
}
impl Hostile {
    fn new() -> Self {
        let mut w = World::new();
        let token = w
            .chain
            .create(unhex(include_str!("../../vault/out/HostileToken.bin")));
        let mut order = w.order(7);
        order.asset = token.into_array();
        let mint = common::mintCall {
            to: order.buyer.into(),
            amount: U256::from(PRICE),
        }
        .abi_encode();
        w.chain.must(RELAYER, token, 1, mint);
        let mut honest = w.order(1);
        honest.deliver_by = 1500;
        w.chain.mint(honest.buyer.into(), PRICE);
        let call = w.fund_call(&honest, &buyer());
        w.must(500, call);
        Self {
            w,
            token,
            order,
            honest,
        }
    }
    fn set(&mut self, mode: u8, callback: Vec<u8>) {
        let call = setCall {
            mode,
            callback: Bytes::from(callback),
        }
        .abi_encode();
        let token = self.token;
        self.w.chain.must(RELAYER, token, 1, call);
    }
    fn fund(&self) -> Vec<u8> {
        self.w.fund_call(&self.order, &buyer())
    }
    fn held(&mut self, token: Address, owner: Address) -> U256 {
        let call = common::balanceOfCall { account: owner }.abi_encode();
        U256::from_be_slice(&self.w.chain.must(RELAYER, token, 1, call))
    }
    fn claim_call(&self, payee: Address) -> Vec<u8> {
        claimCall {
            payee,
            asset: self.token,
        }
        .abi_encode()
    }
}

#[test]
fn a_token_that_credits_less_than_the_amount_cannot_fund() {
    let mut h = Hostile::new();
    h.set(SKIM_DEPOSIT, vec![]);
    let call = h.fund();
    assert_eq!(h.w.refused(500, call), "InexactDeposit");
    let digest = vault::digest(&h.w.deployment(), &h.order);
    assert_eq!(h.w.phase(digest), 0);
    h.set(HONEST, vec![]);
    let call = h.fund();
    h.w.must(500, call);
    assert_eq!(h.w.phase(digest), 1);
}

#[test]
fn a_token_cannot_call_back_into_the_vault_during_a_deposit() {
    let mut h = Hostile::new();
    let honest_buyer: Address = h.honest.buyer.into();
    // The honest order is past its deadline, so its refund is open; a second
    // order is settled, so the seller and treasury have honest claims open.
    let extra = h.w.order(2);
    h.w.chain.mint(honest_buyer, PRICE);
    let call = h.w.fund_call(&extra, &buyer());
    h.w.must(500, call);
    let call = h.w.settle_call(&extra, b"work");
    h.w.must(600, call);
    let honest_claim = claimCall {
        payee: SELLER,
        asset: TOKEN,
    }
    .abi_encode();
    for callback in [
        refund_call(&h.honest),
        h.fund(),
        h.w.settle_call(&h.order, b"work"),
        honest_claim,
    ] {
        h.set(REENTER_ON_DEPOSIT, callback);
        let call = h.fund();
        assert_eq!(h.w.refused(1600, call.clone()), "FundingExpired");
        // Within the funding window the refusal is the lock's.
        assert_eq!(h.w.refused(900, call), "Reentered");
    }
    let vault_address = h.w.vault;
    assert_eq!(h.held(TOKEN, vault_address), U256::from(2 * PRICE));
    assert_eq!(h.w.owed(SELLER, TOKEN), U256::from(997_500u64));
    assert_eq!(h.w.owed(honest_buyer, TOKEN), U256::ZERO);
}

#[test]
fn a_claim_that_does_not_arrive_exactly_reverts_and_stays_owed() {
    // A transfer that returns false, one that returns true and moves nothing,
    // and one that moves the tokens and then returns false.
    for mode in [FALSE_ON_TRANSFER, SILENT_ON_TRANSFER, FALSE_AFTER_MOVING] {
        let mut h = Hostile::new();
        let call = h.fund();
        h.w.must(500, call);
        // Settlement and refund transfer nothing, so the token has no say.
        h.set(mode, vec![]);
        let call = h.w.settle_call(&h.order, b"work");
        h.w.must(600, call);
        let token = h.token;
        assert_eq!(h.w.owed(SELLER, token), U256::from(997_500u64));
        for payee in [SELLER, TREASURY] {
            let call = h.claim_call(payee);
            assert_eq!(h.w.refused(700, call), "InexactPayout");
        }
        assert_eq!(h.w.owed(SELLER, token), U256::from(997_500u64));
        assert_eq!(h.w.owed(TREASURY, token), U256::from(2_500u64));
        // Nothing was lost: the claims pay once the token behaves.
        h.set(HONEST, vec![]);
        for payee in [SELLER, TREASURY] {
            let call = h.claim_call(payee);
            h.w.must(700, call);
        }
        assert_eq!(h.held(token, SELLER), U256::from(997_500u64));
        assert_eq!(h.held(token, TREASURY), U256::from(2_500u64));
        // The honest token's deposit was never involved.
        let vault_address = h.w.vault;
        assert_eq!(h.held(TOKEN, vault_address), U256::from(PRICE));
    }
}

#[test]
fn a_token_cannot_call_back_into_the_vault_during_a_claim() {
    let mut h = Hostile::new();
    let call = h.fund();
    h.w.must(500, call);
    let call = h.w.settle_call(&h.order, b"work");
    h.w.must(600, call);
    let token = h.token;
    let honest_buyer: Address = h.honest.buyer.into();
    // While the seller's claim in the hostile token is being paid, the token
    // tries to claim the same balance again, the treasury's, and to refund
    // the honest order (open: it is past its deadline).
    for callback in [
        h.claim_call(SELLER),
        h.claim_call(TREASURY),
        refund_call(&h.honest),
    ] {
        h.set(REENTER_ON_TRANSFER, callback);
        let call = h.claim_call(SELLER);
        // The inner call is refused with `Reentered`; the vault pays by
        // low-level call, so the outer claim reports `InexactPayout`.
        assert_eq!(h.w.refused(1600, call), "InexactPayout");
    }
    assert_eq!(h.w.owed(SELLER, token), U256::from(997_500u64));
    assert_eq!(h.w.owed(TREASURY, token), U256::from(2_500u64));
    assert_eq!(h.w.owed(honest_buyer, TOKEN), U256::ZERO);
    let vault_address = h.w.vault;
    assert_eq!(h.held(token, vault_address), U256::from(PRICE));
    assert_eq!(h.held(TOKEN, vault_address), U256::from(PRICE));
}
