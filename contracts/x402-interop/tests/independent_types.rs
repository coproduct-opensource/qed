//! Our x402 v2 headers, decoded by `x402-types` 2.0.2 (crates.io), an x402
//! implementation this repository did not write. This checks the envelope:
//! header encoding, member names and value shapes of the v2 messages. It does
//! not check the scheme: `nucleus-vault` is ours and no other implementation
//! settles it.
use base64::Engine;
use k256::ecdsa::SigningKey;
use nucleus_proof_commerce::{
    WalletSignature,
    vault::{self, Deployment, Order, wire},
    x402::TokenDomain,
};
use sha3::{Digest, Keccak256};
use x402_types::proto::v2;

fn wallet(key: &SigningKey) -> [u8; 20] {
    let point = key.verifying_key().to_sec1_point(false);
    let hashed: [u8; 32] = Keccak256::digest(&point.as_bytes()[1..]).into();
    hashed[12..].try_into().unwrap()
}
fn sign(key: &SigningKey, digest: [u8; 32]) -> WalletSignature {
    let (signature, recovery) = key.sign_prehash_recoverable(&digest);
    let mut bytes = [0; 65];
    bytes[..64].copy_from_slice(&signature.to_bytes());
    bytes[64] = recovery.to_byte() + 27;
    WalletSignature(bytes)
}
fn amount(value: u64) -> [u8; 32] {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}
fn token() -> TokenDomain {
    TokenDomain {
        name: "USD Coin".into(),
        version: "2".into(),
    }
}
fn deployment() -> Deployment {
    Deployment {
        chain_id: 8453,
        vault: [3; 20],
        treasury: [5; 20],
        fee_bps: 25,
        maximum_fee_bps: 100,
        rules: nucleus_proof_commerce::vault::Rules::Second,
    }
}
fn buyer() -> SigningKey {
    SigningKey::from_slice(&[1; 32]).unwrap()
}
fn order() -> Order {
    Order {
        buyer: wallet(&buyer()),
        seller: [2; 20],
        asset: [4; 20],
        amount: amount(1_000_000),
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
fn intent() -> wire::Intent {
    let order = order();
    wire::Intent {
        wallet: order.buyer,
        asset: order.asset,
        policy_hash: order.policy_hash,
        context: order.context,
        maximum_amount: order.amount,
        verifiers: vec![order.verifier],
        programs: vec![order.program],
        fund_no_earlier_than: 0,
        deliver_no_later_than: 3000,
        bases: vec![],
    }
}
/// (PAYMENT-REQUIRED value, PAYMENT-SIGNATURE value), built only with our crate.
fn headers() -> (String, String) {
    let accepted = wire::requirements(&deployment(), &token(), &order(), 60);
    let required = wire::required_header(
        serde_json::json!({"url": "https://seller.example/work", "description": "proof of Nucleus.Claim", "mimeType": "application/x-ndjson"}),
        accepted,
    )
    .unwrap();
    let reviewed = wire::review_offer(&deployment(), &token(), &required, &intent(), 10).unwrap();
    let signature = sign(&buyer(), reviewed.signing_digest());
    let payment = wire::signature_header(&deployment(), reviewed, &signature).unwrap();
    (required, payment)
}
fn decode(header: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(header)
        .unwrap()
}

#[test]
fn their_types_read_our_payment_required_header() {
    let (required, _) = headers();
    let theirs: v2::PaymentRequired = serde_json::from_slice(&decode(&required)).unwrap();
    let resource = theirs.resource.as_ref().unwrap();
    assert_eq!(resource.url, "https://seller.example/work");
    assert_eq!(resource.mime_type.as_deref(), Some("application/x-ndjson"));
    assert_eq!(theirs.accepts.len(), 1);
    let offer = &theirs.accepts[0];
    assert_eq!(offer.scheme, "nucleus-vault");
    assert_eq!(offer.network.to_string(), "eip155:8453");
    assert_eq!(offer.amount, "1000000");
    assert_eq!(offer.pay_to, "0x0303030303030303030303030303030303030303");
    assert_eq!(offer.asset, "0x0404040404040404040404040404040404040404");
    assert_eq!(offer.max_timeout_seconds, 60);
    let extra = offer.extra.as_ref().unwrap();
    assert_eq!(extra["assetTransferMethod"], "eip3009-receive");
    assert_eq!(extra["name"], "USD Coin");
    assert_eq!(extra["version"], "2");
}

#[test]
fn their_types_read_our_payment_signature_header() {
    let (_, payment) = headers();
    let theirs: v2::PaymentPayload<v2::PaymentRequirements, serde_json::Value> =
        serde_json::from_slice(&decode(&payment)).unwrap();
    assert_eq!(theirs.accepted.scheme, "nucleus-vault");
    assert_eq!(theirs.accepted.network.to_string(), "eip155:8453");
    let authorization = &theirs.payload["authorization"];
    for member in ["from", "to", "value", "validAfter", "validBefore", "nonce"] {
        assert!(authorization[member].is_string(), "{member}");
    }
    assert_eq!(authorization["value"], "1000000");
    assert_eq!(authorization["validAfter"], "0");
    assert_eq!(authorization["validBefore"], "1001");
    assert!(
        theirs.payload["signature"]
            .as_str()
            .unwrap()
            .starts_with("0x")
    );
}

#[test]
fn our_parser_reads_their_reserialization_of_both_headers() {
    let (required, payment) = headers();
    let encode = |bytes: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(bytes);
    // Their struct, their serializer, then our strict parser.
    let theirs: v2::PaymentRequired = serde_json::from_slice(&decode(&required)).unwrap();
    let reviewed = wire::review_offer(
        &deployment(),
        &token(),
        &encode(serde_json::to_vec(&theirs).unwrap()),
        &intent(),
        10,
    )
    .unwrap();
    assert_eq!(reviewed.order(), &order());

    let theirs: v2::PaymentPayload<v2::PaymentRequirements, serde_json::Value> =
        serde_json::from_slice(&decode(&payment)).unwrap();
    let funding = wire::admit_header(
        &deployment(),
        &token(),
        &encode(serde_json::to_vec(&theirs).unwrap()),
        60,
        10,
    )
    .unwrap();
    assert_eq!(funding.digest(), vault::digest(&deployment(), &order()));
}
