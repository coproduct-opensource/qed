//! The buyer: asks one seller for a proof of one statement, takes the first
//! offer that passes its own review, signs one token authorization, and then
//! believes only the Lean checker and the chain.
//!
//!   nucleus-buyer DEPLOYMENT KEYFILE SELLER STATEMENT PROGRAM_HEX MAXIMUM_PRICE OUT_DIR
//!
//! SELLER is `iroh:<node id>@<ip:port>` or `http://host:port`.
use crate::dpop::dpop_make;
use crate::http::HttpTransport;
use crate::iroh_net::IrohTransport;
use crate::message::{Reply, Request, Transport};
use crate::prelude::*;
use crate::support::policy_json;
use crate::world::*;
use nucleus_proof_acceptance::accept;
use nucleus_proof_commerce::{
    vault::wire as vault_wire,
    x402::wire::{
        BUYER_HEADER, REQUIRED_HEADER, RESPONSE_HEADER, SIGNATURE_HEADER, declaration_header,
        request_hash,
    },
};
use std::{collections::BTreeMap, thread::sleep, time::Duration};

/// One request with a fresh proof of possession for exactly it.
pub fn ask(
    transport: &dyn Transport,
    keys: &Keys,
    method: &str,
    path: &str,
    mut headers: BTreeMap<String, String>,
    body: Vec<u8>,
) -> Res<Reply> {
    let uri = format!("{}{path}", transport.base());
    headers.insert(
        "dpop".into(),
        dpop_make(
            &keys.possession,
            method,
            &uri,
            wall_clock()?,
            transport.node().as_deref(),
        )?,
    );
    transport.send(&Request {
        method: method.to_owned(),
        path: path.to_owned(),
        headers,
        body,
    })
}

fn refusal(what: &str, reply: &Reply) -> String {
    format!(
        "{what}: {} {}",
        reply.status,
        String::from_utf8_lossy(&reply.body)
    )
}

pub fn buyer(args: &[String]) -> Res<()> {
    let [
        deployment,
        keyfile,
        seller,
        statement,
        program,
        maximum,
        out,
    ] = args
    else {
        return Err(
            "usage: nucleus-buyer DEPLOYMENT KEYFILE SELLER STATEMENT PROGRAM_HEX MAXIMUM_PRICE OUT_DIR"
                .into(),
        );
    };
    let world = World::read(deployment)?;
    let keys = Keys::load_or_create(keyfile)?;
    let statement = fs::read(statement)?;
    let program: [u8; 32] = unhex(program)?
        .try_into()
        .map_err(|_| "program id length")?;
    let maximum: u64 = maximum.parse()?;
    // `a2a+iroh:<node id>[@<ip:port>]` speaks A2A 1.0 over iroh
    // (docs/specs/a2a-iroh-transport-binding.md); the flow below is the same.
    let transport: Box<dyn Transport> = if let Some(seller) = seller.strip_prefix("a2a+") {
        Box::new(crate::a2a_iroh::A2aTransport::new_in(
            keys.node,
            keys.possession.clone(),
            seller,
            &crate::iroh_net::Relay::from_environment()?,
        )?)
    } else if seller.starts_with("iroh:") {
        Box::new(IrohTransport::new_in(
            keys.node,
            seller,
            &crate::iroh_net::Relay::from_environment()?,
        )?)
    } else {
        Box::new(HttpTransport::new(seller))
    };
    let policy = Policy {
        statement_sha256: Sha256::digest(&statement).into(),
        claim: "Nucleus.Claim".into(),
        permitted_axioms: vec![],
        maximum_artifact_bytes: 65_536,
    };
    let body = serde_json::to_vec(
        &json!({"policy": policy_json(&policy), "statement": B64.encode(&statement)}),
    )?;
    let uri = format!("{}/work", transport.base());
    let before = world.balance(keys.address())?;
    println!(
        "buyer: {} holds {before}; vault {} fee {} bps; seller at {}{}",
        hex(&keys.address()),
        hex(&world.deployment.vault),
        world.deployment.fee_bps,
        transport.base(),
        transport
            .node()
            .map(|node| format!("; this node {node}"))
            .unwrap_or_default()
    );

    // 1. Ask for the work, sending the statement.
    let declaration =
        declaration_header(keys.address(), keys.binding()).map_err(|e| format!("{e:?}"))?;
    let first = ask(
        transport.as_ref(),
        &keys,
        "POST",
        "/work",
        [(BUYER_HEADER.to_ascii_lowercase(), declaration)].into(),
        body.clone(),
    )?;
    if first.status != 202 {
        return Err(refusal("the seller did not take the request", &first).into());
    }
    let job = first
        .header("location")
        .ok_or("Location missing")?
        .to_owned();
    println!("buyer: seller took the request as {job}; waiting for an offer");

    // 2. Wait for the seller's offer: it comes only once the seller holds a proof.
    let poll = |seconds: u64, rounds: u32, waiting_on: u16| -> Res<Reply> {
        let mut reply = Reply::new(waiting_on);
        for _ in 0..rounds {
            reply = ask(
                transport.as_ref(),
                &keys,
                "GET",
                &job,
                BTreeMap::new(),
                vec![],
            )?;
            if reply.status != waiting_on {
                break;
            }
            sleep(Duration::from_secs(seconds));
        }
        Ok(reply)
    };
    let offered = poll(2, 600, 202)?;
    if offered.status != 402 {
        return Err(refusal("no offer", &offered).into());
    }
    let required = offered
        .header(REQUIRED_HEADER)
        .ok_or("PAYMENT-REQUIRED missing")?
        .to_owned();

    // 3. Review against this buyer's own intent, including who judges; sign once.
    let now = wall_clock()?;
    let intent = vault_wire::Intent {
        wallet: keys.address(),
        asset: world.token,
        policy_hash: policy.hash(),
        context: vault_wire::context(request_hash("POST", &uri, &body), keys.binding()),
        maximum_amount: U256::from(maximum).to_be_bytes(),
        verifiers: vec![world.verifier],
        programs: vec![program],
        fund_no_earlier_than: now + 60,
        deliver_no_later_than: now + 8 * 3600,
        bases: world.bases.clone(),
    };
    let reviewed =
        vault_wire::review_offer(&world.deployment, &world.domain, &required, &intent, now)
            .map_err(|e| format!("offer refused: {e:?}"))?;
    let order = reviewed.order().clone();
    let digest = vault::digest(&world.deployment, &order);
    println!(
        "buyer: offer {} from seller {} for {} passes review; signing one token authorization",
        hex(&digest),
        hex(&order.seller),
        U256::from_be_bytes(order.amount)
    );
    let signature = crate::sign(&keys.wallet, reviewed.signing_digest());
    let payment = vault_wire::signature_header(&world.deployment, reviewed, &signature)
        .map_err(|e| format!("{e:?}"))?;

    // 4. Pay, then poll with a fresh proof of possession each time.
    let paid = ask(
        transport.as_ref(),
        &keys,
        "POST",
        &job,
        [(SIGNATURE_HEADER.to_ascii_lowercase(), payment)].into(),
        vec![],
    )?;
    if paid.status != 202 {
        return Err(refusal("the seller did not take the payment", &paid).into());
    }
    println!("buyer: seller accepted the authorization; polling {job}");
    let delivered = poll(30, 240, 202)?;
    if delivered.status != 200 {
        return Err(refusal("no delivery", &delivered).into());
    }
    let response = delivered
        .header(RESPONSE_HEADER)
        .ok_or("PAYMENT-RESPONSE missing")?
        .to_owned();
    let artifact = delivered.body;
    let claimed: Value = serde_json::from_slice(&B64.decode(&response)?)?;
    println!(
        "buyer: received {} bytes; seller claims fund tx {} and settlement tx {}",
        artifact.len(),
        claimed["transaction"],
        claimed["extensions"]["nucleus-vault"]["settlement"]
    );

    // 5. Trust nothing the seller said: check the work and the chain.
    let accepted = accept(&policy, &statement, &artifact)
        .map_err(|e| format!("delivered artifact refused: {e:?}"))?;
    println!(
        "buyer: Lean check passed locally; proof declaration {}",
        accepted.proof
    );
    let phase = world.chain.call(
        keys.address(),
        world.deployment.vault,
        &phaseCall { d: digest.into() }.abi_encode(),
    )?;
    let recorded = world.chain.call(
        keys.address(),
        world.deployment.vault,
        &artifactOfCall { d: digest.into() }.abi_encode(),
    )?;
    if phase.last() != Some(&2) || recorded != keccak(&artifact) {
        return Err("the vault does not show this order settled for this artifact".into());
    }
    println!(
        "buyer: chain shows the order settled for this artifact; buyer {before} -> {}, seller {}, treasury {}",
        world.balance(keys.address())?,
        world.balance(order.seller)?,
        world.balance(world.deployment.treasury)?
    );
    fs::create_dir_all(out)?;
    fs::write(Path::new(out).join("delivered.ndjson"), &artifact)?;
    fs::write(
        Path::new(out).join("order.json"),
        serde_json::to_vec_pretty(&vault_wire::WireOrder::from_order(&order))?,
    )?;
    Ok(())
}
