//! The buyer posting a task on the board and waiting at its desk.
//!
//!   nucleus-buyer post DEPLOYMENT BOARD KEYFILE STATEMENT PROGRAM_HEX MAXIMUM_PRICE BIND OUT_DIR
//!
//! BIND is the socket address this buyer's iroh endpoint listens on, and the
//! address hint the post carries (so it must be one a seller can reach).
//!
//! The buyer serves the statement as a blob, posts the task, signs for the
//! first offer that passes review (`desk.rs`), and then believes only the
//! chain and the Lean checker: it reads the settlement from the vault, takes
//! the artifact from the settle transaction's calldata, and checks it itself.
//!
//! It withdraws the task only on abandonment: when the posted funding
//! deadline passes with nothing signed. A signed or settled task is not
//! withdrawn; its order lives in the vault and the post is spent.
use crate::board::{self, Board, Task};
use crate::desk::{Desk, Outcome, Posted, Signed};
use crate::iroh_net;
use crate::prelude::*;
use crate::world::*;
use nucleus_proof_acceptance::accept;
use nucleus_proof_commerce::Hash;
use std::{
    sync::{Arc, Mutex},
    thread::sleep,
    time::Duration,
};

/// How long after posting the buyer will still sign for funding.
const FUNDING_WINDOW: u64 = 1_800;
/// How long after posting delivery may take.
const DELIVERY_WINDOW: u64 = 4 * 3_600;

/// The artifact a settled order was paid for, read from the calldata of the
/// transaction that settled it. Fails if the vault's `Settled` log for this
/// digest is not found, or if `settle` was not called directly.
pub(crate) fn settled_artifact(
    form: vault::Form,
    chain: &Chain,
    vault_address: Address,
    digest: Hash,
    from: u64,
) -> Res<Vec<u8>> {
    let topic = settled_topic(form);
    let latest = u64::from_str_radix(
        chain
            .rpc("eth_blockNumber", json!([]))?
            .as_str()
            .ok_or("block number expected")?
            .trim_start_matches("0x"),
        16,
    )?;
    // Asked for in bounded ranges: a long-lived buyer may look back over more
    // blocks than a node answers for in one call.
    let mut transaction = None;
    let mut start = from;
    while transaction.is_none() && start <= latest {
        let end = latest.min(start.saturating_add(4_999));
        let logs = chain.rpc(
            "eth_getLogs",
            json!([{
                "address": hex(&vault_address),
                "topics": [hex(&topic), hex(&digest)],
                "fromBlock": format!("{start:#x}"),
                "toBlock": format!("{end:#x}"),
            }]),
        )?;
        transaction = logs
            .as_array()
            .and_then(|logs| logs.first())
            .and_then(|log| log["transactionHash"].as_str())
            .map(str::to_owned);
        start = end + 1;
    }
    let transaction = transaction.ok_or("no Settled log for this order")?;
    let sent = chain.rpc("eth_getTransactionByHash", json!([transaction]))?;
    let input = unhex(sent["input"].as_str().ok_or("transaction input expected")?)?;
    let artifact = artifact_in(form, &input)
        .ok_or("the settling transaction is not a direct call to settle")?;
    println!(
        "buyer: settled in tx {transaction}; {} byte artifact in its calldata",
        artifact.len()
    );
    Ok(artifact)
}

/// What the vault says about an order.
pub(crate) fn phase_of(world: &World, digest: Hash) -> Res<u8> {
    world
        .chain
        .call(
            [0; 20],
            world.deployment.vault,
            &phaseCall { d: digest.into() }.abi_encode(),
        )?
        .last()
        .copied()
        .ok_or_else(|| "phase reply".into())
}

pub fn post(args: &[String]) -> Res<()> {
    let [
        deployment,
        board_address,
        keyfile,
        statement,
        program,
        maximum,
        bind,
        out,
    ] = args
    else {
        return Err(
            "usage: nucleus-buyer post DEPLOYMENT BOARD KEYFILE STATEMENT PROGRAM_HEX MAXIMUM_PRICE BIND OUT_DIR"
                .into(),
        );
    };
    let world = World::read(deployment)?;
    let keys = Keys::load_or_create(keyfile)?;
    let statement = fs::read(statement)?;
    let program: Hash = unhex(program)?
        .try_into()
        .map_err(|_| "program id length")?;
    let maximum: u64 = maximum.parse()?;
    let board = Board {
        chain: world.chain.clone(),
        address: address_arg(board_address)?,
    };
    if board.vault()? != world.deployment.vault {
        return Err("the board is for another vault than this deployment's".into());
    }
    let policy = Policy {
        statement_sha256: Sha256::digest(&statement).into(),
        claim: "Nucleus.Claim".into(),
        permitted_axioms: vec![],
        maximum_artifact_bytes: 65_536,
    };

    // The endpoint, and the statement as a blob on it.
    let relay = iroh_net::Relay::from_environment()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let endpoint = runtime
        .block_on(async { iroh_net::endpoint_in(keys.node, bind.parse()?, &relay).await })
        .map_err(|e| e.to_string())?;
    let node = endpoint.id().to_string();
    let store = {
        let _guard = runtime.enter();
        crate::blobs::store()
    };
    let blake3 = runtime.block_on(crate::blobs::add(&store, statement.clone()))?;

    let now = wall_clock()?;
    let task = Task {
        statement_sha256: policy.statement_sha256,
        statement_blake3: blake3,
        policy_hash: policy.hash(),
        asset: world.token,
        maximum_amount: U256::from(maximum).to_be_bytes(),
        verifier: world.verifier,
        program,
        fund_by: now + FUNDING_WINDOW,
        deliver_by: now + DELIVERY_WINDOW,
        buyer_node: board::node_bytes(&node)?,
        buyer_key_binding: keys.binding(),
        salt: random32()?,
        // The hint is for a seller with no other way to find this node. With
        // a relay the node ID is enough, and a bind address such as
        // `0.0.0.0:0` would mislead, so none is posted.
        buyer_address: match relay {
            iroh_net::Relay::None => bind.clone(),
            iroh_net::Relay::Default | iroh_net::Relay::Url(_) => String::new(),
        },
    };
    if let Some(refusal) = task.refusal(now) {
        return Err(format!("the board would refuse this task: {refusal}").into());
    }
    let before = world.balance(keys.address())?;
    let from_block = board.latest_block()?;

    // Serve before posting, so the first seller to see the post finds the desk.
    let mut desk = Desk::new(
        world.deployment.clone(),
        world.domain.clone(),
        keys.wallet.clone(),
    );
    desk.accept_bases(world.bases.clone());
    let id = nucleus_board_reference::id(world.chain.id, board.address, keys.address(), &task);
    desk.open(Posted::new(id, task.clone(), policy.clone())?);
    let desk = Arc::new(Mutex::new(desk));
    let _router = {
        let _guard = runtime.enter();
        iroh_net::serve_with(endpoint, desk.clone(), Some(&store))
    };
    let (posted_id, receipt) = board.post(&keys.wallet, &task)?;
    if posted_id != id {
        return Err("the board gave the task another ID than the reference".into());
    }
    println!(
        "buyer: {} holds {before}; posted task {} on board {} in tx {} (gas {}); node {node} at {bind} (relay {relay:?}); cap {maximum}",
        hex(&keys.address()),
        hex(&id),
        hex(&board.address),
        receipt.transaction,
        receipt.gas_used
    );

    // Wait: first for a signature, then for the chain.
    let look = |desk: &Mutex<Desk>| -> Res<Option<Signed>> {
        Ok(desk.lock().map_err(|_| "desk poisoned")?.signed(&id))
    };
    let signed = loop {
        if let Some(signed) = look(&desk)? {
            break signed;
        }
        if wall_clock()? > task.fund_by {
            // Abandonment: nobody was signed for in time.
            desk.lock().map_err(|_| "desk poisoned")?.withdraw(&id);
            let withdrawn = board.withdraw(&keys.wallet, id)?;
            return Err(format!(
                "no offer was signed for before the funding deadline; task withdrawn in tx {}",
                withdrawn.transaction
            )
            .into());
        }
        sleep(Duration::from_secs(2));
    };
    println!(
        "buyer: signed order {} for seller {} at {}; watching the vault",
        hex(&signed.digest),
        hex(&signed.order.seller),
        U256::from_be_bytes(signed.order.amount)
    );
    let outcome = loop {
        let now = wall_clock()?;
        match phase_of(&world, signed.digest)? {
            2 => break Outcome::Settled,
            1 if now > signed.order.deliver_by => break Outcome::Refundable,
            0 if now > signed.order.fund_by => break Outcome::Lapsed,
            _ => sleep(Duration::from_secs(15)),
        }
    };
    desk.lock()
        .map_err(|_| "desk poisoned")?
        .finish(&id, outcome);
    match outcome {
        Outcome::Settled => {}
        Outcome::Refundable => {
            return Err("funded but not delivered by the deadline: refund is open".into());
        }
        Outcome::Lapsed => return Err("the seller never funded the order".into()),
    }

    // Trust nothing a seller said: the artifact comes from the chain, and the
    // checker decides whether it is the work.
    let artifact = settled_artifact(
        world.deployment.rules.form(),
        &world.chain,
        world.deployment.vault,
        signed.digest,
        from_block,
    )?;
    let accepted = accept(&signed.policy, &statement, &artifact)
        .map_err(|e| format!("the settled artifact is refused by the checker: {e:?}"))?;
    let recorded = world.chain.call(
        [0; 20],
        world.deployment.vault,
        &artifactOfCall {
            d: signed.digest.into(),
        }
        .abi_encode(),
    )?;
    if recorded != keccak(&artifact) {
        return Err("the vault recorded another artifact for this order".into());
    }
    println!(
        "buyer: Lean check passed locally; proof declaration {}; buyer {before} -> {}, seller {}",
        accepted.proof,
        world.balance(keys.address())?,
        world.balance(signed.order.seller)?
    );
    fs::create_dir_all(out)?;
    fs::write(Path::new(out).join("delivered.ndjson"), &artifact)?;
    fs::write(
        Path::new(out).join("order.json"),
        serde_json::to_vec_pretty(&nucleus_proof_commerce::vault::wire::WireOrder::from_order(
            &signed.order,
        ))?,
    )?;
    Ok(())
}
