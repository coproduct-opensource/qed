//! The task board as the agents see it on a chain: post, withdraw, and read
//! its notices. Contract: contracts/board/src/NucleusBoard.sol; reference:
//! `nucleus_board_reference`; model: proofs/commerce/Board.lean.
//!
//! A post is a notice. Nothing read here is evidence that a buyer has funds
//! or will sign.
use crate::chain::Receipt;
use crate::prelude::*;
use iroh::EndpointId;
use nucleus_board_reference as reference;
pub use nucleus_board_reference::{Notice, PostedTask, Task};
use nucleus_proof_commerce::{Hash, vault::wire as vault_wire};

/// Blocks asked for in one `eth_getLogs` call.
const LOG_RANGE: u64 = 5_000;

#[derive(Clone)]
pub struct Board {
    pub chain: Chain,
    pub address: Address,
}

fn quantity(value: &Value) -> Res<u64> {
    Ok(u64::from_str_radix(
        value
            .as_str()
            .ok_or("quantity expected")?
            .trim_start_matches("0x"),
        16,
    )?)
}

impl Board {
    /// The vault this board says its tasks settle through.
    pub fn vault(&self) -> Res<Address> {
        self.chain
            .call([0; 20], self.address, &reference::vault_call())?
            .get(12..32)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| "vault reply".into())
    }
    /// Post a task from this wallet. Returns its ID as the reference
    /// computes it; the transaction must have succeeded.
    pub fn post(&self, wallet: &SigningKey, task: &Task) -> Res<(Hash, Receipt)> {
        let receipt =
            self.chain
                .send(wallet, Some(self.address), 0, &reference::post_call(task))?;
        if !receipt.success {
            return Err("post reverted".into());
        }
        Ok((
            reference::id(self.chain.id, self.address, address_of(wallet), task),
            receipt,
        ))
    }
    pub fn withdraw(&self, wallet: &SigningKey, id: Hash) -> Res<Receipt> {
        let receipt =
            self.chain
                .send(wallet, Some(self.address), 0, &reference::withdraw_call(id))?;
        if !receipt.success {
            return Err("withdraw reverted".into());
        }
        Ok(receipt)
    }
    pub fn withdrawn(&self, id: Hash) -> Res<bool> {
        Ok(self
            .chain
            .call([0; 20], self.address, &reference::withdrawn_call(id))?
            .last()
            == Some(&1))
    }
    pub fn latest_block(&self) -> Res<u64> {
        quantity(&self.chain.rpc("eth_blockNumber", json!([]))?)
    }
    /// The board's notices in blocks `from..=to`, oldest first, asked for in
    /// bounded ranges. Logs that are not the board's two events are an error:
    /// the address filter means there should be none.
    pub fn notices(&self, from: u64, to: u64) -> Res<Vec<Notice>> {
        let mut notices = vec![];
        let mut start = from;
        while start <= to {
            let end = to.min(start.saturating_add(LOG_RANGE - 1));
            let logs = self.chain.rpc(
                "eth_getLogs",
                json!([{
                    "address": hex(&self.address),
                    "fromBlock": format!("{start:#x}"),
                    "toBlock": format!("{end:#x}"),
                }]),
            )?;
            for log in logs.as_array().ok_or("logs expected")? {
                notices.push(notice_from_log(&self.address, log)?);
            }
            start = end + 1;
        }
        Ok(notices)
    }
}

/// One `eth_getLogs` entry as a notice of `board`. The node was asked for
/// that address's logs only; the answer is checked rather than trusted,
/// because any contract can emit an event shaped like a post, naming any
/// vault (docs/rfcs/proof-commerce-v3-review-2026-11-13.md, finding 5).
pub fn notice_from_log(board: &Address, log: &Value) -> Res<Notice> {
    let emitter: Address = unhex(log["address"].as_str().ok_or("log address expected")?)?
        .try_into()
        .map_err(|_| "log address length")?;
    if emitter != *board {
        return Err(format!(
            "a log from {} was returned for the board {}",
            hex(&emitter),
            hex(board)
        )
        .into());
    }
    let topics = log["topics"]
        .as_array()
        .ok_or("topics expected")?
        .iter()
        .map(|topic| -> Res<Hash> {
            unhex(topic.as_str().ok_or("topic expected")?)?
                .try_into()
                .map_err(|_| "topic length".into())
        })
        .collect::<Res<Vec<Hash>>>()?;
    let data = unhex(log["data"].as_str().ok_or("log data expected")?)?;
    Ok(reference::decode_log(&topics, &data).map_err(|e| format!("board log: {e:?}"))?)
}

/// An iroh node ID as the 32 bytes a task carries, and back.
pub fn node_bytes(node: &str) -> Res<Hash> {
    let id: EndpointId = node.parse().map_err(|_| "node id")?;
    Ok(*id.as_bytes())
}
pub fn node_text(bytes: &Hash) -> Res<String> {
    Ok(EndpointId::from_bytes(bytes)
        .map_err(|_| "node id bytes")?
        .to_string())
}

/// The `context` of an order answering a posted task: the task's ID and the
/// buyer's possession key. The ID already commits to chain, board, poster
/// and every term of the task, so an authorization signed for one task's
/// order is the nonce of no other task's order.
pub fn context(id: Hash, buyer_key_binding: Hash) -> Hash {
    vault_wire::context(id, buyer_key_binding)
}
/// Where a task is asked about and offered for, on the buyer's node.
pub fn path(id: &Hash) -> String {
    format!("/task/{}", hex(id))
}
pub fn offer_path(id: &Hash) -> String {
    format!("{}/offer", path(id))
}
/// Where a seller asks what an offer would get, without the buyer signing.
pub fn review_path(id: &Hash) -> String {
    format!("{}/review", path(id))
}
