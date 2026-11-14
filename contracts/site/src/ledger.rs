//! The public transaction ledger: a snapshot of settlements read from the
//! chain, and what the site serves from it.
//!
//! `nucleus-site snapshot` is the only part that touches a network. It
//! reads, with plain JSON-RPC calls to public endpoints, each settlement
//! transaction named in `input/ledger.json`, its receipt, its block, the
//! funding transaction (found by the order digest in the vault's `Funded`
//! log), the vault's recorded artifact hash and phase, and the token's
//! name. It writes `input/ledger.snapshot.json` and the delivered artifacts
//! (`input/artifacts/<keccak256>.bin`, taken from the settlement calldata).
//! A build reads those files and never the network.
//!
//! Every receipt field is read from the chain or computed from what was
//! read, except the fields under `asserted`, which are the authors' own
//! statements and say so (`assertedBy: "authors"`).
use crate::{Res, hex, signing::jcs, unhex};
use alloy_primitives::keccak256;
use alloy_sol_types::{SolCall, sol};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{fs, path::Path};

mod second {
    alloy_sol_types::sol! {
        struct Order { address buyer; address seller; address asset; uint256 amount; address verifier; bytes32 program; bytes32 policyHash; uint64 fundBy; uint64 deliverBy; bytes32 salt; bytes32 context; }
        function settle(Order o, bytes artifact, bytes seal);
    }
}
mod third {
    alloy_sol_types::sol! {
        struct Order { address buyer; address seller; address asset; uint256 amount; address verifier; bytes32 program; bytes32 policyHash; bytes32 base; uint64 fundBy; uint64 deliverBy; bytes32 salt; bytes32 context; }
        function settle(Order o, bytes artifact, bytes seal);
    }
}
sol! {
    function artifactOf(bytes32 d) returns (bytes32);
    function phase(bytes32 d) returns (uint8);
    function name() returns (string);
    function symbol() returns (string);
    function decimals() returns (uint8);
}

pub const RECEIPT_SCHEMA: &str = "qed-receipt/1";

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LedgerNetwork {
    pub key: String,
    pub name: String,
    pub chain_id: u64,
    pub testnet: bool,
    pub rpc: String,
    pub explorer: String,
}

/// A token the authors say is real money, with where that is published.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RealToken {
    pub network: String,
    pub address: String,
    pub what: String,
    pub source: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NamedVault {
    pub network: String,
    pub address: String,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KnownProgram {
    pub image_id: String,
    pub name: String,
    /// `published` (its binary is in contracts/proof-acceptance/program),
    /// `not-distributed` or `retired`.
    pub status: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Recorded {
    pub network: String,
    pub settle_transaction: String,
    /// One sentence on what this run was, from the authors' records.
    pub what: String,
    /// Where the authors recorded it.
    pub record: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LedgerInput {
    pub networks: Vec<LedgerNetwork>,
    pub real_tokens: Vec<RealToken>,
    pub vaults: Vec<NamedVault>,
    pub programs: Vec<KnownProgram>,
    pub settlements: Vec<Recorded>,
}

impl LedgerInput {
    pub fn read(path: &Path) -> Res<Self> {
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    }
    pub fn network(&self, key: &str) -> Res<&LedgerNetwork> {
        self.networks
            .iter()
            .find(|n| n.key == key)
            .ok_or_else(|| format!("unknown network {key}").into())
    }
}

/// A snapshot as written by `snapshot` and read by a build.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub value: Value,
    /// Delivered artifacts by keccak-256 (lower-case hex, no 0x).
    pub artifacts: Vec<(String, Vec<u8>)>,
    /// Buyers' acceptance policies by the `policyHash` an order commits to
    /// (`input/policies.json`), where the authors have the policy. A policy
    /// is checkable: it hashes to the order's on-chain `policyHash`.
    pub policies: serde_json::Map<String, Value>,
    /// Buyers' statements by file name `<sha256>.<ndjson|v2>`
    /// (`input/statements/`), each named in a policy.
    pub statements: Vec<(String, Vec<u8>)>,
}

impl Snapshot {
    /// The policy and statement for a receipt, when the authors have them:
    /// `{policy, statement: {url, sha256, bytes, format}}`.
    pub fn acceptance(&self, receipt: &Value) -> Option<Value> {
        let hash = receipt["order"]["policyHash"].as_str()?;
        let p = self.policies.get(hash)?;
        let file = p["statementFile"].as_str()?;
        Some(json!({
            "policy": {
                "statementSha256": p["statementSha256"],
                "claim": p["claim"],
                "permittedAxioms": p["permittedAxioms"],
                "maximumArtifactBytes": p["maximumArtifactBytes"],
            },
            "policyHashesTo": hash,
            "statement": {
                "url": format!("/statements/{file}"),
                "sha256": p["statementSha256"],
                "bytes": p["statementBytes"],
                "format": p["statementFormat"],
            },
        }))
    }
}

impl Snapshot {
    pub fn receipts(&self) -> &[Value] {
        self.value["receipts"].as_array().map_or(&[], Vec::as_slice)
    }
    /// Read `ledger.snapshot.json` and the artifacts beside it.
    pub fn read(path: &Path) -> Res<Self> {
        let value: Value = serde_json::from_slice(&fs::read(path)?)?;
        let dir = path.parent().ok_or("snapshot path")?.join("artifacts");
        let mut artifacts = Vec::new();
        for receipt in value["receipts"].as_array().ok_or("receipts")? {
            let k = receipt["artifact"]["keccak256"]
                .as_str()
                .ok_or("artifact hash")?
                .trim_start_matches("0x")
                .to_owned();
            if artifacts.iter().any(|(h, _)| *h == k) {
                continue;
            }
            let bytes =
                fs::read(dir.join(format!("{k}.bin"))).map_err(|e| format!("artifact {k}: {e}"))?;
            if hex(keccak256(&bytes).as_slice()) != k {
                return Err(format!("artifact {k} does not hash to its name").into());
            }
            artifacts.push((k, bytes));
        }
        let input_dir = path.parent().ok_or("snapshot path")?;
        let policies: serde_json::Map<String, Value> =
            match fs::read(input_dir.join("policies.json")) {
                Ok(bytes) => serde_json::from_slice(&bytes)?,
                Err(_) => serde_json::Map::new(),
            };
        let mut statements = Vec::new();
        for p in policies.values() {
            let file = p["statementFile"].as_str().ok_or("policy statementFile")?;
            if statements
                .iter()
                .any(|(f, _): &(String, Vec<u8>)| f == file)
            {
                continue;
            }
            let bytes = fs::read(input_dir.join("statements").join(file))
                .map_err(|e| format!("statement {file}: {e}"))?;
            let sha = {
                use sha2::Digest as _;
                hex(sha2::Sha256::digest(&bytes).as_slice())
            };
            if Some(sha.as_str()) != p["statementSha256"].as_str() || !file.starts_with(&sha) {
                return Err(format!("statement {file} does not hash to its policy's").into());
            }
            statements.push((file.to_owned(), bytes));
        }
        Ok(Self {
            value,
            artifacts,
            policies,
            statements,
        })
    }
}

pub(crate) fn rpc(url: &str, method: &str, params: Value) -> Res<Value> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(60)))
        .build()
        .into();
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    // Public endpoints rate-limit (HTTP 429); that and only that is retried,
    // with backoff. Any other failure is reported as it is.
    let mut wait = 2;
    let reply: Value = loop {
        match agent
            .post(url)
            .header("content-type", "application/json")
            .send_json(&body)
        {
            Ok(mut response) => break response.body_mut().read_json()?,
            Err(ureq::Error::StatusCode(429)) if wait <= 64 => {
                std::thread::sleep(std::time::Duration::from_secs(wait));
                wait *= 2;
            }
            Err(error) => return Err(error.into()),
        }
    };
    if let Some(error) = reply.get("error") {
        return Err(format!("{method}: {error}").into());
    }
    Ok(reply["result"].clone())
}

fn quantity(v: &Value) -> Res<u64> {
    let s = v.as_str().ok_or("quantity is not a string")?;
    Ok(u64::from_str_radix(s.trim_start_matches("0x"), 16)?)
}

fn h(bytes: &[u8]) -> String {
    format!("0x{}", hex(bytes))
}

fn eth_call(url: &str, to: &str, data: Vec<u8>, block: u64) -> Res<Vec<u8>> {
    let out = rpc(
        url,
        "eth_call",
        json!([{ "to": to, "data": h(&data) }, format!("0x{block:x}")]),
    )?;
    unhex(out.as_str().ok_or("eth_call result")?)
}

fn abi_string(bytes: &[u8]) -> Option<String> {
    let len = usize::try_from(u64::from_be_bytes(bytes.get(56..64)?.try_into().ok()?)).ok()?;
    String::from_utf8(bytes.get(64..64 + len)?.to_vec()).ok()
}

fn word(data: &[u8], n: usize) -> Res<&[u8]> {
    data.get(32 * n..32 * (n + 1))
        .ok_or_else(|| "log data too short".into())
}

fn decimal(word: &[u8]) -> String {
    alloy_primitives::U256::from_be_slice(word).to_string()
}

fn address_of_word(word: &[u8]) -> String {
    h(&word[12..])
}

const PHASES: [&str; 4] = ["empty", "funded", "settled", "refunded"];

/// Read one settlement from the chain and make its receipt.
fn receipt_for(input: &LedgerInput, record: &Recorded, head: u64) -> Res<(Value, Vec<u8>)> {
    let net = input.network(&record.network)?;
    let url = &net.rpc;
    let chain = quantity(&rpc(url, "eth_chainId", json!([]))?)?;
    if chain != net.chain_id {
        return Err(format!("{url} serves chain {chain}, not {}", net.chain_id).into());
    }
    let hash = &record.settle_transaction;
    let tx = rpc(url, "eth_getTransactionByHash", json!([hash]))?;
    let receipt = rpc(url, "eth_getTransactionReceipt", json!([hash]))?;
    if quantity(&receipt["status"])? != 1 {
        return Err(format!("{hash} did not succeed").into());
    }
    let block = quantity(&receipt["blockNumber"])?;
    let header = rpc(
        url,
        "eth_getBlockByNumber",
        json!([format!("0x{block:x}"), false]),
    )?;
    let vault = tx["to"].as_str().ok_or("no to")?.to_ascii_lowercase();
    let calldata = unhex(tx["input"].as_str().ok_or("no input")?)?;

    // The calldata's layout says which form of vault was called.
    let (layout, order, artifact) = if let Ok(call) = third::settleCall::abi_decode(&calldata) {
        let o = call.o;
        (
            "twelve-field",
            json!({
                "buyer": h(o.buyer.as_slice()), "seller": h(o.seller.as_slice()),
                "asset": h(o.asset.as_slice()), "amount": o.amount.to_string(),
                "verifier": h(o.verifier.as_slice()), "program": h(o.program.as_slice()),
                "policyHash": h(o.policyHash.as_slice()), "base": h(o.base.as_slice()),
                "fundBy": o.fundBy, "deliverBy": o.deliverBy,
                "salt": h(o.salt.as_slice()), "context": h(o.context.as_slice()),
            }),
            call.artifact.to_vec(),
        )
    } else if let Ok(call) = second::settleCall::abi_decode(&calldata) {
        let o = call.o;
        (
            "eleven-field",
            json!({
                "buyer": h(o.buyer.as_slice()), "seller": h(o.seller.as_slice()),
                "asset": h(o.asset.as_slice()), "amount": o.amount.to_string(),
                "verifier": h(o.verifier.as_slice()), "program": h(o.program.as_slice()),
                "policyHash": h(o.policyHash.as_slice()),
                "fundBy": o.fundBy, "deliverBy": o.deliverBy,
                "salt": h(o.salt.as_slice()), "context": h(o.context.as_slice()),
            }),
            call.artifact.to_vec(),
        )
    } else {
        return Err(format!("{hash} is not a direct call to settle").into());
    };

    // The Settled log from the vault: the digest and what was booked or paid.
    let (settled_v2, settled_v3) = (
        keccak256(b"Settled(bytes32,bytes32,uint256,uint256)"),
        keccak256(b"Settled(bytes32,bytes32,uint256,uint256,address,uint256)"),
    );
    let mut found = None;
    for log in receipt["logs"].as_array().ok_or("logs")? {
        if log["address"]
            .as_str()
            .map(str::to_ascii_lowercase)
            .as_deref()
            != Some(&vault)
        {
            continue;
        }
        let topics: Vec<String> = log["topics"]
            .as_array()
            .ok_or("topics")?
            .iter()
            .filter_map(|t| t.as_str().map(str::to_ascii_lowercase))
            .collect();
        let topic0 = topics.first().cloned().unwrap_or_default();
        if topic0 == h(settled_v2.as_slice()) || topic0 == h(settled_v3.as_slice()) {
            found = Some((topics, unhex(log["data"].as_str().ok_or("data")?)?));
        }
    }
    let (topics, data) = found.ok_or("no Settled log from the called contract")?;
    let digest = topics.get(1).ok_or("Settled has no digest topic")?.clone();
    let recorded_in_log = h(word(&data, 0)?);
    let booked = if data.len() >= 32 * 5 {
        json!({
            "seller": decimal(word(&data, 1)?), "fee": decimal(word(&data, 2)?),
            "basePayee": address_of_word(word(&data, 3)?), "royalty": decimal(word(&data, 4)?),
            "kind": "owed, paid out by claim",
        })
    } else {
        json!({
            "seller": decimal(word(&data, 1)?), "fee": decimal(word(&data, 2)?),
            "kind": "seller paid in the settlement; fee booked",
        })
    };

    // The vault's own record, at the snapshot block.
    let d: [u8; 32] = unhex(&digest)?.try_into().map_err(|_| "digest length")?;
    let vault_artifact = eth_call(
        url,
        &vault,
        artifactOfCall { d: d.into() }.abi_encode(),
        head,
    )?;
    let phase_now = eth_call(url, &vault, phaseCall { d: d.into() }.abi_encode(), head)?;
    let phase_n = *phase_now.last().ok_or("phase reply")? as usize;

    // Funding: the vault's Funded log for this digest, before the settlement.
    let funded_topic = keccak256(b"Funded(bytes32,address,address,address,uint256)");
    // Public endpoints refuse wide log queries, so search backwards from the
    // settlement in windows of 5,000 blocks, up to 400,000 blocks.
    let mut logs = Value::Null;
    let mut to = block;
    while to > 0 && block - to < 400_000 {
        let from = to.saturating_sub(4_999);
        let found = rpc(
            url,
            "eth_getLogs",
            json!([{ "address": vault, "topics": [h(funded_topic.as_slice()), digest],
                     "fromBlock": format!("0x{from:x}"), "toBlock": format!("0x{to:x}") }]),
        )?;
        if found.as_array().is_some_and(|l| !l.is_empty()) {
            logs = found;
            break;
        }
        to = from.saturating_sub(1);
    }
    let funding = match logs.as_array().and_then(|l| l.first()) {
        Some(log) => {
            let fb = quantity(&log["blockNumber"])?;
            let fh = rpc(
                url,
                "eth_getBlockByNumber",
                json!([format!("0x{fb:x}"), false]),
            )?;
            json!({ "transaction": log["transactionHash"], "block": fb, "timestamp": quantity(&fh["timestamp"])? })
        }
        None => Value::Null,
    };

    // The token, as it names itself.
    let asset = order["asset"].as_str().ok_or("asset")?.to_owned();
    let token = json!({
        "address": asset,
        "name": abi_string(&eth_call(url, &asset, nameCall {}.abi_encode(), head)?),
        "symbol": abi_string(&eth_call(url, &asset, symbolCall {}.abi_encode(), head)?),
        "decimals": eth_call(url, &asset, decimalsCall {}.abi_encode(), head)?.last().copied(),
    });

    let artifact_hash = keccak256(&artifact);
    let real = input
        .real_tokens
        .iter()
        .find(|t| t.network == record.network && t.address == asset);
    let vault_name = input
        .vaults
        .iter()
        .find(|v| v.network == record.network && v.address == vault)
        .map(|v| v.name.clone());
    let program = order["program"]
        .as_str()
        .unwrap_or_default()
        .trim_start_matches("0x")
        .to_owned();
    let program_name = input
        .programs
        .iter()
        .find(|p| p.image_id == program)
        .map(|p| json!({ "name": p.name, "status": p.status }));
    let value = json!({
        "schema": RECEIPT_SCHEMA,
        "id": digest,
        "network": { "chainId": chain, "name": net.name, "testnet": net.testnet },
        "vault": vault,
        "orderLayout": layout,
        "orderDigest": digest,
        "order": order,
        "settlement": {
            "transaction": hash.to_ascii_lowercase(),
            "block": block,
            "timestamp": quantity(&header["timestamp"])?,
            "from": tx["from"].as_str().map(str::to_ascii_lowercase),
            "gasUsed": quantity(&receipt["gasUsed"])?,
        },
        "funding": funding,
        "artifact": {
            "bytes": artifact.len(),
            "keccak256": h(artifact_hash.as_slice()),
            "inSettledLog": recorded_in_log,
            "recordedByVault": h(&vault_artifact),
            "url": format!("/artifacts/{}.bin", hex(artifact_hash.as_slice())),
        },
        "booked": booked,
        "phaseAtSnapshot": PHASES.get(phase_n).copied().unwrap_or("unknown"),
        "token": token,
        "snapshot": { "block": head, "rpc": url },
        "asserted": {
            "assertedBy": "authors",
            "what": record.what,
            "counterparties": "Buyer and seller keys were both held by the authors.",
            "record": record.record,
            "vaultName": vault_name,
            "program": program_name,
            "realMoney": real.map(|t| json!({ "what": t.what, "source": t.source })),
        },
    });
    Ok((value, artifact))
}

/// Read every recorded settlement from its chain and write the snapshot and
/// artifacts into `dir`.
pub fn snapshot(input: &LedgerInput, dir: &Path, now: u64) -> Res<usize> {
    let mut heads = Vec::new();
    for net in &input.networks {
        let head = quantity(&rpc(&net.rpc, "eth_blockNumber", json!([]))?)?;
        heads.push((net.key.clone(), head, net.rpc.clone(), net.chain_id));
    }
    let mut receipts = Vec::new();
    fs::create_dir_all(dir.join("artifacts"))?;
    for record in &input.settlements {
        let head = heads
            .iter()
            .find(|(k, ..)| *k == record.network)
            .map(|(_, b, ..)| *b)
            .ok_or("network head")?;
        let (receipt, artifact) = receipt_for(input, record, head)
            .map_err(|e| format!("{}: {e}", record.settle_transaction))?;
        let k = hex(keccak256(&artifact).as_slice());
        fs::write(dir.join("artifacts").join(format!("{k}.bin")), &artifact)?;
        println!(
            "{} {} artifact {} bytes, vault records {}",
            record.network,
            record.settle_transaction,
            artifact.len(),
            receipt["artifact"]["recordedByVault"]
        );
        receipts.push(receipt);
    }
    receipts.sort_by_key(|r| {
        (
            r["settlement"]["timestamp"].as_u64().unwrap_or(0),
            r["id"].as_str().unwrap_or_default().to_owned(),
        )
    });
    let value = json!({
        "schema": "qed-ledger-snapshot/1",
        "takenAt": now,
        "networks": heads.iter().map(|(key, block, rpc, chain)| json!({ "key": key, "chainId": chain, "block": block, "rpc": rpc })).collect::<Vec<_>>(),
        "receipts": receipts,
    });
    let mut text = serde_json::to_string_pretty(&value)?;
    text.push('\n');
    fs::write(dir.join("ledger.snapshot.json"), text)?;
    Ok(input.settlements.len())
}

/// A receipt's served bytes: RFC 8785 canonical JSON and a newline.
pub fn receipt_bytes(receipt: &Value) -> Res<Vec<u8>> {
    let mut text = jcs(receipt)?;
    text.push('\n');
    Ok(text.into_bytes())
}
