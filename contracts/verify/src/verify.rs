//! One deployment against its rebuild: runtime code, creation code and
//! constructor arguments, the metadata hash, and the upgrade controls.

use crate::abi;
use crate::compile::{Compiled, Context, compile};
use crate::controls;
use crate::evm::{RuntimeVerdict, compare_runtime, metadata};
use crate::rpc::{Rpc, quantity};
use crate::util::{Res, address, base58, hex, ipfs_multihash, keccak, unhex};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// The deterministic deployment proxy forge uses for `new C{salt: s}()`.
pub const CREATE2_PROXY: &str = "0x4e59b44847b379578588920ca78fbf26c0b4956c";

#[derive(Debug, Clone)]
pub struct Deployment {
    pub label: String,
    pub contract: String,
    pub chain_id: Option<u64>,
    pub rpc: String,
    pub address: String,
    pub tx: String,
    pub source_rev: Option<String>,
    /// Constructor argument name → expected value. A value `source:UNIT:NAME`
    /// is the hex literal assigned to NAME in that source unit.
    pub expect: BTreeMap<String, String>,
}

impl Deployment {
    pub fn from_json(v: &Value, labels: &BTreeMap<String, String>) -> Res<Deployment> {
        let s = |k: &str| -> Res<String> {
            Ok(v[k]
                .as_str()
                .ok_or_else(|| format!("deployment entry has no {k}"))?
                .to_string())
        };
        let mut expect = BTreeMap::new();
        if let Some(m) = v["expect"].as_object() {
            for (k, val) in m {
                let text = val.as_str().ok_or("expect values are strings")?;
                // `deployment:LABEL` is that deployment's address.
                let resolved = match text.strip_prefix("deployment:") {
                    Some(l) => labels
                        .get(l)
                        .ok_or_else(|| format!("expect {k}: no deployment {l}"))?
                        .clone(),
                    None => text.to_string(),
                };
                expect.insert(k.clone(), resolved);
            }
        }
        Ok(Deployment {
            label: s("label")?,
            contract: s("contract")?,
            chain_id: v["chainId"].as_u64(),
            rpc: s("rpc")?,
            address: s("address")?.to_ascii_lowercase(),
            tx: s("tx")?,
            source_rev: v["sourceRev"].as_str().map(str::to_string),
            expect,
        })
    }
}

pub fn load_manifest(path: &std::path::Path) -> Res<Vec<Deployment>> {
    let v: Value = serde_json::from_str(
        &std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?,
    )?;
    let entries = v["deployments"]
        .as_array()
        .ok_or("manifest has no deployments")?;
    let labels: BTreeMap<String, String> = entries
        .iter()
        .filter_map(|e| {
            Some((
                e["label"].as_str()?.to_string(),
                e["address"].as_str()?.to_ascii_lowercase(),
            ))
        })
        .collect();
    entries
        .iter()
        .map(|e| Deployment::from_json(e, &labels))
        .collect()
}

pub struct Outcome {
    pub ok: bool,
    pub report: Value,
}

struct Lines {
    ok: bool,
    checks: Vec<Value>,
}

impl Lines {
    fn add(&mut self, what: &str, ok: bool, detail: String) {
        println!("  {}  {what}: {detail}", if ok { "ok  " } else { "FAIL" });
        self.ok &= ok;
        self.checks
            .push(json!({"check": what, "ok": ok, "detail": detail}));
    }
}

/// The hex literal `NAME = hex"..."` in `unit`'s text.
fn source_constant(input: &Value, unit: &str, name: &str) -> Res<String> {
    let text = input["sources"][unit]["content"]
        .as_str()
        .ok_or_else(|| format!("no source unit {unit}"))?;
    let needle = format!("{name} = hex\"");
    let at = text
        .find(&needle)
        .ok_or_else(|| format!("{unit} assigns no hex literal to {name}"))?;
    let rest = &text[at + needle.len()..];
    let end = rest.find('"').ok_or("unterminated hex literal")?;
    Ok(format!("0x{}", rest[..end].to_ascii_lowercase()))
}

pub fn verify(ctx: &Context, d: &Deployment) -> Res<Outcome> {
    println!("{} ({} at {})", d.label, d.contract, d.address);
    let rpc = Rpc::new(&d.rpc);
    let mut lines = Lines {
        ok: true,
        checks: Vec::new(),
    };
    let chain_id = rpc.chain_id()?;
    // Every chain read below is at this block or later.
    let block = rpc.block_number()?;
    let checked_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("  chain {chain_id}, block {block}");
    if let Some(want) = d.chain_id {
        lines.add(
            "chain",
            chain_id == want,
            format!("RPC answers chain {chain_id}, expected {want}"),
        );
    }
    let c: Compiled = compile(ctx, &d.contract, d.source_rev.as_deref())?;
    println!(
        "  build: solc {} (SHA-256 {}), settings {}",
        c.compiler,
        c.solc_sha256,
        serde_json::to_string(&c.settings)?
    );
    for (unit, k) in &c.sources {
        println!("  source {unit}: keccak-256 {k}");
    }
    let code = rpc.code(&d.address, "latest")?;
    if code.is_empty() {
        lines.add("runtime code", false, "no code at the address".into());
        return Ok(Outcome {
            ok: false,
            report: json!({"label": d.label, "checks": lines.checks}),
        });
    }
    let cmp = compare_runtime(&code, &c.runtime, &c.immutables);
    let (runtime_ok, runtime_detail, runtime_match) = match &cmp.verdict {
        RuntimeVerdict::Exact => (
            true,
            format!(
                "{} bytes equal to the rebuild, metadata included, immutables filled",
                code.len()
            ),
            "exact",
        ),
        RuntimeVerdict::MetadataOnly { chain, compiled } => (
            false,
            format!(
                "code equal but metadata differs (partial match): chain ipfs {}, rebuild ipfs {}",
                chain.as_deref().unwrap_or("-"),
                compiled.as_deref().unwrap_or("-")
            ),
            "partial",
        ),
        RuntimeVerdict::Differs { reason } => (false, reason.clone(), "differs"),
    };
    lines.add("runtime code", runtime_ok, runtime_detail);
    let runtime_hash = hex(&keccak(&code));
    println!("  runtime keccak-256 {runtime_hash}");
    let mut immutables = serde_json::Map::new();
    for (name, value) in &cmp.immutables {
        println!("  immutable {name} = {}", hex(value));
        immutables.insert(name.clone(), json!(hex(value)));
    }

    // The metadata hash: what the chain's CBOR names, and whether the
    // rebuild's metadata JSON hashes to it.
    let chain_meta = metadata(&code);
    let meta_desc = chain_meta
        .as_ref()
        .map(|m| m.describe())
        .unwrap_or_else(|| "none".into());
    println!("  metadata in code: {meta_desc}");
    let ipfs = chain_meta.as_ref().and_then(|m| m.ipfs());
    if let Some(ipfs) = &ipfs {
        let computed = base58(&ipfs_multihash(c.metadata.as_bytes())?);
        lines.add(
            "metadata hash",
            &computed == ipfs,
            format!("the rebuild's metadata JSON hashes to {computed}; the code names {ipfs}"),
        );
    } else {
        println!("  metadata hash: the code carries none (bytecodeHash none)");
    }

    // Creation: the transaction, its path, its input.
    let tx = rpc.transaction(&d.tx)?;
    let receipt = rpc.receipt(&d.tx)?;
    let status = quantity(&receipt["status"]).unwrap_or(0);
    let input = unhex(tx["input"].as_str().ok_or("tx has no input")?)?;
    let to = tx["to"].as_str().map(|s| s.to_ascii_lowercase());
    let (init, path, path_ok, path_detail) = match to.as_deref() {
        None => {
            let created = receipt["contractAddress"]
                .as_str()
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();
            let ok = created == d.address && status == 1;
            (
                input.clone(),
                "create",
                ok,
                format!("contract-creation transaction, status {status}, created {created}"),
            )
        }
        Some(p) if p == CREATE2_PROXY => {
            if input.len() < 32 {
                return Err("CREATE2 proxy input shorter than a salt".into());
            }
            let (salt, init) = input.split_at(32);
            let mut pre = vec![0xff];
            pre.extend(address(CREATE2_PROXY)?);
            pre.extend(salt);
            pre.extend(keccak(init));
            let derived = hex(&keccak(&pre)[12..]);
            let ok = derived == d.address && status == 1;
            (
                init.to_vec(),
                "create2",
                ok,
                format!(
                    "CREATE2 through {CREATE2_PROXY}, salt {}, status {status}, derived address {derived}",
                    hex(salt)
                ),
            )
        }
        Some(other) => {
            lines.add(
                "creation path",
                false,
                format!("transaction calls {other}; only direct creation and {CREATE2_PROXY} are supported"),
            );
            return Ok(Outcome {
                ok: false,
                report: json!({"label": d.label, "checks": lines.checks}),
            });
        }
    };
    lines.add("creation transaction", path_ok, path_detail);
    let prefix_ok = init.len() >= c.creation.len() && init[..c.creation.len()] == c.creation[..];
    let creation_detail = if prefix_ok {
        format!(
            "the transaction's init code is the rebuild's {} bytes followed by {} bytes of arguments",
            c.creation.len(),
            init.len() - c.creation.len()
        )
    } else {
        let first = init.iter().zip(c.creation.iter()).position(|(a, b)| a != b);
        format!(
            "init code is not the rebuild's creation code (first difference at {:?}; init {} bytes, rebuild {})",
            first,
            init.len(),
            c.creation.len()
        )
    };
    lines.add("creation code", prefix_ok, creation_detail);

    let inputs = abi::constructor_inputs(&c.abi);
    let mut args_json = Vec::new();
    if prefix_ok {
        match abi::decode(&inputs, &init[c.creation.len()..]) {
            Ok(args) => {
                for a in &args {
                    println!("  argument {} ({}) = {}", a.name, a.ty, a.value);
                    args_json.push(json!({"name": a.name, "type": a.ty, "value": a.value}));
                }
                for (name, want) in &d.expect {
                    let Some(a) = args.iter().find(|a| &a.name == name) else {
                        lines.add(
                            &format!("argument {name}"),
                            false,
                            "no such constructor argument".into(),
                        );
                        continue;
                    };
                    let want = match want.strip_prefix("source:") {
                        Some(r) => {
                            let (unit, cname) = r.rsplit_once(':').ok_or("source:UNIT:NAME")?;
                            let v = source_constant(&c.input, unit, cname)?;
                            println!("  expected {name} from {unit} {cname}: {v}");
                            v
                        }
                        None => abi::normalise(&a.ty, want),
                    };
                    lines.add(
                        &format!("argument {name}"),
                        a.value == want,
                        format!("chain {}, expected {want}", a.value),
                    );
                }
            }
            Err(e) => lines.add("constructor arguments", false, e.to_string()),
        }
    }

    let controls = controls::check(&rpc, &d.address, &code, Some(&c.abi))?;
    let mut controls_json = Vec::new();
    for ctl in &controls {
        lines.add(&ctl.what, ctl.ok, ctl.detail.clone());
        controls_json.push(json!({"check": ctl.what, "ok": ctl.ok, "detail": ctl.detail}));
    }
    println!(
        "  {} {}",
        if lines.ok { "VERIFIED" } else { "NOT VERIFIED" },
        d.label
    );
    let report = json!({
        "label": d.label,
        "contract": d.contract,
        "chainId": chain_id,
        "checkedAtBlock": block,
        "checkedAt": checked_at,
        "rpc": d.rpc,
        "address": d.address,
        "tx": d.tx,
        "creationPath": path,
        "sourceRev": d.source_rev,
        "compiler": c.compiler,
        "solcSha256": c.solc_sha256,
        "settings": c.settings,
        "sources": c.sources,
        "runtimeBytes": code.len(),
        "runtimeKeccak256": runtime_hash,
        "runtimeMatch": runtime_match,
        "metadata": meta_desc,
        "metadataIpfs": ipfs,
        "immutables": immutables,
        "constructorArguments": args_json,
        "controls": controls_json,
        "checks": lines.checks,
        "verified": lines.ok,
    });
    Ok(Outcome {
        ok: lines.ok,
        report,
    })
}

/// Which of `candidates` the code at `address` is, by rebuilding each.
pub fn identify(
    ctx: &Context,
    rpc: &Rpc,
    address_: &str,
    candidates: &[String],
) -> Res<Vec<(String, String)>> {
    let code = rpc.code(address_, "latest")?;
    println!(
        "code at {address_}: {} bytes, keccak-256 {}",
        code.len(),
        hex(&keccak(&code))
    );
    let mut out = Vec::new();
    for name in candidates {
        let c = compile(ctx, name, None)?;
        let r = compare_runtime(&code, &c.runtime, &c.immutables);
        let verdict = match &r.verdict {
            RuntimeVerdict::Exact => {
                let imms: Vec<String> = r
                    .immutables
                    .iter()
                    .map(|(n, v)| format!("{n}={}", hex(v)))
                    .collect();
                format!("MATCH (immutables {})", imms.join(", "))
            }
            RuntimeVerdict::MetadataOnly { .. } => "code equal, metadata differs".into(),
            RuntimeVerdict::Differs { reason } => format!("no: {reason}"),
        };
        println!("  {name}: {verdict}");
        out.push((name.clone(), verdict));
    }
    Ok(out)
}

/// The block and transaction that created `address`: a binary search over
/// `eth_getCode` at past blocks (the RPC must serve historical state), then
/// the block's transactions.
pub fn find_creation(rpc: &Rpc, address_: &str) -> Res<(u64, Option<String>)> {
    let mut hi = rpc.block_number()?;
    if rpc.code(address_, &format!("0x{hi:x}"))?.is_empty() {
        return Err("no code at the latest block".into());
    }
    let mut lo = 0u64;
    // Invariant: no code at lo (or lo == 0), code at hi.
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if rpc.code(address_, &format!("0x{mid:x}"))?.is_empty() {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    let block = rpc.block(hi)?;
    let target = address(address_)?;
    for tx in block["transactions"].as_array().into_iter().flatten() {
        let hash = tx["hash"].as_str().unwrap_or("").to_string();
        let input = unhex(tx["input"].as_str().unwrap_or("0x"))?;
        match tx["to"].as_str().map(|s| s.to_ascii_lowercase()) {
            None => {
                let r = rpc.receipt(&hash)?;
                if r["contractAddress"]
                    .as_str()
                    .map(|s| s.to_ascii_lowercase())
                    == Some(hex(&target))
                {
                    return Ok((hi, Some(hash)));
                }
            }
            Some(to) if to == CREATE2_PROXY && input.len() >= 32 => {
                let (salt, init) = input.split_at(32);
                let mut pre = vec![0xff];
                pre.extend(address(CREATE2_PROXY)?);
                pre.extend(salt);
                pre.extend(keccak(init));
                if keccak(&pre)[12..] == target {
                    return Ok((hi, Some(hash)));
                }
            }
            Some(_) => {}
        }
    }
    Ok((hi, None))
}
