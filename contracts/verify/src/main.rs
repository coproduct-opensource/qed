//! qed-verify: rebuild a deployed contract from source with pinned compiler
//! settings and compare it with the chain.
//!
//! Exit status: 0 when every check holds, 1 when any check fails, 2 when a
//! check could not be made (usage, network, compiler). Nothing here signs or
//! sends a transaction, and nothing needs a key or an account.

mod abi;
mod compile;
mod controls;
mod evm;
mod rpc;
mod sourcify;
mod util;
mod verify;

use compile::Context;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use util::Res;
use verify::Deployment;

const USAGE: &str = "\
usage: qed-verify [--root DIR] [--solc PATH] COMMAND

  manifest FILE [--only LABEL]... [--json OUT] [--redact ARG]...
      verify every deployment a manifest lists (contracts/verify/deployments/*.json);
      --redact replaces a constructor argument's value (and the same address
      wherever it occurs) with \"redacted\" in the JSON written by --json
  deployment --contract NAME --rpc URL --address ADDR --tx HASH
             [--chain-id N] [--source-rev REV] [--expect ARG=VALUE]... [--json OUT]
      verify one deployment
  identify --rpc URL --address ADDR NAME...
      rebuild each named contract and say which one the code at ADDR is
  controls --rpc URL --address ADDR
      only the upgrade-control checks, for code with no source here
  creation --rpc URL --address ADDR
      find the block and transaction that created ADDR (needs historical state)
  std-json --contract NAME [--source-rev REV]
      print the standard-JSON input the rebuild compiles
  sourcify-submit FILE [--only LABEL]...
      submit a manifest's deployments to Sourcify and wait for the result
  sourcify-status FILE
      look each of a manifest's deployments up on Sourcify

The compiler is the official solc release named in contracts/verify/build.json,
downloaded once into $QED_VERIFY_CACHE (default ~/.cache/qed-verify) and checked
against its pinned SHA-256 before each use. --solc PATH uses a local binary,
which must hash to the same pin.";

struct Args {
    rest: Vec<String>,
}

impl Args {
    fn take(&mut self, flag: &str) -> Option<String> {
        let i = self.rest.iter().position(|a| a == flag)?;
        if i + 1 >= self.rest.len() {
            return None;
        }
        let v = self.rest.remove(i + 1);
        self.rest.remove(i);
        Some(v)
    }
    fn take_all(&mut self, flag: &str) -> Vec<String> {
        let mut out = Vec::new();
        while let Some(v) = self.take(flag) {
            out.push(v);
        }
        out
    }
    fn need(&mut self, flag: &str) -> Res<String> {
        self.take(flag)
            .ok_or_else(|| format!("missing {flag}\n\n{USAGE}").into())
    }
}

/// The report with the named constructor arguments and immutables replaced
/// by "redacted", in the JSON written by --json only (the terminal output
/// keeps them). A value is redacted wherever it occurs in the report, so an
/// immutable holding the same address as a redacted argument goes too.
fn redacted(mut report: serde_json::Value, names: &[String]) -> serde_json::Value {
    if names.is_empty() {
        return report;
    }
    let mut values = Vec::new();
    if let Some(args) = report["constructorArguments"].as_array() {
        for a in args {
            if names.iter().any(|n| a["name"] == n.as_str())
                && let Some(v) = a["value"].as_str()
            {
                values.push(v.to_ascii_lowercase());
            }
        }
    }
    if let Some(imms) = report["immutables"].as_object() {
        for (k, v) in imms {
            if names.contains(k)
                && let Some(v) = v.as_str()
            {
                values.push(v.to_ascii_lowercase());
            }
        }
    }
    let mut text = serde_json::to_string(&report).unwrap_or_default();
    for v in &values {
        // An address argument is 40 hex digits; as an immutable it is the
        // same digits left-padded, so replacing the 40 covers both.
        let bare = v
            .trim_start_matches("0x")
            .trim_start_matches("000000000000000000000000");
        if bare.len() >= 40 {
            text = text.replace(bare, "redacted");
        }
    }
    report = serde_json::from_str(&text).unwrap_or(report);
    report["redacted"] = serde_json::json!(names);
    report
}

fn write_json(path: Option<String>, value: &serde_json::Value) -> Res<()> {
    if let Some(p) = path {
        std::fs::write(&p, serde_json::to_string_pretty(value)? + "\n")?;
        println!("wrote {p}");
    }
    Ok(())
}

fn run() -> Res<bool> {
    let mut args = Args {
        rest: std::env::args().skip(1).collect(),
    };
    let root = args
        .take("--root")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    let solc = args.take("--solc").map(PathBuf::from);
    if args.rest.is_empty() || args.rest[0] == "--help" || args.rest[0] == "-h" {
        println!("{USAGE}");
        return Ok(true);
    }
    let command = args.rest.remove(0);
    let ctx = Context::load(&root, solc)?;
    match command.as_str() {
        "manifest" => {
            let only = args.take_all("--only");
            let json_out = args.take("--json");
            let redact = args.take_all("--redact");
            let file = args.rest.first().ok_or(USAGE)?.clone();
            let mut all_ok = true;
            let mut reports = Vec::new();
            for d in verify::load_manifest(file.as_ref())? {
                if !only.is_empty() && !only.contains(&d.label) {
                    continue;
                }
                let o = verify::verify(&ctx, &d)?;
                all_ok &= o.ok;
                reports.push(redacted(o.report, &redact));
                println!();
            }
            println!(
                "{} of {} deployments verified",
                reports.iter().filter(|r| r["verified"] == true).count(),
                reports.len()
            );
            write_json(json_out, &serde_json::json!({"deployments": reports}))?;
            Ok(all_ok)
        }
        "deployment" => {
            let mut expect = BTreeMap::new();
            for e in args.take_all("--expect") {
                let (k, v) = e.split_once('=').ok_or("--expect ARG=VALUE")?;
                expect.insert(k.to_string(), v.to_string());
            }
            let d = Deployment {
                label: args.take("--label").unwrap_or_else(|| "deployment".into()),
                contract: args.need("--contract")?,
                rpc: args.need("--rpc")?,
                address: args.need("--address")?.to_ascii_lowercase(),
                tx: args.need("--tx")?,
                chain_id: args.take("--chain-id").map(|s| s.parse()).transpose()?,
                source_rev: args.take("--source-rev"),
                expect,
            };
            let json_out = args.take("--json");
            let o = verify::verify(&ctx, &d)?;
            write_json(json_out, &o.report)?;
            Ok(o.ok)
        }
        "identify" => {
            let rpc = rpc::Rpc::new(&args.need("--rpc")?);
            let address = args.need("--address")?.to_ascii_lowercase();
            if args.rest.is_empty() {
                return Err(USAGE.into());
            }
            let found = verify::identify(&ctx, &rpc, &address, &args.rest)?;
            let matches: Vec<&String> = found
                .iter()
                .filter(|(_, v)| v.starts_with("MATCH"))
                .map(|(n, _)| n)
                .collect();
            println!(
                "{}",
                match matches.len() {
                    1 => format!("identified: {}", matches[0]),
                    0 => "identified: none of the candidates".into(),
                    _ => format!("identified: more than one ({matches:?})"),
                }
            );
            Ok(matches.len() == 1)
        }
        "controls" => {
            let rpc = rpc::Rpc::new(&args.need("--rpc")?);
            let address = args.need("--address")?.to_ascii_lowercase();
            let code = rpc.code(&address, "latest")?;
            if code.is_empty() {
                return Err(format!("no code at {address}").into());
            }
            println!(
                "{address}: {} bytes of code (no ABI: name checks skipped)",
                code.len()
            );
            let mut ok = true;
            for c in controls::check(&rpc, &address, &code, None)? {
                println!(
                    "  {}  {}: {}",
                    if c.ok { "ok  " } else { "FAIL" },
                    c.what,
                    c.detail
                );
                ok &= c.ok;
            }
            Ok(ok)
        }
        "creation" => {
            let rpc = rpc::Rpc::new(&args.need("--rpc")?);
            let address = args.need("--address")?.to_ascii_lowercase();
            let (block, tx) = verify::find_creation(&rpc, &address)?;
            match tx {
                Some(tx) => {
                    println!("created in block {block} by transaction {tx}");
                    Ok(true)
                }
                None => {
                    println!(
                        "code first appears in block {block}; no transaction in it creates the address directly or through {}",
                        verify::CREATE2_PROXY
                    );
                    Ok(false)
                }
            }
        }
        "std-json" => {
            let name = args.need("--contract")?;
            let rev = args.take("--source-rev");
            let input = compile::standard_json(&ctx, &name, rev.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&input)?);
            Ok(true)
        }
        "sourcify-submit" | "sourcify-status" => {
            let only = args.take_all("--only");
            let file = args.rest.first().ok_or(USAGE)?.clone();
            let mut all_ok = true;
            for d in verify::load_manifest(file.as_ref())? {
                if !only.is_empty() && !only.contains(&d.label) {
                    continue;
                }
                let chain_id = match d.chain_id {
                    Some(c) => c,
                    None => rpc::Rpc::new(&d.rpc).chain_id()?,
                };
                println!(
                    "{} ({} at {}, chain {chain_id})",
                    d.label, d.contract, d.address
                );
                let result = if command == "sourcify-submit" {
                    sourcify::submit(&ctx, &d, chain_id)?
                } else {
                    sourcify::lookup(chain_id, &d.address)?
                };
                let contract = if result.get("contract").is_some() {
                    &result["contract"]
                } else {
                    &result
                };
                println!(
                    "  match {}, creation {}, runtime {}",
                    contract["match"], contract["creationMatch"], contract["runtimeMatch"]
                );
                if !result["error"].is_null() {
                    println!("  error {}", result["error"]);
                }
                println!("  https://repo.sourcify.dev/{chain_id}/{}", d.address);
                all_ok &= contract["match"] == "exact_match";
            }
            Ok(all_ok)
        }
        other => Err(format!("unknown command {other}\n\n{USAGE}").into()),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("qed-verify: {e}");
            ExitCode::from(2)
        }
    }
}
