//! Sourcify's public v2 API: submit a standard-JSON input for verification
//! and look a contract up. No account and no key.

use crate::compile::{Context, standard_json};
use crate::util::Res;
use crate::verify::Deployment;
use serde_json::{Value, json};
use std::time::Duration;

pub const SERVER: &str = "https://sourcify.dev/server";

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        .http_status_as_error(false)
        .build()
        .new_agent()
}

fn read(r: ureq::http::Response<ureq::Body>) -> Res<(u16, Value)> {
    let status = r.status().as_u16();
    let text = r.into_body().read_to_string()?;
    let v = serde_json::from_str(&text).unwrap_or(Value::String(text));
    Ok((status, v))
}

pub fn lookup(chain_id: u64, address: &str) -> Res<Value> {
    let url = format!("{SERVER}/v2/contract/{chain_id}/{address}");
    let (status, v) = read(agent().get(&url).call()?)?;
    if status != 200 && status != 404 {
        return Err(format!("GET {url}: HTTP {status}: {v}").into());
    }
    Ok(v)
}

/// Submit and wait for the job. Returns the job's final JSON.
pub fn submit(ctx: &Context, d: &Deployment, chain_id: u64) -> Res<Value> {
    let c = ctx.contract(&d.contract)?;
    let (build, _) = ctx.build_of(&d.contract)?;
    let target = c["target"].as_str().ok_or("no target")?;
    let mut input = standard_json(ctx, &d.contract, d.source_rev.as_deref())?;
    // Sourcify compiles this input itself; the AST is not needed for that.
    input["settings"]["outputSelection"] = json!({"*": {"*": ["abi", "metadata", "evm.bytecode.object", "evm.deployedBytecode.object", "evm.deployedBytecode.immutableReferences"]}});
    let body = json!({
        "stdJsonInput": input,
        "compilerVersion": build["compiler"],
        "contractIdentifier": format!("{target}:{}", d.contract),
        "creationTransactionHash": d.tx,
    });
    let url = format!("{SERVER}/v2/verify/{chain_id}/{}", d.address);
    let (status, v) = read(agent().post(&url).send_json(&body)?)?;
    if status == 409 {
        println!("  sourcify: already verified ({v})");
        return lookup(chain_id, &d.address);
    }
    if status != 202 {
        return Err(format!("POST {url}: HTTP {status}: {v}").into());
    }
    let id = v["verificationId"]
        .as_str()
        .ok_or("no verificationId")?
        .to_string();
    println!("  sourcify: job {id}");
    for _ in 0..90 {
        std::thread::sleep(Duration::from_secs(4));
        let (status, job) = read(agent().get(&format!("{SERVER}/v2/verify/{id}")).call()?)?;
        if status != 200 {
            return Err(format!("job {id}: HTTP {status}: {job}").into());
        }
        if job["isJobCompleted"] == true {
            return Ok(job);
        }
    }
    Err(format!("job {id} not completed after 6 minutes").into())
}
