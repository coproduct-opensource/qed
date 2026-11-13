//! Pull the buyer's statement and policy out of a seller's recorded proof
//! input (`vault_program::Input`, second or third form, with or without a
//! base witness) so a site can serve them beside the delivered artifact.
//!
//!   cargo run --release --example statements -- OUT_DIR INPUT...
//!
//! For each input it writes `OUT_DIR/statements/<sha256>.<ndjson|v2>` and adds
//! one entry to `OUT_DIR/policies.json`, keyed by the policy hash (the
//! `policyHash` an order commits to on chain), and runs `accept` on the
//! statement and artifact so the entry records the native verdict.
use nucleus_proof_acceptance::{EXPORT_V2_MAGIC, accept, vault_program};
use nucleus_proof_commerce::vault;
use std::{collections::BTreeMap, error::Error, fs, path::Path};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode(bytes: &[u8]) -> Result<vault_program::Input, Box<dyn Error>> {
    if let Ok((input, _)) = vault_program::decode_with_base(bytes) {
        return Ok(input);
    }
    Ok(vault_program::Input::decode(vault::Form::Second, bytes)
        .map_err(|e| format!("not a vault program input: {e:?}"))?)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [out, inputs @ ..] = args.as_slice() else {
        return Err("usage: statements OUT_DIR INPUT...".into());
    };
    let out = Path::new(out);
    fs::create_dir_all(out.join("statements"))?;
    let mut policies: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for path in inputs {
        let input = decode(&fs::read(path)?)?;
        let policy = &input.policy;
        let policy_hash = format!("0x{}", hex(&policy.hash()));
        if policy.hash() != input.order.policy_hash {
            return Err(format!("{path}: the input's policy does not hash to its order's").into());
        }
        let sha = hex(&policy.statement_sha256);
        let format = if input.statement.starts_with(&EXPORT_V2_MAGIC) {
            "v2"
        } else {
            "ndjson"
        };
        let file = format!("{sha}.{format}");
        fs::write(out.join("statements").join(&file), &input.statement)?;
        let verdict = match accept(policy, &input.statement, &input.artifact) {
            Ok(a) => format!("accepted {} ({} declarations)", a.proof, a.declarations),
            Err(r) => format!("refused {r:?}"),
        };
        println!(
            "{path}\n  policy {policy_hash}\n  statement {file} ({} bytes)\n  {verdict}",
            input.statement.len()
        );
        policies.insert(
            policy_hash,
            serde_json::json!({
                "statementSha256": sha,
                "statementFile": file,
                "statementBytes": input.statement.len(),
                "statementFormat": format,
                "claim": policy.claim,
                "permittedAxioms": policy.permitted_axioms,
                "maximumArtifactBytes": policy.maximum_artifact_bytes,
            }),
        );
    }
    let mut json = serde_json::to_vec_pretty(&policies)?;
    json.push(b'\n');
    fs::write(out.join("policies.json"), json)?;
    Ok(())
}
