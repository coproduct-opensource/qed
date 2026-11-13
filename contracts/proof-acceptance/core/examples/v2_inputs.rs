//! Rewrite program inputs with their exports in export v2 (statement format
//! v2), for measuring the v2 path on the same work. Not a production tool:
//! the order fields that depend on the statement (policy hash, base id) are
//! recomputed; everything else is copied.
//!
//!   cargo run --release --example v2_inputs -- order IN OUT [BASE_JOURNAL_HEX_OUT]
//!   cargo run --release --example v2_inputs -- base IN OUT
//!   cargo run --release --example v2_inputs -- export IN.ndjson OUT.v2 [continuation]
use nucleus_proof_acceptance::{
    base, export_v2_from_ndjson,
    vault_program::{BaseWitness, decode_with_base, encode_with_base},
};
use sha2::{Digest, Sha256};
use std::{error::Error, fs};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["export", input, output] => {
            fs::write(output, export_v2_from_ndjson(&fs::read(input)?, true)?)?;
        }
        ["export", input, output, "continuation"] => {
            fs::write(output, export_v2_from_ndjson(&fs::read(input)?, false)?)?;
        }
        ["base", input, output] => {
            let mut b = base::Input::decode(&fs::read(input)?).map_err(|e| format!("{e:?}"))?;
            b.base = export_v2_from_ndjson(&b.base, true)?;
            println!("base_id {}", hex(&base::id(&b.base)));
            println!("base_bytes {}", b.base.len());
            fs::write(output, b.encode())?;
        }
        ["order", input, output, rest @ ..] => {
            let (mut order, witness) = decode_with_base(&fs::read(input)?).map_err(|e| format!("{e:?}"))?;
            let ndjson = order.statement.clone();
            order.statement = export_v2_from_ndjson(&ndjson, true)?;
            order.artifact = export_v2_from_ndjson(&order.artifact, false)?;
            order.policy.statement_sha256 = Sha256::digest(&order.statement).into();
            order.order.policy_hash = order.policy.hash();
            let witness = match witness {
                None => None,
                Some(w) => {
                    let length = usize::try_from(w.length)?;
                    let base_v2 = export_v2_from_ndjson(&ndjson[..length], true)?;
                    if !order.statement.starts_with(&base_v2) {
                        return Err("the v2 base is not a prefix of the v2 statement".into());
                    }
                    order.order.base = Sha256::digest(&base_v2).into();
                    let journal = base::journal(
                        order.order.base,
                        base::axioms_hash(&order.policy.permitted_axioms),
                        w.payee,
                        w.bps,
                    );
                    if let [journal_out] = rest {
                        fs::write(journal_out, hex(&journal))?;
                    }
                    println!("base_id {}", hex(&order.order.base));
                    Some(BaseWitness {
                        length: u32::try_from(base_v2.len())?,
                        ..w
                    })
                }
            };
            println!("statement_bytes {} -> {}", ndjson.len(), order.statement.len());
            println!("artifact_bytes {}", order.artifact.len());
            fs::write(output, encode_with_base(&order, witness.as_ref()))?;
        }
        _ => return Err("usage: v2_inputs order IN OUT [BASE_JOURNAL_HEX_OUT] | base IN OUT | export IN OUT [continuation]".into()),
    }
    Ok(())
}
