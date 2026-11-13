//! Writes inputs for the base program and for the base-aware third-form
//! program, around fixed unsigned order fields. For measuring and exercising
//! the guests; a real order's input comes from the seller.
//!
//!   base_inputs base BASE PAYEE_HEX BPS INPUT_OUT JOURNAL_HEX_OUT [AXIOM...]
//!   base_inputs order STATEMENT ARTIFACT INPUT_OUT [AXIOM...]
//!   base_inputs order-on-base STATEMENT ARTIFACT BASE_LENGTH PAYEE_HEX BPS INPUT_OUT [AXIOM...]
use nucleus_proof_acceptance::{
    Policy, accept, accept_on_base, base,
    vault_program::{BaseWitness, Form, Input, encode_with_base},
};
use nucleus_proof_commerce::vault::Order;
use sha2::{Digest, Sha256};
use std::{error::Error, fs, time::Instant};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn address(text: &str) -> Result<[u8; 20], Box<dyn Error>> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    let bytes: Result<Vec<u8>, _> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2).unwrap_or("zz"), 16))
        .collect();
    Ok(bytes?.try_into().map_err(|_| "address length")?)
}
fn order_input(statement: Vec<u8>, artifact: Vec<u8>, axioms: &[String], base: [u8; 32]) -> Input {
    let policy = Policy {
        statement_sha256: Sha256::digest(&statement).into(),
        claim: "Nucleus.Claim".into(),
        permitted_axioms: axioms.to_vec(),
        maximum_artifact_bytes: 65_536,
    };
    Input {
        form: Form::Third,
        chain_id: 421614,
        vault: [3; 20],
        order: Order {
            buyer: [1; 20],
            seller: [2; 20],
            asset: [4; 20],
            amount: [9; 32],
            verifier: [5; 20],
            program: [6; 32],
            policy_hash: policy.hash(),
            base,
            fund_by: 1000,
            deliver_by: 2000,
            salt: [7; 32],
            context: [8; 32],
        },
        policy,
        statement,
        artifact,
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [
            command,
            base_file,
            payee,
            bps,
            out,
            journal_out,
            axioms @ ..,
        ] if command == "base" => {
            let input = base::Input {
                payee: address(payee)?,
                bps: bps.parse()?,
                permitted_axioms: axioms.to_vec(),
                base: fs::read(base_file)?,
            };
            let started = Instant::now();
            let journal = base::check(&input).map_err(|e| format!("{e:?}"))?;
            println!("base_bytes {}", input.base.len());
            println!("base_id {}", hex(&base::id(&input.base)));
            println!("native_seconds {:.3}", started.elapsed().as_secs_f64());
            println!("journal {}", hex(&journal));
            fs::write(out, input.encode())?;
            fs::write(journal_out, hex(&journal))?;
        }
        [command, statement, artifact, out, axioms @ ..] if command == "order" => {
            let input = order_input(fs::read(statement)?, fs::read(artifact)?, axioms, [0; 32]);
            let started = Instant::now();
            let verdict = accept(&input.policy, &input.statement, &input.artifact);
            println!("native_seconds {:.3}", started.elapsed().as_secs_f64());
            println!("verdict {verdict:?}");
            fs::write(out, encode_with_base(&input, None))?;
        }
        [
            command,
            statement,
            artifact,
            length,
            payee,
            bps,
            out,
            axioms @ ..,
        ] if command == "order-on-base" => {
            let statement = fs::read(statement)?;
            let length: u32 = length.parse()?;
            let prefix = statement
                .get(..usize::try_from(length)?)
                .ok_or("base length exceeds the statement")?;
            let id = base::id(prefix);
            let input = order_input(statement.clone(), fs::read(artifact)?, axioms, id);
            let started = Instant::now();
            let verdict = accept_on_base(
                &input.policy,
                &input.statement,
                &input.artifact,
                usize::try_from(length)?,
                id,
            );
            println!("base_id {}", hex(&id));
            println!("native_seconds {:.3}", started.elapsed().as_secs_f64());
            println!("verdict {verdict:?}");
            let witness = BaseWitness {
                length,
                payee: address(payee)?,
                bps: bps.parse()?,
            };
            fs::write(out, encode_with_base(&input, Some(&witness)))?;
        }
        _ => {
            return Err(
                "usage: base ... | order ... | order-on-base ... (see the file header)".into(),
            );
        }
    }
    Ok(())
}
