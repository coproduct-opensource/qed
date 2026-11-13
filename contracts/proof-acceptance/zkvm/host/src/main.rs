//! Runs a vault's proof guest on an encoded input file. Commands prefixed
//! `vault3-` use the third-form program (NucleusVault3 orders) and `base-`
//! the base program. Built with the `second-form` feature, the same commands
//! prefixed `vault-` use the second-form program (NucleusVault2 orders); that
//! program's binary is kept in this repository and is not part of a public
//! release, so the feature is off unless asked for.
//!
//!   nucleus-acceptance-host vault-execute INPUT            cycles and journal, no proof
//!   nucleus-acceptance-host vault-prove INPUT RECEIPT      succinct receipt, verified before it is written
//!   nucleus-acceptance-host vault-verify RECEIPT           verify a receipt file against the built image
//!   nucleus-acceptance-host vault-groth16 RECEIPT OUT SEAL wrap a succinct receipt for an on-chain verifier
//!   nucleus-acceptance-host vault-image                    print the image ID
//!   nucleus-acceptance-host vault-image-of FILE            image ID of a program binary file
//!
//! The third-form program also accepts orders naming a checked base. Such an
//! order is proved with the base program's succinct receipt as a third
//! argument:
//!
//!   nucleus-acceptance-host base-prove BASE_INPUT BASE_RECEIPT
//!   nucleus-acceptance-host vault3-prove INPUT RECEIPT BASE_RECEIPT
//!   nucleus-acceptance-host vault3-execute-assuming INPUT BASE_JOURNAL_HEX_FILE   cycles only
//!
//! `vault-groth16` wraps in this process by default (`NUCLEUS_GROTH16=native`,
//! data files in `NUCLEUS_GROTH16_DATA` or rzup's `risc0-groth16` 0.2.0
//! directory); `NUCLEUS_GROTH16=container` uses RISC Zero's x86 prover image.
//!
//! An input is `nucleus_proof_acceptance::vault_program::Input::encode()`; the
//! `measure` example of that crate writes one.
/// The second-form proof program (contracts/proof-acceptance/program). Its
/// image ID is computed from these bytes, so the ID printed here is a fact
/// about the file, whoever built it. Only with the `second-form` feature.
#[cfg(feature = "second-form")]
const NUCLEUS_VAULT_GUEST_ELF: &[u8] =
    include_bytes!("../../../program/nucleus-vault-acceptance.bin");
/// The published program for the third vault (NucleusVault3). It also accepts
/// orders naming a checked base.
const NUCLEUS_VAULT3_GUEST_ELF: &[u8] =
    include_bytes!("../../../program/nucleus-vault3-acceptance.bin");
/// The base program: checks a base library and commits that it did.
const NUCLEUS_BASE_GUEST_ELF: &[u8] = include_bytes!("../../../program/nucleus-base-check.bin");
/// Statement format v2 (docs/rfcs/proof-commerce-statement-format-v2-2026-11-13.md):
/// the order program and base program that read an export once, in place,
/// as NDJSON or as export v2. `order2-` and `base2-` address them. The order
/// program accepts only the base program published beside it.
const NUCLEUS_ORDER2_GUEST_ELF: &[u8] = include_bytes!("../../../program/nucleus-order-fmt2.bin");
const NUCLEUS_BASE2_GUEST_ELF: &[u8] =
    include_bytes!("../../../program/nucleus-base-check-fmt2.bin");
use risc0_zkvm::{
    default_executor, default_prover, sha::Digest, ExecutorEnv, ProverOpts, Receipt, ReceiptClaim,
};
use std::{error::Error, fs, process::ExitCode, time::Instant};

mod wrap;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if !text.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(text.get(i..i + 2).ok_or("hex")?, 16)?))
        .collect()
}
fn image_of(program: &[u8]) -> Result<Digest, Box<dyn Error>> {
    Ok(risc0_zkvm::compute_image_id(program)?)
}
fn env(input: &[u8]) -> Result<ExecutorEnv<'_>, Box<dyn Error>> {
    Ok(ExecutorEnv::builder().write_slice(input).build()?)
}
fn read_receipt(path: &str) -> Result<Receipt, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let words: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    Ok(risc0_zkvm::serde::from_slice(&words)?)
}
fn receipt_bytes(receipt: &Receipt) -> Result<Vec<u8>, Box<dyn Error>> {
    let encoded = risc0_zkvm::serde::to_vec(receipt)?;
    Ok(encoded.iter().flat_map(|w| w.to_le_bytes()).collect())
}

#[cfg(feature = "second-form")]
fn second_form() -> Result<&'static [u8], Box<dyn Error>> {
    Ok(NUCLEUS_VAULT_GUEST_ELF)
}
#[cfg(not(feature = "second-form"))]
fn second_form() -> Result<&'static [u8], Box<dyn Error>> {
    Err("this build does not carry the second-form program; build with `--features second-form` in a tree that has program/nucleus-vault-acceptance.bin".into())
}

fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    let usage = "usage: vault3-execute INPUT | vault3-prove INPUT RECEIPT [BASE_RECEIPT] | vault3-verify RECEIPT | vault3-groth16 RECEIPT OUT SEAL | vault3-seal GROTH16_RECEIPT SEAL | vault3-image | vault3-image-of FILE (base-... for the base program; order2-... and base2-... for the statement-format-v2 pair; vault-... for the second form, in a build with the `second-form` feature)";
    let Some((command, rest)) = args.split_first() else {
        return Err(usage.into());
    };
    // Execute any program binary file, for measuring a variant build against
    // the published one: `file-execute PROGRAM INPUT [BASE_JOURNAL_HEX_FILE]`.
    // With a third argument the base program's journal is assumed, as in
    // `vault3-execute-assuming`. Nothing a verifier accepts comes of it.
    //
    // `proving_cycles` is the sum over segments of 2^po2: what a prover works
    // through, padding included. The split of the overhead into paging and
    // reserved cycles is not in what the executor returns over IPC; the r0vm
    // server logs it when run with `RISC0_INFO=1 RUST_LOG=info`.
    if command == "file-execute" {
        let (program, input, assumed) = match rest {
            [program, input] => (program, input, None),
            [program, input, journal] => (program, input, Some(journal)),
            _ => return Err("usage: file-execute PROGRAM INPUT [BASE_JOURNAL_HEX_FILE]".into()),
        };
        let program = fs::read(program)?;
        let input = fs::read(input)?;
        let mut builder = ExecutorEnv::builder();
        builder.write_slice(&input);
        // Segment size is the prover's choice, not part of the program: it
        // changes no image ID. Larger segments repeat less paging and need
        // more prover memory.
        if let Some(po2) = std::env::var_os("NUCLEUS_SEGMENT_PO2") {
            let po2: u32 = po2.to_str().ok_or("NUCLEUS_SEGMENT_PO2")?.parse()?;
            builder.segment_limit_po2(po2);
        }
        if let Some(journal) = assumed {
            let journal = unhex(fs::read_to_string(journal)?.trim())?;
            // The assumed journal is the published base program's, unless
            // NUCLEUS_BASE_PROGRAM names another base program file (a variant
            // build whose order program names that base program).
            let base_program = match std::env::var_os("NUCLEUS_BASE_PROGRAM") {
                Some(path) => fs::read(path)?,
                None => NUCLEUS_BASE_GUEST_ELF.to_vec(),
            };
            builder.add_assumption(ReceiptClaim::ok(image_of(&base_program)?, journal));
        }
        let started = Instant::now();
        let session = default_executor().execute(builder.build()?, &program)?;
        let proving: u64 = session.segments.iter().map(|s| 1u64 << s.po2).sum();
        println!("image_id {}", hex(image_of(&program)?.as_bytes()));
        println!("program_bytes {}", program.len());
        println!("exit {:?}", session.exit_code);
        println!("user_cycles {}", session.cycles());
        println!("proving_cycles {proving}");
        println!("segments {}", session.segments.len());
        println!("seconds {:.1}", started.elapsed().as_secs_f64());
        return Ok(());
    }
    // `vault3-` addresses the third-form program, `base-` the base program,
    // and `vault-` the second-form one where this build carries it.
    // `order2-` and `base2-` address the statement-format-v2 pair. Each order
    // program is paired with the base program whose receipts it accepts.
    let (program, base_program, command) = if let Some(command) = command.strip_prefix("base-") {
        (NUCLEUS_BASE_GUEST_ELF, NUCLEUS_BASE_GUEST_ELF, command)
    } else if let Some(command) = command.strip_prefix("vault3-") {
        (NUCLEUS_VAULT3_GUEST_ELF, NUCLEUS_BASE_GUEST_ELF, command)
    } else if let Some(command) = command.strip_prefix("base2-") {
        (NUCLEUS_BASE2_GUEST_ELF, NUCLEUS_BASE2_GUEST_ELF, command)
    } else if let Some(command) = command.strip_prefix("order2-") {
        (NUCLEUS_ORDER2_GUEST_ELF, NUCLEUS_BASE2_GUEST_ELF, command)
    } else if let Some(command) = command.strip_prefix("vault-") {
        (second_form()?, NUCLEUS_BASE_GUEST_ELF, command)
    } else {
        return Err(usage.into());
    };
    let image = image_of(program)?;
    match (command, rest) {
        ("image", []) => println!("image_id {}", hex(image.as_bytes())),
        // The image ID of any program binary file, without building anything.
        ("image-of", [file]) => {
            println!("image_id {}", hex(image_of(&fs::read(file)?)?.as_bytes()))
        }
        // Execute an order that names a base without holding the base's
        // receipt: the base program's journal is assumed, not proved. For
        // counting cycles only; nothing a verifier accepts comes of it.
        ("execute-assuming", [input, base_journal_hex]) => {
            let input = fs::read(input)?;
            let journal = unhex(fs::read_to_string(base_journal_hex)?.trim())?;
            let assumed = ReceiptClaim::ok(image_of(base_program)?, journal);
            let started = Instant::now();
            let env = ExecutorEnv::builder()
                .write_slice(&input)
                .add_assumption(assumed)
                .build()?;
            let session = default_executor().execute(env, program)?;
            println!("exit {:?}", session.exit_code);
            println!("user_cycles {}", session.cycles());
            println!("segments {}", session.segments.len());
            println!("journal {}", hex(&session.journal.bytes));
            println!("seconds {:.1}", started.elapsed().as_secs_f64());
        }
        // Prove an order that names a base. BASE_RECEIPT is the base
        // program's succinct receipt; the result is unconditional.
        ("prove", [input, out, base_receipt]) => {
            let input = fs::read(input)?;
            let base = read_receipt(base_receipt)?;
            base.verify(image_of(base_program)?)?;
            let started = Instant::now();
            let env = ExecutorEnv::builder()
                .write_slice(&input)
                .add_assumption(base)
                .build()?;
            let info = default_prover().prove_with_opts(env, program, &ProverOpts::succinct())?;
            info.receipt.verify(image)?;
            let bytes = receipt_bytes(&info.receipt)?;
            fs::write(out, &bytes)?;
            println!("image_id {}", hex(image.as_bytes()));
            println!("journal {}", hex(&info.receipt.journal.bytes));
            println!("receipt_bytes {}", bytes.len());
            println!("seconds {:.1}", started.elapsed().as_secs_f64());
        }
        ("execute", [input]) => {
            let input = fs::read(input)?;
            let started = Instant::now();
            let session = default_executor().execute(env(&input)?, program)?;
            println!("exit {:?}", session.exit_code);
            println!("user_cycles {}", session.cycles());
            println!("segments {}", session.segments.len());
            println!("journal {}", hex(&session.journal.bytes));
            println!("seconds {:.1}", started.elapsed().as_secs_f64());
        }
        ("prove", [input, out]) => {
            let input = fs::read(input)?;
            let started = Instant::now();
            let info =
                default_prover().prove_with_opts(env(&input)?, program, &ProverOpts::succinct())?;
            info.receipt.verify(image)?;
            let bytes = receipt_bytes(&info.receipt)?;
            fs::write(out, &bytes)?;
            println!("image_id {}", hex(image.as_bytes()));
            println!("journal {}", hex(&info.receipt.journal.bytes));
            println!("receipt_bytes {}", bytes.len());
            println!("seconds {:.1}", started.elapsed().as_secs_f64());
        }
        ("verify", [receipt]) => {
            let receipt = read_receipt(receipt)?;
            receipt.verify(image)?;
            println!("verified image_id {}", hex(image.as_bytes()));
            println!("journal {}", hex(&receipt.journal.bytes));
        }
        // Wrap an existing succinct receipt into the Groth16 form an on-chain
        // verifier takes. Writes the receipt and the 260-byte seal
        // (4-byte selector, then the proof) as hex.
        ("groth16", [receipt, out, seal_out]) => {
            let succinct = read_receipt(receipt)?;
            succinct.verify(image)?;
            let choice = wrap::Choice::from_env()?;
            let started = Instant::now();
            let wrapped = wrap::groth16(choice, &succinct, image)?;
            println!("groth16_path {}", choice.name());
            let inner = wrapped.inner.groth16()?;
            let selector = &inner.verifier_parameters.as_bytes()[..4];
            let seal = [selector, inner.seal.as_slice()].concat();
            fs::write(out, receipt_bytes(&wrapped)?)?;
            fs::write(seal_out, hex(&seal))?;
            println!("image_id {}", hex(image.as_bytes()));
            println!("journal {}", hex(&wrapped.journal.bytes));
            println!("selector {}", hex(selector));
            println!("seal_bytes {}", seal.len());
            println!("seconds {:.1}", started.elapsed().as_secs_f64());
        }
        // The 260-byte seal of an existing Groth16 receipt (4-byte selector,
        // then the proof), after verifying the receipt for this program. A
        // seller that had another party do the wrap derives the seal itself
        // from the receipt it got back, so it never takes the seal on trust.
        // Verifying a Groth16 receipt uses RISC Zero's built-in verifying key;
        // it needs none of the circuit data the wrap needs.
        ("seal", [wrapped, seal_out]) => {
            let wrapped = read_receipt(wrapped)?;
            wrapped.verify(image)?;
            let inner = wrapped.inner.groth16()?;
            let selector = &inner.verifier_parameters.as_bytes()[..4];
            let seal = [selector, inner.seal.as_slice()].concat();
            fs::write(seal_out, hex(&seal))?;
            println!("image_id {}", hex(image.as_bytes()));
            println!("journal {}", hex(&wrapped.journal.bytes));
            println!("selector {}", hex(selector));
            println!("seal_bytes {}", seal.len());
        }
        _ => return Err(usage.into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("refused: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ID recorded beside each published binary is the ID of that binary.
    #[test]
    fn the_recorded_image_ids_are_the_published_binaries() {
        let third = include_str!("../../../program/IMAGE_ID_VAULT3").trim();
        let base = include_str!("../../../program/IMAGE_ID_BASE").trim();
        let order2 = include_str!("../../../program/IMAGE_ID_ORDER_FMT2").trim();
        let base2 = include_str!("../../../program/IMAGE_ID_BASE_FMT2").trim();
        let id = |program: &[u8]| {
            image_of(program)
                .map(|d| hex(d.as_bytes()))
                .unwrap_or_default()
        };
        assert_eq!(id(NUCLEUS_VAULT3_GUEST_ELF), third);
        assert_eq!(id(NUCLEUS_BASE_GUEST_ELF), base);
        assert_eq!(id(NUCLEUS_ORDER2_GUEST_ELF), order2);
        assert_eq!(id(NUCLEUS_BASE2_GUEST_ELF), base2);
        let mut all = [third, base, order2, base2];
        all.sort_unstable();
        assert!(
            all.windows(2).all(|w| w[0] != w[1]),
            "four distinct programs"
        );

        // A flipped byte of loaded code is a different program. (The ID
        // commits to the loaded memory image, not to the file: flipping the
        // file's last byte, which is not loaded, leaves the ID unchanged.)
        for (program, recorded) in [
            (NUCLEUS_BASE_GUEST_ELF, base),
            (NUCLEUS_VAULT3_GUEST_ELF, third),
            (NUCLEUS_ORDER2_GUEST_ELF, order2),
            (NUCLEUS_BASE2_GUEST_ELF, base2),
        ] {
            let mut other = program.to_vec();
            let middle = other.len() / 2;
            other[middle] ^= 1;
            assert_ne!(id(&other), recorded);
        }
    }

    /// The second-form program, where this build carries it: the ID a live
    /// vault's settled order names is still the ID of the file.
    #[cfg(feature = "second-form")]
    #[test]
    fn the_second_form_binary_still_has_its_recorded_id() {
        let second = include_str!("../../../program/IMAGE_ID").trim();
        let id = image_of(NUCLEUS_VAULT_GUEST_ELF)
            .map(|d| hex(d.as_bytes()))
            .unwrap_or_default();
        assert_eq!(id, second);
    }
}
