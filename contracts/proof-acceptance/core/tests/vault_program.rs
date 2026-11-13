use nucleus_proof_acceptance::{
    Policy, Refusal, accept,
    vault_program::{Input, ProgramRefusal, journal},
};
use nucleus_proof_commerce::vault;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

const STATEMENT: &[u8] = include_bytes!("fixtures/task.ndjson");
const ARTIFACT: &[u8] = include_bytes!("fixtures/suffix.ndjson");

fn input() -> Input {
    let policy = Policy {
        statement_sha256: Sha256::digest(STATEMENT).into(),
        claim: "Nucleus.Claim".into(),
        permitted_axioms: vec![],
        maximum_artifact_bytes: 65_536,
    };
    Input {
        form: vault::Form::Second,
        chain_id: 84532,
        vault: [3; 20],
        order: vault::Order {
            buyer: [1; 20],
            seller: [2; 20],
            asset: [4; 20],
            amount: [9; 32],
            verifier: [6; 20],
            program: [7; 32],
            policy_hash: policy.hash(),
            base: [0; 32],
            fund_by: 1000,
            deliver_by: 2000,
            salt: [10; 32],
            context: [11; 32],
        },
        policy,
        statement: STATEMENT.to_vec(),
        artifact: ARTIFACT.to_vec(),
    }
}

#[test]
fn the_journal_is_the_vaults_acceptance_statement_for_this_order_and_artifact() {
    let input = input();
    let deployment = vault::Deployment {
        chain_id: 84532,
        vault: [3; 20],
        treasury: [5; 20],
        fee_bps: 25,
        maximum_fee_bps: 100,
        rules: vault::Rules::Second,
    };
    let expected = vault::acceptance_journal(
        &deployment,
        &input.order,
        Keccak256::digest(ARTIFACT).into(),
    );
    assert_eq!(journal(&input, accept), Ok(expected));
}

#[test]
fn input_encoding_round_trips_and_refuses_trailing_or_missing_bytes() {
    let bytes = input().encode();
    let decoded = Input::decode(vault::Form::Second, &bytes).unwrap();
    assert_eq!(decoded.encode(), bytes);
    assert_eq!(decoded.order, input().order);
    assert_eq!(
        Input::decode(vault::Form::Second, &bytes[..bytes.len() - 1]).err(),
        Some(ProgramRefusal::Malformed)
    );
    assert_eq!(
        Input::decode(vault::Form::Second, &[bytes, vec![0]].concat()).err(),
        Some(ProgramRefusal::Malformed)
    );
}

#[test]
fn a_laxer_policy_or_a_missing_proof_yields_no_journal() {
    let mut lax = input();
    lax.policy.permitted_axioms.push("Classical.choice".into());
    assert_eq!(journal(&lax, accept), Err(ProgramRefusal::PolicyNotInOrder));
    let mut cut = input();
    let end = cut.artifact[..cut.artifact.len() - 1]
        .iter()
        .rposition(|b| *b == b'\n')
        .unwrap()
        + 1;
    cut.artifact.truncate(end);
    assert_eq!(
        journal(&cut, accept),
        Err(ProgramRefusal::Acceptance(Refusal::ClaimNotProved))
    );
}

// ---- The third form.

fn third() -> Input {
    Input {
        form: vault::Form::Third,
        ..input()
    }
}

#[test]
fn the_second_forms_input_layout_is_the_one_the_published_program_reads() {
    // This file was written by the encoder before the third form existed and
    // is what the published second-form binary proved on 2026-11-12.
    let fixture: &[u8] = include_bytes!("../../../vault-conformance/fixtures/real-order.input");
    let decoded = Input::decode(vault::Form::Second, fixture).unwrap();
    assert_eq!(decoded.encode(), fixture);
    assert_eq!(decoded.order.base, [0; 32]);
    // The third form's layout carries the base and is 32 bytes longer.
    assert_eq!(third().encode().len(), input().encode().len() + 32);
    assert!(Input::decode(vault::Form::Third, &input().encode()).is_err());
    let bytes = third().encode();
    assert_eq!(
        Input::decode(vault::Form::Third, &bytes).unwrap().encode(),
        bytes
    );
}

#[test]
fn the_third_forms_journal_commits_the_third_forms_digest_and_no_based_order() {
    let deployment = vault::Deployment {
        chain_id: 84532,
        vault: [3; 20],
        treasury: [5; 20],
        fee_bps: 25,
        maximum_fee_bps: 100,
        rules: vault::Rules::Third {
            maximum_term: 3600,
            registry: [12; 20],
        },
    };
    let input = third();
    let expected = vault::acceptance_journal(
        &deployment,
        &input.order,
        Keccak256::digest(ARTIFACT).into(),
    );
    assert_eq!(journal(&input, accept), Ok(expected));
    assert_ne!(journal(&self::input(), accept), Ok(expected));
    // An order that names a base gets no journal from this program.
    let mut based = third();
    based.order.base = [13; 32];
    assert_eq!(
        journal(&based, accept),
        Err(ProgramRefusal::UnsupportedBase)
    );
}
