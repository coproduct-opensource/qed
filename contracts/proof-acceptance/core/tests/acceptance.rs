use nucleus_proof_acceptance::{Policy, Refusal, accept};
use sha2::{Digest, Sha256};

const STATEMENT: &[u8] = include_bytes!("fixtures/task.ndjson");
const ARTIFACT: &[u8] = include_bytes!("fixtures/suffix.ndjson");
const FULL: &[u8] = include_bytes!("fixtures/full.ndjson");

fn policy_for(statement: &[u8]) -> Policy {
    Policy {
        statement_sha256: Sha256::digest(statement).into(),
        claim: "Nucleus.Claim".into(),
        permitted_axioms: vec![],
        maximum_artifact_bytes: 65_536,
    }
}
fn line(json: &str) -> Vec<u8> {
    let mut bytes = json.as_bytes().to_vec();
    bytes.push(b'\n');
    bytes
}

#[test]
fn fixtures_are_one_export_split_at_the_claim() {
    assert_eq!([STATEMENT, ARTIFACT].concat(), FULL);
    assert_eq!(ARTIFACT.len(), 1876);
}

#[test]
fn a_delivered_proof_of_the_pinned_claim_is_accepted() {
    let policy = policy_for(STATEMENT);
    let accepted = accept(&policy, STATEMENT, ARTIFACT).unwrap();
    assert_eq!(accepted.proof, "Nucleus.proof");
    assert_eq!(accepted.policy_hash, policy.hash());
    assert!(accepted.declarations > 20);
}

#[test]
fn every_policy_field_changes_the_policy_hash() {
    let base = policy_for(STATEMENT);
    let changes: [fn(&mut Policy); 4] = [
        |p| p.statement_sha256[0] ^= 1,
        |p| p.claim.push('x'),
        |p| p.permitted_axioms.push("propext".into()),
        |p| p.maximum_artifact_bytes -= 1,
    ];
    for change in changes {
        let mut other = base.clone();
        change(&mut other);
        assert_ne!(other.hash(), base.hash());
    }
    // Moving a byte between adjacent fields changes the hash.
    let mut a = base.clone();
    a.permitted_axioms = vec!["ab".into(), "c".into()];
    let mut b = base.clone();
    b.permitted_axioms = vec!["a".into(), "bc".into()];
    assert_ne!(a.hash(), b.hash());
}

#[test]
fn statement_and_size_limits_are_enforced_before_checking() {
    let policy = policy_for(STATEMENT);
    let mut altered = STATEMENT.to_vec();
    altered[100] ^= 1;
    assert_eq!(
        accept(&policy, &altered, ARTIFACT),
        Err(Refusal::StatementMismatch)
    );
    assert_eq!(accept(&policy, STATEMENT, b""), Err(Refusal::ArtifactEmpty));
    let mut small = policy.clone();
    small.maximum_artifact_bytes = 1875;
    assert_eq!(
        accept(&small, STATEMENT, ARTIFACT),
        Err(Refusal::ArtifactTooLarge)
    );
    let unterminated = &STATEMENT[..STATEMENT.len() - 1];
    assert_eq!(
        accept(&policy_for(unterminated), unterminated, ARTIFACT),
        Err(Refusal::StatementUnterminated)
    );
    let mut absent = policy.clone();
    absent.claim = "Nucleus.Other".into();
    assert_eq!(
        accept(&absent, STATEMENT, ARTIFACT),
        Err(Refusal::ClaimNotDeclared)
    );
}

/// The claim must be declared by the buyer's bytes. Moving the claim's
/// declaration from the end of the statement to the start of the artifact
/// leaves an export that checks and proves "a" claim, and it must still be
/// refused: the declarations the statement's own bytes make are found by the
/// parser at the end of the statement, in one parse (statement format v2's
/// optimization pass), NDJSON and export v2 alike.
#[test]
fn a_claim_declared_by_the_artifact_is_not_the_buyers_claim() {
    let text = std::str::from_utf8(STATEMENT).unwrap();
    let claim_declaration = text.lines().last().unwrap();
    let statement = &STATEMENT[..STATEMENT.len() - claim_declaration.len() - 1];
    let artifact = [line(claim_declaration), ARTIFACT.to_vec()].concat();
    // The same bytes, split at the claim, are accepted.
    assert_eq!([statement, &artifact[..]].concat(), FULL);
    assert_eq!(
        accept(&policy_for(statement), statement, &artifact),
        Err(Refusal::ClaimNotDeclared)
    );
    let statement_v2 = nucleus_proof_acceptance::export_v2_from_ndjson(statement, true).unwrap();
    let artifact_v2 = nucleus_proof_acceptance::export_v2_from_ndjson(&artifact, false).unwrap();
    assert_eq!(
        accept(&policy_for(&statement_v2), &statement_v2, &artifact_v2),
        Err(Refusal::ClaimNotDeclared)
    );
}

#[test]
fn an_artifact_without_a_proof_of_the_claim_is_refused() {
    let policy = policy_for(STATEMENT);
    // Everything but the last declaration: the helper lemma alone.
    let cut = ARTIFACT[..ARTIFACT.len() - 1]
        .iter()
        .rposition(|b| *b == b'\n')
        .unwrap()
        + 1;
    assert_eq!(
        accept(&policy, STATEMENT, &ARTIFACT[..cut]),
        Err(Refusal::ClaimNotProved)
    );
    // A well-formed line that declares nothing.
    assert_eq!(
        accept(
            &policy,
            STATEMENT,
            &line(r#"{"in":105,"str":{"pre":0,"str":"zz_unused"}}"#)
        ),
        Err(Refusal::ClaimNotProved)
    );
}

#[test]
fn an_artifact_that_assumes_the_claim_as_an_axiom_is_refused() {
    // Find the claim's name index in the buyer's export, then declare
    // `axiom cheat : Nucleus.Claim`.
    let text = std::str::from_utf8(STATEMENT).unwrap();
    let number_after = |line: &str, key: &str| -> u32 {
        let rest = line.split(key).nth(1).unwrap();
        rest[..rest.find(|c: char| !c.is_ascii_digit()).unwrap()]
            .parse()
            .unwrap()
    };
    let claim_name = number_after(text.lines().last().unwrap(), "\"name\":");
    let ty = text
        .lines()
        .filter(|l| l.contains("\"ie\":"))
        .map(|l| number_after(l, "\"ie\":"))
        .max()
        .unwrap()
        + 1;
    let artifact = [
        line(&format!(
            r#"{{"const":{{"name":{claim_name},"us":[]}},"ie":{ty}}}"#
        )),
        line(r#"{"in":105,"str":{"pre":0,"str":"cheat"}}"#),
        line(&format!(
            r#"{{"axiom":{{"name":105,"levelParams":[],"type":{ty},"isUnsafe":false}}}}"#
        )),
    ]
    .concat();
    // With no permitted axioms the parser refuses the declaration outright.
    let policy = policy_for(STATEMENT);
    assert!(matches!(
        accept(&policy, STATEMENT, &artifact),
        Err(Refusal::ExportInvalid(_))
    ));
    // Even if the buyer's policy permits an axiom of that name, the artifact may not declare it.
    let mut permissive = policy.clone();
    permissive.permitted_axioms = vec!["cheat".into()];
    assert_eq!(
        accept(&permissive, STATEMENT, &artifact),
        Err(Refusal::ArtifactDeclaresAxiom("cheat".into()))
    );
    // The complete cheat: the axiom, then a theorem of the claim's type whose
    // value is the axiom. The kernel accepts this export; only the rule that
    // an artifact declares no axiom refuses it.
    let value = ty + 1;
    let complete = [
        artifact.clone(),
        line(&format!(
            r#"{{"const":{{"name":105,"us":[]}},"ie":{value}}}"#
        )),
        line(r#"{"in":106,"str":{"pre":0,"str":"stolen"}}"#),
        line(&format!(
            r#"{{"thm":{{"all":[106],"levelParams":[],"name":106,"type":{ty},"value":{value}}}}}"#
        )),
    ]
    .concat();
    assert_eq!(
        accept(&permissive, STATEMENT, &complete),
        Err(Refusal::ArtifactDeclaresAxiom("cheat".into()))
    );
    // Shown directly: the kernel checker, permitted that axiom, passes the
    // whole export and reports a theorem whose type is the claim.
    let whole = [STATEMENT, &complete].concat();
    let entries = nanoda_lib::acceptance::inspect(&whole, &["cheat".to_string()], true).unwrap();
    let stolen = entries.last().unwrap();
    assert_eq!(stolen.name, "stolen");
    assert_eq!(stolen.kind, nanoda_lib::acceptance::Kind::Theorem);
    assert_eq!(
        stolen.type_is_declaration.map(|i| entries[i].name.as_str()),
        Some("Nucleus.Claim")
    );
}

#[test]
fn an_ill_typed_proof_is_refused_by_the_kernel() {
    // The delivered theorem claims the type, but its value is the helper's
    // statement (a proposition), not a proof of it.
    let text = std::str::from_utf8(ARTIFACT).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let helper_value = lines
        .iter()
        .find(|l| l.contains("\"thm\""))
        .unwrap()
        .split("\"type\":")
        .nth(1)
        .unwrap()
        .split(',')
        .next()
        .unwrap()
        .to_owned();
    let last = lines.last_mut().unwrap();
    let head = last.split("\"value\":").next().unwrap().to_owned();
    *last = format!("{head}\"value\":{helper_value}}}}}");
    let artifact = lines.iter().flat_map(|l| line(l)).collect::<Vec<u8>>();
    assert_ne!(artifact, ARTIFACT);
    assert_eq!(
        accept(&policy_for(STATEMENT), STATEMENT, &artifact),
        Err(Refusal::KernelRefused)
    );
}

#[test]
fn an_artifact_cannot_redeclare_the_buyers_claim() {
    let text = std::str::from_utf8(STATEMENT).unwrap();
    let claim_declaration = text.lines().last().unwrap();
    assert!(claim_declaration.contains("\"def\""));
    assert_eq!(
        accept(&policy_for(STATEMENT), STATEMENT, &line(claim_declaration)),
        Err(Refusal::KernelRefused)
    );
}

#[test]
fn the_known_malformed_recursor_export_is_refused() {
    // Lean Kernel Arena nested-rec-rule-nfields, exported 2026-11-11. Split
    // after its first line so the fixture's own header is the "statement".
    let exploit = include_bytes!("fixtures/nucleus-nested-field-count-exploit.ndjson");
    let cut = exploit.iter().position(|b| *b == b'\n').unwrap() + 1;
    let (statement, artifact) = exploit.split_at(cut);
    let mut policy = policy_for(statement);
    policy.maximum_artifact_bytes = u32::MAX;
    // Refused. Since statement format v2's one-parse rule the whole export is
    // parsed and checked before the claim is looked up, so the kernel's
    // refusal comes first; before it, the header-only statement was refused
    // for declaring no claim. Either way nothing is accepted.
    assert_eq!(
        accept(&policy, statement, artifact),
        Err(Refusal::KernelRefused)
    );
    // Checked directly, the kernel refuses it.
    let whole = exploit.to_vec();
    let refused = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || nanoda_lib::acceptance::inspect(&whole, &[], true))
        .unwrap()
        .join();
    assert!(refused.is_err());
}
