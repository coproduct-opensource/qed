//! Checked bases: the verdict with a base equals the verdict without one
//! whenever the base checks on its own, and a base that does not check
//! cannot be committed.
//! (docs/rfcs/proof-commerce-checked-bases-2026-11-12.md)
use nucleus_proof_acceptance::{
    Policy, Refusal, accept, accept_on_base,
    base::{self, Input as BaseInput},
    vault_program::{
        BaseWitness, ProgramRefusal, decode_with_base, encode_with_base, journal_on_base,
    },
};
use sha2::{Digest, Sha256};

const BASE: &[u8] = include_bytes!("fixtures/base/base.ndjson");
const STATEMENT: &[u8] = include_bytes!("fixtures/base/task-on-base.ndjson");
const ARTIFACT: &[u8] = include_bytes!("fixtures/base/suffix-on-base.ndjson");

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
fn lines(bytes: &[u8]) -> Vec<String> {
    std::str::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}
fn unlines(lines: &[String]) -> Vec<u8> {
    lines.iter().flat_map(|l| line(l)).collect()
}
fn base_input(base: &[u8]) -> BaseInput {
    BaseInput {
        payee: [0xba; 20],
        bps: 10,
        permitted_axioms: vec![],
        base: base.to_vec(),
    }
}
/// Replace the value of the last declaration on the last line with its own
/// type: a proposition where a proof, or a type where a term, is required.
fn ill_typed_last(bytes: &[u8]) -> Vec<u8> {
    let mut all = lines(bytes);
    let last = all.last_mut().unwrap();
    let ty = last
        .split("\"type\":")
        .nth(1)
        .unwrap()
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap()
        .to_owned();
    let head = last.split("\"value\":").next().unwrap().to_owned();
    *last = format!("{head}\"value\":{ty}}}}}");
    let out = unlines(&all);
    assert_ne!(out, bytes);
    out
}

#[test]
fn the_base_is_a_prefix_of_the_statement_and_checks_alone() {
    assert!(STATEMENT.starts_with(BASE));
    assert_eq!(BASE.last(), Some(&b'\n'));
    let journal = base::check(&base_input(BASE)).unwrap();
    assert_eq!(journal.len(), 160);
    assert_eq!(&journal[32..64], base::id(BASE).as_slice());
    assert_eq!(&journal[64..96], base::axioms_hash(&[]).as_slice());
    assert_eq!(&journal[108..128], &[0xba; 20]);
    assert_eq!(&journal[158..160], &10u16.to_be_bytes());
    // Round trip of the program's input.
    let input = base_input(BASE);
    assert_eq!(BaseInput::decode(&input.encode()).unwrap(), input);
}

#[test]
fn a_base_that_does_not_check_cannot_be_committed() {
    assert_eq!(
        base::check(&base_input(&ill_typed_last(BASE))),
        Err(base::Refusal::KernelRefused)
    );
    // Not ending at a line end, no payee, a rate above the whole.
    assert_eq!(
        base::check(&base_input(&BASE[..BASE.len() - 1])),
        Err(base::Refusal::Unterminated)
    );
    let mut no_payee = base_input(BASE);
    no_payee.payee = [0; 20];
    assert_eq!(base::check(&no_payee), Err(base::Refusal::Terms));
    let mut greedy = base_input(BASE);
    greedy.bps = 10_001;
    assert_eq!(base::check(&greedy), Err(base::Refusal::Terms));
    // An axiom outside the list is not admitted into a base.
    let cheat = [
        BASE.to_vec(),
        line(r#"{"in":900,"str":{"pre":0,"str":"cheat"}}"#),
    ]
    .concat();
    assert!(matches!(
        base::check(&base_input(&cheat)),
        Err(base::Refusal::Invalid(_)) | Err(base::Refusal::KernelRefused)
    ));
}

/// Verdicts with and without the base, for one statement and artifact.
fn both(statement: &[u8], artifact: &[u8]) -> (Result<String, Refusal>, Result<String, Refusal>) {
    let policy = policy_for(statement);
    let without = accept(&policy, statement, artifact).map(|a| format!("{a:?}"));
    let with = accept_on_base(&policy, statement, artifact, BASE.len(), base::id(BASE))
        .map(|a| format!("{a:?}"));
    (without, with)
}

#[test]
fn with_a_checked_base_the_verdict_is_the_verdict_without_one() {
    // Accepted: identical evidence, including the declaration count.
    let (without, with) = both(STATEMENT, ARTIFACT);
    assert!(without.is_ok());
    assert_eq!(without, with);

    let truncated = unlines(&lines(ARTIFACT)[..lines(ARTIFACT).len() - 1]);
    let redeclared = line(lines(STATEMENT).last().unwrap());
    let next_name = lines(&[STATEMENT, ARTIFACT].concat())
        .iter()
        .filter_map(|l| l.strip_prefix("{\"in\":"))
        .filter_map(|l| l.split(',').next()?.parse::<u32>().ok())
        .max()
        .unwrap()
        + 1;
    let axiom = [
        ARTIFACT.to_vec(),
        line(&format!(
            r#"{{"in":{next_name},"str":{{"pre":0,"str":"cheat"}}}}"#
        )),
        line(&format!(
            r#"{{"axiom":{{"name":{next_name},"levelParams":[],"type":0,"isUnsafe":false}}}}"#
        )),
    ]
    .concat();
    let garbage = [ARTIFACT.to_vec(), line("{\"not\":\"a record\"}")].concat();
    let cases: [(&str, Vec<u8>); 6] = [
        ("no proof of the claim", truncated),
        ("ill-typed proof", ill_typed_last(ARTIFACT)),
        ("artifact redeclares the claim", redeclared),
        ("artifact declares an axiom", axiom),
        ("artifact has an unreadable line", garbage),
        ("empty artifact", vec![]),
    ];
    for (name, artifact) in cases {
        let (without, with) = both(STATEMENT, &artifact);
        assert!(without.is_err(), "{name}: refused without a base");
        assert!(with.is_err(), "{name}: refused with a base, got {with:?}");
    }

    // A statement altered after the base (its last declaration made
    // ill-typed) is refused both ways, under its own policy.
    let altered = ill_typed_last(STATEMENT);
    assert!(altered.starts_with(BASE));
    let (without, with) = both(&altered, ARTIFACT);
    assert!(without.is_err() && with.is_err(), "{without:?} {with:?}");
    // And a statement that is not the pinned one is refused before any check.
    let policy = policy_for(STATEMENT);
    assert_eq!(
        accept_on_base(&policy, &altered, ARTIFACT, BASE.len(), base::id(BASE)),
        Err(Refusal::StatementMismatch)
    );
}

#[test]
fn the_split_and_the_base_id_are_checked_against_the_bytes() {
    let policy = policy_for(STATEMENT);
    let id = base::id(BASE);
    // Another line end: those bytes are not the base.
    let shorter = BASE.len() - lines(BASE).last().unwrap().len() - 1;
    assert_eq!(STATEMENT[shorter - 1], b'\n');
    // Mid-line, zero, and past the statement.
    for length in [shorter, BASE.len() - 3, 0, STATEMENT.len() + 1] {
        assert_eq!(
            accept_on_base(&policy, STATEMENT, ARTIFACT, length, id),
            Err(Refusal::BaseMismatch),
            "length {length}"
        );
    }
    // The id of other bytes.
    assert_eq!(
        accept_on_base(
            &policy,
            STATEMENT,
            ARTIFACT,
            BASE.len(),
            base::id(b"other\n")
        ),
        Err(Refusal::BaseMismatch)
    );
    // A split whose bytes do hash to the id given, but which is not the end
    // of a line, is refused by the parser's mark.
    let mid = BASE.len() - 3;
    assert!(matches!(
        accept_on_base(
            &policy,
            STATEMENT,
            ARTIFACT,
            mid,
            base::id(&STATEMENT[..mid])
        ),
        Err(Refusal::ExportInvalid(_))
    ));
}

/// What the base program's proof is for. With a prefix that does NOT check,
/// the base-skipping decision accepts where the full check refuses; only the
/// requirement of a base commitment stands between that and a payout.
#[test]
fn skipping_is_only_as_good_as_the_base_commitment() {
    // Append to the base one ill-typed definition nothing else uses. It is
    // named by a binder name already in the export and reuses existing
    // expressions, so no later line's numbering moves.
    let last = lines(BASE).last().unwrap().clone();
    let ty = last
        .split("\"type\":")
        .nth(1)
        .unwrap()
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap()
        .to_owned();
    let binder = lines(BASE)
        .iter()
        .find_map(|l| {
            l.contains("\"forallE\"")
                .then(|| {
                    l.split("\"name\":")
                        .nth(1)?
                        .split(',')
                        .next()
                        .map(str::to_owned)
                })
                .flatten()
        })
        .unwrap();
    let bogus = line(&format!(
        r#"{{"def":{{"all":[{binder}],"hints":{{"regular":1}},"levelParams":[],"name":{binder},"safety":"safe","type":{ty},"value":{ty}}}}}"#
    ));
    let bad_base = [BASE.to_vec(), bogus].concat();
    let statement = [bad_base.clone(), STATEMENT[BASE.len()..].to_vec()].concat();
    let policy = policy_for(&statement);
    assert_eq!(
        base::check(&base_input(&bad_base)),
        Err(base::Refusal::KernelRefused)
    );
    assert_eq!(
        accept(&policy, &statement, ARTIFACT),
        Err(Refusal::KernelRefused)
    );
    let skipped = accept_on_base(
        &policy,
        &statement,
        ARTIFACT,
        bad_base.len(),
        base::id(&bad_base),
    );
    assert!(skipped.is_ok(), "{skipped:?}");
}

fn program_input(
    statement: &[u8],
    artifact: &[u8],
    base: [u8; 32],
) -> nucleus_proof_acceptance::vault_program::Input {
    use nucleus_proof_acceptance::vault_program::{Form, Input};
    use nucleus_proof_commerce::vault::Order;
    let policy = policy_for(statement);
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
        statement: statement.to_vec(),
        artifact: artifact.to_vec(),
    }
}

#[test]
fn the_program_requires_the_base_commitment_it_names() {
    let witness = BaseWitness {
        length: BASE.len() as u32,
        payee: [0xba; 20],
        bps: 10,
    };
    let input = program_input(STATEMENT, ARTIFACT, base::id(BASE));
    let committed = base::check(&base_input(BASE)).unwrap();
    let run = |input: &_, witness: Option<&BaseWitness>, shown: &[u8; 160]| {
        journal_on_base(input, witness, accept, accept_on_base, |asked| {
            asked == shown
        })
    };
    // The commitment the base program made is the one the order program asks for.
    let journal = run(&input, Some(&witness), &committed).unwrap();
    assert_eq!(journal.len(), 160);
    // A commitment for other axioms, another payee, another rate or another
    // base is not the one asked for.
    let mut other_axioms = base_input(BASE);
    other_axioms.permitted_axioms = vec!["propext".into()];
    let others = [
        base::journal(
            base::id(BASE),
            base::axioms_hash(&["propext".into()]),
            [0xba; 20],
            10,
        ),
        base::journal(base::id(BASE), base::axioms_hash(&[]), [0xbb; 20], 10),
        base::journal(base::id(BASE), base::axioms_hash(&[]), [0xba; 20], 11),
        base::journal(base::id(b"other\n"), base::axioms_hash(&[]), [0xba; 20], 10),
    ];
    for shown in &others {
        assert_eq!(
            run(&input, Some(&witness), shown),
            Err(ProgramRefusal::BaseNotChecked)
        );
    }
    // A witness is required exactly when the order names a base.
    assert_eq!(
        run(&input, None, &committed),
        Err(ProgramRefusal::Malformed)
    );
    let baseless = program_input(STATEMENT, ARTIFACT, [0; 32]);
    assert_eq!(
        run(&baseless, Some(&witness), &committed),
        Err(ProgramRefusal::Malformed)
    );
    // Without a base the same order is accepted by the full check, and its
    // journal differs only through the order digest.
    let plain = run(&baseless, None, &committed).unwrap();
    assert_eq!(plain[..96], journal[..96]);
    assert_ne!(plain[96..128], journal[96..128]);
    assert_eq!(plain[128..], journal[128..]);

    // Input encoding round trips, with and without a witness.
    let bytes = encode_with_base(&input, Some(&witness));
    let (decoded, decoded_witness) = decode_with_base(&bytes).unwrap();
    assert_eq!(decoded_witness, Some(witness));
    assert_eq!(decoded.encode(), input.encode());
    assert!(decode_with_base(&input.encode()).is_err());
    let (decoded, none) = decode_with_base(&baseless.encode()).unwrap();
    assert_eq!(none, None);
    assert_eq!(decoded.encode(), baseless.encode());
    assert!(decode_with_base(&encode_with_base(&baseless, Some(&witness))).is_err());
}
