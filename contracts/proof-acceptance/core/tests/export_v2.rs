//! Export v2, the binary form of an export (statement format v2;
//! docs/rfcs/proof-commerce-statement-format-v2-2026-11-13.md).
use nucleus_proof_acceptance::{
    EXPORT_V2_MAGIC, Policy, Refusal, accept, accept_on_base, export_v2_decode_all,
    export_v2_from_ndjson, export_v2_round_trip,
};
use sha2::{Digest, Sha256};

const STATEMENT: &[u8] = include_bytes!("fixtures/task.ndjson");
const ARTIFACT: &[u8] = include_bytes!("fixtures/suffix.ndjson");
const BASE: &[u8] = include_bytes!("fixtures/base/base.ndjson");
const ON_BASE: &[u8] = include_bytes!("fixtures/base/task-on-base.ndjson");
const ON_BASE_ARTIFACT: &[u8] = include_bytes!("fixtures/base/suffix-on-base.ndjson");
const EXPLOIT: &[u8] = include_bytes!("fixtures/nucleus-nested-field-count-exploit.ndjson");

fn policy(statement: &[u8]) -> Policy {
    Policy {
        statement_sha256: Sha256::digest(statement).into(),
        claim: "Nucleus.Claim".into(),
        permitted_axioms: vec![],
        maximum_artifact_bytes: 65_536,
    }
}

fn v2(ndjson: &[u8]) -> Vec<u8> {
    export_v2_from_ndjson(ndjson, true).unwrap()
}
fn v2_continuation(ndjson: &[u8]) -> Vec<u8> {
    export_v2_from_ndjson(ndjson, false).unwrap()
}

fn verdict(r: Result<nucleus_proof_acceptance::Accepted, Refusal>) -> String {
    match r {
        Ok(a) => format!("accepted {} {}", a.declarations, a.proof),
        Err(e) => format!("{e:?}").split('(').next().unwrap_or("").to_owned(),
    }
}

#[test]
fn every_fixture_line_decodes_to_what_it_was() {
    for (name, bytes) in [
        ("statement", STATEMENT),
        ("artifact", ARTIFACT),
        ("base", BASE),
        ("statement on base", ON_BASE),
        ("artifact on base", ON_BASE_ARTIFACT),
        ("nested-field exploit", EXPLOIT),
    ] {
        let lines = bytes.split_inclusive(|&b| b == b'\n').count();
        assert_eq!(export_v2_round_trip(bytes), Ok(lines), "{name}");
        assert_eq!(export_v2_decode_all(&v2(bytes), true), Ok(lines), "{name}");
    }
    // Shorter than the text it encodes.
    assert!(v2(STATEMENT).len() * 2 < STATEMENT.len());
}

#[test]
fn the_verdict_on_v2_is_the_verdict_on_ndjson() {
    let (s, a) = (v2(STATEMENT), v2_continuation(ARTIFACT));
    assert_eq!(
        verdict(accept(&policy(&s), &s, &a)),
        verdict(accept(&policy(STATEMENT), STATEMENT, ARTIFACT))
    );
    assert!(accept(&policy(&s), &s, &a).is_ok());
    // The same cases, mutated line by line in NDJSON, then encoded.
    let lines: Vec<&[u8]> = ARTIFACT.split_inclusive(|&b| b == b'\n').collect();
    for drop in 0..lines.len() {
        let shorter: Vec<u8> = lines
            .iter()
            .enumerate()
            .filter(|(k, _)| *k != drop)
            .flat_map(|(_, l)| l.iter().copied())
            .collect();
        let Ok(encoded) = export_v2_from_ndjson(&shorter, false) else {
            continue;
        };
        assert_eq!(
            verdict(accept(&policy(&s), &s, &encoded)),
            verdict(accept(&policy(STATEMENT), STATEMENT, &shorter)),
            "artifact without line {drop}"
        );
    }
    // A v2 statement does not take an NDJSON artifact, nor the reverse.
    assert!(accept(&policy(&s), &s, ARTIFACT).is_err());
    assert!(accept(&policy(STATEMENT), STATEMENT, &a).is_err());
}

#[test]
fn a_base_prefix_in_ndjson_is_a_base_prefix_in_v2() {
    assert!(ON_BASE.starts_with(BASE));
    let (base, statement) = (v2(BASE), v2(ON_BASE));
    assert!(statement.starts_with(&base));
    let artifact = v2_continuation(ON_BASE_ARTIFACT);
    let id: [u8; 32] = Sha256::digest(&base).into();
    assert_eq!(
        verdict(accept_on_base(
            &policy(&statement),
            &statement,
            &artifact,
            base.len(),
            id
        )),
        verdict(accept(&policy(&statement), &statement, &artifact))
    );
    assert!(accept_on_base(&policy(&statement), &statement, &artifact, base.len(), id).is_ok());
    // A split one byte short of the base's last record end is refused.
    let short: [u8; 32] = Sha256::digest(&base[..base.len() - 1]).into();
    assert!(
        accept_on_base(
            &policy(&statement),
            &statement,
            &artifact,
            base.len() - 1,
            short
        )
        .is_err()
    );
}

#[test]
fn every_truncation_of_a_v2_artifact_is_refused() {
    let (s, a) = (v2(STATEMENT), v2_continuation(ARTIFACT));
    for cut in 0..a.len() {
        assert!(
            accept(&policy(&s), &s, &a[..cut]).is_err(),
            "accepted a truncation at {cut}"
        );
    }
}

#[test]
fn a_v2_statement_cut_inside_a_record_does_not_decode() {
    let s = v2(STATEMENT);
    let records = export_v2_decode_all(&s, true).unwrap();
    let mut ends = 0;
    for cut in EXPORT_V2_MAGIC.len()..s.len() {
        if let Ok(n) = export_v2_decode_all(&s[..cut], true) {
            ends += 1;
            assert!(n < records);
        }
    }
    // Exactly one clean cut per record end before the last (the header's end
    // counts as the cut after zero records).
    assert_eq!(ends, records);
}

#[test]
fn single_byte_changes_are_refused_or_decode_to_valid_records() {
    // No change may make the decoder or the acceptance rule abort the host;
    // a change that still decodes is judged by the kernel like any export.
    let (s, a) = (v2(STATEMENT), v2_continuation(ARTIFACT));
    let (mut refused, mut accepted) = (0, 0);
    for i in 0..a.len() {
        for flip in [0x01u8, 0x80] {
            let mut m = a.clone();
            m[i] ^= flip;
            match accept(&policy(&s), &s, &m) {
                Ok(_) => accepted += 1,
                Err(_) => refused += 1,
            }
        }
    }
    assert!(refused > accepted, "refused {refused} accepted {accepted}");
}

/// One NAME_STR record for name index `n` with prefix 0 and suffix "Probe".
fn name_record(n: u8) -> Vec<u8> {
    vec![1, 0, 5, b'P', b'r', b'o', b'b', b'e', 1, n]
}

fn next_name(s: &[u8]) -> u8 {
    let lines = std::str::from_utf8(STATEMENT).unwrap();
    let _ = s;
    (lines.lines().filter(|l| l.contains("\"in\":")).count() + 1) as u8
}

#[test]
fn only_the_one_encoding_of_each_value_decodes() {
    let s = v2(STATEMENT);
    let n = next_name(&s);
    let with = |record: Vec<u8>| {
        let mut out = s.clone();
        out.extend_from_slice(&record);
        nucleus_proof_acceptance::base::check(&nucleus_proof_acceptance::base::Input {
            payee: [1; 20],
            bps: 0,
            permitted_axioms: vec![],
            base: out,
        })
    };
    assert!(with(name_record(n)).is_ok(), "the canonical record");
    // The decoder itself must refuse each of these, before the checker sees
    // a value: several would also be refused later for other reasons, which
    // would hide a decoder that let them through.
    let decodes = |record: Vec<u8>| {
        let mut out = s.clone();
        out.extend_from_slice(&record);
        nanoda_lib_decode(&out)
    };
    assert!(
        decodes(name_record(n)).is_ok(),
        "the canonical record decodes"
    );
    // The prefix index 0 written in two bytes.
    let mut overlong = name_record(n);
    overlong.splice(1..2, [0x80, 0x00]);
    assert!(decodes(overlong).is_err(), "an overlong integer");
    // A back-reference wider than 32 bits, in the five bytes 32 bits allow.
    let mut wide = name_record(n);
    wide.truncate(wide.len() - 1);
    wide.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x7f]);
    assert!(decodes(wide).is_err(), "an integer wider than its field");
    // A string longer than the input.
    let mut long = name_record(n);
    long[2] = 100;
    assert!(decodes(long).is_err(), "a length past the end");
    // An unknown tag (9 is where `mdata` would be), an unknown
    // back-reference kind.
    // Each is the last record, so no later byte can be refused instead.
    assert!(decodes(vec![9, 0]).is_err(), "an unknown tag");
    assert!(decodes(vec![16, 0, 0]).is_ok(), "a sort record decodes");
    assert!(
        decodes(vec![16, 0, 4]).is_err(),
        "an unknown back-reference kind"
    );
    // A boolean other than 0 or 1: a let-expression's `nondep`.
    let let_record = |nondep: u8| vec![10, 0, 0, 0, 0, nondep, 3, 0];
    for bad in [2u8, 0xff] {
        let mut out = s.clone();
        out.extend_from_slice(&let_record(bad));
        assert!(nanoda_lib_decode(&out).is_err(), "a boolean {bad} decoded");
    }
    // A natural with a trailing zero byte.
    let nat = |bytes: &[u8]| {
        let mut r = vec![7, bytes.len() as u8];
        r.extend_from_slice(bytes);
        r.extend_from_slice(&[3, 0]);
        r
    };
    let mut out = s.clone();
    out.extend_from_slice(&nat(&[5, 0]));
    assert!(
        nanoda_lib_decode(&out).is_err(),
        "a natural with a trailing zero"
    );
    let mut out = s.clone();
    out.extend_from_slice(&nat(&[5]));
    assert!(nanoda_lib_decode(&out).is_ok(), "a canonical natural");
}

fn nanoda_lib_decode(bytes: &[u8]) -> Result<usize, String> {
    export_v2_decode_all(bytes, true)
}
