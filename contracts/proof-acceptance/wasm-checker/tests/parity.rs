//! The browser checker and the native acceptance rule agree.
//!
//! Every case runs twice: natively through `nucleus_proof_acceptance::accept`
//! (the host's rule, which reports a kernel panic as `KernelRefused`), and
//! through the compiled `wasm32-unknown-unknown` module under wasmi, an
//! independent interpreter. A trap in the module is read as `KernelRefused`,
//! the way the site reads it ("the checker aborted").
//!
//! The module is the release build: set `QED_CHECKER_WASM` to its path, or
//! build it first with
//! `cargo build --release --target wasm32-unknown-unknown` (target dir
//! `CARGO_TARGET_DIR`, default `target`).
use nucleus_proof_acceptance::{Policy, accept};
use qed_wasm_checker::verdict;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use wasmi::{Config, Engine, Linker, Module, Store, TypedFunc};

const STATEMENT: &[u8] = include_bytes!("../../core/tests/fixtures/task.ndjson");
const ARTIFACT: &[u8] = include_bytes!("../../core/tests/fixtures/suffix.ndjson");

fn module_path() -> PathBuf {
    if let Ok(path) = std::env::var("QED_CHECKER_WASM") {
        return PathBuf::from(path);
    }
    let target = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".into());
    Path::new(&target).join("wasm32-unknown-unknown/release/qed_wasm_checker.wasm")
}

struct Checker {
    store: Store<()>,
    memory: wasmi::Memory,
    alloc: TypedFunc<u32, u32>,
    free: TypedFunc<(u32, u32), ()>,
    check: TypedFunc<(u32, u32, u32, u32, u32, u32), u64>,
}

impl Checker {
    fn load() -> Self {
        let bytes = std::fs::read(module_path()).expect("build the wasm module first");
        let mut config = Config::default();
        config.set_max_recursion_depth(1 << 20);
        config.set_max_stack_height(1 << 30);
        let engine = Engine::new(&config);
        let module = Module::new(&engine, &bytes[..]).unwrap();
        let mut store = Store::new(&engine, ());
        let instance = Linker::<()>::new(&engine)
            .instantiate_and_start(&mut store, &module)
            .expect("the module imports nothing");
        let memory = instance.get_memory(&store, "memory").unwrap();
        Checker {
            alloc: instance.get_typed_func(&store, "qed_alloc").unwrap(),
            free: instance.get_typed_func(&store, "qed_free").unwrap(),
            check: instance.get_typed_func(&store, "qed_check").unwrap(),
            memory,
            store,
        }
    }

    fn put(&mut self, bytes: &[u8]) -> (u32, u32) {
        let len = u32::try_from(bytes.len()).unwrap();
        let ptr = self.alloc.call(&mut self.store, len).unwrap();
        self.memory
            .write(&mut self.store, ptr as usize, bytes)
            .unwrap();
        (ptr, len)
    }

    /// Run one check in a fresh instance (a trap leaves an instance unusable,
    /// as it does in a browser).
    fn run(policy: &[u8], statement: &[u8], artifact: &[u8]) -> Value {
        let mut c = Checker::load();
        let (p, pl) = c.put(policy);
        let (s, sl) = c.put(statement);
        let (a, al) = c.put(artifact);
        match c.check.call(&mut c.store, (p, pl, s, sl, a, al)) {
            Ok(packed) => {
                let (ptr, len) = ((packed >> 32) as u32, packed as u32);
                let mut out = vec![0u8; len as usize];
                c.memory.read(&c.store, ptr as usize, &mut out).unwrap();
                c.free.call(&mut c.store, (ptr, len)).unwrap();
                serde_json::from_slice(&out).unwrap()
            }
            Err(_) => json!({ "verdict": "refused", "refusal": "KernelRefused", "aborted": true }),
        }
    }
}

fn policy_json(policy: &Policy) -> Vec<u8> {
    let sha: String = policy
        .statement_sha256
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    serde_json::to_vec(&json!({
        "statementSha256": sha,
        "claim": policy.claim,
        "permittedAxioms": policy.permitted_axioms,
        "maximumArtifactBytes": policy.maximum_artifact_bytes,
    }))
    .unwrap()
}

/// What both sides must agree on.
fn key(v: &Value) -> (Value, Value, Value, Value) {
    (
        v["verdict"].clone(),
        v["refusal"].clone(),
        v["declarations"].clone(),
        v["proof"].clone(),
    )
}

fn both(name: &str, policy: &Policy, statement: &[u8], artifact: &[u8]) -> Value {
    let native = verdict(policy, artifact, &accept(policy, statement, artifact));
    let wasm = Checker::run(&policy_json(policy), statement, artifact);
    assert_eq!(
        key(&native),
        key(&wasm),
        "{name}: native {native} wasm {wasm}"
    );
    if wasm.get("aborted").is_none() {
        assert_eq!(native["policyHash"], wasm["policyHash"], "{name}");
        assert_eq!(
            native["artifactKeccak256"], wasm["artifactKeccak256"],
            "{name}"
        );
    }
    // Printed so a browser run can be compared with the native verdict.
    let (verdict, refusal, declarations, proof) = key(&native);
    eprintln!("{name}: {verdict} {refusal} declarations={declarations} proof={proof}");
    wasm
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes).into()
}

fn fixture_policy(statement: &[u8]) -> Policy {
    Policy {
        statement_sha256: sha256(statement),
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
fn the_fixture_cases_agree() {
    let p = fixture_policy(STATEMENT);
    let accepted = both("accept", &p, STATEMENT, ARTIFACT);
    assert_eq!(accepted["verdict"], "accepted");

    let mut wrong = p.clone();
    wrong.statement_sha256[0] ^= 1;
    both("statement mismatch", &wrong, STATEMENT, ARTIFACT);
    both("artifact empty", &p, STATEMENT, b"");
    let mut small = p.clone();
    small.maximum_artifact_bytes = 10;
    both("artifact too large", &small, STATEMENT, ARTIFACT);
    let unterminated = &STATEMENT[..STATEMENT.len() - 1];
    both(
        "statement unterminated",
        &fixture_policy(unterminated),
        unterminated,
        ARTIFACT,
    );
    let mut other_claim = p.clone();
    other_claim.claim = "Nucleus.Other".into();
    both("claim not declared", &other_claim, STATEMENT, ARTIFACT);
    both(
        "claim not proved",
        &p,
        STATEMENT,
        &line(r#"{"in":105,"str":{"pre":0,"str":"zz_unused"}}"#),
    );
    both("export invalid", &p, STATEMENT, b"not json\n");
    // Redeclaring the buyer's claim: the kernel refuses (a trap in the module).
    let claim_declaration = std::str::from_utf8(STATEMENT)
        .unwrap()
        .lines()
        .last()
        .unwrap();
    let refused = both("kernel refused", &p, STATEMENT, &line(claim_declaration));
    assert_eq!(refused["refusal"], "KernelRefused");
    // The proof, then `def Nat.gcd : Nat := Nat.zero`: a kernel-reserved name
    // the statement does not declare. In the fixture, name 1 is `Nat`,
    // expression 1 is `Nat` and expression 6 is `Nat.zero`.
    let next_name = std::str::from_utf8(&[STATEMENT, ARTIFACT].concat())
        .unwrap()
        .lines()
        .filter_map(|l| l.strip_prefix(r#"{"in":"#))
        .map(|rest| rest.split(',').next().unwrap().parse::<u32>().unwrap())
        .max()
        .unwrap()
        + 1;
    let reserved = [
        ARTIFACT.to_vec(),
        line(&format!(
            r#"{{"in":{next_name},"str":{{"pre":1,"str":"gcd"}}}}"#
        )),
        line(&format!(
            r#"{{"def":{{"all":[{next_name}],"hints":{{"regular":1}},"levelParams":[],"name":{next_name},"safety":"safe","type":1,"value":6}}}}"#
        )),
    ]
    .concat();
    let refused = both("reserved name", &p, STATEMENT, &reserved);
    assert_eq!(refused["refusal"], "ArtifactDeclaresReservedName");
}

#[test]
fn every_settled_artifact_on_the_site_agrees() {
    let site = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../site/input");
    let policies: Value =
        serde_json::from_slice(&std::fs::read(site.join("policies.json")).unwrap()).unwrap();
    let snapshot: Value =
        serde_json::from_slice(&std::fs::read(site.join("ledger.snapshot.json")).unwrap()).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for receipt in snapshot["receipts"].as_array().unwrap() {
        let policy_hash = receipt["order"]["policyHash"].as_str().unwrap();
        let keccak = receipt["artifact"]["keccak256"].as_str().unwrap();
        if !seen.insert((policy_hash.to_owned(), keccak.to_owned())) {
            continue;
        }
        let entry = &policies[policy_hash];
        let statement = std::fs::read(
            site.join("statements")
                .join(entry["statementFile"].as_str().unwrap()),
        )
        .unwrap();
        let artifact = std::fs::read(
            site.join("artifacts")
                .join(format!("{}.bin", keccak.trim_start_matches("0x"))),
        )
        .unwrap();
        let policy =
            qed_wasm_checker::policy_from_json(&serde_json::to_vec(entry).unwrap()).unwrap();
        let wasm = both(policy_hash, &policy, &statement, &artifact);
        assert_eq!(wasm["verdict"], "accepted", "{policy_hash}");
        assert_eq!(
            wasm["policyHash"], policy_hash,
            "the served policy is the order's"
        );
        assert_eq!(
            wasm["artifactKeccak256"], keccak,
            "the served artifact is the settled one"
        );
    }
    // Distinct (policy, artifact) pairs; the sixth is the first trade on the
    // reproducible programs (task on the toy base, 2026-11-13).
    assert_eq!(seen.len(), 6);
}

/// `/visits` runs the shipped module on the analytics claim
/// (`contracts/analytics/browser-check`, exported by `examples/visits_claim.rs`
/// into `contracts/site/input/visits-check`). Both runtimes accept it, and
/// both refuse it with one byte of the artifact changed or the statement of
/// another claim.
#[test]
fn the_visits_claim_is_accepted_and_tampering_is_refused() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../site/input/visits-check");
    let read = |name: &str| std::fs::read(dir.join(name)).unwrap();
    let (statement, artifact) = (read("statement.v2"), read("artifact.v2"));
    let policy = qed_wasm_checker::policy_from_json(&read("policy.json")).unwrap();
    let record: Value = serde_json::from_slice(&read("record.json")).unwrap();
    let accepted = both("visits claim", &policy, &statement, &artifact);
    assert_eq!(accepted["verdict"], "accepted");
    assert_eq!(accepted["proof"], "QedVisits.proof");
    assert_eq!(accepted["declarations"], record["declarations"]);
    assert_eq!(accepted["policyHash"], record["policyHash"]);
    assert_eq!(policy.permitted_axioms, ["propext"]);
    // Red: one byte of the proof changed, at its last record.
    let mut tampered = artifact.clone();
    let at = tampered.len() - 2;
    tampered[at] ^= 1;
    let refused = both("visits claim, tampered", &policy, &statement, &tampered);
    assert_eq!(refused["verdict"], "refused");
    // Red: the same proof against another claim's statement.
    let mut other = policy.clone();
    other.statement_sha256 = sha256(STATEMENT);
    let refused = both(
        "visits claim, other statement",
        &other,
        STATEMENT,
        &artifact,
    );
    assert_eq!(refused["verdict"], "refused");
}
