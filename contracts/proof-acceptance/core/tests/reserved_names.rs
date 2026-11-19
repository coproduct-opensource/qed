//! A seller may not declare a name the kernel checker treats specially by
//! name. The checker reduces those constants on literals (`Nat.add`,
//! `Nat.gcd`, ...), builds literals with them (`Nat.succ`, `String.ofList`,
//! `Char.ofNat`, `List.cons`, `Bool.true`, ...) or checks quotients against
//! them (`Quot.*`, `Eq`), whatever the export's own declaration of that name
//! says. So only the statement, which the policy hash fixes, may declare them.
//! (docs/rfcs/proof-acceptance-reserved-names-2026-11-19.md)
//!
//! The set is the checker's own (`nanoda_lib::acceptance::kernel_reserved_names`,
//! generated from the list its name cache is built from); these tests iterate
//! it rather than restating it.
use nanoda_lib::acceptance::{inspect, is_kernel_reserved, kernel_reserved_names};
use nucleus_proof_acceptance::{Policy, Refusal, accept, accept_on_base, base};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const STATEMENT: &[u8] = include_bytes!("fixtures/task.ndjson");
const ARTIFACT: &[u8] = include_bytes!("fixtures/suffix.ndjson");
const BASE: &[u8] = include_bytes!("fixtures/base/base.ndjson");
const STATEMENT_ON_BASE: &[u8] = include_bytes!("fixtures/base/task-on-base.ndjson");
const ARTIFACT_ON_BASE: &[u8] = include_bytes!("fixtures/base/suffix-on-base.ndjson");

fn policy_for(statement: &[u8]) -> Policy {
    Policy {
        statement_sha256: Sha256::digest(statement).into(),
        claim: "Nucleus.Claim".into(),
        permitted_axioms: vec![],
        maximum_artifact_bytes: 65_536,
    }
}

/// Appends NDJSON lines that continue an export. Names and expressions are
/// hash-consed by the reader (a second line for the same name or expression
/// is refused), so existing ones are reused and new ones get the next index.
struct Continuation {
    names: HashMap<(u64, String), u64>,
    exprs: HashMap<String, u64>,
    next_name: u64,
    next_expr: u64,
    lines: Vec<String>,
}

fn without_index(mut value: Value, key: &str) -> (Option<u64>, String) {
    let index = value
        .as_object_mut()
        .and_then(|o| o.remove(key))
        .and_then(|i| i.as_u64());
    (index, value.to_string())
}

impl Continuation {
    fn after(export: &[u8]) -> Self {
        let mut c = Continuation {
            names: HashMap::new(),
            exprs: HashMap::new(),
            next_name: 1,
            next_expr: 0,
            lines: Vec::new(),
        };
        for line in std::str::from_utf8(export).unwrap().lines() {
            let value: Value = serde_json::from_str(line).unwrap();
            if let Some(n) = value["in"].as_u64() {
                if let (Some(pre), Some(s)) =
                    (value["str"]["pre"].as_u64(), value["str"]["str"].as_str())
                {
                    c.names.insert((pre, s.to_owned()), n);
                }
                c.next_name = c.next_name.max(n + 1);
            } else if value.get("ie").is_some() {
                let (e, key) = without_index(value, "ie");
                let e = e.unwrap();
                c.exprs.insert(key, e);
                c.next_expr = c.next_expr.max(e + 1);
            }
        }
        c
    }

    fn name(&mut self, dotted: &str) -> u64 {
        let mut pre = 0;
        for part in dotted.split('.') {
            pre = match self.names.get(&(pre, part.to_owned())) {
                Some(&n) => n,
                None => {
                    let n = self.next_name;
                    self.next_name += 1;
                    self.lines
                        .push(json!({"in": n, "str": {"pre": pre, "str": part}}).to_string());
                    self.names.insert((pre, part.to_owned()), n);
                    n
                }
            };
        }
        pre
    }

    fn expr(&mut self, body: Value) -> u64 {
        let key = body.to_string();
        if let Some(&e) = self.exprs.get(&key) {
            return e;
        }
        let e = self.next_expr;
        self.next_expr += 1;
        let mut line = body;
        line["ie"] = json!(e);
        self.lines.push(line.to_string());
        self.exprs.insert(key, e);
        e
    }

    fn constant(&mut self, dotted: &str) -> u64 {
        let n = self.name(dotted);
        self.expr(json!({"const": {"name": n, "us": []}}))
    }

    fn binder(&mut self, kind: &str, ty: u64, body: u64) -> u64 {
        let x = self.name("x");
        self.expr(json!({kind: {"binderInfo": "default", "body": body, "name": x, "type": ty}}))
    }

    /// `def NAME : Nat := Nat.zero`.
    fn nat_definition(&mut self, dotted: &str) {
        let ty = self.constant("Nat");
        let value = self.constant("Nat.zero");
        self.definition(dotted, ty, value);
    }

    /// `def NAME : Nat → Nat → Nat := fun _ _ => Nat.zero`: a binary Nat
    /// operation whose value is not the checker's.
    fn binary_nat_definition(&mut self, dotted: &str) {
        let nat = self.constant("Nat");
        let zero = self.constant("Nat.zero");
        let inner = self.binder("forallE", nat, nat);
        let ty = self.binder("forallE", nat, inner);
        let lam = self.binder("lam", nat, zero);
        let value = self.binder("lam", nat, lam);
        self.definition(dotted, ty, value);
    }

    /// `def NAME : Nat → Nat := fun x => x`: a unary helper with a value
    /// that is not the checker's.
    fn unary_nat_definition(&mut self, dotted: &str) {
        let nat = self.constant("Nat");
        let ty = self.binder("forallE", nat, nat);
        let var = self.expr(json!({"bvar": 0}));
        let value = self.binder("lam", nat, var);
        self.definition(dotted, ty, value);
    }

    fn definition(&mut self, dotted: &str, ty: u64, value: u64) {
        let n = self.name(dotted);
        self.lines.push(
            json!({"def": {"all": [n], "hints": {"regular": 1}, "levelParams": [], "name": n,
                "safety": "safe", "type": ty, "value": value}})
            .to_string(),
        );
    }

    fn bytes(&self) -> Vec<u8> {
        self.lines
            .iter()
            .flat_map(|l| [l.as_bytes(), b"\n"].concat())
            .collect()
    }
}

/// The fixture's artifact (a real proof of the claim) followed by whatever
/// `extend` declares.
fn artifact_with(
    statement: &[u8],
    artifact: &[u8],
    extend: impl FnOnce(&mut Continuation),
) -> Vec<u8> {
    let mut more = Continuation::after(&[statement, artifact].concat());
    extend(&mut more);
    [artifact, &more.bytes()].concat()
}

fn declared(export: &[u8]) -> Vec<String> {
    inspect(export, &[], false)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect()
}

#[test]
fn the_reserved_set_is_the_checkers_name_list() {
    let names = kernel_reserved_names();
    // Every family the checker special-cases is in it, and nothing twice.
    for expected in [
        "Nat",
        "Nat.zero",
        "Nat.succ",
        "Nat.add",
        "Nat.gcd",
        "Nat.shiftRight",
        "Bool.true",
        "String",
        "String.ofList",
        "Char",
        "Char.ofNat",
        "List.nil",
        "List.cons",
        "Quot",
        "Quot.lift",
        "Eq",
        "Eq.refl",
        "eagerReduce",
    ] {
        assert!(names.iter().any(|n| n == expected), "{expected}");
    }
    let mut unique = names.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), names.len());
    assert!(names.iter().all(|n| is_kernel_reserved(n)));
    // Neighbours of a reserved name are not reserved.
    for other in [
        "Nat.add_succ",
        "Nat.gcd.induct",
        "Nucleus.Nat.gcd",
        "Eq.rec",
        "Nat.rec",
        "Eqrefl",
        "Eq.refl.x",
    ] {
        assert!(!is_kernel_reserved(other), "{other}");
    }
}

#[test]
fn the_fixture_artifact_is_accepted_and_declares_no_reserved_name() {
    let policy = policy_for(STATEMENT);
    assert_eq!(
        accept(&policy, STATEMENT, ARTIFACT).unwrap().proof,
        "Nucleus.proof"
    );
    let sellers = &declared(&[STATEMENT, ARTIFACT].concat())[declared(STATEMENT).len()..];
    assert!(
        sellers.iter().all(|n| !is_kernel_reserved(n)),
        "{sellers:?}"
    );
}

/// Exhaustive over the checker's list: for each reserved name the statement
/// does not declare, an artifact that proves the claim and also declares that
/// name is refused, naming it. For each one the statement does declare, the
/// artifact's second declaration is refused as before.
#[test]
fn every_reserved_name_the_statement_omits_is_refused_from_the_seller() {
    let policy = policy_for(STATEMENT);
    let buyers = declared(STATEMENT);
    let mut omitted = 0;
    for name in kernel_reserved_names() {
        let artifact = artifact_with(STATEMENT, ARTIFACT, |c| c.nat_definition(&name));
        let verdict = accept(&policy, STATEMENT, &artifact);
        if buyers.contains(&name) {
            assert!(
                matches!(
                    verdict,
                    Err(Refusal::KernelRefused | Refusal::ExportInvalid(_))
                ),
                "{name}: {verdict:?}"
            );
        } else {
            omitted += 1;
            // The checker alone passes the whole export ...
            let whole = [STATEMENT, &artifact].concat();
            assert!(inspect(&whole, &[], true).is_ok(), "{name}");
            // ... and the rule refuses it.
            assert_eq!(
                verdict,
                Err(Refusal::ArtifactDeclaresReservedName(name.clone())),
                "{name}"
            );
        }
    }
    // The fixture statement declares Nat, its constructors, Nat.add and Eq:
    // most of the list is exercised on the omitted side.
    assert!(omitted >= kernel_reserved_names().len() - 7, "{omitted}");
}

#[test]
fn a_redefined_nat_operation_is_refused() {
    let policy = policy_for(STATEMENT);
    for name in [
        "Nat.gcd",
        "Nat.mul",
        "Nat.pow",
        "Nat.lor",
        "Nat.xor",
        "Nat.shiftLeft",
        "Nat.beq",
    ] {
        let artifact = artifact_with(STATEMENT, ARTIFACT, |c| c.binary_nat_definition(name));
        // Well typed: the checker alone passes the whole export.
        assert!(
            inspect(&[STATEMENT, &artifact].concat(), &[], true).is_ok(),
            "{name}"
        );
        assert_eq!(
            accept(&policy, STATEMENT, &artifact),
            Err(Refusal::ArtifactDeclaresReservedName(name.into()))
        );
    }
}

#[test]
fn a_redefined_literal_helper_is_refused() {
    let policy = policy_for(STATEMENT);
    for name in ["Char.ofNat", "String.ofList", "Nat.succ"] {
        let statement_has_it = declared(STATEMENT).iter().any(|n| n == name);
        let artifact = artifact_with(STATEMENT, ARTIFACT, |c| c.unary_nat_definition(name));
        let verdict = accept(&policy, STATEMENT, &artifact);
        if statement_has_it {
            assert!(
                matches!(
                    verdict,
                    Err(Refusal::KernelRefused | Refusal::ExportInvalid(_))
                ),
                "{name}"
            );
        } else {
            assert_eq!(
                verdict,
                Err(Refusal::ArtifactDeclaresReservedName(name.into()))
            );
        }
    }
}

#[test]
fn a_seller_name_beside_a_reserved_one_is_accepted() {
    let policy = policy_for(STATEMENT);
    let artifact = artifact_with(STATEMENT, ARTIFACT, |c| {
        c.binary_nat_definition("Nucleus.Nat.gcd");
        c.nat_definition("Nat.gcd.helper");
    });
    assert_eq!(
        accept(&policy, STATEMENT, &artifact).unwrap().proof,
        "Nucleus.proof"
    );
}

#[test]
fn the_rule_holds_on_a_checked_base_too() {
    let policy = policy_for(STATEMENT_ON_BASE);
    let id = base::id(BASE);
    accept_on_base(&policy, STATEMENT_ON_BASE, ARTIFACT_ON_BASE, BASE.len(), id).unwrap();
    let artifact = artifact_with(STATEMENT_ON_BASE, ARTIFACT_ON_BASE, |c| {
        c.binary_nat_definition("Nat.gcd")
    });
    assert_eq!(
        accept_on_base(&policy, STATEMENT_ON_BASE, &artifact, BASE.len(), id),
        Err(Refusal::ArtifactDeclaresReservedName("Nat.gcd".into()))
    );
    assert_eq!(
        accept(&policy, STATEMENT_ON_BASE, &artifact),
        Err(Refusal::ArtifactDeclaresReservedName("Nat.gcd".into()))
    );
}
