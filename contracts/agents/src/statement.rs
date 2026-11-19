//! A statement generated from a Nucleus commit (QED ladder, build item 1).
//!
//!   nucleus-buyer statement REPO COMMIT PACKAGE ROW LEAN4EXPORT WORK_DIR OUT_DIR [LAKE]
//!
//! `S = v2(lean4export Statements.S<id> -- <permitted axioms> Statements.S<id>.claim Nat)`,
//! where every input is fixed by a commit on the repository
//! (`docs/rfcs/qed-nucleus-merge-ladder-2026-11-14.md`, section 3):
//!
//! - the package directory is taken from the commit with `git archive`, never
//!   from a working tree, so an uncommitted edit cannot reach `S`;
//! - its `lean-toolchain` must name Lean 4.30.0, and `lean --version` under
//!   `lake env` must report that version and its commit;
//! - the statement module is `Statements/S<id>.lean` in the package, its claim
//!   `Statements.S<id>.claim`, and the permitted axioms are the three below;
//! - the exporter's first line must name `lean4export` 3.1.0, format 3.1.0 and
//!   Lean 4.30.0 at its commit.
//!
//! The export is then screened before anything is printed as a pin. The
//! screen exists because `lean4export` exits 0 after panicking on a root it
//! cannot find, and writes an export without that root (the RFC's "Wrong
//! beliefs corrected"). So the exit status is necessary and not sufficient:
//!
//! 1. the exporter exited 0 **and** wrote nothing to standard error;
//! 2. its meta line names the pinned exporter, format and Lean;
//! 3. every root asked for is declared in the export;
//! 4. no axiom is declared other than the three permitted (so no `sorryAx`,
//!    no native-decide axiom, no home-made `axiom`);
//! 5. the claim is declared once, universe-monomorphic, as a definition,
//!    opaque constant or inductive type (the acceptance rule's own test);
//! 6. the whole export type-checks in the kernel checker the acceptance rule
//!    uses, admitting only the three axioms.
//!
//! What it does not check, and the RFC's screening steps 1 to 3 need a person
//! for: that the claim is not already proved in the package, that it is not
//! false on small instances, and that its hypotheses are satisfiable.
//!
//! The exporter's source revision (`a3e35a5`) cannot be read from its binary or
//! its output: the meta line identifies version 3.1.0 only. The binary's
//! SHA-256 is recorded beside the pin so a reader can tell which build made it.
use crate::prelude::*;
use nanoda_lib::acceptance::{Kind, inspect};
use nucleus_proof_acceptance::export_v2_from_ndjson;
use std::{
    collections::HashMap,
    path::{Component, PathBuf},
    process::{Command, Stdio},
};

/// The toolchain every statement is generated with: Nucleus's pin.
pub const TOOLCHAIN: &str = "leanprover/lean4:v4.30.0";
pub const LEAN_VERSION: &str = "4.30.0";
/// The Lean 4.30.0 release commit, as `lean --version` and the exporter's
/// meta line report it.
pub const LEAN_GITHASH: &str = "d024af099ca4bf2c86f649261ebf59565dc8c622";
pub const EXPORTER_NAME: &str = "lean4export";
pub const EXPORTER_VERSION: &str = "3.1.0";
pub const FORMAT_VERSION: &str = "3.1.0";
/// The axioms a ladder statement may declare, in the order they are roots.
pub const PERMITTED_AXIOMS: [&str; 3] = ["propext", "Classical.choice", "Quot.sound"];
/// Names every statement exports after its claim, so a bundle's commitment
/// (`Statements.S<id>.sourceSha256 : Nat`) needs no seller declaration of a
/// name the acceptance rule reserves.
pub const STATEMENT_PRELUDE_ROOTS: [&str; 1] = ["Nat"];

/// A ladder row's identifier, `S` followed by digits (`S0001`). Every Lean
/// name and path a row uses is derived from it, so a statement, its proof and
/// its source commitment cannot be named apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row(String);

impl Row {
    pub fn parse(text: &str) -> Result<Self, Refusal> {
        let digits = text.strip_prefix('S').unwrap_or("");
        if digits.is_empty() || digits.len() > 12 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Refusal::Row(text.to_owned()));
        }
        Ok(Self(text.to_owned()))
    }
    /// The row a policy's claim name belongs to, if it is a ladder claim.
    pub fn from_claim(claim: &str) -> Option<Self> {
        let id = claim.strip_prefix("Statements.")?.strip_suffix(".claim")?;
        Self::parse(id).ok()
    }
    pub fn id(&self) -> &str {
        &self.0
    }
    /// `Statements.S<id>`: the statement module, and the namespace of every
    /// declaration the row names.
    pub fn module(&self) -> String {
        format!("Statements.{}", self.0)
    }
    pub fn claim(&self) -> String {
        format!("Statements.{}.claim", self.0)
    }
    pub fn proof(&self) -> String {
        format!("Statements.{}.proof", self.0)
    }
    /// The definition that commits the artifact to its source manifest.
    pub fn source_commitment(&self) -> String {
        format!("Statements.{}.sourceSha256", self.0)
    }
    pub fn statement_path(&self) -> PathBuf {
        PathBuf::from(format!("Statements/{}.lean", self.0))
    }
    /// `Statements.S<id>.Proof`, at `Statements/S<id>/Proof.lean`. The path is
    /// part of the terms: the export embeds the module's name.
    pub fn proof_module(&self) -> String {
        format!("Statements.{}.Proof", self.0)
    }
    pub fn proof_path(&self) -> PathBuf {
        PathBuf::from(format!("Statements/{}/Proof.lean", self.0))
    }
    pub fn source_module(&self) -> String {
        format!("Statements.{}.Source", self.0)
    }
    pub fn source_path(&self) -> PathBuf {
        PathBuf::from(format!("Statements/{}/Source.lean", self.0))
    }
    /// The statement's export roots: the permitted axioms, then the claim,
    /// then [`STATEMENT_PRELUDE_ROOTS`]. A root already in the claim's closure
    /// adds nothing to the export, so a statement that reaches `Nat` exports to
    /// the same bytes as before; one that does not now carries `Nat` itself, so
    /// a seller's artifact never has to declare it.
    pub fn statement_roots(&self) -> Vec<String> {
        PERMITTED_AXIOMS
            .iter()
            .map(|a| (*a).to_owned())
            .chain([self.claim()])
            .chain(STATEMENT_PRELUDE_ROOTS.iter().map(|r| (*r).to_owned()))
            .collect()
    }
}

/// Why a statement was not generated. A refusal is a definite answer about
/// the inputs; an I/O failure (a tool missing, a disk full) is an `Err` of the
/// outer `Res` instead, because it says nothing about the statement.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The row identifier is not `S` followed by digits.
    Row(String),
    /// The package path is not a relative path inside the repository.
    Package(String),
    /// The commit does not resolve, or the package is not in it.
    Commit(String),
    /// The package's `lean-toolchain` at the commit, or the Lean that `lake env`
    /// runs, is not the pinned one.
    Toolchain(String),
    /// The statement module is not at `Statements/S<id>.lean` in the package.
    ModuleMissing(String),
    /// `lake build` of the statement module failed.
    Build(String),
    /// The exporter exited non-zero.
    ExporterFailed(String),
    /// The exporter wrote to standard error (it panics and exits 0).
    ExporterStderr(String),
    /// The export's meta line is not the pinned exporter, format and Lean.
    Meta(String),
    /// The export does not parse.
    Parse(String),
    /// A root asked for is not declared in the export.
    RootMissing(String),
    /// The export declares an axiom outside the three permitted.
    Axiom(String),
    /// The claim is not declared once as a universe-monomorphic definition,
    /// opaque constant or inductive type.
    Claim(String),
    /// The kernel checker refused a declaration.
    KernelRefused(String),
}
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Row(text) => write!(f, "`{text}` is not a row id (S followed by digits)"),
            Self::Package(text) => {
                write!(f, "`{text}` is not a relative path inside the repository")
            }
            Self::Commit(why) => write!(f, "commit: {why}"),
            Self::Toolchain(why) => write!(f, "toolchain is not {TOOLCHAIN}: {why}"),
            Self::ModuleMissing(path) => write!(f, "no statement module at {path}"),
            Self::Build(why) => write!(f, "lake build failed: {why}"),
            Self::ExporterFailed(why) => write!(f, "the exporter failed: {why}"),
            Self::ExporterStderr(line) => write!(
                f,
                "the exporter wrote to standard error (it exits 0 after a panic): {line}"
            ),
            Self::Meta(why) => write!(f, "the export's meta line is not the pinned one: {why}"),
            Self::Parse(why) => write!(f, "the export does not parse: {why}"),
            Self::RootMissing(name) => write!(f, "root `{name}` is not declared in the export"),
            Self::Axiom(name) => write!(
                f,
                "the export declares axiom `{name}`, which is not permitted"
            ),
            Self::Claim(why) => write!(f, "the claim is not a checkable proposition: {why}"),
            Self::KernelRefused(why) => write!(f, "the kernel checker refused the export: {why}"),
        }
    }
}
impl std::error::Error for Refusal {}

/// What a declaration is, as the NDJSON export says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclKind {
    Axiom,
    Definition,
    Theorem,
    Opaque,
    Quot,
    Inductive,
    Constructor,
    Recursor,
}

/// The declarations of an NDJSON export, by name, read without the kernel:
/// enough to say which roots are declared, which axioms, and what natural
/// number literals a definition's value holds.
pub struct Declared {
    pub declarations: Vec<(String, DeclKind)>,
    /// Definition name to the index of its value expression.
    values: HashMap<String, u64>,
    exprs: HashMap<u64, Value>,
}

fn index(value: &Value) -> Option<u64> {
    value.as_u64()
}

impl Declared {
    pub fn read(ndjson: &[u8]) -> Result<Self, Refusal> {
        let text = std::str::from_utf8(ndjson).map_err(|e| Refusal::Parse(e.to_string()))?;
        // Name index to (prefix index, last component). Index 0 is anonymous.
        let mut names: HashMap<u64, (u64, String)> = HashMap::new();
        let mut declared: Vec<(u64, DeclKind)> = vec![];
        let mut values: Vec<(u64, u64)> = vec![];
        let mut exprs: HashMap<u64, Value> = HashMap::new();
        for (number, line) in text.lines().enumerate().skip(1) {
            let record: Value = serde_json::from_str(line)
                .map_err(|e| Refusal::Parse(format!("line {}: {e}", number + 1)))?;
            let bad = || Refusal::Parse(format!("line {}: unexpected record", number + 1));
            if let Some(n) = record.get("in").and_then(index) {
                if let Some(s) = record.get("str") {
                    let pre = s.get("pre").and_then(index).ok_or_else(bad)?;
                    let part = s.get("str").and_then(Value::as_str).ok_or_else(bad)?;
                    names.insert(n, (pre, part.to_owned()));
                } else if let Some(s) = record.get("num") {
                    let pre = s.get("pre").and_then(index).ok_or_else(bad)?;
                    let part = s.get("i").and_then(index).ok_or_else(bad)?;
                    names.insert(n, (pre, part.to_string()));
                } else {
                    return Err(bad());
                }
                continue;
            }
            if let Some(e) = record.get("ie").and_then(index) {
                exprs.insert(e, record);
                continue;
            }
            if record.get("il").is_some() {
                continue;
            }
            let single = [
                ("axiom", DeclKind::Axiom),
                ("def", DeclKind::Definition),
                ("thm", DeclKind::Theorem),
                ("opaque", DeclKind::Opaque),
                ("quot", DeclKind::Quot),
            ];
            let mut matched = false;
            for (key, kind) in single {
                if let Some(body) = record.get(key) {
                    let name = body.get("name").and_then(index).ok_or_else(bad)?;
                    declared.push((name, kind));
                    if kind == DeclKind::Definition {
                        values.push((name, body.get("value").and_then(index).ok_or_else(bad)?));
                    }
                    matched = true;
                }
            }
            if let Some(body) = record.get("inductive") {
                for (key, kind) in [
                    ("types", DeclKind::Inductive),
                    ("ctors", DeclKind::Constructor),
                    ("recs", DeclKind::Recursor),
                ] {
                    for item in body.get(key).and_then(Value::as_array).ok_or_else(bad)? {
                        declared.push((item.get("name").and_then(index).ok_or_else(bad)?, kind));
                    }
                }
                matched = true;
            }
            if !matched {
                return Err(bad());
            }
        }
        let render = |mut n: u64| -> Result<String, Refusal> {
            let mut parts = vec![];
            while n != 0 {
                let (pre, part) = names
                    .get(&n)
                    .ok_or_else(|| Refusal::Parse(format!("name {n} is not declared")))?;
                parts.push(part.clone());
                if *pre >= n {
                    return Err(Refusal::Parse(format!("name {n} refers forward")));
                }
                n = *pre;
            }
            parts.reverse();
            Ok(parts.join("."))
        };
        Ok(Self {
            declarations: declared
                .iter()
                .map(|(n, kind)| Ok((render(*n)?, *kind)))
                .collect::<Result<_, Refusal>>()?,
            values: values
                .iter()
                .map(|(n, v)| Ok((render(*n)?, *v)))
                .collect::<Result<_, Refusal>>()?,
            exprs,
        })
    }

    pub fn kinds_of(&self, name: &str) -> Vec<DeclKind> {
        self.declarations
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, k)| *k)
            .collect()
    }

    /// Every natural-number literal in the value of definition `name`.
    /// `def x : Nat := 0x…` elaborates to `OfNat.ofNat Nat n (instOfNatNat n)`,
    /// so one literal appears twice; the caller wants exactly one distinct
    /// value.
    pub fn nat_literals_of(&self, name: &str) -> Option<Vec<String>> {
        let root = *self.values.get(name)?;
        let mut out = vec![];
        let mut stack = vec![root];
        let mut seen = std::collections::HashSet::new();
        while let Some(e) = stack.pop() {
            if !seen.insert(e) {
                continue;
            }
            let record = self.exprs.get(&e)?;
            if let Some(n) = record.get("natVal").and_then(Value::as_str) {
                out.push(n.to_owned());
            }
            for (key, fields) in [
                ("app", &["fn", "arg"][..]),
                ("lam", &["type", "body"][..]),
                ("forallE", &["type", "body"][..]),
                ("letE", &["type", "value", "body"][..]),
                ("proj", &["struct"][..]),
                ("mdata", &["expr"][..]),
            ] {
                if let Some(body) = record.get(key) {
                    for field in fields {
                        stack.extend(body.get(*field).and_then(index));
                    }
                }
            }
        }
        out.sort();
        out.dedup();
        Some(out)
    }
}

/// What the exporter returned.
pub struct Exported {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// An export that passed every screen. Minted only by `screen`.
#[derive(Debug)]
pub struct Screened {
    ndjson: Vec<u8>,
    v2: Vec<u8>,
    declarations: usize,
}
impl Screened {
    pub fn ndjson(&self) -> &[u8] {
        &self.ndjson
    }
    /// The statement as posted: export v2 bytes.
    pub fn v2(&self) -> &[u8] {
        &self.v2
    }
    /// SHA-256 of the v2 bytes: the policy's `statement_sha256`.
    pub fn statement_sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.v2).into()
    }
    pub fn declarations(&self) -> usize {
        self.declarations
    }
}

/// The meta line's fields, checked against the pins.
pub fn check_meta(first_line: &[u8]) -> Result<(), Refusal> {
    let meta: Value =
        serde_json::from_slice(first_line).map_err(|e| Refusal::Meta(e.to_string()))?;
    let found = |path: &[&str]| {
        path.iter()
            .try_fold(&meta["meta"], |v, key| v.get(*key))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    for (path, want) in [
        (&["exporter", "name"][..], EXPORTER_NAME),
        (&["exporter", "version"][..], EXPORTER_VERSION),
        (&["format", "version"][..], FORMAT_VERSION),
        (&["lean", "version"][..], LEAN_VERSION),
        (&["lean", "githash"][..], LEAN_GITHASH),
    ] {
        let got = found(path);
        if got != want {
            return Err(Refusal::Meta(format!(
                "{} is `{got}`, not `{want}`",
                path.join(".")
            )));
        }
    }
    Ok(())
}

/// Screen one export of `row`'s statement.
pub fn screen(row: &Row, exported: Exported) -> Result<Screened, Refusal> {
    let first_line = |bytes: &[u8]| {
        String::from_utf8_lossy(bytes.split(|b| *b == b'\n').next().unwrap_or_default())
            .into_owned()
    };
    // 1. Exit status and standard error, both.
    if !exported.success {
        return Err(Refusal::ExporterFailed(first_line(&exported.stderr)));
    }
    if !exported.stderr.is_empty() {
        return Err(Refusal::ExporterStderr(first_line(&exported.stderr)));
    }
    let ndjson = exported.stdout;
    if ndjson.last() != Some(&b'\n') {
        return Err(Refusal::Parse(
            "the export does not end in a newline".into(),
        ));
    }
    // 2. The meta line.
    check_meta(ndjson.split(|b| *b == b'\n').next().unwrap_or_default())?;
    // 3 to 5, read without the kernel, so each refusal names what it found.
    let declared = Declared::read(&ndjson)?;
    for root in row.statement_roots() {
        if declared.kinds_of(&root).is_empty() {
            return Err(Refusal::RootMissing(root));
        }
    }
    if let Some((name, _)) = declared
        .declarations
        .iter()
        .find(|(name, kind)| *kind == DeclKind::Axiom && !PERMITTED_AXIOMS.contains(&name.as_str()))
    {
        return Err(Refusal::Axiom(name.clone()));
    }
    match declared.kinds_of(&row.claim()).as_slice() {
        [DeclKind::Definition | DeclKind::Opaque | DeclKind::Inductive] => {}
        kinds => {
            return Err(Refusal::Claim(format!(
                "`{}` is declared as {kinds:?}; one definition, opaque constant or inductive type is needed",
                row.claim()
            )));
        }
    }
    // 6. The kernel, admitting only the three axioms. It also decides the
    // claim's universe parameters, which the reader does not.
    let axioms: Vec<String> = PERMITTED_AXIOMS.iter().map(|a| (*a).to_owned()).collect();
    let entries = {
        let owned = ndjson.clone();
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || inspect(&owned, &axioms, true))
            .map_err(|e| Refusal::KernelRefused(e.to_string()))?
            .join()
            .map_err(|_| Refusal::KernelRefused("the checker panicked".into()))?
            .map_err(Refusal::KernelRefused)?
    };
    let claims: Vec<_> = entries.iter().filter(|e| e.name == row.claim()).collect();
    match claims.as_slice() {
        [claim]
            if claim.universe_parameters == 0
                && matches!(
                    claim.kind,
                    Kind::Definition | Kind::Opaque | Kind::Inductive
                ) => {}
        _ => {
            return Err(Refusal::Claim(
                "the checker does not find one universe-monomorphic claim".into(),
            ));
        }
    }
    let v2 = export_v2_from_ndjson(&ndjson, true).map_err(Refusal::Parse)?;
    Ok(Screened {
        ndjson,
        v2,
        declarations: entries.len(),
    })
}

/// A statement generated from a commit, screened.
#[derive(Debug)]
pub struct Generated {
    pub commit: String,
    pub package: String,
    pub row: Row,
    pub screened: Screened,
    /// SHA-256 of the exporter binary that made it.
    pub exporter_sha256: [u8; 32],
}

/// Where and with what to generate.
pub struct Request {
    pub repo: PathBuf,
    pub commit: String,
    pub package: String,
    pub row: Row,
    pub lean4export: PathBuf,
    /// An empty or absent directory; the package is unpacked under it.
    pub work: PathBuf,
    /// The `lake` to run (default `lake`, through elan).
    pub lake: String,
}

/// A package unpacked from a commit.
pub struct Unpacked {
    /// The commit, resolved to its full hash.
    pub commit: String,
    /// The package directory under the work directory.
    pub directory: PathBuf,
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

/// The last few lines of a tool's output, for a refusal.
fn tail(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(6)..].join(" | ")
}

/// Unpack `package` as it is at `commit` into `work/tree`, with `git
/// archive`, and check its toolchain file. `work` must be absent or empty.
pub fn unpack(
    repo: &Path,
    commit: &str,
    package: &str,
    work: &Path,
) -> Res<Result<Unpacked, Refusal>> {
    let inside = Path::new(package);
    if package.is_empty()
        || !inside
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
    {
        return Ok(Err(Refusal::Package(package.to_owned())));
    }
    let resolved = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--verify", "--quiet", "--end-of-options"])
        .arg(format!("{commit}^{{commit}}"))
        .output()?;
    if !resolved.status.success() {
        return Ok(Err(Refusal::Commit(format!(
            "`{commit}` is not a commit here"
        ))));
    }
    let commit = text(&resolved.stdout);
    let archive = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["archive", "--format=tar", &commit, "--"])
        .arg(package)
        .output()?;
    if !archive.status.success() {
        return Ok(Err(Refusal::Commit(format!(
            "`{package}` is not in {commit}: {}",
            tail(&archive.stderr)
        ))));
    }
    if work.exists() && fs::read_dir(work)?.next().is_some() {
        return Err(format!("{} is not empty", work.display()).into());
    }
    let tree = work.join("tree");
    fs::create_dir_all(&tree)?;
    tar::Archive::new(archive.stdout.as_slice()).unpack(&tree)?;
    let directory = tree.join(inside);
    let toolchain = fs::read(directory.join("lean-toolchain"))
        .map(|bytes| text(&bytes))
        .unwrap_or_else(|_| "(no lean-toolchain)".into());
    if toolchain != TOOLCHAIN {
        return Ok(Err(Refusal::Toolchain(format!(
            "{package}/lean-toolchain says `{toolchain}`"
        ))));
    }
    Ok(Ok(Unpacked { commit, directory }))
}

/// Check that `lake env lean` in `directory` is the pinned Lean, then build
/// `modules`.
pub fn build(directory: &Path, lake: &str, modules: &[String]) -> Res<Result<(), Refusal>> {
    let version = Command::new(lake)
        .args(["env", "lean", "--version"])
        .current_dir(directory)
        .stdin(Stdio::null())
        .output()?;
    let said = text(&version.stdout);
    if !version.status.success()
        || !said.contains(&format!("version {LEAN_VERSION},"))
        || !said.contains(LEAN_GITHASH)
    {
        return Ok(Err(Refusal::Toolchain(format!(
            "`lake env lean --version` says `{said}` {}",
            tail(&version.stderr)
        ))));
    }
    let built = Command::new(lake)
        .arg("build")
        .args(modules)
        .current_dir(directory)
        .stdin(Stdio::null())
        .output()?;
    if !built.status.success() {
        return Ok(Err(Refusal::Build(format!(
            "{} {}",
            tail(&built.stdout),
            tail(&built.stderr)
        ))));
    }
    Ok(Ok(()))
}

/// `lake env LEAN4EXPORT MODULES... -- ROOTS...` in `directory`, with no
/// shell: each root is its own argument.
pub fn export(
    directory: &Path,
    lake: &str,
    lean4export: &Path,
    modules: &[String],
    roots: &[String],
) -> Res<Exported> {
    let out = Command::new(lake)
        .arg("env")
        .arg(lean4export)
        .args(modules)
        .arg("--")
        .args(roots)
        .current_dir(directory)
        .stdin(Stdio::null())
        .output()?;
    Ok(Exported {
        success: out.status.success(),
        stdout: out.stdout,
        stderr: out.stderr,
    })
}

/// Generate and screen. `Ok(Err(_))` is a refusal about the inputs.
pub fn generate(request: &Request) -> Res<Result<Generated, Refusal>> {
    let row = &request.row;
    let exporter_sha256: [u8; 32] = Sha256::digest(fs::read(&request.lean4export)?).into();
    let unpacked = match unpack(
        &request.repo,
        &request.commit,
        &request.package,
        &request.work,
    )? {
        Ok(unpacked) => unpacked,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if !unpacked.directory.join(row.statement_path()).is_file() {
        return Ok(Err(Refusal::ModuleMissing(
            Path::new(&request.package)
                .join(row.statement_path())
                .display()
                .to_string(),
        )));
    }
    if let Err(refusal) = build(&unpacked.directory, &request.lake, &[row.module()])? {
        return Ok(Err(refusal));
    }
    let exported = export(
        &unpacked.directory,
        &request.lake,
        &request.lean4export,
        &[row.module()],
        &row.statement_roots(),
    )?;
    Ok(screen(row, exported).map(|screened| Generated {
        commit: unpacked.commit,
        package: request.package.clone(),
        row: row.clone(),
        screened,
        exporter_sha256,
    }))
}

/// `nucleus-buyer statement REPO COMMIT PACKAGE ROW LEAN4EXPORT WORK_DIR OUT_DIR [LAKE]`
pub fn statement(args: &[String]) -> Res<()> {
    let (repo, commit, package, row, lean4export, work, out, lake) = match args {
        [repo, commit, package, row, lean4export, work, out] => {
            (repo, commit, package, row, lean4export, work, out, "lake")
        }
        [repo, commit, package, row, lean4export, work, out, lake] => (
            repo,
            commit,
            package,
            row,
            lean4export,
            work,
            out,
            lake.as_str(),
        ),
        _ => {
            return Err("usage: nucleus-buyer statement REPO COMMIT PACKAGE ROW LEAN4EXPORT WORK_DIR OUT_DIR [LAKE]".into());
        }
    };
    let request = Request {
        repo: repo.into(),
        commit: commit.clone(),
        package: package.clone(),
        row: Row::parse(row)?,
        lean4export: lean4export.into(),
        work: work.into(),
        lake: lake.to_owned(),
    };
    let generated = generate(&request)??;
    write_out(&generated, Path::new(out))
}

/// Write `statement.ndjson`, `statement.v2` and `statement.json`.
pub fn write_out(generated: &Generated, out: &Path) -> Res<()> {
    let row = &generated.row;
    let screened = &generated.screened;
    fs::create_dir_all(out)?;
    fs::write(out.join("statement.ndjson"), screened.ndjson())?;
    fs::write(out.join("statement.v2"), screened.v2())?;
    let record = json!({
        "row": row.id(),
        "commit": generated.commit,
        "package": generated.package,
        "module": row.module(),
        "modulePath": row.statement_path(),
        "claim": row.claim(),
        "proofModule": row.proof_module(),
        "proofPath": row.proof_path(),
        "sourceCommitment": row.source_commitment(),
        "permittedAxioms": PERMITTED_AXIOMS,
        "statement": "statement.v2",
        "statementSha256": hex(&screened.statement_sha256()),
        "statementBytes": screened.v2().len(),
        "ndjsonSha256": hex(&<[u8; 32]>::from(Sha256::digest(screened.ndjson()))),
        "ndjsonBytes": screened.ndjson().len(),
        "declarations": screened.declarations(),
        "toolchain": TOOLCHAIN,
        "exporter": {
            "name": EXPORTER_NAME,
            "version": EXPORTER_VERSION,
            "binarySha256": hex(&generated.exporter_sha256),
        },
    });
    fs::write(
        out.join("statement.json"),
        serde_json::to_vec_pretty(&record)?,
    )?;
    println!(
        "statement {} at {}: {} v2 bytes, sha256 {}",
        row.id(),
        generated.commit,
        screened.v2().len(),
        hex(&screened.statement_sha256())
    );
    Ok(())
}

/// Fixtures: real exports, made 2026-11-14 on the operator Mac by Lean 4.30.0
/// and `lean4export` 3.1.0 from the modules in `tests/fixtures/statement/`
/// (`lake build`, then `lake env lean4export Statements.S000n -- propext
/// Classical.choice Quot.sound Statements.S000n.claim`). The missing-root pair
/// is the same command with the claim misspelt `claimm`: it printed the PANIC
/// kept in the `.stderr` file and exited 0. `tests/statement.rs` regenerates
/// `s0001.ndjson` from a commit and requires the same bytes.
#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &[u8] = include_bytes!("../tests/fixtures/statement/s0001.ndjson");
    const MISSING_ROOT: &[u8] =
        include_bytes!("../tests/fixtures/statement/s0001-missing-root.ndjson");
    const PANIC: &[u8] = include_bytes!("../tests/fixtures/statement/s0001-missing-root.stderr");
    const AXIOM: &[u8] = include_bytes!("../tests/fixtures/statement/s0003-axiom.ndjson");
    const THEOREM_CLAIM: &[u8] =
        include_bytes!("../tests/fixtures/statement/s0004-theorem-claim.ndjson");

    fn row(id: &str) -> Row {
        Row::parse(id).unwrap()
    }
    fn ok(stdout: &[u8]) -> Exported {
        Exported {
            success: true,
            stdout: stdout.to_vec(),
            stderr: vec![],
        }
    }

    #[test]
    fn a_row_names_everything_from_its_id() {
        let r = row("S0001");
        assert_eq!(r.module(), "Statements.S0001");
        assert_eq!(r.claim(), "Statements.S0001.claim");
        assert_eq!(r.proof(), "Statements.S0001.proof");
        assert_eq!(r.source_commitment(), "Statements.S0001.sourceSha256");
        assert_eq!(r.statement_path(), Path::new("Statements/S0001.lean"));
        assert_eq!(r.proof_module(), "Statements.S0001.Proof");
        assert_eq!(r.proof_path(), Path::new("Statements/S0001/Proof.lean"));
        assert_eq!(r.source_path(), Path::new("Statements/S0001/Source.lean"));
        assert_eq!(
            r.statement_roots(),
            [
                "propext",
                "Classical.choice",
                "Quot.sound",
                "Statements.S0001.claim",
                "Nat"
            ]
        );
        assert_eq!(Row::from_claim("Statements.S0001.claim"), Some(r));
        assert_eq!(Row::from_claim("Nucleus.Claim"), None);
        assert_eq!(Row::from_claim("Statements.S00x1.claim"), None);
        for bad in [
            "",
            "S",
            "s0001",
            "S00a1",
            "S0001.x",
            "S/0001",
            "S1234567890123",
        ] {
            assert_eq!(Row::parse(bad), Err(Refusal::Row(bad.into())), "{bad}");
        }
    }

    #[test]
    fn the_reader_finds_declarations_by_name() {
        let declared = Declared::read(GOOD).unwrap();
        assert_eq!(
            declared.kinds_of("Statements.S0001.claim"),
            [DeclKind::Definition]
        );
        assert_eq!(declared.kinds_of("propext"), [DeclKind::Axiom]);
        assert_eq!(declared.kinds_of("And"), [DeclKind::Inductive]);
        assert_eq!(declared.kinds_of("And.intro"), [DeclKind::Constructor]);
        assert!(declared.kinds_of("Statements.S0001.claimm").is_empty());
    }

    #[test]
    fn a_good_export_is_screened_and_pinned_by_its_v2_bytes() {
        let screened = screen(&row("S0001"), ok(GOOD)).unwrap();
        assert!(
            screened
                .v2()
                .starts_with(&nucleus_proof_acceptance::EXPORT_V2_MAGIC)
        );
        assert_eq!(
            screened.statement_sha256(),
            <[u8; 32]>::from(Sha256::digest(screened.v2()))
        );
        assert!(screened.declarations() > 0);
        // The posted policy accepts its own statement as a statement: the
        // claim is declared where the acceptance rule looks for it.
        assert_eq!(screened.ndjson(), GOOD);
    }

    #[test]
    fn an_exporter_that_panicked_and_exited_zero_is_refused() {
        // Measured: `lean4export … -- … Statements.S0001.claimm` printed a
        // PANIC, wrote an export without that root, and exited 0.
        let refused = screen(
            &row("S0001"),
            Exported {
                success: true,
                stdout: MISSING_ROOT.to_vec(),
                stderr: PANIC.to_vec(),
            },
        )
        .unwrap_err();
        assert!(
            matches!(refused, Refusal::ExporterStderr(ref l) if l.contains("PANIC")),
            "{refused:?}"
        );
        // The same export with standard error lost (a quieter exporter, or a
        // log redirected) is still refused: the root is not declared.
        assert_eq!(
            screen(&row("S0001"), ok(MISSING_ROOT)).unwrap_err(),
            Refusal::RootMissing("Statements.S0001.claim".into())
        );
    }

    #[test]
    fn a_non_zero_exit_is_refused_even_with_a_good_export() {
        let refused = screen(
            &row("S0001"),
            Exported {
                success: false,
                stdout: GOOD.to_vec(),
                stderr: vec![],
            },
        )
        .unwrap_err();
        assert!(matches!(refused, Refusal::ExporterFailed(_)), "{refused:?}");
    }

    #[test]
    fn an_export_declaring_another_axiom_is_refused() {
        assert_eq!(
            screen(&row("S0003"), ok(AXIOM)).unwrap_err(),
            Refusal::Axiom("Statements.S0003.cheat".into())
        );
    }

    #[test]
    fn a_claim_declared_as_a_theorem_is_refused() {
        let refused = screen(&row("S0004"), ok(THEOREM_CLAIM)).unwrap_err();
        assert!(matches!(refused, Refusal::Claim(_)), "{refused:?}");
    }

    #[test]
    fn the_row_must_match_the_export() {
        // A good export screened as another row: its claim is not there.
        assert_eq!(
            screen(&row("S0002"), ok(GOOD)).unwrap_err(),
            Refusal::RootMissing("Statements.S0002.claim".into())
        );
    }

    #[test]
    fn another_exporter_or_lean_is_refused() {
        let text = std::str::from_utf8(GOOD).unwrap();
        for (from, to) in [
            (
                "\"version\":\"3.1.0\"},\"format\"",
                "\"version\":\"3.0.0\"},\"format\"",
            ),
            ("\"version\":\"4.30.0\"", "\"version\":\"4.31.0\""),
            ("d024af099ca4", "0000af099ca4"),
        ] {
            assert!(text.contains(from), "{from}");
            let changed = text.replacen(from, to, 1);
            let refused = screen(&row("S0001"), ok(changed.as_bytes())).unwrap_err();
            assert!(matches!(refused, Refusal::Meta(_)), "{from}: {refused:?}");
        }
    }
}
