//! A ladder seller's source bundle (QED ladder, build item 2).
//!
//!   nucleus-seller ladder-build REPO COMMIT PACKAGE TASK.json KEYFILE LEAN4EXPORT PROOF_DIR WORK_DIR BUILD_DIR [LAKE]
//!   nucleus-seller ladder-publish DEPLOYMENT KEYFILE TASK.json BUILD_DIR ORDER.json OUT_DIR
//!
//! The semantics, written before this code, are in
//! `docs/rfcs/qed-nucleus-merge-ladder-2026-11-14.md`, "Item 2's semantics":
//!
//! ```text
//! Drafted ─commit→ Committed ─build→ Built ─settled→ Settled ─sign→ Signed ─publish→
//! ```
//!
//! Each arrow's target is a type whose only constructor is the check that
//! arrow names, so publishing or signing before the chain says the artifact
//! was settled cannot be written (ADR 0007 C-1, D-1): `sign` takes `Settled`
//! by value, and only `settled` mints one.
//!
//! The artifact commits to the source by declaring
//! `def Statements.S<id>.sourceSha256 : Nat := 0x<SHA-256 of MANIFEST>` (owner
//! decision D2). The manifest lists every file but `Source.lean`, so the
//! commitment is not circular.
//!
//! **The grant text is a placeholder.** Owner decision D4: legal review of
//! the contributor grant, and of whether a signature by the payout key is an
//! acceptable assent, is required before a stranger's paid proof is merged.
//! Until then the manifest's grant status is `placeholder` and its text says
//! it is not a licence grant. Nothing here may describe a bundle as licensed.
use crate::prelude::*;
use crate::statement::{self, DeclKind, Declared, Exported, Row};
use nucleus_proof_acceptance::{accept, export_v2_from_ndjson};
use std::collections::BTreeMap;

pub const MANIFEST_VERSION: &str = "qed-source-manifest v1";
/// The only grant status this code can write until D4's legal review.
pub const GRANT_STATUS: &str = "placeholder";
/// PLACEHOLDER pending D4's legal review. Not a licence grant.
pub const GRANT_PLACEHOLDER: &str = "PLACEHOLDER, not a licence grant: the wording awaits legal review (QED ladder decision D4). The seller intends these files to be contributed under MIT OR Apache-2.0.";

/// Why a bundle step refused. Each is a definite answer about the inputs.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A file path is not a `.lean` file under `Statements/S<id>/`, is
    /// `Source.lean`, or holds whitespace.
    Path(String),
    /// No `Statements/S<id>/Proof.lean`.
    NoProof,
    /// The manifest does not parse, is not canonical, or a file does not hash
    /// to its entry, or `Source.lean` is not the one the manifest gives.
    Manifest(String),
    /// The statement export was refused by the screen.
    Statement(statement::Refusal),
    /// The statement export is not the posted statement.
    StatementMismatch,
    /// The full export was refused by the screen.
    Export(statement::Refusal),
    /// The statement export is not a byte prefix of the full export, or the
    /// v2 forms do not concatenate.
    NotAPrefix,
    /// The acceptance rule refused the artifact.
    Accept(String),
    /// The accepted proof is not `Statements.S<id>.proof`.
    WrongProofName(String),
    /// The artifact does not commit to this manifest.
    Commitment(String),
    /// The vault's phase for the order is not settled.
    NotSettled(u8),
    /// The vault recorded another artifact for the order.
    ArtifactNotRecorded,
    /// The order's seller is not this key, or not the manifest's seller.
    NotTheSeller,
    /// The order is for another policy.
    OtherPolicy,
}
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Refusal {}

/// The source manifest. Canonical: `parse(render(m)) = m` and
/// `render(parse(b)) = b` for every `b` that parses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    row: Row,
    seller: Address,
    /// Package-relative path to SHA-256, sorted by path.
    files: BTreeMap<String, [u8; 32]>,
}

fn check_path(row: &Row, path: &str) -> Result<(), Refusal> {
    let directory = format!("Statements/{}/", row.id());
    let inside = path.strip_prefix(&directory).unwrap_or("");
    let fine = !inside.is_empty()
        && path.ends_with(".lean")
        && path != row.source_path().to_string_lossy()
        && !path.chars().any(char::is_whitespace)
        && Path::new(inside)
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)));
    if fine {
        Ok(())
    } else {
        Err(Refusal::Path(path.to_owned()))
    }
}

impl Manifest {
    pub fn new(row: &Row, seller: Address, files: &[(String, Vec<u8>)]) -> Result<Self, Refusal> {
        let mut listed = BTreeMap::new();
        for (path, bytes) in files {
            check_path(row, path)?;
            if listed
                .insert(path.clone(), Sha256::digest(bytes).into())
                .is_some()
            {
                return Err(Refusal::Path(path.clone()));
            }
        }
        if !listed.contains_key(&*row.proof_path().to_string_lossy()) {
            return Err(Refusal::NoProof);
        }
        Ok(Self {
            row: row.clone(),
            seller,
            files: listed,
        })
    }
    pub fn row(&self) -> &Row {
        &self.row
    }
    pub fn seller(&self) -> Address {
        self.seller
    }
    pub fn render(&self) -> Vec<u8> {
        let mut text = format!(
            "{MANIFEST_VERSION}\nrow {}\nseller {}\ngrant-status {GRANT_STATUS}\ngrant {GRANT_PLACEHOLDER}\n",
            self.row.id(),
            hex(&self.seller)
        );
        for (path, digest) in &self.files {
            text.push_str(&format!(
                "file {} {path}\n",
                hex(digest).trim_start_matches("0x")
            ));
        }
        text.into_bytes()
    }
    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(self.render()).into()
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, Refusal> {
        let bad = |why: &str| Refusal::Manifest(why.to_owned());
        let text = std::str::from_utf8(bytes).map_err(|_| bad("not UTF-8"))?;
        let mut lines = text.lines();
        let mut field = |prefix: &str| -> Result<String, Refusal> {
            lines
                .next()
                .and_then(|line| line.strip_prefix(prefix))
                .map(str::to_owned)
                .ok_or_else(|| bad(prefix))
        };
        if field("")? != MANIFEST_VERSION {
            return Err(bad("version"));
        }
        let row = Row::parse(&field("row ")?).map_err(|_| bad("row"))?;
        let seller: Address = unhex(&field("seller ")?)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| bad("seller"))?;
        if field("grant-status ")? != GRANT_STATUS || field("grant ")? != GRANT_PLACEHOLDER {
            return Err(bad("grant"));
        }
        let mut files = BTreeMap::new();
        for line in lines {
            let (digest, path) = line
                .strip_prefix("file ")
                .and_then(|rest| rest.split_once(' '))
                .ok_or_else(|| bad("file line"))?;
            check_path(&row, path)?;
            let digest: [u8; 32] = unhex(digest)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| bad("file digest"))?;
            files.insert(path.to_owned(), digest);
        }
        let manifest = Self { row, seller, files };
        if !manifest
            .files
            .contains_key(&*manifest.row.proof_path().to_string_lossy())
        {
            return Err(Refusal::NoProof);
        }
        if manifest.render() != bytes {
            return Err(bad("not canonical"));
        }
        Ok(manifest)
    }
    /// `Statements/S<id>/Source.lean` for this manifest.
    pub fn source_lean(&self) -> String {
        format!(
            "-- The SHA-256 of this row's source MANIFEST (QED ladder, decision D2). Generated.\n\
             def {} : Nat :=\n  0x{}\n",
            self.row.source_commitment(),
            hex(&self.sha256()).trim_start_matches("0x")
        )
    }
    /// That every file hashes to its entry.
    pub fn check_files(&self, files: &[(String, Vec<u8>)]) -> Result<(), Refusal> {
        let given: BTreeMap<String, [u8; 32]> = files
            .iter()
            .map(|(p, b)| (p.clone(), Sha256::digest(b).into()))
            .collect();
        if given != self.files {
            return Err(Refusal::Manifest("the files are not the manifest's".into()));
        }
        Ok(())
    }
}

/// `Drafted → Committed`: the manifest and `Source.lean` for the seller's
/// files.
#[derive(Debug)]
pub struct Committed {
    manifest: Manifest,
    files: Vec<(String, Vec<u8>)>,
}
impl Committed {
    pub fn new(row: &Row, seller: Address, files: Vec<(String, Vec<u8>)>) -> Result<Self, Refusal> {
        Ok(Self {
            manifest: Manifest::new(row, seller, &files)?,
            files,
        })
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn files(&self) -> &[(String, Vec<u8>)] {
        &self.files
    }
}

/// `Committed → Built`. Minted only by `check_built`.
pub struct Built {
    committed: Committed,
    statement_ndjson: Vec<u8>,
    full_ndjson: Vec<u8>,
    statement: Vec<u8>,
    artifact: Vec<u8>,
}
impl std::fmt::Debug for Built {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Built")
            .field("manifest", &hex(&self.manifest().sha256()))
            .field("statement_bytes", &self.statement.len())
            .field("artifact_bytes", &self.artifact.len())
            .finish()
    }
}
impl Built {
    pub fn manifest(&self) -> &Manifest {
        &self.committed.manifest
    }
    /// The posted statement, v2.
    pub fn statement(&self) -> &[u8] {
        &self.statement
    }
    /// What the seller delivers: v2 bytes continuing the statement.
    pub fn artifact(&self) -> &[u8] {
        &self.artifact
    }
}

/// The natural-number literals `name` holds in `full`, where it must be
/// declared after the statement's declarations.
fn check_commitment(
    row: &Row,
    manifest: &Manifest,
    statement: &Declared,
    full: &Declared,
) -> Result<(), Refusal> {
    let name = row.source_commitment();
    if !statement.kinds_of(&name).is_empty() {
        return Err(Refusal::Commitment(format!(
            "`{name}` is declared by the statement, not the artifact"
        )));
    }
    if full.kinds_of(&name) != [DeclKind::Definition] {
        return Err(Refusal::Commitment(format!(
            "`{name}` is not one definition in the artifact"
        )));
    }
    let literals = full
        .nat_literals_of(&name)
        .ok_or_else(|| Refusal::Commitment(format!("`{name}` has no readable value")))?;
    let want = U256::from_be_bytes(manifest.sha256()).to_string();
    match literals.as_slice() {
        [one] if *one == want => Ok(()),
        _ => Err(Refusal::Commitment(format!(
            "`{name}` holds {literals:?}; this manifest's SHA-256 is {want}"
        ))),
    }
}

/// The checks from two screened-or-not exports to `Built`.
pub fn check_built(
    committed: Committed,
    policy: &Policy,
    statement_export: Exported,
    full_export: Exported,
) -> Result<Built, Refusal> {
    let row = committed.manifest.row.clone();
    let statement_screened =
        statement::screen(&row, statement_export).map_err(Refusal::Statement)?;
    if statement_screened.statement_sha256() != policy.statement_sha256 {
        return Err(Refusal::StatementMismatch);
    }
    let full_screened = statement::screen(&row, full_export).map_err(Refusal::Export)?;
    let (s, f) = (statement_screened.ndjson(), full_screened.ndjson());
    let suffix = f.strip_prefix(s).ok_or(Refusal::NotAPrefix)?;
    let artifact = export_v2_from_ndjson(suffix, false).map_err(Refusal::Accept)?;
    if [statement_screened.v2(), &artifact].concat() != full_screened.v2() {
        return Err(Refusal::NotAPrefix);
    }
    let accepted = accept(policy, statement_screened.v2(), &artifact)
        .map_err(|e| Refusal::Accept(format!("{e:?}")))?;
    if accepted.proof != row.proof() {
        return Err(Refusal::WrongProofName(accepted.proof));
    }
    check_commitment(
        &row,
        &committed.manifest,
        &Declared::read(s).map_err(Refusal::Statement)?,
        &Declared::read(f).map_err(Refusal::Export)?,
    )?;
    Ok(Built {
        committed,
        statement_ndjson: s.to_vec(),
        full_ndjson: f.to_vec(),
        statement: statement_screened.v2().to_vec(),
        artifact,
    })
}

/// What the vault says about an order. The real one is the chain.
pub trait VaultReads {
    fn phase(&self, digest: [u8; 32]) -> Res<u8>;
    fn artifact_of(&self, digest: [u8; 32]) -> Res<[u8; 32]>;
}

/// `Built → Settled`. Minted only by `settled`.
#[derive(Debug)]
pub struct Settled {
    order: vault::Order,
    digest: [u8; 32],
}
impl Settled {
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// The vault phase that means settled.
pub const SETTLED: u8 = 2;

/// Read the vault: the order is settled with this artifact, for this policy,
/// to this seller. `Ok(Err(_))` is a definite refusal; `Err` could not look.
pub fn settled(
    reads: &dyn VaultReads,
    deployment: &vault::Deployment,
    order: vault::Order,
    built: &Built,
    policy: &Policy,
    seller: Address,
) -> Res<Result<Settled, Refusal>> {
    if order.policy_hash != policy.hash() {
        return Ok(Err(Refusal::OtherPolicy));
    }
    if order.seller != seller || built.manifest().seller() != seller {
        return Ok(Err(Refusal::NotTheSeller));
    }
    let digest = vault::digest(deployment, &order);
    let phase = reads.phase(digest)?;
    if phase != SETTLED {
        return Ok(Err(Refusal::NotSettled(phase)));
    }
    if reads.artifact_of(digest)? != keccak(built.artifact()) {
        return Ok(Err(Refusal::ArtifactNotRecorded));
    }
    Ok(Ok(Settled { order, digest }))
}

/// EIP-191 (`personal_sign`) digest of the manifest's SHA-256.
pub fn signing_digest(manifest_sha256: [u8; 32]) -> [u8; 32] {
    keccak(
        &[
            b"\x19Ethereum Signed Message:\n32".as_slice(),
            &manifest_sha256,
        ]
        .concat(),
    )
}

/// The address a `SIGNATURE` over a manifest recovers to.
pub fn recover(manifest_sha256: [u8; 32], signature: &[u8; 65]) -> Option<Address> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    let id = RecoveryId::from_byte(signature[64].checked_sub(27)?)?;
    let sig = Signature::from_slice(&signature[..64]).ok()?;
    let key =
        VerifyingKey::recover_from_prehash(&signing_digest(manifest_sha256), &sig, id).ok()?;
    let point = key.to_sec1_point(false);
    let mut out = [0; 20];
    out.copy_from_slice(&keccak(&point.as_bytes()[1..])[12..]);
    Some(out)
}

/// `Settled → Signed`.
#[derive(Debug)]
pub struct Signed {
    built: Built,
    signature: [u8; 65],
}
impl Signed {
    pub fn signature(&self) -> &[u8; 65] {
        &self.signature
    }
}

/// Sign the manifest with the payout key. Takes the `Settled` witness by
/// value: there is no other way to a signature.
pub fn sign(built: Built, settled: Settled, key: &SigningKey) -> Result<Signed, Refusal> {
    let signer = address_of(key);
    if settled.order.seller != signer || built.manifest().seller() != signer {
        return Err(Refusal::NotTheSeller);
    }
    let signature = crate::sign(key, signing_digest(built.manifest().sha256())).0;
    Ok(Signed { built, signature })
}

/// `Signed → Published`: the manifest, the files, `Source.lean` and the
/// signature under `out`, and nothing else.
pub fn publish(signed: &Signed, out: &Path) -> Res<()> {
    let manifest = signed.built.manifest();
    manifest.check_files(&signed.built.committed.files)?;
    fs::create_dir_all(out)?;
    fs::write(out.join("MANIFEST"), manifest.render())?;
    for (path, bytes) in &signed.built.committed.files {
        let target = out.join(path);
        fs::create_dir_all(target.parent().ok_or("file path")?)?;
        fs::write(target, bytes)?;
    }
    let source = out.join(manifest.row().source_path());
    fs::create_dir_all(source.parent().ok_or("source path")?)?;
    fs::write(source, manifest.source_lean())?;
    fs::write(
        out.join("SIGNATURE"),
        format!("{}\n", hex(&signed.signature)),
    )?;
    Ok(())
}

/// The seller's files under `dir`, by package-relative path.
pub fn read_files(dir: &Path) -> Res<Vec<(String, Vec<u8>)>> {
    let mut out = vec![];
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in fs::read_dir(&next)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let relative = path
                    .strip_prefix(dir)?
                    .to_str()
                    .ok_or("a file path is not UTF-8")?
                    .to_owned();
                out.push((relative, fs::read(&path)?));
            }
        }
    }
    out.sort();
    Ok(out)
}

const STATEMENT_NDJSON: &str = "statement.ndjson";
const FULL_NDJSON: &str = "full.ndjson";
const STATEMENT_V2: &str = "statement.v2";
const ARTIFACT_V2: &str = "artifact.v2";

impl Built {
    /// Keep a build for publishing after settlement: the manifest, the
    /// files, `Source.lean`, both exports, the statement and the artifact.
    pub fn save(&self, dir: &Path) -> Res<()> {
        let manifest = self.manifest();
        fs::create_dir_all(dir)?;
        fs::write(dir.join("MANIFEST"), manifest.render())?;
        for (path, bytes) in self.committed.files.iter().chain([&(
            manifest.row().source_path().to_string_lossy().into_owned(),
            manifest.source_lean().into_bytes(),
        )]) {
            let target = dir.join(path);
            fs::create_dir_all(target.parent().ok_or("file path")?)?;
            fs::write(target, bytes)?;
        }
        fs::write(dir.join(STATEMENT_NDJSON), &self.statement_ndjson)?;
        fs::write(dir.join(FULL_NDJSON), &self.full_ndjson)?;
        fs::write(dir.join(STATEMENT_V2), &self.statement)?;
        fs::write(dir.join(ARTIFACT_V2), &self.artifact)?;
        Ok(())
    }

    /// Read a saved build back and check it again from the start: a `Built`
    /// read from disk is minted by the same checks as one just built.
    pub fn load(dir: &Path, policy: &Policy) -> Res<Result<Self, Refusal>> {
        let manifest = match Manifest::parse(&fs::read(dir.join("MANIFEST"))?) {
            Ok(manifest) => manifest,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let row = manifest.row().clone();
        let mut files = vec![];
        for path in manifest.files.keys() {
            files.push((path.clone(), fs::read(dir.join(path))?));
        }
        let committed = match Committed::new(&row, manifest.seller(), files) {
            Ok(committed) if committed.manifest == manifest => committed,
            Ok(_) => {
                return Ok(Err(Refusal::Manifest(
                    "the files are not the manifest's".into(),
                )));
            }
            Err(refusal) => return Ok(Err(refusal)),
        };
        if fs::read(dir.join(row.source_path()))? != manifest.source_lean().as_bytes() {
            return Ok(Err(Refusal::Manifest(
                "Source.lean is not the manifest's".into(),
            )));
        }
        let ok = |bytes| Exported {
            success: true,
            stdout: bytes,
            stderr: vec![],
        };
        let built = match check_built(
            committed,
            policy,
            ok(fs::read(dir.join(STATEMENT_NDJSON))?),
            ok(fs::read(dir.join(FULL_NDJSON))?),
        ) {
            Ok(built) => built,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if fs::read(dir.join(ARTIFACT_V2))? != built.artifact {
            return Ok(Err(Refusal::Manifest(
                "artifact.v2 is not the artifact the exports give".into(),
            )));
        }
        Ok(Ok(built))
    }
}

/// Where and with what to build: the statement's commit and Lean.
pub struct Toolchain<'a> {
    pub repo: &'a Path,
    pub commit: &'a str,
    pub package: &'a str,
    pub lean4export: &'a Path,
    pub work: &'a Path,
    pub lake: &'a str,
}

/// `Committed → Built` with Lean: place the files and `Source.lean` in the
/// package at the commit, build, export the statement and the whole, check.
pub fn build(
    committed: Committed,
    policy: &Policy,
    lean: &Toolchain<'_>,
) -> Res<Result<Built, Refusal>> {
    let row = committed.manifest.row().clone();
    let unpacked = match statement::unpack(lean.repo, lean.commit, lean.package, lean.work)? {
        Ok(unpacked) => unpacked,
        Err(refusal) => return Ok(Err(Refusal::Statement(refusal))),
    };
    let directory = &unpacked.directory;
    if !directory.join(row.statement_path()).is_file() {
        return Ok(Err(Refusal::Statement(statement::Refusal::ModuleMissing(
            row.statement_path().display().to_string(),
        ))));
    }
    let source = (
        row.source_path().to_string_lossy().into_owned(),
        committed.manifest.source_lean().into_bytes(),
    );
    for (path, bytes) in committed.files.iter().chain([&source]) {
        let target = directory.join(path);
        if target.exists() {
            // The commit already has this file: the row is answered there.
            return Ok(Err(Refusal::Path(path.clone())));
        }
        fs::create_dir_all(target.parent().ok_or("file path")?)?;
        fs::write(target, bytes)?;
    }
    let mut modules = vec![row.module(), row.proof_module(), row.source_module()];
    for (path, _) in &committed.files {
        let module = path.trim_end_matches(".lean").replace('/', ".");
        if !modules.contains(&module) {
            modules.push(module);
        }
    }
    if let Err(refusal) = statement::build(directory, lean.lake, &modules)? {
        return Ok(Err(Refusal::Statement(refusal)));
    }
    let statement_export = statement::export(
        directory,
        lean.lake,
        lean.lean4export,
        &[row.module()],
        &row.statement_roots(),
    )?;
    let mut roots = row.statement_roots();
    roots.extend([row.proof(), row.source_commitment()]);
    let full_export = statement::export(
        directory,
        lean.lake,
        lean.lean4export,
        &[row.module(), row.proof_module(), row.source_module()],
        &roots,
    )?;
    Ok(check_built(
        committed,
        policy,
        statement_export,
        full_export,
    ))
}

impl VaultReads for crate::world::World {
    fn phase(&self, digest: [u8; 32]) -> Res<u8> {
        crate::post::phase_of(self, digest)
    }
    fn artifact_of(&self, digest: [u8; 32]) -> Res<[u8; 32]> {
        let word = self.chain.call(
            [0; 20],
            self.deployment.vault,
            &crate::world::artifactOfCall { d: digest.into() }.abi_encode(),
        )?;
        word.try_into()
            .map_err(|_| "artifactOf returned another length".into())
    }
}

fn existing_keys(path: &str) -> Res<Keys> {
    if !Path::new(path).is_file() {
        return Err(format!("{path}: no key file (this command never makes one)").into());
    }
    Keys::load_or_create(path)
}

/// The ladder row a task file is for.
fn ladder_task(task: &str) -> Res<(crate::tasks::Spec, Row)> {
    let spec = crate::tasks::Spec::read(task)?;
    let row = match &spec.row {
        Some(row) => row.clone(),
        None => Row::from_claim(&spec.policy.claim)
            .ok_or("the task's claim is not a ladder row's (Statements.S<id>.claim)")?,
    };
    Ok((spec, row))
}

/// `nucleus-seller ladder-build REPO COMMIT PACKAGE TASK.json KEYFILE LEAN4EXPORT PROOF_DIR WORK_DIR BUILD_DIR [LAKE]`
///
/// `PROOF_DIR` holds the seller's files at their package paths
/// (`Statements/S<id>/Proof.lean`, and any other `.lean` file beside it).
/// `BUILD_DIR/artifact.v2` is what the seller delivers; with the task's
/// statement it is what `nucleus-fixture-prover` serves to the seller agent.
pub fn ladder_build(args: &[String]) -> Res<()> {
    let (fixed, lake) = match args {
        [fixed @ .., lake] if fixed.len() == 9 => (fixed, lake.as_str()),
        fixed if fixed.len() == 9 => (fixed, "lake"),
        _ => {
            return Err("usage: nucleus-seller ladder-build REPO COMMIT PACKAGE TASK.json KEYFILE LEAN4EXPORT PROOF_DIR WORK_DIR BUILD_DIR [LAKE]".into());
        }
    };
    let [
        repo,
        commit,
        package,
        task,
        keyfile,
        lean4export,
        proof_dir,
        work,
        out,
    ] = fixed
    else {
        return Err("usage".into());
    };
    let (spec, row) = ladder_task(task)?;
    let seller = address_of(&existing_keys(keyfile)?.wallet);
    let committed = Committed::new(&row, seller, read_files(Path::new(proof_dir))?)?;
    let built = build(
        committed,
        &spec.policy,
        &Toolchain {
            repo: Path::new(repo),
            commit,
            package,
            lean4export: Path::new(lean4export),
            work: Path::new(work),
            lake,
        },
    )??;
    built.save(Path::new(out))?;
    println!(
        "ladder: {} built for seller {}: manifest sha256 {}; artifact {} v2 bytes, keccak256 {}, in {}",
        row.id(),
        hex(&seller),
        hex(&built.manifest().sha256()),
        built.artifact().len(),
        hex(&keccak(built.artifact())),
        Path::new(out).join(ARTIFACT_V2).display()
    );
    Ok(())
}

/// `nucleus-seller ladder-publish DEPLOYMENT KEYFILE TASK.json BUILD_DIR ORDER.json OUT_DIR`
///
/// Reads the vault; signs and writes the bundle only if the order is settled
/// with this build's artifact, for this task's policy, to this key.
pub fn ladder_publish(args: &[String]) -> Res<()> {
    let [deployment, keyfile, task, build_dir, order, out] = args else {
        return Err("usage: nucleus-seller ladder-publish DEPLOYMENT KEYFILE TASK.json BUILD_DIR ORDER.json OUT_DIR".into());
    };
    let (spec, row) = ladder_task(task)?;
    let keys = existing_keys(keyfile)?;
    let built = Built::load(Path::new(build_dir), &spec.policy)??;
    let order: vault::wire::WireOrder = serde_json::from_slice(&fs::read(order)?)?;
    let order = order.to_order().map_err(|e| format!("{e:?}"))?;
    let world = crate::world::World::read(deployment)?;
    let settled = settled(
        &world,
        &world.deployment,
        order,
        &built,
        &spec.policy,
        address_of(&keys.wallet),
    )??;
    let digest = settled.digest();
    let manifest_sha256 = built.manifest().sha256();
    let signed = sign(built, settled, &keys.wallet)?;
    publish(&signed, Path::new(out))?;
    println!(
        "ladder: {} settled as order {}; bundle published to {} (manifest sha256 {}, signature {}). The grant in it is a PLACEHOLDER pending legal review (D4).",
        row.id(),
        hex(&digest),
        out,
        hex(&manifest_sha256),
        hex(signed.signature())
    );
    Ok(())
}

/// Fixtures: `tests/fixtures/statement/`. `s0001-full.ndjson` is the export,
/// by Lean 4.30.0 and `lean4export` 3.1.0, of the fixture package with
/// `Statements/S0001/Proof.lean` and the `Source.lean` these tests expect,
/// for the manifest whose seller is the address of secret key 1
/// (`0x7e5f…5bdf`). Roots: the statement's, then the proof, then the
/// commitment.
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const STATEMENT: &[u8] = include_bytes!("../tests/fixtures/statement/s0001.ndjson");
    const FULL: &[u8] = include_bytes!("../tests/fixtures/statement/s0001-full.ndjson");
    const PROOF: &[u8] = include_bytes!("../tests/fixtures/statement/Statements/S0001/Proof.lean");
    const MANIFEST_SHA256: &str =
        "0x87b12f8a0e4976ad677705369b31c918f69c00d1bce4d91c74e55343c11b941c";

    fn key() -> SigningKey {
        let mut secret = [0u8; 32];
        secret[31] = 1;
        SigningKey::from_slice(&secret).unwrap()
    }
    fn row() -> Row {
        Row::parse("S0001").unwrap()
    }
    fn files() -> Vec<(String, Vec<u8>)> {
        vec![("Statements/S0001/Proof.lean".into(), PROOF.to_vec())]
    }
    fn committed_by(seller: Address) -> Committed {
        Committed::new(&row(), seller, files()).unwrap()
    }
    fn ok(bytes: &[u8]) -> Exported {
        Exported {
            success: true,
            stdout: bytes.to_vec(),
            stderr: vec![],
        }
    }
    fn policy() -> Policy {
        Policy {
            statement_sha256: Sha256::digest(export_v2_from_ndjson(STATEMENT, true).unwrap())
                .into(),
            claim: row().claim(),
            permitted_axioms: statement::PERMITTED_AXIOMS
                .iter()
                .map(|a| (*a).to_owned())
                .collect(),
            maximum_artifact_bytes: 90_000,
        }
    }
    fn built() -> Built {
        check_built(
            committed_by(address_of(&key())),
            &policy(),
            ok(STATEMENT),
            ok(FULL),
        )
        .unwrap()
    }

    #[test]
    fn the_manifest_is_canonical_and_source_lean_commits_to_it() {
        let committed = committed_by(address_of(&key()));
        let manifest = committed.manifest();
        assert_eq!(hex(&manifest.sha256()), MANIFEST_SHA256);
        assert_eq!(Manifest::parse(&manifest.render()).unwrap(), *manifest);
        let text = String::from_utf8(manifest.render()).unwrap();
        assert!(text.contains("grant-status placeholder\n"), "{text}");
        assert!(text.contains("PLACEHOLDER, not a licence grant"), "{text}");
        assert!(manifest.source_lean().contains(&format!(
            "def Statements.S0001.sourceSha256 : Nat :=\n  0x{}\n",
            MANIFEST_SHA256.trim_start_matches("0x")
        )));
        // Not canonical: a trailing line, another grant, a reordered file list.
        let mut trailing = manifest.render();
        trailing.extend_from_slice(b"\n");
        assert!(matches!(
            Manifest::parse(&trailing),
            Err(Refusal::Manifest(_))
        ));
        let granted = text.replace("grant-status placeholder", "grant-status granted");
        assert!(matches!(
            Manifest::parse(granted.as_bytes()),
            Err(Refusal::Manifest(_))
        ));
    }

    #[test]
    fn files_outside_the_rows_directory_or_without_a_proof_are_refused() {
        let with = |path: &str| {
            let mut f = files();
            f.push((path.into(), b"x".to_vec()));
            Committed::new(&row(), [1; 20], f).unwrap_err()
        };
        for path in [
            "Statements/S0002/Proof2.lean",
            "Statements/S0001/Source.lean",
            "Statements/S0001/notes.md",
            "Statements/S0001/a b.lean",
            "Statements/S0001/../S0002/X.lean",
            "Other/X.lean",
        ] {
            assert_eq!(with(path), Refusal::Path(path.into()), "{path}");
        }
        assert_eq!(
            Committed::new(
                &row(),
                [1; 20],
                vec![("Statements/S0001/Lemma.lean".into(), b"x".to_vec())]
            )
            .unwrap_err(),
            Refusal::NoProof
        );
    }

    #[test]
    fn a_built_artifact_proves_the_claim_and_commits_to_the_manifest() {
        let built = built();
        let accepted = accept(&policy(), built.statement(), built.artifact()).unwrap();
        assert_eq!(accepted.proof, "Statements.S0001.proof");
        assert_eq!(
            hex(&<[u8; 32]>::from(Sha256::digest(built.statement()))),
            hex(&policy().statement_sha256)
        );
    }

    #[test]
    fn an_artifact_committing_to_another_manifest_is_refused() {
        // The same export, built for a manifest naming another seller: the
        // literal in the artifact is not this manifest's SHA-256.
        let refused =
            check_built(committed_by([0x22; 20]), &policy(), ok(STATEMENT), ok(FULL)).unwrap_err();
        assert!(matches!(refused, Refusal::Commitment(_)), "{refused:?}");
        // And for the right seller with a changed proof file.
        let mut changed = files();
        changed[0].1.push(b'\n');
        let refused = check_built(
            Committed::new(&row(), address_of(&key()), changed).unwrap(),
            &policy(),
            ok(STATEMENT),
            ok(FULL),
        )
        .unwrap_err();
        assert!(matches!(refused, Refusal::Commitment(_)), "{refused:?}");
    }

    #[test]
    fn another_statement_or_a_statement_export_that_is_not_a_prefix_is_refused() {
        let mut other = policy();
        other.statement_sha256 = [7; 32];
        assert_eq!(
            check_built(
                committed_by(address_of(&key())),
                &other,
                ok(STATEMENT),
                ok(FULL)
            )
            .unwrap_err(),
            Refusal::StatementMismatch
        );
    }

    struct Vault {
        phase: u8,
        artifact: Cell<[u8; 32]>,
    }
    impl VaultReads for Vault {
        fn phase(&self, _: [u8; 32]) -> Res<u8> {
            Ok(self.phase)
        }
        fn artifact_of(&self, _: [u8; 32]) -> Res<[u8; 32]> {
            Ok(self.artifact.get())
        }
    }
    fn deployment() -> vault::Deployment {
        vault::Deployment {
            chain_id: 8453,
            vault: [0x95; 20],
            treasury: [0x77; 20],
            fee_bps: 25,
            maximum_fee_bps: 100,
            rules: vault::Rules::Third {
                maximum_term: 2_592_000,
                registry: [0x48; 20],
            },
        }
    }
    fn order(seller: Address) -> vault::Order {
        vault::Order {
            buyer: [0xbb; 20],
            seller,
            asset: [0xcc; 20],
            amount: U256::from(1_000_000u64).to_be_bytes(),
            verifier: [0xdd; 20],
            program: [0xee; 32],
            policy_hash: policy().hash(),
            base: [0; 32],
            fund_by: 1,
            deliver_by: 2,
            salt: [3; 32],
            context: [4; 32],
        }
    }

    #[test]
    fn only_a_settled_order_for_this_artifact_policy_and_seller_mints_settled() {
        let built = built();
        let me = address_of(&key());
        let paid = Vault {
            phase: SETTLED,
            artifact: Cell::new(keccak(built.artifact())),
        };
        let check = |vault: &Vault, order: vault::Order| {
            settled(vault, &deployment(), order, &built, &policy(), me).unwrap()
        };
        assert!(check(&paid, order(me)).is_ok());
        let funded = Vault {
            phase: 1,
            artifact: Cell::new([0; 32]),
        };
        assert_eq!(
            check(&funded, order(me)).unwrap_err(),
            Refusal::NotSettled(1)
        );
        let other_artifact = Vault {
            phase: SETTLED,
            artifact: Cell::new([9; 32]),
        };
        assert_eq!(
            check(&other_artifact, order(me)).unwrap_err(),
            Refusal::ArtifactNotRecorded
        );
        assert_eq!(
            check(&paid, order([0x22; 20])).unwrap_err(),
            Refusal::NotTheSeller
        );
        let mut other_policy = order(me);
        other_policy.policy_hash = [5; 32];
        assert_eq!(
            check(&paid, other_policy).unwrap_err(),
            Refusal::OtherPolicy
        );
    }

    #[test]
    fn the_signature_is_by_the_paid_seller_and_recovers_to_it() {
        let me = address_of(&key());
        let paid = |built: &Built| Vault {
            phase: SETTLED,
            artifact: Cell::new(keccak(built.artifact())),
        };
        let b = built();
        let s = settled(&paid(&b), &deployment(), order(me), &b, &policy(), me)
            .unwrap()
            .unwrap();
        let sha = b.manifest().sha256();
        let signed = sign(b, s, &key()).unwrap();
        assert_eq!(recover(sha, signed.signature()), Some(me));
        // Another key cannot sign for this settlement.
        let b = built();
        let s = settled(&paid(&b), &deployment(), order(me), &b, &policy(), me)
            .unwrap()
            .unwrap();
        let mut other = [0u8; 32];
        other[31] = 2;
        assert_eq!(
            sign(b, s, &SigningKey::from_slice(&other).unwrap()).unwrap_err(),
            Refusal::NotTheSeller
        );
    }

    #[test]
    fn publishing_writes_the_manifest_files_source_and_signature_only() {
        let me = address_of(&key());
        let b = built();
        let vault = Vault {
            phase: SETTLED,
            artifact: Cell::new(keccak(b.artifact())),
        };
        let s = settled(&vault, &deployment(), order(me), &b, &policy(), me)
            .unwrap()
            .unwrap();
        let signed = sign(b, s, &key()).unwrap();
        let out = std::env::temp_dir().join(format!("qed-bundle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&out);
        publish(&signed, &out).unwrap();
        let mut written = vec![];
        let mut stack = vec![out.clone()];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    written.push(path.strip_prefix(&out).unwrap().display().to_string());
                }
            }
        }
        written.sort();
        assert_eq!(
            written,
            [
                "MANIFEST",
                "SIGNATURE",
                "Statements/S0001/Proof.lean",
                "Statements/S0001/Source.lean"
            ]
        );
        let manifest = Manifest::parse(&fs::read(out.join("MANIFEST")).unwrap()).unwrap();
        assert_eq!(
            fs::read_to_string(out.join("Statements/S0001/Source.lean")).unwrap(),
            manifest.source_lean()
        );
        let signature: [u8; 65] = unhex(fs::read_to_string(out.join("SIGNATURE")).unwrap().trim())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(recover(manifest.sha256(), &signature), Some(me));
        fs::remove_dir_all(&out).unwrap();
    }
}
