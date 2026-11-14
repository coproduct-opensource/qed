//! The pinned compiler and one contract's compilation, from `build.json`.

use crate::evm::Immutable;
use crate::util::{Res, hex, keccak, sha256, unhex};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub struct Context {
    /// The repository root: `path` sources are relative to it.
    pub root: PathBuf,
    pub spec: Value,
    pub cache: PathBuf,
    /// A solc binary given on the command line; it must still hash to a pin.
    pub solc_override: Option<PathBuf>,
}

impl Context {
    pub fn load(root: &Path, solc_override: Option<PathBuf>) -> Res<Context> {
        let spec_path = root.join("contracts/verify/build.json");
        let spec: Value = serde_json::from_str(
            &std::fs::read_to_string(&spec_path)
                .map_err(|e| format!("{}: {e}", spec_path.display()))?,
        )?;
        let cache = match std::env::var_os("QED_VERIFY_CACHE") {
            Some(p) => PathBuf::from(p),
            None => {
                let home =
                    std::env::var_os("HOME").ok_or("HOME is not set; set QED_VERIFY_CACHE")?;
                PathBuf::from(home).join(".cache/qed-verify")
            }
        };
        Ok(Context {
            root: root.to_path_buf(),
            spec,
            cache,
            solc_override,
        })
    }

    pub fn contract(&self, name: &str) -> Res<&Value> {
        let c = &self.spec["contracts"][name];
        if c.is_null() {
            let known: Vec<&String> = self.spec["contracts"]
                .as_object()
                .map(|o| o.keys().collect())
                .unwrap_or_default();
            return Err(format!("no contract {name} in build.json (known: {known:?})").into());
        }
        Ok(c)
    }

    pub fn build_of(&self, name: &str) -> Res<(&Value, String)> {
        let c = self.contract(name)?;
        let build_name = c["build"].as_str().ok_or("contract has no build")?;
        let build = &self.spec["builds"][build_name];
        if build.is_null() {
            return Err(format!("no build {build_name}").into());
        }
        Ok((build, build_name.to_string()))
    }
}

pub fn platform() -> Res<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        // The official macOS builds are universal (x86_64 and arm64).
        ("macos", _) => Ok("macosx-amd64"),
        ("linux", "x86_64") => Ok("linux-amd64"),
        ("linux", "aarch64") => Ok("linux-arm64"),
        (os, arch) => Err(format!("no official solc build is pinned for {os}/{arch}").into()),
    }
}

fn get(url: &str) -> Res<Vec<u8>> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(300)))
        .build()
        .new_agent();
    let mut last = String::new();
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        match agent.get(url).call() {
            Ok(r) => {
                return Ok(r
                    .into_body()
                    .with_config()
                    .limit(200 * 1024 * 1024)
                    .read_to_vec()?);
            }
            Err(ureq::Error::StatusCode(code)) => {
                return Err(format!("GET {url}: HTTP {code}").into());
            }
            Err(e) => last = format!("GET {url}: {e}"),
        }
    }
    Err(last.into())
}

/// The pinned solc for `version` on this platform, downloaded once into the
/// cache and hashed before every use.
pub fn solc(ctx: &Context, version: &str) -> Res<(PathBuf, String)> {
    let platform = platform()?;
    let pin = ctx.spec["compilers"][version][platform]
        .as_str()
        .ok_or_else(|| format!("no solc {version} is pinned for {platform}"))?;
    let path = match &ctx.solc_override {
        Some(p) => p.clone(),
        None => ctx
            .cache
            .join("solc")
            .join(format!("solc-{platform}-v{version}")),
    };
    if ctx.solc_override.is_none() && !path.exists() {
        let url =
            format!("https://binaries.soliditylang.org/{platform}/solc-{platform}-v{version}");
        eprintln!("fetching {url}");
        let bytes = get(&url)?;
        let got = hex(&sha256(&bytes))[2..].to_string();
        if got != pin {
            return Err(format!("{url}: SHA-256 {got}, pinned {pin}; not used").into());
        }
        std::fs::create_dir_all(path.parent().expect("parent"))?;
        let tmp = path.with_extension("part");
        std::fs::write(&tmp, &bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
        }
        std::fs::rename(&tmp, &path)?;
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let got = hex(&sha256(&bytes))[2..].to_string();
    if got != pin {
        return Err(format!(
            "{}: SHA-256 {got} is not the pinned {platform} build of solc {version} ({pin})",
            path.display()
        )
        .into());
    }
    Ok((path, got))
}

/// A source's text: from the repository (at `rev` when given, by `git show`)
/// or fetched and checked against its pin.
fn source_text(ctx: &Context, spec: &Value, rev: Option<&str>) -> Res<String> {
    if let Some(p) = spec["path"].as_str() {
        return match rev {
            None => {
                std::fs::read_to_string(ctx.root.join(p)).map_err(|e| format!("{p}: {e}").into())
            }
            Some(rev) => {
                let out = Command::new("git")
                    .arg("-C")
                    .arg(&ctx.root)
                    .arg("show")
                    .arg(format!("{rev}:{p}"))
                    .output()?;
                if !out.status.success() {
                    return Err(format!(
                        "git show {rev}:{p}: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    )
                    .into());
                }
                Ok(String::from_utf8(out.stdout)?)
            }
        };
    }
    let url = spec["url"]
        .as_str()
        .ok_or("source has neither path nor url")?;
    let pin = spec["sha256"].as_str().ok_or("url source has no sha256")?;
    let cached = ctx.cache.join("src").join(pin);
    let bytes = match std::fs::read(&cached) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("fetching {url}");
            let b = get(url)?;
            std::fs::create_dir_all(cached.parent().expect("parent"))?;
            std::fs::write(&cached, &b)?;
            b
        }
    };
    let got = hex(&sha256(&bytes))[2..].to_string();
    if got != pin {
        return Err(format!("{url}: SHA-256 {got}, pinned {pin}").into());
    }
    Ok(String::from_utf8(bytes)?)
}

/// The standard-JSON input for one contract.
pub fn standard_json(ctx: &Context, name: &str, rev: Option<&str>) -> Res<Value> {
    let c = ctx.contract(name)?;
    let (build, _) = ctx.build_of(name)?;
    let mut sources = serde_json::Map::new();
    for (unit, spec) in c["sources"].as_object().ok_or("no sources")? {
        sources.insert(
            unit.clone(),
            json!({"content": source_text(ctx, spec, rev)?}),
        );
    }
    let mut settings = build["settings"].clone();
    settings["outputSelection"] = json!({
        "*": {
            "*": ["abi", "metadata", "evm.bytecode.object", "evm.bytecode.linkReferences",
                  "evm.deployedBytecode.object", "evm.deployedBytecode.immutableReferences",
                  "evm.deployedBytecode.linkReferences"],
            "": ["ast"]
        }
    });
    Ok(json!({"language": "Solidity", "sources": sources, "settings": settings}))
}

pub struct Compiled {
    pub compiler: String,
    pub solc_sha256: String,
    pub settings: Value,
    pub input: Value,
    pub abi: Value,
    pub metadata: String,
    pub creation: Vec<u8>,
    pub runtime: Vec<u8>,
    pub immutables: Vec<Immutable>,
    /// Source unit → keccak-256 of its text (what the metadata records).
    pub sources: BTreeMap<String, String>,
}

pub fn compile(ctx: &Context, name: &str, rev: Option<&str>) -> Res<Compiled> {
    let (build, _) = ctx.build_of(name)?;
    let version = build["compiler"].as_str().ok_or("build has no compiler")?;
    let (solc_path, solc_sha256) = solc(ctx, version)?;
    let input = standard_json(ctx, name, rev)?;
    let mut child = Command::new(&solc_path)
        .arg("--standard-json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(serde_json::to_string(&input)?.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(format!(
            "solc exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    let output: Value = serde_json::from_slice(&out.stdout)?;
    let errors: Vec<String> = output["errors"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["severity"] == "error")
        .map(|e| e["formattedMessage"].as_str().unwrap_or("?").to_string())
        .collect();
    if !errors.is_empty() {
        return Err(format!("solc: {}", errors.join("\n")).into());
    }
    let c = ctx.contract(name)?;
    let target = c["target"].as_str().ok_or("no target")?;
    let o = &output["contracts"][target][name];
    if o.is_null() {
        return Err(format!("solc produced no {target}:{name}").into());
    }
    for link in [
        &o["evm"]["bytecode"]["linkReferences"],
        &o["evm"]["deployedBytecode"]["linkReferences"],
    ] {
        if link.as_object().is_some_and(|m| !m.is_empty()) {
            return Err(format!("{name} needs linked libraries; not supported").into());
        }
    }
    let mut immutables = Vec::new();
    if let Some(refs) = o["evm"]["deployedBytecode"]["immutableReferences"].as_object() {
        for (id, ranges) in refs {
            let ranges = ranges
                .as_array()
                .ok_or("immutable ranges")?
                .iter()
                .map(|r| {
                    Ok((
                        r["start"].as_u64().ok_or("start")? as usize,
                        r["length"].as_u64().ok_or("length")? as usize,
                    ))
                })
                .collect::<Res<Vec<_>>>()?;
            let id_num: u64 = id.parse()?;
            let name = output["sources"]
                .as_object()
                .into_iter()
                .flat_map(|m| m.values())
                .find_map(|s| ast_name(&s["ast"], id_num))
                .unwrap_or_else(|| format!("#{id}"));
            immutables.push(Immutable { name, ranges });
        }
    }
    let mut sources = BTreeMap::new();
    for (unit, s) in input["sources"].as_object().expect("sources") {
        let text = s["content"].as_str().expect("content");
        sources.insert(unit.clone(), hex(&keccak(text.as_bytes())));
    }
    Ok(Compiled {
        compiler: version.to_string(),
        solc_sha256,
        settings: build["settings"].clone(),
        abi: o["abi"].clone(),
        metadata: o["metadata"].as_str().unwrap_or("").to_string(),
        creation: unhex(
            o["evm"]["bytecode"]["object"]
                .as_str()
                .ok_or("no bytecode")?,
        )?,
        runtime: unhex(
            o["evm"]["deployedBytecode"]["object"]
                .as_str()
                .ok_or("no deployed bytecode")?,
        )?,
        immutables,
        sources,
        input,
    })
}

/// The name of the AST node with `id`, searching the whole tree.
fn ast_name(node: &Value, id: u64) -> Option<String> {
    match node {
        Value::Object(m) => {
            if m.get("id").and_then(Value::as_u64) == Some(id)
                && let Some(n) = m.get("name").and_then(Value::as_str)
            {
                return Some(n.to_string());
            }
            m.values().find_map(|v| ast_name(v, id))
        }
        Value::Array(a) => a.iter().find_map(|v| ast_name(v, id)),
        _ => None,
    }
}
