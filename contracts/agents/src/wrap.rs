//! The optional Groth16 wrap service, and the seller's client for it.
//!
//! The last step of a settlement proof turns RISC Zero's succinct receipt into
//! the 260-byte Groth16 seal an on-chain verifier accepts. Doing it locally
//! needs 4.2 GB of RISC Zero's circuit data. This service does it for a seller
//! that does not hold the data.
//!
//! What the service is trusted with, and what it is not
//! (docs/rfcs/qed-seller-distribution-2026-11-13.md):
//! - It receives the succinct receipt only. The receipt's journal commits to
//!   the chain, the vault, the order digest and the keccak-256 of the artifact,
//!   not to the artifact's bytes.
//! - It cannot redirect payment: `settle` pays the order's named seller,
//!   whoever submits it.
//! - It can refuse or delay. The seller then wraps locally if it holds the
//!   data, or reports that it cannot.
//! - It cannot hand back a bad seal that the seller uses: the seller verifies
//!   the returned Groth16 receipt for its program and compares its journal
//!   with its own receipt's before deriving the seal from it itself
//!   (`RemoteWrap::wrap`).
//!
//! Every request carries a fresh proof of possession (RFC 9449 shape, ES256)
//! naming the method, the URL and the SHA-256 of the receipt bytes; a replayed,
//! stale, re-targeted or re-bodied proof is refused. There are no accounts and
//! no tokens. Abuse is bounded by a receipt size cap, an allow-list of
//! programs and of (chain, vault) pairs, per-key and per-address hourly
//! limits, and a cap on how many requests may wait for the one wrap slot.
use crate::dpop::{DPOP_TYP, proof_check, proof_make};
use crate::message::{Reply, Request};
use crate::prelude::*;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    path::PathBuf,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

/// The order programs a wrap may be for, by the prover host's command prefix.
/// Base registrations are wrapped by whoever proves the base; not here.
pub const PREFIXES: [&str; 3] = ["order2r", "order2", "vault3"];
/// `keccak256("NucleusAcceptanceV1")`, the first word of every order journal.
fn acceptance_tag() -> [u8; 32] {
    keccak(b"NucleusAcceptanceV1")
}

/// The limits a service enforces.
#[derive(Clone, Debug)]
pub struct Policy {
    /// (chain ID, vault) pairs a receipt's journal may name.
    pub allowed: Vec<(u64, Address)>,
    pub maximum_receipt: usize,
    pub per_key_per_hour: usize,
    pub per_address_per_hour: usize,
    /// How many requests may wait for the wrap slot at once, the running one
    /// included.
    pub queue: usize,
}

/// What does the work. The host backend runs the prover host binary; tests
/// substitute their own.
pub trait Backend: Send + Sync {
    /// The journal of `receipt` if it verifies for the program `prefix`
    /// names; an error otherwise.
    fn journal(&self, prefix: &str, receipt: &[u8]) -> Res<Vec<u8>>;
    /// The Groth16 receipt (serialized) and its seal, hex.
    fn wrap(&self, prefix: &str, receipt: &[u8]) -> Res<(Vec<u8>, String)>;
}

/// The prover host binary, with the circuit data in `data`.
pub struct HostBackend {
    pub host: String,
    pub data: Option<String>,
    pub work: PathBuf,
}
impl HostBackend {
    fn job(&self) -> Res<PathBuf> {
        let dir = self.work.join(hex(&random32()?));
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }
    fn host(&self, args: &[&std::ffi::OsStr], work: &Path) -> Res<String> {
        let mut command = Command::new(&self.host);
        command
            .args(args)
            .env("RISC0_WORK_DIR", work)
            .env("NUCLEUS_GROTH16", "native");
        if let Some(data) = &self.data {
            command.env("NUCLEUS_GROTH16_DATA", data);
        }
        let output = command.output()?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr)
                .trim()
                .to_owned()
                .into());
        }
        Ok(String::from_utf8(output.stdout)?)
    }
}
/// The value after `name ` on a line of the host's output.
fn field(output: &str, name: &str) -> Res<String> {
    output
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name} ")))
        .map(str::to_owned)
        .ok_or_else(|| format!("host printed no {name}").into())
}
impl Backend for HostBackend {
    fn journal(&self, prefix: &str, receipt: &[u8]) -> Res<Vec<u8>> {
        let job = self.job()?;
        let path = job.join("receipt");
        fs::write(&path, receipt)?;
        let out = self.host(
            &[format!("{prefix}-verify").as_ref(), path.as_os_str()],
            &job,
        );
        let _ = fs::remove_dir_all(&job);
        unhex(&field(&out?, "journal")?)
    }
    fn wrap(&self, prefix: &str, receipt: &[u8]) -> Res<(Vec<u8>, String)> {
        let job = self.job()?;
        let (input, wrapped, seal) = (job.join("receipt"), job.join("wrapped"), job.join("seal"));
        fs::write(&input, receipt)?;
        let result = self
            .host(
                &[
                    format!("{prefix}-groth16").as_ref(),
                    input.as_os_str(),
                    wrapped.as_os_str(),
                    seal.as_os_str(),
                ],
                &job,
            )
            .and_then(|_| {
                Ok((
                    fs::read(&wrapped)?,
                    fs::read_to_string(&seal)?.trim().to_owned(),
                ))
            });
        let _ = fs::remove_dir_all(&job);
        result
    }
}

/// Requests in the last hour, per key and per address.
#[derive(Default)]
pub(crate) struct Window {
    seen: HashMap<String, VecDeque<u64>>,
}
impl Window {
    /// Count one more for `who` at `now` unless that would exceed `limit`.
    pub(crate) fn admit(&mut self, who: &str, now: u64, limit: usize) -> bool {
        self.admit_within(who, now, limit, 3600)
    }
    /// The same over the last `span` seconds.
    pub(crate) fn admit_within(&mut self, who: &str, now: u64, limit: usize, span: u64) -> bool {
        let times = self.seen.entry(who.to_owned()).or_default();
        while times
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= span)
        {
            times.pop_front();
        }
        if times.len() >= limit {
            return false;
        }
        times.push_back(now);
        true
    }
}

pub struct Service {
    pub policy: Policy,
    /// The scheme and authority this service is reached at, as a proof's
    /// `htu` names it: `https://wrap.example` (behind TLS) or
    /// `http://127.0.0.1:4460` (tests).
    pub base: String,
    backend: Arc<dyn Backend>,
    replay: Mutex<HashSet<String>>,
    keys: Mutex<Window>,
    addresses: Mutex<Window>,
    waiting: AtomicUsize,
    slot: Mutex<()>,
}

/// Leaves the queue count when dropped, however the request ends.
struct InQueue<'a>(&'a AtomicUsize);
impl Drop for InQueue<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Service {
    pub fn new(policy: Policy, base: &str, backend: Arc<dyn Backend>) -> Self {
        Self {
            policy,
            base: base.trim_end_matches('/').to_owned(),
            backend,
            replay: Mutex::new(HashSet::new()),
            keys: Mutex::new(Window::default()),
            addresses: Mutex::new(Window::default()),
            waiting: AtomicUsize::new(0),
            slot: Mutex::new(()),
        }
    }

    /// One request: `POST /wrap/<prefix>` with the succinct receipt as the
    /// body and a `DPoP` header. Replies 200 with
    /// `{"journal": hex, "seal": hex, "receipt": base64}`.
    pub fn handle(&self, peer: IpAddr, request: &Request, now: u64) -> Reply {
        let Some(prefix) = request.path.strip_prefix("/wrap/") else {
            return Reply::text(404, "not found");
        };
        if request.method != "POST" {
            return Reply::text(404, "not found");
        }
        if !PREFIXES.contains(&prefix) {
            return Reply::text(422, "unknown program");
        }
        if request.body.is_empty() || request.body.len() > self.policy.maximum_receipt {
            return Reply::text(413, "receipt size refused");
        }
        let Some(proof) = request.headers.get("dpop") else {
            return Reply::text(401, "DPoP proof missing");
        };
        let uri = format!("{}{}", self.base, request.path);
        let proved = {
            let Ok(mut replay) = self.replay.lock() else {
                return Reply::text(500, "state poisoned");
            };
            proof_check(
                proof,
                DPOP_TYP,
                "POST",
                &uri,
                Some(&request.body),
                now,
                &mut replay,
            )
        };
        let proved = match proved {
            Ok(proved) => proved,
            Err(error) => return Reply::text(401, &error.to_string()),
        };
        let admitted = |window: &Mutex<Window>, who: &str, limit| {
            window
                .lock()
                .map(|mut w| w.admit(who, now, limit))
                .unwrap_or(false)
        };
        if !admitted(&self.keys, &proved.thumbprint, self.policy.per_key_per_hour)
            || !admitted(
                &self.addresses,
                &peer.to_string(),
                self.policy.per_address_per_hour,
            )
        {
            return Reply::text(429, "hourly limit reached");
        }
        if self.waiting.fetch_add(1, Ordering::SeqCst) >= self.policy.queue {
            self.waiting.fetch_sub(1, Ordering::SeqCst);
            return Reply::text(503, "queue full");
        }
        let _in_queue = InQueue(&self.waiting);
        // The receipt must verify for the program the path names, and its
        // journal must be an order journal for an allowed vault.
        let journal = match self.backend.journal(prefix, &request.body) {
            Ok(journal) => journal,
            Err(_) => return Reply::text(422, "receipt does not verify for this program"),
        };
        if let Err(why) = self.allowed(&journal) {
            return Reply::text(403, why);
        }
        let Ok(_slot) = self.slot.lock() else {
            return Reply::text(500, "state poisoned");
        };
        match self.backend.wrap(prefix, &request.body) {
            Ok((wrapped, seal)) => {
                let body =
                    json!({"journal": hex(&journal), "seal": seal, "receipt": B64.encode(wrapped)});
                let mut reply = Reply::new(200).with("content-type", "application/json".into());
                reply.body = body.to_string().into_bytes();
                reply
            }
            // The cause goes to the operator's log, not to the caller: the
            // first end-to-end failure answered 500 with nothing logged.
            Err(why) => {
                eprintln!("qed-wrap: {prefix} wrap failed: {why}");
                Reply::text(500, "wrap failed")
            }
        }
    }

    fn allowed(&self, journal: &[u8]) -> Result<(), &'static str> {
        if journal.len() != 160 || journal[..32] != acceptance_tag() {
            return Err("not an order journal");
        }
        let chain = &journal[32..64];
        if chain[..24].iter().any(|b| *b != 0) {
            return Err("chain id out of range");
        }
        let chain = u64::from_be_bytes(chain[24..].try_into().map_err(|_| "chain id")?);
        let vault: Address = journal[76..96].try_into().map_err(|_| "vault")?;
        if journal[64..76].iter().any(|b| *b != 0) {
            return Err("vault word malformed");
        }
        if self.policy.allowed.contains(&(chain, vault)) {
            Ok(())
        } else {
            Err("vault not served here")
        }
    }
}

/// Serve over plain HTTP/1.1, one thread per connection. Put TLS in front of
/// it; the proof names the public URL. `forwarded` trusts `X-Forwarded-For`
/// from a local proxy for the per-address limit.
pub fn serve(listener: std::net::TcpListener, service: Arc<Service>, forwarded: bool) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let service = service.clone();
        std::thread::spawn(move || {
            let _ = crate::http::answer(stream, |peer, request| {
                let peer = if forwarded {
                    request
                        .headers
                        .get("x-forwarded-for")
                        .and_then(|v| v.split(',').next()?.trim().parse().ok())
                        .unwrap_or(peer)
                } else {
                    peer
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                service.handle(peer, request, now)
            });
        });
    }
}

/// A key for proving possession to a wrap service: generated per seller
/// process, never logged.
#[derive(Clone)]
pub struct WrapKey(p256::ecdsa::SigningKey);
impl WrapKey {
    pub fn fresh() -> Res<Self> {
        Ok(Self(p256::ecdsa::SigningKey::from_slice(&random32()?)?))
    }
    pub fn from_secret(secret: [u8; 32]) -> Res<Self> {
        Ok(Self(p256::ecdsa::SigningKey::from_slice(&secret)?))
    }
}
impl std::fmt::Debug for WrapKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WrapKey(redacted)")
    }
}
impl PartialEq for WrapKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.verifying_key() == other.0.verifying_key()
    }
}
impl Eq for WrapKey {}

/// What the service answered, before the seller has checked any of it.
pub struct Answer {
    pub journal: Vec<u8>,
    pub seal: String,
    pub receipt: Vec<u8>,
}

/// Ask a wrap service for the Groth16 receipt of `receipt`.
pub fn request(url: &str, prefix: &str, receipt: &[u8], key: &WrapKey, now: u64) -> Res<Answer> {
    let target = format!("{}/wrap/{prefix}", url.trim_end_matches('/'));
    let proof = proof_make(&key.0, DPOP_TYP, "POST", &target, now, None, Some(receipt))?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(900)))
        .build()
        .into();
    let mut response = agent
        .post(&target)
        .header("dpop", &proof)
        .header("content-type", "application/octet-stream")
        .send(receipt)?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .with_config()
        .limit(1 << 20)
        .read_to_vec()?;
    if status != 200 {
        return Err(format!(
            "wrap service answered {status}: {}",
            String::from_utf8_lossy(&body)
        )
        .into());
    }
    let value: Value = serde_json::from_slice(&body)?;
    let text = |name: &str| -> Res<String> {
        Ok(value[name]
            .as_str()
            .ok_or_else(|| format!("{name} missing"))?
            .to_owned())
    };
    Ok(Answer {
        journal: unhex(&text("journal")?)?,
        seal: text("seal")?,
        receipt: B64.decode(text("receipt")?)?,
    })
}

/// Check an answer locally before using any of it, and return the seal the
/// seller derived itself. `host` verifies the returned Groth16 receipt for
/// the program (`<prefix>-seal`, built-in verifying key, no circuit data); its
/// journal must equal the journal of the seller's own succinct receipt; the
/// seal is taken from the verified receipt, never from the answer.
pub fn accept_answer(
    host: &str,
    prefix: &str,
    own_journal: &[u8],
    answer: &Answer,
    work: &Path,
) -> Res<Vec<u8>> {
    fs::create_dir_all(work)?;
    let (wrapped, seal) = (
        work.join("remote.groth16.receipt"),
        work.join("remote.seal.hex"),
    );
    fs::write(&wrapped, &answer.receipt)?;
    let output = Command::new(host)
        .arg(format!("{prefix}-seal"))
        .arg(&wrapped)
        .arg(&seal)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "the returned Groth16 receipt does not verify: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    let printed = unhex(&field(&String::from_utf8(output.stdout)?, "journal")?)?;
    if printed != own_journal || answer.journal != own_journal {
        return Err("the returned receipt is for another journal".into());
    }
    let derived = unhex(fs::read_to_string(&seal)?.trim())?;
    if unhex(&answer.seal)? != derived {
        return Err("the returned seal is not the returned receipt's".into());
    }
    Ok(derived)
}
