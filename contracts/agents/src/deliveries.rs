//! The bounty buyer's record of delivery attempts, as files beside its
//! journal, and the client that fetches the signed summary from a desk.
//!
//! - `<journal>.deliveries.jsonl`: the record, one line per attempt, each
//!   appended in one write and synced (`nucleus_jsonl`). Append-only; never
//!   rewritten.
//! - `<journal>.deliveries.jws`: the summary of that record, signed with the
//!   buyer's possession key, rewritten whole after every attempt. The desk
//!   also serves it at `GET /deliveries` over its iroh endpoint (DPoP).
//! - `ours.txt` beside the journal: the authors' own wallet addresses, one a
//!   line. An offer naming one of them is `ours`; any other is `outside`.
//!   The address is used for that and dropped: the record never holds it.
//!
//! Format and rules: `contracts/deliveries` (crate `qed-deliveries`);
//! docs/rfcs/qed-deliveries-2026-11-14.md.
use crate::buyer::ask;
use crate::desk::{Recorder, Seen};
use crate::iroh_net::{IrohTransport, Relay};
use crate::prelude::*;
use qed_deliveries::{Attempt, MAXIMUM_LINES, Party};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

/// The authors' wallets from `path`: one address a line, with or without
/// `0x`; blank lines and `#` comments ignored. An absent file is an empty
/// list (every seller then counts as outside); a malformed line is an error.
pub fn ours(path: &Path) -> Res<HashSet<Address>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(error) => return Err(error.into()),
    };
    let mut out = HashSet::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let digits = line.strip_prefix("0x").unwrap_or(line);
        let address: Address = unhex(digits)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| format!("{} line {}: not an address", path.display(), index + 1))?;
        out.insert(address);
    }
    Ok(out)
}

/// The record and its signed summary on disk.
pub struct Record {
    path: PathBuf,
    summary_path: PathBuf,
    key: p256::ecdsa::SigningKey,
    ours: HashSet<Address>,
    lines: usize,
    /// Attempts seen and not written since this process started.
    unrecorded: u64,
    signed: Result<String, String>,
    clock: fn() -> u64,
}

fn system_clock() -> u64 {
    crate::world::wall_clock().unwrap_or(0)
}

impl Record {
    /// Open the record at `path`, creating it with its header line for
    /// `buyer` if absent, and sign its summary once.
    pub fn open(
        path: &Path,
        summary_path: &Path,
        buyer: Address,
        key: p256::ecdsa::SigningKey,
        ours: HashSet<Address>,
    ) -> Res<Self> {
        Self::open_with(path, summary_path, buyer, key, ours, system_clock)
    }

    pub fn open_with(
        path: &Path,
        summary_path: &Path,
        buyer: Address,
        key: p256::ecdsa::SigningKey,
        ours: HashSet<Address>,
        clock: fn() -> u64,
    ) -> Res<Self> {
        let existing = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        let lines = if existing.is_empty() {
            let header = qed_deliveries::header_line(clock(), &hex(&buyer));
            let kept = nucleus_jsonl::append_line_synced(path, &header)?;
            if !kept.proves(path, &header) {
                return Err("the record did not keep its header".into());
            }
            1
        } else {
            existing.lines().count()
        };
        let mut record = Self {
            path: path.to_owned(),
            summary_path: summary_path.to_owned(),
            key,
            ours,
            lines,
            unrecorded: 0,
            signed: Err("not signed yet".into()),
            clock,
        };
        record.refresh();
        record.signed.clone()?;
        Ok(record)
    }

    /// Summarize the record as it is on disk, sign it, and write the
    /// summary file whole.
    fn refresh(&mut self) {
        let signed = fs::read_to_string(&self.path)
            .map_err(|e| e.to_string())
            .and_then(|text| qed_deliveries::summarize(&text, self.unrecorded, (self.clock)()))
            .map(|summary| qed_deliveries::sign(&summary, &self.key));
        if let Ok(jws) = &signed {
            let mut temporary = self.summary_path.as_os_str().to_owned();
            temporary.push(".new");
            let temporary = PathBuf::from(temporary);
            let written = fs::write(&temporary, format!("{jws}\n"))
                .and_then(|()| fs::rename(&temporary, &self.summary_path));
            if let Err(error) = written {
                println!(
                    "buyer: degraded: the delivery summary {} could not be written: {error}",
                    self.summary_path.display()
                );
            }
        }
        self.signed = signed;
    }
}

impl Recorder for Record {
    fn record(&mut self, seen: &Seen) {
        let party = match seen.named_seller {
            Some(address) if self.ours.contains(&address) => Party::Ours,
            Some(_) => Party::Outside,
            None => Party::Unnamed,
        };
        let line = Attempt {
            at: seen.at,
            route: seen.route,
            task: seen.task,
            outcome: seen.outcome,
            seller_key: seen.seller_key,
            party,
        }
        .line();
        self.append(&line);
    }
    fn attribute(&mut self, attribution: &qed_deliveries::Attribution) {
        self.append(&attribution.line());
    }
    fn signed_summary(&self) -> Result<String, String> {
        self.signed.clone()
    }
}

impl Record {
    /// Append one line, synced, then sign the summary again.
    fn append(&mut self, line: &str) {
        if self.lines >= MAXIMUM_LINES {
            self.unrecorded += 1;
        } else {
            match nucleus_jsonl::append_line_synced(&self.path, line) {
                Ok(kept) if kept.proves(&self.path, line) => self.lines += 1,
                Ok(_) => {
                    self.unrecorded += 1;
                    println!("buyer: degraded: the delivery record did not keep a line");
                }
                Err(error) => {
                    self.unrecorded += 1;
                    println!("buyer: degraded: the delivery record could not be appended: {error}");
                }
            }
        }
        self.refresh();
    }
}

/// Fetch a desk's signed summary over iroh, as any seller could: a fresh
/// node key and a fresh possession key, and a DPoP proof for the request.
/// The caller verifies it against the buyer's key binding.
pub fn fetch(node: &str, relay: &Relay) -> Res<String> {
    let keys = Keys {
        wallet: SigningKey::from_slice(&random32()?)?,
        possession: p256::ecdsa::SigningKey::from_slice(&random32()?)?,
        node: random32()?,
    };
    let transport = IrohTransport::new_in(keys.node, &format!("iroh:{node}"), relay)?;
    let reply = ask(
        &transport,
        &keys,
        "GET",
        "/deliveries",
        BTreeMap::new(),
        vec![],
    )?;
    let body = String::from_utf8(reply.body)?;
    if reply.status != 200 {
        return Err(format!("the desk answered {}: {}", reply.status, body.trim()).into());
    }
    Ok(body.trim().to_owned())
}

/// `nucleus-buyer deliveries-fetch NODE_ID OUT [BINDING]`: fetch the signed
/// summary from the buyer's desk (relay from `NUCLEUS_RELAY`, `default` if
/// unset) and write it to OUT. With BINDING (the buyer's key binding, hex),
/// it is verified before it is written.
pub fn deliveries_fetch(args: &[String]) -> Res<()> {
    let (node, out, binding) = match args {
        [node, out] => (node, out, None),
        [node, out, binding] => (node, out, Some(binding)),
        _ => return Err("usage: nucleus-buyer deliveries-fetch NODE_ID OUT [BINDING]".into()),
    };
    let relay = match std::env::var(crate::iroh_net::RELAY_VARIABLE) {
        Ok(_) => Relay::from_environment()?,
        Err(_) => Relay::Default,
    };
    let jws = fetch(node, &relay)?;
    if let Some(binding) = binding {
        let binding: qed_deliveries::Hash = unhex(binding)?
            .try_into()
            .map_err(|_| "the binding is 32 bytes")?;
        let summary = qed_deliveries::verify(&jws, &binding).map_err(|e| e.to_string())?;
        println!(
            "deliveries: {} attempts ({} unreadable, {} unrecorded); accepted {}, reviewed {}, refused {}; {} sellers, {} not known to be the authors'; signed at {}",
            summary.records,
            summary.unreadable,
            summary.unrecorded,
            summary.accepted,
            summary.reviewed,
            summary.refused_total(),
            summary.sellers.distinct,
            summary.sellers.unknown,
            summary.signed_at
        );
    }
    fs::write(out, format!("{jws}\n"))?;
    println!("wrote {out}");
    Ok(())
}

/// `nucleus-seller test-delivery DEPLOYMENT BOARD FROM_BLOCK TASK_ID KEYFILE`:
/// one labelled test of the delivery record, end to end, that cannot move
/// funds. From a seller key file (created if absent, so a fresh throwaway
/// key), it builds an offer for the posted task priced one unit above the
/// post's cap, and:
///
/// 1. reviews it here with the desk's own rule (`Posted::review`, the code
///    the buyer runs) and stops unless that refuses it as over the cap;
/// 2. sends it on the desk's **review** route, which never signs
///    (`Desk::review_only` takes the desk by reference and has no signing
///    key path), so even a desk that passed it would release nothing.
///
/// Nothing is sent to the chain, and the key needs no funds.
pub fn test_delivery(args: &[String]) -> Res<()> {
    let [deployment, board_address, from_block, task_id, keyfile] = args else {
        return Err(
            "usage: nucleus-seller test-delivery DEPLOYMENT BOARD FROM_BLOCK TASK_ID KEYFILE"
                .into(),
        );
    };
    let world = crate::world::World::read(deployment)?;
    let board = crate::board::Board {
        chain: world.chain.clone(),
        address: crate::world::address_arg(board_address)?,
    };
    let id: nucleus_proof_commerce::Hash = unhex(task_id)?
        .try_into()
        .map_err(|_| "TASK_ID is 32 bytes")?;
    let to = board.latest_block()?;
    let posted = board
        .notices(from_block.parse()?, to)?
        .into_iter()
        .find_map(|notice| match notice {
            nucleus_board_reference::Notice::Posted(posted) if posted.id == id => Some(posted),
            _ => None,
        })
        .ok_or("no such task posted on this board in that range")?;
    if board.withdrawn(id)? {
        return Err("the task is withdrawn".into());
    }
    let keys = Keys::load_or_create(keyfile)?;
    let now = crate::world::wall_clock()?;
    let task = &posted.task;
    let over_cap = U256::from_be_bytes(task.maximum_amount) + U256::from(1u8);
    let order = vault::Order {
        buyer: posted.poster,
        seller: keys.address(),
        asset: task.asset,
        amount: over_cap.to_be_bytes(),
        verifier: task.verifier,
        program: task.program,
        policy_hash: task.policy_hash,
        base: [0; 32],
        fund_by: task.fund_by.min(now + 900),
        deliver_by: task.deliver_by,
        salt: random32()?,
        context: crate::board::context(id, task.buyer_key_binding),
    };
    let header = nucleus_proof_commerce::vault::wire::required_header(
        json!({"url": "qed-deliveries test delivery"}),
        nucleus_proof_commerce::vault::wire::requirements(
            &world.deployment,
            &world.domain,
            &order,
            60,
        ),
    )
    .map_err(|e| format!("{e:?}"))?;
    let relay = Relay::Default;
    let link = crate::watch::IrohBuyer::new_in(&keys, &posted, &relay, false)
        .map_err(|skip| format!("the buyer cannot be reached: {skip}"))?;
    use crate::watch::BuyerLink as _;
    let policy = link.policy(&id)?;
    // 1. The desk's own rule, here, before anything is sent.
    let local = crate::desk::Posted::new(id, task.clone(), policy)?.review(
        &world.deployment,
        &world.domain,
        posted.poster,
        &header,
        now,
        &world.bases,
    );
    match local {
        Err(refused) if refused.reason() == qed_deliveries::Reason::OverLimit => {
            println!("test-delivery: the desk's rule refuses this offer here: {refused}")
        }
        Err(refused) => {
            return Err(format!("not sent: refused here for another reason: {refused}").into());
        }
        Ok(_) => return Err("not sent: the desk's rule would pass this offer".into()),
    }
    // 2. The review route: nothing can be signed there.
    println!(
        "test-delivery: TEST, not a trade. Seller key thumbprint {} (wallet {} holds nothing); task {}; price {} over a cap of {}; route review",
        hex(&keys.binding()),
        hex(&keys.address()),
        hex(&id),
        over_cap,
        U256::from_be_bytes(task.maximum_amount)
    );
    let reply = link.review(&id, header)?;
    println!(
        "test-delivery: the desk answered {}: {}",
        reply.status,
        String::from_utf8_lossy(&reply.body)
    );
    if reply
        .header(nucleus_proof_commerce::x402::wire::SIGNATURE_HEADER)
        .is_some()
    {
        return Err("the desk released an authorization on the review route".into());
    }
    Ok(())
}
