//! A function from input files to a static site (docs/rfcs/qed-site-2026-11-13.md):
//! documents as HTML and Markdown, the signed A2A Agent Card and its JWKS,
//! the ledger's canonical receipts and delivered artifacts, a
//! machine-readable `deployment.json`, the contracts' ABIs, test vectors,
//! `robots.txt` and `sitemap.xml`. A build reads files and writes files; it
//! never touches a network. Only `snapshot` (ledger.rs) and `check-live`
//! (live.rs) do, and only to read.
#![deny(clippy::unwrap_used, clippy::panic)]

pub mod commands;
pub mod doc;
pub mod docs;
pub mod harness;
pub mod html;
pub mod ledger;
pub mod live;
pub mod pages;
pub mod preview;
pub mod schema;
pub mod serving;
pub mod signing;
pub mod status;
pub mod words;

use nucleus_board_reference as board;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{error::Error, fs, path::Path};

pub type Res<T> = Result<T, Box<dyn Error>>;

/// The A2A release the card is written against.
pub const A2A_VERSION: &str = "1.0.1";
pub const CARD_PATH: &str = ".well-known/agent-card.json";
/// The JWKS the card's signature names in its `jku`.
pub const JWKS_PATH: &str = ".well-known/jwks.json";
/// An example of the card a seller's own node serves over iroh.
pub const SELLER_CARD_PATH: &str = "seller-card.example.json";
/// The A2A-over-iroh specification, rendered.
pub const SPEC_PATH: &str = "protocol/a2a-iroh-binding";
/// Where the specification's source is, relative to the repository root.
pub const SPEC_SOURCE: &str = "docs/specs/a2a-iroh-transport-binding.md";
/// A node ID used only in the example seller card. No node holds its key.
pub const EXAMPLE_NODE: &str = "0000000000000000000000000000000000000000000000000000000000000001";
pub use nucleus_a2a_iroh_card::{BINDING, POSSESSION_EXTENSION, SETTLEMENT_EXTENSION, SUPERSEDED};
pub const ALPN: &str = "nucleus-commerce/1";
pub const X402_SCHEME: &str = "nucleus-vault";

/// Said on the page and in the card for as long as it is true.
pub const AUTHORS_ONLY: &str = "Every settlement so far was between the authors' own keys.";
pub const UNAUDITED: &str = "The contracts are unaudited.";
/// The acceptance rule compiled for a browser
/// (contracts/proof-acceptance/wasm-checker, built with
/// `cargo build --release --target wasm32-unknown-unknown`, then `wasm-opt -Oz`).
/// Fetched only when a reader asks for an in-browser check.
pub const CHECKER_PATH: &str = "checker/qed-checker.wasm";
pub const CHECKER_WASM: &[u8] = include_bytes!("../assets/qed-checker.wasm");
/// The only page that runs the checker; the host grants it
/// `'wasm-unsafe-eval'` and nothing else does.
pub const CHECKER_PAGE: &str = "verify";
/// The page every missing path is answered with, status 404
/// (`doc::not_found`; the host's `handle_errors`, the local preview).
pub const NOT_FOUND_PATH: &str = "404.html";
/// The page that explains the Agent Card and the documents it links.
pub const AGENT_PAGE: &str = "agent-card";
/// The seller's instructions for an agent, moved out of the card's skill
/// (owner review, 2026-11-14): Markdown, linked from the card.
pub const SELLER_SKILL_PATH: &str = "agent-card/seller-skill.md";
/// What the protocol offers and where its interfaces are: contracts,
/// programs, commitments. JSON, linked from the card.
pub const MANIFEST_PATH: &str = "agent-card/protocol-manifest.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Input {
    pub name: String,
    pub version: String,
    pub network: Network,
    pub board: Deployed,
    pub vault: Vault,
    pub registry: Registry,
    pub verifier: Deployed,
    pub token: Token,
    pub programs: Vec<Program>,
    pub assurance: Assurance,
    pub software: Software,
    pub our_addresses: Vec<Named>,
    /// Whether the site names the authors' own wallet addresses: the
    /// `ourAddresses` list, the vault's treasury value, the live board's
    /// "(ours)" marks and each receipt's per-settlement counterparty note.
    /// Off unless the input says otherwise. The general statement
    /// `AUTHORS_ONLY` is said either way. Contract addresses are always
    /// shown, because checking them is the point of the site.
    #[serde(default)]
    pub disclose_author_addresses: bool,
    pub settlements: Vec<Settlement>,
    pub earlier: Vec<Earlier>,
    /// A deployment on a main network with a standing bounty, beside the
    /// test deployment above. Absent: the site describes the test deployment
    /// only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mainnet: Option<Mainnet>,
    /// The date from which no buyer runs on the test deployment above. Set,
    /// with a main network present: every page presents the test deployment
    /// as history (its runs stay in the ledger) and the main network as the
    /// only live offer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_buyers_stopped: Option<String>,
}

impl Input {
    /// The test deployment is history: its buyers stopped and a main network
    /// carries the live offer.
    pub fn test_is_history(&self) -> bool {
        self.test_buyers_stopped.is_some() && self.mainnet.is_some()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Network {
    pub name: String,
    pub chain_id: u64,
    pub testnet: bool,
    /// A public endpoint the page reads from by default. The reader can
    /// change it on the page.
    pub rpc: String,
    pub explorer: String,
    /// Most blocks the default endpoint answers in one `eth_getLogs`.
    /// Absent: the page uses its own default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_range: Option<u64>,
}

/// The same contracts on a main network, and the bounty its board carries.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mainnet {
    pub network: Network,
    pub board: Deployed,
    pub vault: Vault,
    /// What the treasury is, said without its address: the address is one
    /// of the authors' and is shown only when author addresses are disclosed.
    pub treasury_kind: String,
    pub registry: Registry,
    pub verifier: Deployed,
    pub token: Token,
    pub bounty: Bounty,
    /// What the status page reads from the chain. Absent: no status page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusInput>,
}

/// The wallets and limits the status page's queries name.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusInput {
    /// The bounty buyer's wallet: it posts the tasks and funds the orders.
    pub buyer: String,
    /// The gas relayer's wallet: it sends relayed fund, settle and claim.
    pub relayer: String,
    pub relayer_url: String,
    /// The balance the relayer keeps, in wei, and where that is configured.
    pub relayer_floor_wei: String,
    pub relayer_floor_source: String,
    /// The vaults the relayer sends to, with the block each was deployed in
    /// (the first is the bounty's).
    pub vaults: Vec<StatusVault>,
    /// The build switch for naming `buyer` and `relayer` on the status page
    /// and its Markdown twin (owner decision, 2026-11-14: "publish buyer and
    /// relayer only"). Off: both are shown as "not listed here" and the
    /// queries that need them carry a placeholder.
    #[serde(default)]
    pub publish_wallets: bool,
    /// The bounty buyer's record of delivery attempts: which key signs its
    /// summary, and the authors' notes on it (docs/rfcs/qed-deliveries-2026-11-14.md).
    #[serde(default)]
    pub deliveries: Option<DeliveriesInput>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeliveriesInput {
    /// The buyer's key binding (`buyerKeyBinding` in each of its posts):
    /// only a summary signed by that key is shown.
    pub key_binding: String,
    /// The buyer's iroh node ID, which the check command dials.
    pub node: String,
    /// The authors' word on particular attempts, shown as such.
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusVault {
    pub address: String,
    pub deploy_block: u64,
}

/// A standing offer on the main-network board. Amounts are in the token's
/// smallest unit.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bounty {
    pub price: u64,
    pub budget: u64,
    pub tasks: u32,
    pub post_window_seconds: u64,
    /// The order program the posts name.
    pub program: String,
    pub first_post_transaction: String,
    pub first_task: String,
}

impl Mainnet {
    /// What a seller receives for one task: the price less the fee, which is
    /// rounded up as the vault rounds it.
    pub fn seller_receives(&self) -> u64 {
        let fee = (self.bounty.price * u64::from(self.vault.fee_bps)).div_ceil(10_000);
        self.bounty.price - fee
    }
}

/// `units` of a token with `decimals` decimals, without trailing zeros.
pub fn amount(units: u64, decimals: u8) -> String {
    let scale = 10u64.pow(u32::from(decimals));
    let (whole, frac) = (units / scale, units % scale);
    if frac == 0 {
        return whole.to_string();
    }
    let frac = format!("{frac:0width$}", width = usize::from(decimals));
    format!("{whole}.{}", frac.trim_end_matches('0'))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Deployed {
    pub address: String,
    /// Keccak-256 of the code `eth_getCode` returns, and its length.
    pub code_keccak: String,
    pub code_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deploy_block: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deploy_transaction: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Vault {
    pub address: String,
    pub code_keccak: String,
    pub code_bytes: u64,
    pub deploy_transaction: String,
    pub treasury: String,
    pub fee_bps: u16,
    pub maximum_fee_bps: u16,
    pub maximum_term_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Registry {
    pub address: String,
    pub code_keccak: String,
    pub code_bytes: u64,
    pub deploy_transaction: String,
    pub maximum_bps: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Token {
    pub address: String,
    pub name: String,
    pub decimals: u8,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Proves that an artifact satisfies an order's policy.
    Order,
    /// Proves that a base library type-checks.
    Base,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Program {
    pub role: Role,
    pub image_id: String,
    /// Path of the published binary, relative to the repository root.
    pub binary: String,
}

/// Who has traded through these contracts. A closed choice, so that moving
/// off `AuthorsOnly` is an edit someone makes on purpose, with evidence.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum Counterparties {
    AuthorsOnly,
    #[serde(rename_all = "camelCase")]
    Outside {
        /// A settlement whose seller or buyer was not the authors.
        first_outside_settlement: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Assurance {
    pub audited: bool,
    /// What review there has been, in one sentence.
    pub review: String,
    pub counterparties: Counterparties,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", tag = "availability")]
pub enum Software {
    /// Not public. No link is printed.
    OnRequest,
    /// Not public yet; where it will be published. Printed as a plain
    /// address, not a link, until it exists.
    Planned {
        url: String,
    },
    Public {
        url: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Named {
    pub role: String,
    pub address: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settlement {
    pub what: String,
    pub transaction: String,
}

/// A settlement on another deployment: an earlier vault, or another chain.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Earlier {
    pub what: String,
    pub network: String,
    pub vault: String,
    pub transaction: String,
    /// Full link to the transaction on that network's explorer.
    pub link: String,
}

/// A published program binary as found on disk.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Published {
    pub role: Role,
    pub image_id: String,
    pub file: String,
    pub bytes: usize,
    pub sha256: String,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Res<Vec<u8>> {
    let text = text.trim().trim_start_matches("0x");
    if !text.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            text.get(i..i + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| "not hex".into())
        })
        .collect()
}

fn address_shape(text: &str) -> Res<()> {
    let ok = text.len() == 42
        && text.starts_with("0x")
        && text
            .bytes()
            .skip(2)
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(format!("not a lower-case 0x address: {text}").into())
    }
}

fn word_shape(text: &str, prefixed: bool) -> Res<()> {
    let digits = if prefixed {
        text.strip_prefix("0x").ok_or("missing 0x")?
    } else {
        text
    };
    let ok = digits.len() == 64
        && digits
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(format!("not 32 bytes of lower-case hex: {text}").into())
    }
}

impl Input {
    pub fn read(path: &Path) -> Res<Self> {
        let input: Self = serde_json::from_slice(&fs::read(path)?)?;
        input.check()?;
        Ok(input)
    }

    /// Shapes only. Whether the values are the chain's is for the reader to
    /// check with the commands the page prints.
    pub fn check(&self) -> Res<()> {
        for address in [
            &self.board.address,
            &self.vault.address,
            &self.vault.treasury,
            &self.registry.address,
            &self.verifier.address,
            &self.token.address,
        ]
        .into_iter()
        .chain(self.our_addresses.iter().map(|n| &n.address))
        {
            address_shape(address)?;
        }
        for word in [
            &self.board.code_keccak,
            &self.vault.code_keccak,
            &self.registry.code_keccak,
            &self.verifier.code_keccak,
            &self.vault.deploy_transaction,
            &self.registry.deploy_transaction,
        ]
        .into_iter()
        .chain(self.settlements.iter().map(|s| &s.transaction))
        .chain(self.earlier.iter().map(|s| &s.transaction))
        {
            word_shape(word, true)?;
        }
        for program in &self.programs {
            word_shape(&program.image_id, false)?;
        }
        for role in [Role::Order, Role::Base] {
            if self.programs.iter().filter(|p| p.role == role).count() != 1 {
                return Err("exactly one order program and one base program".into());
            }
        }
        if self.board.deploy_block.is_none() {
            return Err("the board's deployment block is needed to bound log queries".into());
        }
        if self.assurance.audited {
            return Err(
                "this generator's page says the contracts are unaudited; an audited deployment needs its wording changed, with the audit named".into(),
            );
        }
        if self.vault.fee_bps == 0 || self.vault.fee_bps > self.vault.maximum_fee_bps {
            return Err("fee outside its cap".into());
        }
        Ok(())
    }

    pub fn program(&self, role: Role) -> &Program {
        // `check` established there is exactly one of each.
        self.programs
            .iter()
            .find(|p| p.role == role)
            .unwrap_or(&self.programs[0])
    }

    pub fn authors_only(&self) -> bool {
        matches!(self.assurance.counterparties, Counterparties::AuthorsOnly)
    }
}

/// Hash the published binaries named by the input.
pub fn published(input: &Input, repository: &Path) -> Res<Vec<Published>> {
    input
        .programs
        .iter()
        .map(|program| {
            let bytes = fs::read(repository.join(&program.binary))
                .map_err(|e| format!("{}: {e}", program.binary))?;
            Ok(Published {
                role: program.role,
                image_id: program.image_id.clone(),
                file: Path::new(&program.binary)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or("binary path")?
                    .to_owned(),
                bytes: bytes.len(),
                sha256: hex(&Sha256::digest(&bytes)),
            })
        })
        .collect()
}

/// The path an `https://coproduct.one/…` identifier names on the apex host.
pub fn apex_path(uri: &str) -> Res<&str> {
    uri.strip_prefix("https://coproduct.one/")
        .ok_or_else(|| format!("not under the apex: {uri}").into())
}

/// What the card's extension carries, and `deployment.json`.
pub fn deployment(input: &Input, programs: &[Published]) -> Value {
    let mut value = deployment_with_treasury(input, programs);
    if !input.disclose_author_addresses {
        // The treasury is one of the authors' keys. `treasury()` on the
        // vault still answers it for anyone who asks the chain.
        if let Some(vault) = value["vault"].as_object_mut() {
            vault.remove("treasury");
        }
        if let Some(vault) = value["mainnet"]["vault"].as_object_mut() {
            vault.remove("treasury");
        }
    }
    value
}

fn mainnet_deployment(m: &Mainnet) -> Value {
    json!({
        "network": {
            "name": m.network.name,
            "chainId": m.network.chain_id,
            "caip2": format!("eip155:{}", m.network.chain_id),
            "testnet": m.network.testnet,
            "rpc": m.network.rpc,
            "explorer": m.network.explorer,
        },
        "board": {
            "address": m.board.address,
            "deployBlock": m.board.deploy_block,
            "codeKeccak256": m.board.code_keccak,
        },
        "vault": {
            "address": m.vault.address,
            "codeKeccak256": m.vault.code_keccak,
            "treasury": m.vault.treasury,
            "treasuryKind": m.treasury_kind,
            "feeBps": m.vault.fee_bps,
            "maximumFeeBps": m.vault.maximum_fee_bps,
            "maximumTermSeconds": m.vault.maximum_term_seconds,
            "registry": m.registry.address,
        },
        "registry": {
            "address": m.registry.address,
            "codeKeccak256": m.registry.code_keccak,
            "verifier": m.verifier.address,
            "maximumBps": m.registry.maximum_bps,
        },
        "verifier": {
            "address": m.verifier.address,
            "codeKeccak256": m.verifier.code_keccak,
        },
        "token": m.token,
        "bounty": {
            "price": m.bounty.price,
            "sellerReceives": m.seller_receives(),
            "budget": m.bounty.budget,
            "tasks": m.bounty.tasks,
            "oneOpenAtATime": true,
            "postWindowSeconds": m.bounty.post_window_seconds,
            "program": m.bounty.program,
            "firstPostTransaction": m.bounty.first_post_transaction,
            "firstTask": m.bounty.first_task,
            "page": "/bounty",
        },
    })
}

/// A receipt as published. With author addresses not disclosed, the
/// per-settlement note on who held the keys is dropped: it would mark that
/// receipt's buyer and seller as the authors'. The site-wide statement
/// `AUTHORS_ONLY` still says it of every settlement.
pub fn elide_counterparties(receipt: &Value, disclose: bool) -> Value {
    let mut receipt = receipt.clone();
    if !disclose && let Some(asserted) = receipt["asserted"].as_object_mut() {
        asserted.remove("counterparties");
    }
    receipt
}

fn deployment_with_treasury(input: &Input, programs: &[Published]) -> Value {
    let mut value = json!({
        "network": {
            "name": input.network.name,
            "chainId": input.network.chain_id,
            "caip2": format!("eip155:{}", input.network.chain_id),
            "testnet": input.network.testnet,
        },
        "board": {
            "address": input.board.address,
            "deployBlock": input.board.deploy_block,
            "codeKeccak256": input.board.code_keccak,
        },
        "vault": {
            "address": input.vault.address,
            "codeKeccak256": input.vault.code_keccak,
            "treasury": input.vault.treasury,
            "feeBps": input.vault.fee_bps,
            "maximumFeeBps": input.vault.maximum_fee_bps,
            "maximumTermSeconds": input.vault.maximum_term_seconds,
            "registry": input.registry.address,
        },
        "registry": {
            "address": input.registry.address,
            "codeKeccak256": input.registry.code_keccak,
            "verifier": input.verifier.address,
            "baseProgram": input.program(Role::Base).image_id,
            "maximumBps": input.registry.maximum_bps,
        },
        "verifier": {
            "address": input.verifier.address,
            "codeKeccak256": input.verifier.code_keccak,
        },
        "token": input.token,
        "programs": programs,
        "transport": {
            "iroh": { "alpn": ALPN },
            "x402": { "version": 2, "scheme": X402_SCHEME },
            "proofOfPossession": "A fresh DPoP-shaped proof on every request, bound to the method, the peer's node ID, a time window, a one-time ID and the caller's own node ID.",
        },
        "assurance": {
            "audited": input.assurance.audited,
            "review": input.assurance.review,
            "counterparties": input.assurance.counterparties,
        },
    });
    if let Some(day) = &input.test_buyers_stopped {
        // The deployment above is history; `mainnet` is the live offer.
        value["network"]["buyersStopped"] = json!(day);
    }
    if let Some(m) = &input.mainnet {
        value["mainnet"] = mainnet_deployment(m);
    }
    value
}

/// `path` on the site: absolute when the site's address is known.
pub fn site_url(site: Option<&str>, path: &str) -> String {
    match site {
        Some(site) => format!("{}/{path}", site.trim_end_matches('/')),
        None => format!("/{path}"),
    }
}

/// The Agent Card, per A2A 1.0.1: who this is, what it offers and where the
/// evidence is. `supportedInterfaces` is empty because no A2A interface is
/// served (docs/rfcs/proof-commerce-static-page-a2a-2026-11-13.md); the
/// protocol's own interfaces are in the manifest the card links
/// ([`MANIFEST_PATH`]), and the seller's steps in [`SELLER_SKILL_PATH`].
pub fn card(input: &Input, site: Option<&str>) -> Value {
    let mut facts = vec![UNAUDITED.to_owned()];
    if input.authors_only() {
        facts.push(AUTHORS_ONLY.to_owned());
    }
    let at = |path: &str| site_url(site, path);
    let how = "This is not an A2A operation: this card lists no A2A interface. It is done by running the agent software against the contracts the protocol manifest names.";
    let (network, token) = match &input.mainnet {
        Some(m) => (&m.network.name, &m.token.name),
        None => (&input.network.name, &input.token.name),
    };
    let mut card = json!({
        "name": input.name,
        "description": format!(
            "Payment for Lean 4 proofs on {network}. A contract releases {token} to the seller only after cryptographic evidence shows the agreed Lean checker accepted the proof; with no valid proof by the deadline, the buyer reclaims the deposit. {} No A2A interface is served here: this card is for discovery. Protocol interfaces, contracts and commitments: {}. Evidence: {} and {}. A seller's own iroh node serves its own card, with protocol binding {BINDING}, a draft custom binding.",
            facts.join(" "),
            at(MANIFEST_PATH),
            at("transactions"),
            at("receipts/index.json"),
        ),
        "version": input.version,
        "supportedInterfaces": [],
        "capabilities": {
            "streaming": false,
            "pushNotifications": false,
            "extensions": [{
                "uri": SETTLEMENT_EXTENSION,
                "description": "Where an agent finds this deployment's protocol manifest, deployment record, receipts and seller instructions. Parameters are described at the extension's URI.",
                // `required` is a plain proto bool, so `false` is its default
                // and is left out (A2A 1.0.1 §8.4.1: the signed form omits it).
                "params": {
                    "manifest": at(MANIFEST_PATH),
                    "deployment": at("deployment.json"),
                    "receipts": at("receipts/index.json"),
                    "sellerSkill": at(SELLER_SKILL_PATH),
                },
            }],
        },
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {
                "id": "post-task",
                "name": "Post a task for a Lean proof",
                "description": format!("A buyer posts a Lean 4 statement's hash, a price cap and deadlines on the board contract, and funds the first acceptable offer. {how}"),
                "tags": ["lean4", "proof", "buyer", "x402", "escrow"],
            },
            {
                "id": "sell-proof",
                "name": "Sell a Lean proof",
                "description": format!("A seller answers a post, proves the statement, and settles with the evidence that releases payment.{} Steps an agent can follow: {}. {how}", bounty_sentence(input, site), at(SELLER_SKILL_PATH)),
                "tags": ["lean4", "proof", "seller", "x402"],
            },
            {
                "id": "check-settlement",
                "name": "Check a settlement",
                "description": format!("Read a settlement from the chain, take the delivered artifact from its calldata, and re-run the Lean checker on it. Receipts: {}. {how}", at("receipts/index.json")),
                "tags": ["verification", "lean4", "audit"],
            },
        ],
    });
    if let Some(site) = site {
        card["documentationUrl"] = json!(format!("{}/", site.trim_end_matches('/')));
    }
    card
}

/// The protocol manifest the card links: what the protocol offers, the
/// interfaces that do exist (the contracts' ABIs, iroh, x402), the
/// deployment, the cryptographic commitments, and where the evidence is.
pub fn manifest(
    input: &Input,
    programs: &[Published],
    site: Option<&str>,
    card_kid: Option<&str>,
    with_checker: bool,
) -> Value {
    let at = |path: &str| site_url(site, path);
    let checker = with_checker.then(|| {
        json!({
            "path": at(CHECKER_PATH),
            "sha256": hex(Sha256::digest(CHECKER_WASM).as_slice()),
            "bytes": CHECKER_WASM.len(),
            "what": "The proof program's Lean acceptance rule as WebAssembly; /verify runs it in a browser on request.",
        })
    });
    json!({
        "schema": "qed-protocol-manifest/1",
        "name": input.name,
        "card": at(CARD_PATH),
        "a2a": {
            "supportedInterfaces": [],
            "why": "No A2A operation is served by this site. The card is for discovery; the interfaces below are the protocol's own.",
        },
        "capabilities": [
            { "id": "post-task", "what": "A buyer posts a statement's hash, a price cap and deadlines on the board, and funds the first acceptable offer in the vault." },
            { "id": "sell-proof", "what": "A seller proves the statement and settles; the vault books payment only if the verifier accepts the proof program's evidence.", "steps": at(SELLER_SKILL_PATH) },
            { "id": "check-settlement", "what": "Anyone reads a settlement, takes the artifact from its calldata and re-runs the Lean checker." },
            { "id": "refund", "what": "With no accepted proof by the order's deadline, anyone can call refund and the buyer is owed the whole deposit." },
        ],
        "interfaces": {
            "contracts": {
                "abis": {
                    "NucleusVault3": at("abi/NucleusVault3.json"),
                    "NucleusBoard": at("abi/NucleusBoard.json"),
                    "BaseRegistry": at("abi/BaseRegistry.json"),
                },
                "stateChanging": {
                    "vault": ["fund", "settle", "refund", "claim"],
                    "board": ["post", "withdraw"],
                    "registry": ["register"],
                },
                "anyoneMayCall": true,
            },
            "iroh": {
                "alpn": ALPN,
                "binding": BINDING,
                "status": "draft: a custom binding of A2A to iroh streams, not an official A2A transport",
                "specification": at(SPEC_PATH),
                "exampleSellerCard": at(SELLER_CARD_PATH),
            },
            "x402": { "version": 2, "scheme": X402_SCHEME },
            "relayer": input.mainnet.as_ref().and_then(|m| m.status.as_ref()).map(|s| json!({
                "url": s.relayer_url,
                "what": "Sends fund, settle and claim for sellers and pays the gas; it cannot change payee or amount.",
            })),
        },
        "deployment": deployment(input, programs),
        "commitments": {
            "orderDigest": "EIP-712 hash of the order under the domain name NucleusVault, version 3, the chain ID and the vault's address",
            "journal": "abi.encode(keccak256(\"NucleusAcceptanceV1\"), chainId, vault, orderDigest, keccak256(artifact)), 160 bytes, checked by verify(seal, program, sha256(journal))",
            "artifact": "keccak256 of the delivered artifact, recorded by the vault (artifactOf) and in its Settled log",
            "programs": "each program's image ID, computed from its published binary; the binaries' SHA-256 are under deployment.programs",
            "contractCode": "keccak256 of each contract's runtime code, under deployment",
            "receipts": "RFC 8785 canonical JSON and a newline",
            "checker": checker,
            "card": { "alg": "ES256", "kid": card_kid, "jwks": at(JWKS_PATH) },
        },
        "evidence": {
            "ledger": at("transactions"),
            "receipts": at("receipts/index.json"),
            "verify": at("verify"),
            "status": at("status"),
            "source": match &input.software {
                Software::Public { url } => Some(url.clone()),
                _ => None,
            },
        },
    })
}

/// One sentence on the main-network bounty, for the card; empty without one.
fn bounty_sentence(input: &Input, site: Option<&str>) -> String {
    let Some(m) = &input.mainnet else {
        return String::new();
    };
    let page = match site {
        Some(site) => format!("{}/bounty", site.trim_end_matches('/')),
        None => "/bounty".into(),
    };
    format!(
        " A standing bounty on {} pays {} {} per task ({} after the fee), at most {} tasks, one open at a time: {page}.",
        m.network.name,
        amount(m.bounty.price, m.token.decimals),
        m.token.name,
        amount(m.seller_receives(), m.token.decimals),
        m.bounty.tasks,
    )
}

/// The example card of a seller's own node: what `nucleus-seller` serves
/// over iroh, built by the same function (contracts/a2a-iroh-card).
pub fn seller_card() -> Value {
    nucleus_a2a_iroh_card::card(
        EXAMPLE_NODE,
        "Example seller (not a service)",
        "An example of the Agent Card a seller's own iroh node serves under the A2A-over-iroh binding. The node ID is a placeholder whose key nobody holds; a real seller's card names its own node.",
        "0.1.0",
    )
}

/// The description the settlement extension's URI resolves to.
pub fn extension() -> Value {
    json!({
        "uri": SETTLEMENT_EXTENSION,
        "version": 1,
        "summary": "Where an agent finds what it needs to check and trade through one deployment of the vault and task board. It declares no A2A operation.",
        "params": {
            "manifest": "URL of the protocol manifest: what the protocol offers, its interfaces (the contracts' ABIs, the iroh ALPN and binding, the x402 scheme), the deployment's contracts and programs, and the cryptographic commitments",
            "deployment": "URL of the deployment record: chain, contracts with code hashes and fixed values, programs, token, transport and assurance",
            "receipts": "URL of the receipt index: every recorded settlement, as canonical JSON",
            "sellerSkill": "URL of step-by-step instructions an agent can follow to run a seller",
        },
    })
}

/// Logs the page's decoder must read the way the Rust reference does.
pub fn vectors(input: &Input) -> Res<Value> {
    use alloy_primitives::{Address, B256, U256};
    use alloy_sol_types::SolEvent;
    let vault: [u8; 20] = unhex(&input.vault.address)?
        .try_into()
        .map_err(|_| "vault address length")?;
    let tasks = [
        (1u8, String::new(), U256::from(100_000u64)),
        (2, "203.0.113.7:4460".to_owned(), U256::from(2_000_000u64)),
        // The longest hint the contract takes, and not ASCII.
        (3, "é".repeat(64), U256::MAX),
    ];
    let mut out = Vec::new();
    for (seed, hint, amount) in tasks {
        let word = |n: u8| [seed.wrapping_mul(16).wrapping_add(n); 32];
        let task = board::Task {
            statement_sha256: word(1),
            statement_blake3: word(2),
            policy_hash: word(3),
            asset: [seed.wrapping_add(0x40); 20],
            maximum_amount: amount.to_be_bytes(),
            verifier: [seed.wrapping_add(0x50); 20],
            program: word(4),
            fund_by: 1_794_000_000 + u64::from(seed),
            deliver_by: 1_796_000_000 + u64::from(seed),
            buyer_node: word(5),
            buyer_key_binding: word(6),
            salt: word(7),
            buyer_address: hint,
        };
        let (id, poster) = (word(8), [seed.wrapping_add(0x60); 20]);
        let event = board::Posted {
            id: B256::from(id),
            poster: Address::from(poster),
            vault: Address::from(vault),
            task: task.abi(),
        };
        let data = event.encode_data();
        let mut padded = [0u8; 32];
        padded[12..].copy_from_slice(&poster);
        let topics = [board::posted_topic(), id, padded];
        // The reference must read back what it wrote.
        match board::decode_log(&topics, &data) {
            Ok(board::Notice::Posted(read)) if read.task == task && read.vault == vault => {}
            other => return Err(format!("reference round trip: {other:?}").into()),
        }
        out.push(json!({
            "topics": topics.iter().map(|t| format!("0x{}", hex(t))).collect::<Vec<_>>(),
            "data": format!("0x{}", hex(&data)),
            "expect": {
                "kind": "posted",
                "id": format!("0x{}", hex(&id)),
                "poster": format!("0x{}", hex(&poster)),
                "vault": format!("0x{}", hex(&vault)),
                "statementSha256": format!("0x{}", hex(&task.statement_sha256)),
                "statementBlake3": format!("0x{}", hex(&task.statement_blake3)),
                "policyHash": format!("0x{}", hex(&task.policy_hash)),
                "asset": format!("0x{}", hex(&task.asset)),
                "maximumAmount": U256::from_be_bytes(task.maximum_amount).to_string(),
                "verifier": format!("0x{}", hex(&task.verifier)),
                "program": format!("0x{}", hex(&task.program)),
                "fundBy": task.fund_by.to_string(),
                "deliverBy": task.deliver_by.to_string(),
                "buyerNode": format!("0x{}", hex(&task.buyer_node)),
                "buyerKeyBinding": format!("0x{}", hex(&task.buyer_key_binding)),
                "salt": format!("0x{}", hex(&task.salt)),
                "buyerAddress": task.buyer_address,
            },
        }));
    }
    let withdrawn = [0x99u8; 32];
    out.push(json!({
        "topics": [format!("0x{}", hex(&board::withdrawn_topic())), format!("0x{}", hex(&withdrawn))],
        "data": "0x",
        "expect": { "kind": "withdrawn", "id": format!("0x{}", hex(&withdrawn)) },
    }));
    Ok(Value::Array(out))
}

/// What a build takes besides the deployment input.
#[derive(Default)]
pub struct Options<'a> {
    /// `https://…` of the site's root, for canonical links, the card's
    /// documentation link, the JWKS `jku` and the sitemap.
    pub site_url: Option<&'a str>,
    /// The ledger and its snapshot (`input/ledger.json`,
    /// `input/ledger.snapshot.json`).
    pub ledger: Option<(&'a ledger::LedgerInput, &'a ledger::Snapshot)>,
    /// The card-signing key. Without it the card is served unsigned.
    pub card_key: Option<&'a p256::ecdsa::SigningKey>,
    /// The commit the build was made from, said on every page.
    pub source_commit: Option<&'a str>,
}

/// Test vectors for RFC 8785 as the receipts and the card use it.
pub fn jcs_vectors() -> Res<Value> {
    let cases = [
        json!({"b": 2, "a": {"z": [3, "x"], "y": null}}),
        json!({"amount": "1000000", "id": "0xab", "ok": true, "text": "a\"b\\c\u{1}\n"}),
        json!({"\u{20ac}": 1, "\r": 2, "\u{fb33}": 3, "1": 4, "\u{1f600}": 5, "\u{80}": 6, "\u{f6}": 7}),
    ];
    Ok(Value::Array(
        cases
            .iter()
            .map(|c| Ok(json!({ "input": c, "canonical": signing::jcs(c)? })))
            .collect::<Res<Vec<_>>>()?,
    ))
}

/// Where RFC 9116 puts the security contact file.
pub const SECURITY_TXT_PATH: &str = ".well-known/security.txt";

/// `seconds` since the epoch as an RFC 3339 UTC timestamp (to the second).
fn rfc3339(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let rem = seconds % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// An RFC 9116 `security.txt`, only when the source is public (its private
/// vulnerability reporting is the contact) and a snapshot dates the build:
/// `Expires` is 360 days after the snapshot, under the RFC's one-year advice,
/// so a site not rebuilt for a year stops advertising a stale contact. No
/// email address: reports go through the repository's private reporting.
/// Unsigned; the RFC recommends an OpenPGP signature, which is not done here.
pub fn security_txt(
    input: &Input,
    site_url: Option<&str>,
    snapshot: Option<&Value>,
) -> Option<String> {
    let Software::Public { url } = &input.software else {
        return None;
    };
    let site = site_url?.trim_end_matches('/');
    let taken = snapshot?.get("takenAt")?.as_u64()?;
    let repo = url.trim_end_matches('/');
    Some(format!(
        "Contact: {repo}/security/advisories/new\nExpires: {}\nPolicy: {repo}/blob/main/SECURITY.md\nPreferred-Languages: en\nCanonical: {site}/{SECURITY_TXT_PATH}\n",
        rfc3339(taken + 360 * 86_400)
    ))
}

/// Everything the site consists of, as (relative path, bytes).
pub fn site(input: &Input, repository: &Path, options: &Options) -> Res<Vec<(String, Vec<u8>)>> {
    let site_url = options.site_url.map(|s| s.trim_end_matches('/'));
    // Who has traded is the ledger's to say when its receipts carry their
    // counterparty notes: recording an outside settlement moves every page
    // off "authors only" with no edit here. The input's value is used when
    // the ledger cannot say (no ledger, or notes removed, as in the public
    // copy), and may not claim an outside trade the notes contradict.
    let mut effective = input.clone();
    if let Some(from_ledger) = options.ledger.and_then(|(_, s)| s.counterparties()) {
        if let (Counterparties::Outside { .. }, Counterparties::AuthorsOnly) =
            (&input.assurance.counterparties, &from_ledger)
        {
            return Err(
                "the input names an outside settlement that the ledger's receipts do not show"
                    .into(),
            );
        }
        effective.assurance.counterparties = from_ledger;
    }
    let input = &effective;
    let programs = published(input, repository)?;
    let unsigned = card(input, site_url);
    let seller = seller_card();
    for (name, card) in [("service", &unsigned), ("seller", &seller)] {
        let violations = card_violations(card);
        if !violations.is_empty() {
            return Err(
                format!("the {name} card does not fit the A2A schema: {violations:?}").into(),
            );
        }
    }
    let (card, jwks, signed_by) = match options.card_key {
        Some(key) => {
            let jku = format!("{}/{JWKS_PATH}", site_url.unwrap_or(""));
            let signed = signing::sign(&unsigned, key, &jku)?;
            let jwks = signing::jwks(key.verifying_key());
            let kid = signing::verify(&signed, &jwks)?;
            (signed, Some(jwks), Some(kid))
        }
        None => (unsigned, None, None),
    };
    let spec = fs::read_to_string(repository.join(SPEC_SOURCE))
        .map_err(|e| format!("{SPEC_SOURCE}: {e}"))?;
    let pretty = |value: &Value| -> Res<Vec<u8>> {
        let mut text = serde_json::to_string_pretty(value)?;
        text.push('\n');
        Ok(text.into_bytes())
    };
    let abi = |name: &str, path: &str| -> Res<(String, Vec<u8>)> {
        Ok((
            format!("abi/{name}.json"),
            fs::read(repository.join(path)).map_err(|e| format!("{path}: {e}"))?,
        ))
    };
    let vectors = vectors(input)?;
    let build_kid = signed_by.clone();
    let build = pages::Build {
        site: site_url,
        source_commit: options.source_commit,
        ledger: options.ledger,
        signed_by,
    };
    // Chain readings made before the build (`snapshot-status`, and
    // `qed-verify manifest --json`); a build reads them, never the network.
    let read_json = |path: &str| -> Res<Option<Value>> {
        match fs::read(repository.join(path)) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).map_err(|e| format!("{path}: {e}"))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{path}: {e}").into()),
        }
    };
    let status_snapshot = read_json(status::SNAPSHOT_PATH)?;
    let verified = read_json(pages::VERIFIED_PATH)?;
    let fee_bps = deployed_fee_bps(input, verified.as_ref())?;
    let mut docs_list = vec![
        pages::home(input, &build, fee_bps)?,
        pages::protocol(input, &build),
        pages::agent_card(input, &build),
        pages::participate(input),
        pages::specification(input, &programs),
        pages::threat_model(input),
        pages::transactions(input, &build, &vectors, &programs),
        pages::verify(input, &programs, &build, verified.as_ref()),
        pages::test_vectors(),
        pages::source(input),
        pages::run_a_seller(
            input.mainnet.as_ref(),
            match &input.software {
                Software::Public { url } => Some(url.as_str()),
                _ => None,
            },
        ),
        pages::a2a_binding(&spec),
    ];
    // Taking part points to the seller page's steps, which include building
    // from the public source, so the page exists only when there is both a
    // main-network bounty and public source.
    if let (Some(m), Software::Public { .. }) = (&input.mainnet, &input.software) {
        docs_list.push(pages::bounty(m, &vectors, &programs));
    }
    if let Some(page) = status::page(input, status_snapshot.as_ref()) {
        docs_list.push(page);
    }
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some((ledger_input, snapshot)) = options.ledger {
        let mut index = Vec::new();
        for receipt in snapshot.receipts() {
            let mut receipt = elide_counterparties(receipt, input.disclose_author_addresses);
            if let Some(acceptance) = snapshot.acceptance(&receipt) {
                receipt["acceptance"] = acceptance;
            }
            let receipt = &receipt;
            let id = receipt["id"].as_str().ok_or("receipt id")?;
            if !id.starts_with("0x") || id.len() != 66 {
                return Err(format!("receipt id {id} is not a digest").into());
            }
            docs_list.push(pages::transaction(receipt, ledger_input, &build));
            files.push((
                format!("receipts/{id}.json"),
                ledger::receipt_bytes(receipt)?,
            ));
            index.push(json!({
                "id": id,
                "url": format!("/receipts/{id}.json"),
                "settled": receipt["settlement"]["timestamp"],
                "chainId": receipt["network"]["chainId"],
            }));
        }
        files.push((
            "receipts/index.json".into(),
            ledger::receipt_bytes(&json!({
                "schema": "qed-receipt-index/1",
                "snapshot": { "takenAt": snapshot.value["takenAt"], "networks": snapshot.value["networks"] },
                "note": "A projection of chain state and of the authors' records. Each receipt's fields are read from the chain except those under asserted, and acceptance (the buyer's policy and statement), which is checkable: the policy hashes to order.policyHash and the statement to the policy's statementSha256. The vault is the authority for every settlement.",
                "receipts": index,
            }))?,
        ));
        for (k, bytes) in &snapshot.artifacts {
            files.push((format!("artifacts/{k}.bin"), bytes.clone()));
        }
        for (file, bytes) in &snapshot.statements {
            files.push((format!("statements/{file}"), bytes.clone()));
        }
        files.push((CHECKER_PATH.into(), CHECKER_WASM.to_vec()));
    }
    let footer = pages::footer();
    for d in &docs_list {
        files.push((d.html_file(), doc::page(d, site_url, &footer).into_bytes()));
        files.push((d.markdown_file(), doc::markdown(d, site_url).into_bytes()));
    }
    if let (Some(text), Some(_)) = (
        security_txt(input, site_url, options.ledger.map(|(_, s)| &s.value)),
        site_url,
    ) {
        files.push((SECURITY_TXT_PATH.into(), text.into_bytes()));
    }
    let mut robots = String::from("User-agent: *\nAllow: /\n");
    if let Some(site) = site_url {
        robots.push_str(&format!("Sitemap: {site}/sitemap.xml\n"));
        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n",
        );
        for d in &docs_list {
            xml.push_str(&format!(
                "  <url><loc>{}</loc></url>\n",
                html::esc(&format!("{site}{}", d.url()))
            ));
        }
        xml.push_str("</urlset>\n");
        files.push(("sitemap.xml".into(), xml.into_bytes()));
    }
    files.push(("robots.txt".into(), robots.into_bytes()));
    files.push((NOT_FOUND_PATH.into(), doc::not_found().into_bytes()));
    files.extend([
        (
            "qed.css".into(),
            include_bytes!("../assets/qed.css").to_vec(),
        ),
        ("qed.js".into(), include_bytes!("../assets/qed.js").to_vec()),
        (CARD_PATH.into(), pretty(&card)?),
        ("agent-card.json".into(), pretty(&card)?),
        (
            MANIFEST_PATH.into(),
            pretty(&manifest(
                input,
                &programs,
                site_url,
                build_kid.as_deref(),
                options.ledger.is_some(),
            ))?,
        ),
        (SELLER_CARD_PATH.into(), pretty(&seller)?),
        (
            "deployment.json".into(),
            pretty(&deployment(input, &programs))?,
        ),
        (
            "verification/test-vectors/board-logs.json".into(),
            pretty(&vectors)?,
        ),
        (
            "verification/test-vectors/jcs.json".into(),
            pretty(&jcs_vectors()?)?,
        ),
        abi("NucleusBoard", "contracts/board/out/NucleusBoard.abi")?,
        abi("NucleusVault3", "contracts/vault/out/NucleusVault3.abi")?,
        abi("BaseRegistry", "contracts/vault/out/BaseRegistry.abi")?,
    ]);
    if let Some(m) = &input.mainnet {
        files.push((
            SELLER_SKILL_PATH.into(),
            pages::seller_skill(m, site_url).into_bytes(),
        ));
    }
    if let Some(jwks) = jwks {
        files.push((JWKS_PATH.into(), pretty(&jwks)?));
    }
    Ok(files)
}

/// The live vault's fee, as the deployed contract holds it: `qed-verify`'s
/// reading of the constructor argument `feeBps_` at the vault's address
/// when the build has that report. A build whose input disagrees with the
/// chain's value is refused, so the home page's fee line cannot drift from
/// the contract. Without a report: the input's value, which /verify prints
/// with the call that reads it.
pub fn deployed_fee_bps(input: &Input, verified: Option<&Value>) -> Res<u16> {
    let vault = match &input.mainnet {
        Some(m) => &m.vault,
        None => &input.vault,
    };
    let read = verified
        .and_then(|r| r["deployments"].as_array())
        .into_iter()
        .flatten()
        .find(|d| d["address"].as_str() == Some(vault.address.as_str()))
        .and_then(|d| d["constructorArguments"].as_array())
        .into_iter()
        .flatten()
        .find(|a| a["name"] == "feeBps_")
        .and_then(|a| a["value"].as_str());
    match read {
        None => Ok(vault.fee_bps),
        Some(value) => {
            let bps: u16 = value
                .parse()
                .map_err(|_| format!("feeBps_ {value} is not a number"))?;
            if bps != vault.fee_bps {
                return Err(format!(
                    "the input's fee ({} basis points) is not the deployed vault's ({bps})",
                    vault.fee_bps
                )
                .into());
            }
            Ok(bps)
        }
    }
}

/// Everything the A2A schema and the proto's required fields find wrong with a card.
pub fn card_violations(card: &Value) -> Vec<String> {
    schema::Bundle::vendored()
        .check("AgentCard", card)
        .into_iter()
        .chain(schema::required(card))
        .map(|v| format!("{}: {}", v.path, v.what))
        .collect()
}

/// The documents the three extension identifiers dereference to. They live on
/// the apex host (`https://coproduct.one/…`), not on this site, and are handed
/// over as files: (path on the apex host, bytes). A2A's extension guidance
/// says an extension's specification "should be hosted at the extension's
/// URI"; each path ends in `/v1/index.html`, so a host that serves a
/// directory's index answers the URI itself.
pub fn apex(repository: &Path, site_url: Option<&str>) -> Res<Vec<(String, Vec<u8>)>> {
    let spec = fs::read_to_string(repository.join(SPEC_SOURCE))
        .map_err(|e| format!("{SPEC_SOURCE}: {e}"))?;
    let site = site_url.map(|s| s.trim_end_matches('/'));
    let index = |uri: &str| -> Res<String> { Ok(format!("{}/index.html", apex_path(uri)?)) };
    let mut extension_json = serde_json::to_string_pretty(&extension())?;
    extension_json.push('\n');
    Ok(vec![
        (
            index(BINDING)?,
            docs::spec_page(
                &spec,
                &format!("{BINDING} — A2A over iroh, a custom protocol binding"),
            )?
            .into_bytes(),
        ),
        (
            index(POSSESSION_EXTENSION)?,
            docs::possession_page(site)?.into_bytes(),
        ),
        (
            index(SETTLEMENT_EXTENSION)?,
            docs::settlement_page(&extension(), site)?.into_bytes(),
        ),
        (
            format!("{}/extension.json", apex_path(SETTLEMENT_EXTENSION)?),
            extension_json.into_bytes(),
        ),
    ])
}
