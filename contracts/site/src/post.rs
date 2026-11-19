//! "Post a task": how anyone posts a Lean-proof task on the main-network
//! board with the published release, from a worked example whose statement
//! was built and exported on 2026-11-18 (owner approval of that date;
//! docs/rfcs/qed-post-a-task-2026-11-18.md has the run and its findings).
//!
//! Every command shown is one release `SELLER_RELEASE.tag` (v0.2.4) has.
//! What it lacks (the statement screen, a v2 converter) is said in a table
//! and is never offered as a command.
use crate::Mainnet;
use crate::doc::{Block, Doc, code, code_link, h2, p, t};
use crate::pages::{SELLER_RELEASE, deployment_json, percent, template, verification_command};

/// The worked example's claim, one line of Lean using only `Init`.
const CLAIM: &str = "def Statements.S1.claim : Prop := ∀ a b : Nat, a + b = b + a";
/// Measured 2026-11-18: Lean 4.30.0, lean4export 3.1.0 built at `a3e35a5`.
const NDJSON_BYTES: &str = "41,278";
const NDJSON_SHA256: &str = "8086c29b596eb3be2d23b89521980ae66a5ab89dfb0f34afb785e228f20436b6";
const V2_BYTES: &str = "6,003";
const V2_SHA256: &str = "6b5eead329530f4efab1a898c79203919d06b4440c50787a4a1474a23b2b7731";
/// The relayer's per-call gas cap and the largest artifact a relayed
/// `settle` fits under it (relay.rs `relayed_artifact_bytes`, live since
/// 2026-11-16).
const RELAY_CAP: &str = "1,750,000";
const RELAY_REACH: &str = "34,824";
/// The order program a new post names: the newest published pair (fmt2s), whose
/// acceptance rule refuses an artifact declaring a kernel-reserved name.
pub const ORDER_PROGRAM: &str =
    include_str!("../../proof-acceptance/program/IMAGE_ID_ORDER_FMT2S").trim_ascii();

fn statement_steps() -> String {
    format!(
        "# Lean 4.30.0 (elan installs it from lean-toolchain); lean4export 3.1.0 from its source
git clone https://github.com/leanprover/lean4export
(cd lean4export && git checkout a3e35a5 && lake build)

# The package. This claim is a rehearsal: Nat.add_comm in Lean's core proves it,
# so anyone can answer.
mkdir -p task/Statements && cd task
echo 'leanprover/lean4:v4.30.0' > lean-toolchain
printf 'name = \"task\"\\n\\n[[lean_lib]]\\nname = \"Statements\"\\nglobs = [\"Statements.+\"]\\n' > lakefile.toml
echo '{CLAIM}' > Statements/S1.lean
lake build Statements.S1

# Export the three axioms, the claim, then Nat: a proof may not declare Nat (the
# checker treats it as built in), so the statement must. Nat is already in this
# claim's closure, so the bytes are the same. Exit 0 is not enough: lean4export
# exits 0 after dropping a root it cannot find.
lake env ../lean4export/.lake/build/bin/lean4export Statements.S1 -- \\
  propext Classical.choice Quot.sound Statements.S1.claim Nat > statement.ndjson 2> export.err
test ! -s export.err && head -n 1 statement.ndjson

# Export v2, the form the order program pins (smaller). {tag} ships no
# converter; its source has one, as an example program (needs Rust):
git clone --depth 1 --branch {tag} https://github.com/coproduct-opensource/qed ../qed
S=$PWD
(cd ../qed/contracts/proof-acceptance/core &&
  cargo run --release --locked --example v2_inputs -- export \"$S/statement.ndjson\" \"$S/statement.v2\")
shasum -a 256 statement.v2",
        tag = SELLER_RELEASE.tag
    )
}

fn task_json() -> String {
    format!(
        "{{\"name\": \"add-comm\",
 \"statement\": \"statement.v2\",
 \"claim\": \"Statements.S1.claim\",
 \"permittedAxioms\": [\"propext\", \"Classical.choice\", \"Quot.sound\"],
 \"maximumArtifactBytes\": 34824,
 \"program\": \"0x{program}\",
 \"maximumPrice\": 1000000,
 \"fundingWindowSeconds\": 86400,
 \"deliveryWindowSeconds\": 172800}}",
        program = ORDER_PROGRAM
    )
}

fn row(cells: [&str; 3]) -> Vec<Vec<crate::doc::Inline>> {
    cells.iter().map(|c| vec![t(*c)]).collect()
}

/// The page. `fee_bps` is the deployed vault's (`crate::deployed_fee_bps`).
pub fn page(m: &Mainnet, fee_bps: u16) -> Doc {
    let r = &SELLER_RELEASE;
    let ex = &m.network.explorer;
    let term = m.vault.maximum_term_seconds;
    let fee = percent(fee_bps);
    let blocks = vec![
        h2("need", "You need"),
        Block::Table {
            caption: "Before posting".into(),
            head: vec!["What".into(), "Why".into(), "Detail".into()],
            rows: vec![
                row([
                    "A wallet on Base with USDC and a little ETH",
                    "The deposit, and your own transactions",
                    "USDC up to your price cap stays in the wallet until a seller funds an order with your signed authorization (EIP-3009; no approve). post, withdraw, refund and claim are yours to send: about 284,505 gas in all, 0.0000017 ETH at 0.006 gwei. post-tasks posts nothing while the wallet holds less USDC than the cap, or less ETH than that gas at twice the current price.",
                ]),
                row([
                    "A machine that stays up",
                    "Sellers fetch the statement from your process, and it signs the order",
                    "Until the task ends: up to the delivery window, at most the vault's term. On a Mac, run under caffeinate -i.",
                ]),
                row([
                    "Lean 4.30.0 and lean4export 3.1.0 (a3e35a5)",
                    "The statement",
                    "Other versions export other bytes",
                ]),
                row([
                    "Rust",
                    "Export v2",
                    "The converter is an example program in the source.",
                ]),
            ],
        },
        h2("statement", "1. Statement"),
        template("post-statement", statement_steps()),
        Block::Table {
            caption: "The worked example, run 2026-11-18 on an Apple-silicon Mac".into(),
            head: vec!["File".into(), "Bytes".into(), "SHA-256".into()],
            rows: vec![
                vec![vec![code("statement.ndjson")], vec![t(format!("{NDJSON_BYTES}, 707 lines; export.err empty"))], vec![code(NDJSON_SHA256)]],
                vec![vec![code("statement.v2")], vec![t(format!("{V2_BYTES}; 45 declarations"))], vec![code(V2_SHA256)]],
            ],
        },
        Block::Table {
            caption: "What a statement must pass. nucleus-buyer statement checks all six and gave the same v2 hash; by hand as below".into(),
            head: vec!["Check".into(), "Why".into(), "By hand".into()],
            rows: vec![
                row(["The exporter exited 0 and wrote nothing to stderr", "It exits 0 after a missing root", "test ! -s export.err"]),
                row(["Its first line names lean4export 3.1.0, format 3.1.0, Lean 4.30.0", "The screen pins this toolchain", "head -n 1 statement.ndjson"]),
                row(["Every root is declared", "A missing claim cannot be proved", "grep the claim's name"]),
                row(["No axiom but propext, Classical.choice, Quot.sound", "No sorryAx, no axiom of your own", "grep -c '\"axiom\"' statement.ndjson prints 3"]),
                row(["The claim is one universe-monomorphic definition", "The acceptance rule's test", "def, no universe variables"]),
                row(["The export type-checks in the checker the program runs", "Else no proof can pass", "lake build checks the source, not the export"]),
            ],
        },
        h2("task", "2. Task file"),
        p(vec![code("task/task.json"), t(":")]),
        template("post-task-json", task_json()),
        Block::Table {
            caption: format!("Each field, as {} reads it", r.tag),
            head: vec!["Field".into(), "Here".into(), "Rule".into()],
            rows: vec![
                row(["statement", "statement.v2", "Relative to the task file; its SHA-256 is pinned in the post"]),
                row(["claim, permittedAxioms", "Statements.S1.claim; the three", "No name repeated; the checker admits only these axioms"]),
                row(["maximumArtifactBytes", "34824", "The largest proof accepted; above 34,824 the relayer will not send the seller's settle"]),
                row(["program", "the newest published order program", "It refuses a proof that declares a name the checker treats as built in; sellers skip a post naming a program they do not run"]),
                row(["maximumPrice", "1000000 (1 USDC)", "Units of 0.000001 USDC; the most you pay"]),
                row(["fundingWindowSeconds", "86400", "At least 300; sellers skip a post with under 1,800 s left to deliver"]),
                row(["deliveryWindowSeconds", "172800", "Longer than funding; at most the vault's term, else refused before posting"]),
            ],
        },
        h2("post", "3. Post"),
        verification_command(
            "post-release",
            format!(
                "# Release {tag}, checked as on /sellers/run (Linux: another archive, and sha256sum -c)\ngh release download {tag} -R coproduct-opensource/qed -p qed-aarch64-apple-darwin.tar.gz -p SHA256SUMS\nshasum -a 256 -c --ignore-missing SHA256SUMS\ngh attestation verify qed-aarch64-apple-darwin.tar.gz --repo coproduct-opensource/qed\ntar xzf qed-aarch64-apple-darwin.tar.gz",
                tag = r.tag
            ),
        ),
        template(
            "post-run",
            format!(
                "cd qed-aarch64-apple-darwin
./nucleus-vault-ops keys buyer.keys    # prints the address: send it the USDC and the ETH, then go on
printf '%s\\n' '{base}' > base.json
NUCLEUS_RELAY=default ./nucleus-buyer post-tasks base.json {board} buyer.keys 0.0.0.0:0 out ../task/task.json
# One task file per run, journaled in out/journal.jsonl. Logs \"posted task 0x… in tx …\",
# then runs until the task ends. Killed? Run the same command: it resumes from the
# journal and never posts twice. To stop instead, with it not running:
#   NUCLEUS_RELAY=default ./nucleus-buyer task-withdraw base.json {board} buyer.keys 0.0.0.0:0 out ../task/task.json",
                base = deployment_json(m),
                board = m.board.address
            ),
        ),
        h2("next", "Outcomes"),
        Block::Table {
            caption: format!("Every end, as {}'s post-tasks handles it. Gas: post measured on Base; the rest on Arbitrum Sepolia", r.tag),
            head: vec!["End".into(), "What happens".into(), "Your transactions".into()],
            rows: vec![
                row(["A proof settles", "It reads the artifact from the chain, checks it with the Lean checker, writes out/add-comm/; exit 0", "post, 58,893 gas"]),
                row(["No offer signed by the funding deadline", "It withdraws the post and stops; the USDC never left", "post; withdraw, 47,545 gas"]),
                row(["Signed, never funded", "The order lapses at its funding deadline; it journals that and stops; nothing moved", "post"]),
                row(["Funded, not settled by the order's delivery deadline", "A running post-tasks refunds and claims by itself. If it is not running, task-refund (same six arguments) sends refund, then claim; before the deadline it refuses and changes nothing", "refund, 64,325 gas; claim, 68,523 gas"]),
                row(["The process stops early", "Run the same post-tasks again: it reads out/journal.jsonl, reopens the desk for the posted task and never posts a second time. To stop instead, task-withdraw withdraws an unsigned post and refuses over a signed order", "withdraw, if you stop"]),
            ],
        },
        Block::Table {
            caption: format!("Not in {}", r.tag),
            head: vec!["".into(), "Instead".into(), "Where".into()],
            rows: vec![
                row(["A Lean toolchain or lean4export", "Install Lean 4.30.0 with elan and build lean4export 3.1.0", "See 1. Statement"]),
            ],
        },
        h2("terms", "Terms"),
        Block::Table {
            caption: "The contracts, the deployed vault's terms, and the relayer".into(),
            head: vec!["".into(), "Value".into(), "Detail".into()],
            rows: vec![
                vec![vec![t("Board")], vec![code_link(format!("{ex}/address/{}", m.board.address), m.board.address.clone())], vec![t(format!("On {}; post is open to any address, withdraw only to the poster", m.network.name))]],
                vec![vec![t("Vault")], vec![code_link(format!("{ex}/address/{}", m.vault.address), m.vault.address.clone())], vec![t("Holds deposits; settle, refund and claim")]],
                row(["Fee", &format!("{fee} ({fee_bps} basis points)"), "Of the order's amount, at settlement, from the deposit; the seller gets the rest. A refund pays it all back"]),
                row(["Vault term", &format!("{term} s ({} days)", term / 86_400), "The longest delivery deadline a fund accepts"]),
                row(["Seller's gas", &format!("relayed up to {RELAY_REACH} artifact bytes"), &format!("The relayer sends fund, settle and claim for sellers, settle at most {RELAY_CAP} gas; a larger artifact's seller pays its own settle, about 0.00002 ETH")]),
                row(["Who answers", "a seller with a prover for your claim", "The released seller, as /sellers/run sets it up, answers only the bounty's statement"]),
            ],
        },
    ];
    Doc {
        path: "post".into(),
        title: "Post a task — QED".into(),
        description: format!(
            "How anyone posts a Lean-proof task on the {} board with release {}: a worked statement with its measured bytes and hash, the task file, the command, every way a task ends, fees and limits.",
            m.network.name, r.tag
        ),
        heading: "Post a task".into(),
        blocks,
        // Copy controls on the release check.
        script: true,
        data: None,
    }
}
