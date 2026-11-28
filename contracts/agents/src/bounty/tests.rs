//! The bounty's rules against a market that is a few maps and a clock. A
//! "process" is one `Fake`; the chain it talks to outlives it, and so does
//! the journal file, so a kill and a restart are a dropped `Fake`, a reopened
//! journal and a new `Fake` on the same chain.
//!
//! Each rule was driven red once; the table is in
//! docs/rfcs/proof-commerce-standing-bounty-2026-11-13.md.
use super::*;
use crate::chain::{
    Chain as RpcChain,
    fault::{Reply, serve},
};
use crate::ladder;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    path::PathBuf,
    rc::Rc,
    sync::atomic::{AtomicU32, Ordering},
};

const BUYER: Address = [0xb1; 20];
const SELLER: Address = [0x5e; 20];

fn header() -> Header {
    Header {
        chain: 421614,
        vault: [0x11; 20],
        board: [0xb0; 20],
        token: [0x33; 20],
        buyer: BUYER,
        block: 1_000,
    }
}
fn scratch() -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "nucleus-bounty-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    fs::create_dir_all(&dir).unwrap();
    dir.join("journal.jsonl")
}
fn open(path: &Path) -> Shared {
    Arc::new(Mutex::new(Journal::open(path, header()).unwrap()))
}

/// What outlives a process.
#[derive(Default)]
struct World {
    clock: u64,
    block: u64,
    wallet: u64,
    /// Task ID to whether it is withdrawn.
    board: HashMap<Hash, bool>,
    phases: HashMap<Hash, Phase>,
    amounts: HashMap<Hash, u64>,
    owed: u64,
    deposits: Vec<(u64, Hash)>,
    paid: u64,
    /// The most that was ever paid plus held in the vault at once.
    peak_exposure: u64,
    /// Posts on the board that are neither withdrawn nor ended.
    posts: u32,
    refunds: u32,
    withdrawals: u32,
    /// The statement file is gone (R-3).
    statement_missing: bool,
    /// Waits for which a transaction from the buyer is still pending.
    pending: u32,
    /// The buyer's ether and the price per gas it would offer (gap 3).
    ether: u128,
    gas_price: u128,
    /// Posts ever made on the board (a withdrawn post still counts).
    posts_ever: u32,
    /// Rows of one desk sharing this wallet: that many live posts at once
    /// (`ladder::run`). Zero is one, the standing bounty's rule 1.
    rows: u32,
}
impl World {
    fn at_risk(&self) -> u64 {
        self.phases
            .iter()
            .filter(|(_, phase)| **phase == Phase::Funded)
            .map(|(digest, _)| self.amounts[digest])
            .sum()
    }
    fn note_exposure(&mut self) {
        self.peak_exposure = self.peak_exposure.max(self.paid + self.at_risk());
    }
    fn fund(&mut self, digest: Hash) {
        let amount = self.amounts[&digest];
        assert!(self.wallet >= amount, "the wallet cannot fund this order");
        self.wallet -= amount;
        self.phases.insert(digest, Phase::Funded);
        self.deposits.push((self.block, digest));
        self.note_exposure();
    }
    fn settle(&mut self, digest: Hash) {
        assert_eq!(self.phases[&digest], Phase::Funded);
        self.phases.insert(digest, Phase::Settled);
        self.paid += self.amounts[&digest];
        self.note_exposure();
    }
}
type Chain = Rc<RefCell<World>>;

/// What a seller does while the buyer waits.
type Script = Box<dyn FnMut(&mut Fake)>;

struct Fake {
    world: Chain,
    journal: Shared,
    /// Desks this process holds open.
    desks: HashSet<Hash>,
    prepared: u8,
    /// Fail the named operation: before its effect, or after it.
    kill: Option<(&'static str, bool)>,
    verdict: Result<(), String>,
    script: Option<Script>,
    waits: u32,
    /// A real RPC client `on_board` asks first, against a scripted
    /// endpoint (`chain::fault`): its failures reach the bounty as they
    /// would from a node.
    probe: Option<RpcChain>,
    /// Every health report, in order.
    reports: Vec<Health>,
    /// The wallet reads empty once this many posts were withdrawn: how a
    /// test ends a bounty nobody answers (R-4: unanswered windows no longer
    /// stop it).
    broke_after: Option<u32>,
    /// Each `savings` call: the order, its cap and its referral.
    savings: Vec<Seen>,
    /// Shares `pay_owed` was asked to pay, each call.
    owed_asked: Vec<usize>,
}
/// One `savings` call as the fake saw it.
type Seen = (Hash, u64, Option<(Address, Hash)>);
const STATEMENT_GONE: &str = "the statement file /var/lib/qed-buyer/statement.v2 cannot be read: No such file or directory (os error 2)";
impl Fake {
    fn new(world: &Chain, journal: &Shared) -> Self {
        Self {
            world: world.clone(),
            journal: journal.clone(),
            desks: HashSet::new(),
            prepared: 0,
            kill: None,
            verdict: Ok(()),
            script: None,
            waits: 0,
            probe: None,
            reports: vec![],
            broke_after: None,
            savings: vec![],
            owed_asked: vec![],
        }
    }
    fn degraded(&self) -> usize {
        self.reports
            .iter()
            .filter(|health| matches!(health, Health::Degraded { .. }))
            .count()
    }
    fn killed(&mut self, operation: &'static str, after: bool) -> Res<()> {
        if self.kill == Some((operation, after)) {
            self.kill = None;
            return Err(format!("killed at {operation}").into());
        }
        Ok(())
    }
    fn open_task(&self) -> Option<TaskRef> {
        match &self.journal.lock().unwrap().ledger().open {
            Some(Open::Posted(task)) => Some(task.clone()),
            _ => None,
        }
    }
    /// A seller's offer passes review and the desk signs: journaled first,
    /// as the real desk does, then the desk is closed.
    fn sign(&mut self, amount: u64) -> Hash {
        let task = self.open_task().expect("a posted task");
        assert!(
            self.desks.contains(&task.id),
            "this process holds no desk for the task"
        );
        let mut digest = task.id;
        digest[0] ^= 0xff;
        let order = vault::Order {
            buyer: BUYER,
            seller: SELLER,
            asset: [0x33; 20],
            amount: U256::from(amount).to_be_bytes(),
            verifier: [0x44; 20],
            program: [0x55; 32],
            policy_hash: [0x66; 32],
            base: [0; 32],
            fund_by: task.fund_by,
            deliver_by: task.deliver_by,
            salt: [7; 32],
            context: [8; 32],
        };
        self.journal
            .lock()
            .unwrap()
            .record(Entry::Signed {
                task: task.id,
                order: OrderRef {
                    digest,
                    amount,
                    order,
                },
            })
            .expect("the journal takes the signature");
        self.desks.remove(&task.id);
        let mut world = self.world.borrow_mut();
        world.amounts.insert(digest, amount);
        world.phases.insert(digest, Phase::Empty);
        digest
    }
    /// The whole of a seller's part: offer, fund, settle.
    fn trade(&mut self, amount: u64) {
        let digest = self.sign(amount);
        let mut world = self.world.borrow_mut();
        world.fund(digest);
        world.settle(digest);
    }
}

impl Market for Fake {
    fn savings(
        &mut self,
        order: &OrderRef,
        cap: u64,
        referral: Option<(Address, Hash)>,
    ) -> Res<Vec<Entry>> {
        self.savings.push((order.digest, cap, referral));
        let split = qed_savings::split(
            &qed_savings::Rule::MODEL,
            u128::from(cap),
            u128::from(order.amount),
            referral.is_some(),
            0,
        );
        // The wallet covers nothing yet: every share is owed.
        Ok(
            crate::payout::shares(order.digest, referral.map(|r| r.0), &[], &split)
                .into_iter()
                .map(|share| Entry::Owed { share })
                .collect(),
        )
    }
    fn pay_owed(&mut self, owed: &[crate::payout::Share]) -> Res<Vec<Entry>> {
        self.owed_asked.push(owed.len());
        Ok(owed
            .iter()
            .map(|s| Entry::Paid {
                share: s.clone(),
                transaction: Some("0xpaid".into()),
            })
            .collect())
    }
    fn now(&mut self) -> Res<u64> {
        Ok(self.world.borrow().clock)
    }
    fn block(&mut self) -> Res<u64> {
        Ok(self.world.borrow().block)
    }
    fn ether(&mut self) -> Res<(u128, u128)> {
        let world = self.world.borrow();
        Ok((world.ether, world.gas_price))
    }
    fn wallet(&mut self) -> Res<u64> {
        let world = self.world.borrow();
        if self.broke_after.is_some_and(|n| world.withdrawals >= n) {
            return Ok(0);
        }
        Ok(world.wallet)
    }
    fn prepare(&mut self, price: u64) -> Res<TaskRef> {
        self.prepared += 1;
        let mut world = self.world.borrow_mut();
        if world.statement_missing {
            return Err(STATEMENT_GONE.into());
        }
        world.block += 1;
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&world.block.to_be_bytes());
        Ok(TaskRef {
            id,
            price,
            fund_by: world.clock + 600,
            deliver_by: world.clock + 3_600,
            salt: Some([0x5a; 32]),
        })
    }
    fn resume(&mut self, task: &TaskRef) -> Res<Resumption> {
        let world = self.world.borrow();
        let why = if task.salt.is_none() {
            "the journal kept no salt for it"
        } else if world.board.get(&task.id) == Some(&true) {
            "the board shows it withdrawn already"
        } else if world.statement_missing {
            STATEMENT_GONE
        } else {
            self.desks.insert(task.id);
            return Ok(Resumption::Resumed);
        };
        Ok(Resumption::Unresumable(why.into()))
    }
    fn quiet(&mut self) -> Res<bool> {
        Ok(self.world.borrow().pending == 0)
    }
    fn report(&mut self, health: &Health) {
        self.reports.push(health.clone());
    }
    fn post(&mut self, task: &TaskRef) -> Res<String> {
        self.killed("post", false)?;
        {
            // Rule 1, seen from outside: never two live posts.
            let mut world = self.world.borrow_mut();
            assert!(
                world.posts < world.rows.max(1),
                "a second task was posted while one was open"
            );
            world.posts += 1;
            world.posts_ever += 1;
            world.board.insert(task.id, false);
        }
        self.desks.insert(task.id);
        self.killed("post", true)?;
        Ok("0xpost".into())
    }
    fn on_board(&mut self, task: Hash) -> Res<bool> {
        if let Some(probe) = &self.probe {
            probe.rpc("eth_call", json!([{}, "latest"]))?;
        }
        Ok(self.world.borrow().board.contains_key(&task))
    }
    fn desk_open(&mut self, task: Hash) -> Res<bool> {
        Ok(self.desks.contains(&task))
    }
    fn close_desk(&mut self, task: Hash) -> Res<bool> {
        Ok(self.desks.remove(&task))
    }
    fn withdraw(&mut self, task: Hash) -> Res<String> {
        let mut world = self.world.borrow_mut();
        let withdrawn = world.board.get_mut(&task).expect("a posted task");
        assert!(!*withdrawn, "withdrawn twice");
        *withdrawn = true;
        world.posts -= 1;
        world.withdrawals += 1;
        Ok("0xwithdraw".into())
    }
    fn phase(&mut self, order: &OrderRef) -> Res<Phase> {
        self.killed("phase", false)?;
        Ok(self.world.borrow().phases[&order.digest])
    }
    fn check_settled(&mut self, _: &OrderRef) -> Res<Result<(), String>> {
        self.world.borrow_mut().posts -= 1;
        Ok(self.verdict.clone())
    }
    fn refund(&mut self, order: &OrderRef) -> Res<String> {
        let mut world = self.world.borrow_mut();
        assert_eq!(world.phases[&order.digest], Phase::Funded);
        assert!(
            world.clock > order.order.deliver_by,
            "refund before the deadline"
        );
        world.phases.insert(order.digest, Phase::Refunded);
        world.owed += order.amount;
        world.refunds += 1;
        Ok("0xrefund".into())
    }
    fn recover(&mut self) -> Res<String> {
        let mut world = self.world.borrow_mut();
        world.wallet += world.owed;
        world.owed = 0;
        world.posts -= 1;
        Ok("0xclaim".into())
    }
    fn deposits(&mut self, from: u64, to: u64) -> Res<Vec<Hash>> {
        Ok(self
            .world
            .borrow()
            .deposits
            .iter()
            .filter(|(block, _)| (from..=to).contains(block))
            .map(|(_, digest)| *digest)
            .collect())
    }
    fn wait(&mut self, seconds: u64) -> Res<()> {
        self.killed("wait", false)?;
        {
            let mut world = self.world.borrow_mut();
            world.clock += seconds;
            world.block += seconds * 4;
            world.pending = world.pending.saturating_sub(1);
        }
        self.waits += 1;
        assert!(self.waits < 10_000, "the bounty never stops");
        if let Some(mut script) = self.script.take() {
            script(self);
            self.script = Some(script);
        }
        Ok(())
    }
}

fn chain(wallet: u64) -> Chain {
    Rc::new(RefCell::new(World {
        clock: 10_000,
        block: 1_000,
        wallet,
        ..World::default()
    }))
}
const LIMITS: Limits = Limits {
    price: 100,
    budget: 250,
    tasks: 10,
    pause: 30,
    posts: None,
    gas: None,
};

/// A seller that answers every post it sees, at the cap.
fn eager() -> Script {
    Box::new(|fake: &mut Fake| {
        if fake
            .open_task()
            .is_some_and(|task| fake.desks.contains(&task.id))
        {
            fake.trade(100);
        }
    })
}

#[test]
fn it_trades_until_the_budget_does_not_cover_another_task() {
    let (path, world) = (scratch(), chain(1_000));
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    fake.script = Some(eager());
    assert_eq!(run(LIMITS, &journal, &mut fake).unwrap(), Stop::Budget);
    let world = world.borrow();
    // Two tasks at 100 fit a budget of 250; a third would not.
    assert_eq!((world.paid, world.wallet), (200, 800));
    assert!(world.peak_exposure <= LIMITS.budget);
    let journal = journal.lock().unwrap();
    assert_eq!((journal.ledger().spent, journal.ledger().posted), (200, 2));
    // What is on disk says the same.
    let replayed = replay(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(&replayed, journal.ledger());
}

#[test]
fn the_budget_holds_across_a_kill_between_post_and_settlement() {
    let (path, world) = (scratch(), chain(1_000));
    {
        let journal = open(&path);
        let mut fake = Fake::new(&world, &journal);
        // The seller is signed for and funds; the buyer dies before it looks.
        fake.script = Some(Box::new(|fake: &mut Fake| {
            if fake.open_task().is_some() {
                let digest = fake.sign(100);
                fake.world.borrow_mut().fund(digest);
                fake.kill = Some(("phase", false));
            }
        }));
        let error = run(LIMITS, &journal, &mut fake).unwrap_err();
        assert_eq!(error.to_string(), "killed at phase");
    }
    // While the buyer is down the seller settles.
    let funded = *world.borrow().phases.keys().next().unwrap();
    world.borrow_mut().settle(funded);

    let journal = open(&path);
    assert!(matches!(
        journal.lock().unwrap().ledger().open,
        Some(Open::Signed(..))
    ));
    let mut fake = Fake::new(&world, &journal);
    fake.script = Some(eager());
    assert_eq!(run(LIMITS, &journal, &mut fake).unwrap(), Stop::Budget);
    let world = world.borrow();
    // The order from before the kill is counted once, and one more fits.
    assert_eq!((world.paid, world.wallet), (200, 800));
    assert!(world.peak_exposure <= LIMITS.budget);
    assert_eq!(journal.lock().unwrap().ledger().spent, 200);
    assert_eq!(journal.lock().unwrap().ledger().posted, 2);
}

#[test]
fn a_post_whose_receipt_was_lost_is_found_and_resumed_not_withdrawn() {
    let (path, world) = (scratch(), chain(1_000));
    {
        let journal = open(&path);
        let mut fake = Fake::new(&world, &journal);
        fake.kill = Some(("post", true));
        assert!(run(LIMITS, &journal, &mut fake).is_err());
        assert!(matches!(
            journal.lock().unwrap().ledger().open,
            Some(Open::Intent(_))
        ));
    }
    assert_eq!(world.borrow().posts, 1);
    let journal = open(&path);
    let limits = Limits { tasks: 1, ..LIMITS };
    let mut fake = Fake::new(&world, &journal);
    fake.broke_after = Some(1);
    assert_eq!(run(limits, &journal, &mut fake).unwrap(), Stop::Wallet);
    // R-3: the restarted process reopened the desk, and the post stood for
    // its whole funding window before it was withdrawn (not a task since
    // 2026-11-14, R-4).
    let world = world.borrow();
    assert_eq!((world.withdrawals, world.posts, world.paid), (1, 0, 0));
    assert!(world.clock > 10_000 + 600);
    let journal = journal.lock().unwrap();
    assert_eq!((journal.ledger().posted, journal.ledger().settled), (1, 0));
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .contains("\"reason\":\"window\"")
    );
}

/// A kill while the post is open, then a restart: R-3's case, and the one
/// the mainnet crash loop withdrew four times.
fn killed_while_posted(path: &Path, world: &Chain) {
    let journal = open(path);
    let mut fake = Fake::new(world, &journal);
    fake.kill = Some(("wait", false));
    assert_eq!(
        run(LIMITS, &journal, &mut fake).unwrap_err().to_string(),
        "killed at wait"
    );
    assert!(matches!(
        journal.lock().unwrap().ledger().open,
        Some(Open::Posted(_))
    ));
}

#[test]
fn a_restart_resumes_an_open_unsigned_post_and_a_seller_can_still_win() {
    let (path, world) = (scratch(), chain(1_000));
    killed_while_posted(&path, &world);
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    fake.script = Some(eager());
    let limits = Limits { tasks: 1, ..LIMITS };
    assert_eq!(run(limits, &journal, &mut fake).unwrap(), Stop::TaskLimit);
    let world = world.borrow();
    // The same post was won and settled; nothing was withdrawn.
    assert_eq!((world.withdrawals, world.paid), (0, 100));
    let ledger = journal.lock().unwrap().ledger().clone();
    assert_eq!((ledger.posted, ledger.settled, ledger.spent), (1, 1, 100));
    assert!(!fs::read_to_string(&path).unwrap().contains("\"withdrawn\""));
}

#[test]
fn a_restart_without_the_statement_withdraws_and_says_why() {
    let (path, world) = (scratch(), chain(1_000));
    killed_while_posted(&path, &world);
    world.borrow_mut().statement_missing = true;
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    let limits = Limits { tasks: 1, ..LIMITS };
    // One unresumable post is as many failures as one task allows.
    assert_eq!(run(limits, &journal, &mut fake).unwrap(), Stop::Failures);
    assert_eq!(world.borrow().withdrawals, 1);
    let ledger = journal.lock().unwrap().ledger().clone();
    assert_eq!((ledger.settled, ledger.failures), (0, 1));
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"reason\":\"unresumable\""), "{text}");
    assert!(text.contains("statement.v2 cannot be read"), "{text}");

    // With room for another task it would post again, and cannot: that
    // is an error to exit on, not a loop.
    let mut fake = Fake::new(&world, &journal);
    let error = run(LIMITS, &journal, &mut fake).unwrap_err();
    assert!(error.to_string().contains("cannot be read"), "{error}");
    assert!(matches!(fake.reports.last(), Some(Health::Failed { .. })));
}

#[test]
fn only_settled_orders_use_up_a_task_and_old_journals_still_replay() {
    let opened = Entry::Opened(header()).to_json().to_string();
    let lines = |entries: &[Entry]| {
        let mut text = opened.clone();
        for entry in entries {
            text.push('\n');
            text.push_str(&entry.to_json().to_string());
        }
        replay(&text).unwrap()
    };
    let task = |n: u8| TaskRef {
        id: [n; 32],
        price: 100,
        fund_by: 10,
        deliver_by: 20,
        salt: None,
    };
    let post = |n: u8| {
        [
            Entry::Intent(task(n)),
            Entry::Posted {
                task: [n; 32],
                transaction: "(found on the board after a restart)".into(),
            },
        ]
    };
    let withdrawn = |n: u8, reason: Withdrawal| Entry::Withdrawn {
        task: [n; 32],
        transaction: "(already withdrawn)".into(),
        block: 5,
        reason,
    };
    // The mainnet journal's shape: four posts, each withdrawn by a restart,
    // journaled before reasons were. None of them is a task.
    let mut mainnet = vec![];
    for n in 1..=4 {
        mainnet.extend(post(n));
        mainnet.push(withdrawn(n, Withdrawal::Unrecorded));
    }
    mainnet.push(Entry::Stopped {
        reason: "the task limit is reached".into(),
    });
    let ledger = lines(&mainnet);
    assert_eq!(
        (
            ledger.posted,
            ledger.settled,
            ledger.failures,
            ledger.spent,
            ledger.open
        ),
        (4, 0, 0, 0, None)
    );
    // An unresumable post is a failure, not a task. A window that ended was
    // a task until 2026-11-14 and is not now; the journal line is the same,
    // only how it counts changed (R-4). An operator's close is neither.
    let mut entries = post(1).to_vec();
    entries.push(withdrawn(1, Withdrawal::Unresumable("gone".into())));
    entries.extend(post(2));
    entries.push(withdrawn(2, Withdrawal::WindowEnded));
    entries.extend(post(3));
    entries.push(withdrawn(3, Withdrawal::Closed));
    let ledger = lines(&entries);
    assert_eq!((ledger.posted, ledger.settled, ledger.failures), (3, 0, 1));
    // Refunded and lapsed orders are not tasks either; a refund is counted
    // on its own (`Stop::Refunds`), a lapse not at all.
    let order = |n: u8| OrderRef {
        digest: [n; 32],
        amount: 100,
        order: nucleus_proof_commerce::vault::Order {
            buyer: [1; 20],
            seller: [2; 20],
            asset: [3; 20],
            amount: [0; 32],
            verifier: [4; 20],
            program: [5; 32],
            policy_hash: [6; 32],
            base: [0; 32],
            fund_by: 10,
            deliver_by: 20,
            salt: [7; 32],
            context: [8; 32],
        },
    };
    let mut entries = vec![];
    for (n, end) in [(1u8, "refunded"), (2, "lapsed"), (3, "settled")] {
        entries.extend(post(n));
        entries.push(Entry::Signed {
            task: [n; 32],
            order: order(n),
        });
        entries.push(match end {
            "refunded" => Entry::Refunded {
                digest: [n; 32],
                block: 6,
            },
            "lapsed" => Entry::Lapsed {
                digest: [n; 32],
                block: 6,
            },
            _ => Entry::Settled {
                digest: [n; 32],
                paid: 100,
                checked: true,
                block: 6,
            },
        });
    }
    let ledger = lines(&entries);
    assert_eq!(
        (ledger.posted, ledger.settled, ledger.refunded, ledger.spent),
        (3, 1, 1, 100)
    );
}

#[test]
fn a_rate_limited_rpc_does_not_end_the_bounty_and_the_post_stays_open() {
    // A node that answers 403 "rate limited" to everything after the
    // connect, for longer than one call's patience, then recovers.
    let started = std::time::Instant::now();
    let node = serve(Box::new(move |method, _, _| {
        if method == "eth_chainId" {
            Reply::result(json!("0x2105"))
        } else if started.elapsed() < std::time::Duration::from_millis(2_500) {
            Reply::error(403, -32005, "rate limit exceeded")
        } else {
            Reply::result(json!("0x"))
        }
    }));
    let probe =
        RpcChain::connect_any(std::slice::from_ref(&node.url), crate::chain::fault::QUICK).unwrap();

    let (path, world) = (scratch(), chain(1_000));
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    // Post first, then let the node fail: the outage falls while it is open.
    fake.probe = None;
    let limits = Limits { tasks: 1, ..LIMITS };
    fake.kill = Some(("wait", false));
    assert!(run(limits, &journal, &mut fake).is_err());
    fake.probe = Some(probe);
    // The seller wins while the buyer is degraded: its desk still serves.
    fake.script = Some(Box::new(|fake: &mut Fake| {
        if fake.degraded() > 0 && fake.open_task().is_some_and(|t| fake.desks.contains(&t.id)) {
            fake.trade(100);
        }
    }));
    assert_eq!(run(limits, &journal, &mut fake).unwrap(), Stop::TaskLimit);
    assert!(fake.degraded() >= 1, "{:?}", fake.reports);
    let world = world.borrow();
    assert_eq!((world.withdrawals, world.paid), (0, 100));
    assert_eq!(journal.lock().unwrap().ledger().settled, 1);
}

#[test]
fn an_intent_is_not_abandoned_while_a_transaction_from_the_buyer_is_pending() {
    let (path, world) = (scratch(), chain(1_000));
    {
        let journal = open(&path);
        let mut fake = Fake::new(&world, &journal);
        fake.kill = Some(("post", false));
        assert!(run(LIMITS, &journal, &mut fake).is_err());
    }
    // The post is in a mempool for two more looks, then lands.
    world.borrow_mut().pending = 2;
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    let id = match journal.lock().unwrap().ledger().open.clone() {
        Some(Open::Intent(task)) => task.id,
        other => panic!("{other:?}"),
    };
    fake.script = Some(Box::new(move |fake: &mut Fake| {
        let mut world = fake.world.borrow_mut();
        if world.pending == 0 && !world.board.contains_key(&id) {
            world.board.insert(id, false);
            world.posts += 1;
        }
    }));
    let limits = Limits { tasks: 1, ..LIMITS };
    fake.broke_after = Some(1);
    assert_eq!(run(limits, &journal, &mut fake).unwrap(), Stop::Wallet);
    let text = fs::read_to_string(&path).unwrap();
    assert!(!text.contains("\"abandoned\""), "{text}");
    // The post that landed stood its window and was withdrawn: one post,
    // and the window's end is not a task (R-4, 2026-11-14).
    assert_eq!(journal.lock().unwrap().ledger().posted, 1);
    assert_eq!(world.borrow().withdrawals, 1);
}

#[test]
fn an_intent_that_never_reached_the_board_is_dropped() {
    let (path, world) = (scratch(), chain(1_000));
    {
        let journal = open(&path);
        let mut fake = Fake::new(&world, &journal);
        fake.kill = Some(("post", false));
        assert!(run(LIMITS, &journal, &mut fake).is_err());
    }
    let journal = open(&path);
    let limits = Limits { tasks: 1, ..LIMITS };
    let mut fake = Fake::new(&world, &journal);
    fake.script = Some(eager());
    assert_eq!(run(limits, &journal, &mut fake).unwrap(), Stop::TaskLimit);
    // The dropped intent is not a post: one real post was still made.
    assert_eq!(journal.lock().unwrap().ledger().posted, 1);
    assert_eq!(world.borrow().paid, 100);
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"abandoned\""));
}

#[test]
fn a_post_nobody_answers_is_withdrawn_at_its_funding_deadline() {
    let (path, world) = (scratch(), chain(1_000));
    let journal = open(&path);
    let limits = Limits { tasks: 2, ..LIMITS };
    let mut fake = Fake::new(&world, &journal);
    // Nobody answers; the run ends when the wallet does, after two windows.
    fake.broke_after = Some(2);
    assert_eq!(run(limits, &journal, &mut fake).unwrap(), Stop::Wallet);
    let world = world.borrow();
    assert_eq!((world.withdrawals, world.posts), (2, 0));
    assert_eq!((world.paid, world.wallet), (0, 1_000));
    assert_eq!(journal.lock().unwrap().ledger().spent, 0);
    // Not withdrawn early: each post stood for its whole funding window.
    assert!(world.clock >= 10_000 + 2 * 600);
}

#[test]
fn a_funded_order_that_is_not_delivered_is_refunded_and_claimed() {
    let (path, world) = (scratch(), chain(1_000));
    let journal = open(&path);
    let limits = Limits { tasks: 1, ..LIMITS };
    let mut fake = Fake::new(&world, &journal);
    fake.script = Some(Box::new(|fake: &mut Fake| {
        if fake
            .open_task()
            .is_some_and(|task| fake.desks.contains(&task.id))
        {
            let digest = fake.sign(100);
            fake.world.borrow_mut().fund(digest);
        }
    }));
    // A refund is not a task (R-4, 2026-11-14); as many refunds as the task
    // limit stop the bounty for the operator.
    assert_eq!(run(limits, &journal, &mut fake).unwrap(), Stop::Refunds);
    assert_eq!(journal.lock().unwrap().ledger().settled, 0);
    let world = world.borrow();
    // The deposit is back in the wallet and nothing counts as spent.
    assert_eq!(
        (world.refunds, world.owed, world.wallet, world.paid),
        (1, 0, 1_000, 0)
    );
    assert_eq!(journal.lock().unwrap().ledger().spent, 0);
    assert!(fs::read_to_string(&path).unwrap().contains("\"refunded\""));
}

#[test]
fn a_signed_order_that_is_never_funded_lapses_and_costs_nothing() {
    let (path, world) = (scratch(), chain(1_000));
    let journal = open(&path);
    let limits = Limits { tasks: 1, ..LIMITS };
    let mut fake = Fake::new(&world, &journal);
    fake.script = Some(Box::new(|fake: &mut Fake| {
        if fake.prepared == 1
            && fake
                .open_task()
                .is_some_and(|task| fake.desks.contains(&task.id))
        {
            fake.sign(100);
            // Nobody funds; the fake counts a live post until it ends.
            fake.world.borrow_mut().posts -= 1;
        }
    }));
    // A lapse is not a task (R-4, 2026-11-14): the bounty posts again, and
    // nobody answers that post, whose window ends; then the wallet is empty.
    fake.broke_after = Some(1);
    assert_eq!(run(limits, &journal, &mut fake).unwrap(), Stop::Wallet);
    assert_eq!(journal.lock().unwrap().ledger().posted, 2);
    assert_eq!(journal.lock().unwrap().ledger().settled, 0);
    assert_eq!((world.borrow().paid, world.borrow().wallet), (0, 1_000));
    assert!(fs::read_to_string(&path).unwrap().contains("\"lapsed\""));
}

#[test]
fn it_stops_at_the_task_limit_and_at_an_empty_wallet() {
    let (path, world) = (scratch(), chain(1_000));
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    fake.script = Some(eager());
    let limits = Limits { tasks: 1, ..LIMITS };
    assert_eq!(run(limits, &journal, &mut fake).unwrap(), Stop::TaskLimit);
    assert_eq!(world.borrow().paid, 100);
    // Run again with the same journal: the limit still holds.
    assert_eq!(run(limits, &journal, &mut fake).unwrap(), Stop::TaskLimit);
    assert_eq!(journal.lock().unwrap().ledger().posted, 1);

    let (path, world) = (scratch(), chain(99));
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    assert_eq!(run(LIMITS, &journal, &mut fake).unwrap(), Stop::Wallet);
    assert_eq!(journal.lock().unwrap().ledger().posted, 0);
    assert!(fs::read_to_string(&path).unwrap().contains("\"stopped\""));
}

#[test]
fn a_settled_artifact_the_checker_refuses_stops_the_bounty_and_is_still_counted() {
    let (path, world) = (scratch(), chain(1_000));
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    fake.script = Some(eager());
    fake.verdict = Err("ClaimNotProved".into());
    let error = run(LIMITS, &journal, &mut fake).unwrap_err();
    assert!(error.to_string().contains("ClaimNotProved"), "{error}");
    assert_eq!(journal.lock().unwrap().ledger().spent, 100);
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"checked\":false") && text.contains("\"stopped\""));
}

#[test]
fn it_refuses_to_start_when_the_vault_holds_a_deposit_the_journal_did_not_sign() {
    let (path, world) = (scratch(), chain(1_000));
    let journal = open(&path);
    {
        let mut world = world.borrow_mut();
        world.amounts.insert([0xee; 32], 100);
        world.fund([0xee; 32]);
    }
    let mut fake = Fake::new(&world, &journal);
    let error = run(LIMITS, &journal, &mut fake).unwrap_err();
    assert_eq!(
        error.downcast_ref::<Irreconcilable>(),
        Some(&Irreconcilable::UnknownDeposit([0xee; 32]))
    );
    assert_eq!(journal.lock().unwrap().ledger().posted, 0);
}

#[test]
fn it_refuses_a_journal_for_another_deployment_or_one_it_cannot_read() {
    let path = scratch();
    drop(open(&path));
    for change in [
        (|h: &mut Header| h.chain = 1) as fn(&mut Header),
        |h| h.vault = [9; 20],
        |h| h.board = [9; 20],
        |h| h.token = [9; 20],
        |h| h.buyer = [9; 20],
    ] {
        let mut other = header();
        change(&mut other);
        let error = Journal::open(&path, other).err().expect("refused");
        assert_eq!(
            error.downcast_ref::<Irreconcilable>(),
            Some(&Irreconcilable::AnotherJournal)
        );
    }
    // A later block is the same journal continued.
    let mut later = header();
    later.block = 9_999;
    assert_eq!(
        Journal::open(&path, later).unwrap().ledger().checkpoint,
        1_000
    );

    let opened = Entry::Opened(header()).to_json().to_string();
    let unreadable = |text: String| match replay(&text) {
        Err(Irreconcilable::Unreadable { line, .. }) => line,
        other => panic!("not refused as unreadable: {other:?}"),
    };
    assert_eq!(unreadable(format!("{opened}\nnot json\n")), 2);
    assert_eq!(unreadable(format!("{opened}\n{{\"event\":\"paid\"}}\n")), 2);
    assert_eq!(
        unreadable(format!(
            "{opened}\n{{\"event\":\"intent\",\"task\":\"0x01\"}}\n"
        )),
        2
    );
}

#[test]
fn a_journal_records_only_the_moves_of_the_diagram() {
    let task = TaskRef {
        id: [1; 32],
        price: 100,
        fund_by: 10,
        deliver_by: 20,
        salt: None,
    };
    let other = TaskRef {
        id: [2; 32],
        ..task.clone()
    };
    let order = |amount: u64| OrderRef {
        digest: [3; 32],
        amount,
        order: vault::Order {
            buyer: BUYER,
            seller: SELLER,
            asset: [0x33; 20],
            amount: U256::from(amount).to_be_bytes(),
            verifier: [0x44; 20],
            program: [0x55; 32],
            policy_hash: [0x66; 32],
            base: [0; 32],
            fund_by: 10,
            deliver_by: 20,
            salt: [7; 32],
            context: [8; 32],
        },
    };
    let posted = Entry::Posted {
        task: task.id,
        transaction: "0x".into(),
    };
    let signed = Entry::Signed {
        task: task.id,
        order: order(100),
    };
    let settled = |paid| Entry::Settled {
        digest: [3; 32],
        paid,
        checked: true,
        block: 5,
    };
    let refused = |entries: &[Entry]| {
        let path = scratch();
        let mut journal = Journal::open(&path, header()).unwrap();
        let (last, before) = entries.split_last().unwrap();
        for entry in before {
            journal.record(entry.clone()).unwrap();
        }
        let length = fs::metadata(&path).unwrap().len();
        let refused = journal.record(last.clone()).is_err();
        // A refused event leaves the file as it was.
        if refused {
            assert_eq!(fs::metadata(&path).unwrap().len(), length);
        }
        refused
    };
    // Rule 1: no second task while one is open, at any stage.
    assert!(refused(&[
        Entry::Intent(task.clone()),
        Entry::Intent(other.clone())
    ]));
    assert!(refused(&[
        Entry::Intent(task.clone()),
        posted.clone(),
        Entry::Intent(other.clone())
    ]));
    assert!(refused(&[
        Entry::Intent(task.clone()),
        posted.clone(),
        signed.clone(),
        Entry::Intent(other.clone())
    ]));
    // A post needs its own intent; a signature needs its post.
    assert!(refused(std::slice::from_ref(&posted)));
    assert!(refused(&[Entry::Intent(other), posted.clone()]));
    assert!(refused(&[Entry::Intent(task.clone()), signed.clone()]));
    // Nothing above the posted cap is signed for.
    assert!(refused(&[
        Entry::Intent(task.clone()),
        posted.clone(),
        Entry::Signed {
            task: task.id,
            order: order(101)
        }
    ]));
    // An outcome needs the open order, and a settlement pays its amount.
    assert!(refused(&[
        Entry::Intent(task.clone()),
        posted.clone(),
        settled(100)
    ]));
    assert!(refused(&[
        Entry::Intent(task.clone()),
        posted.clone(),
        signed.clone(),
        settled(99)
    ]));
    // A signed post is not withdrawn.
    assert!(refused(&[
        Entry::Intent(task.clone()),
        posted.clone(),
        signed.clone(),
        Entry::Withdrawn {
            task: task.id,
            transaction: "0x".into(),
            block: 5,
            reason: Withdrawal::WindowEnded,
        }
    ]));
    // And the allowed path is allowed.
    assert!(!refused(&[
        Entry::Intent(task),
        posted,
        signed,
        settled(100)
    ]));
}

#[test]
fn it_refuses_to_continue_when_the_board_does_not_know_a_post_the_journal_records() {
    let (path, world) = (scratch(), chain(1_000));
    {
        let mut journal = Journal::open(&path, header()).unwrap();
        let task = TaskRef {
            id: [1; 32],
            price: 100,
            fund_by: 99_999,
            deliver_by: 199_999,
            salt: None,
        };
        journal.record(Entry::Intent(task.clone())).unwrap();
        journal
            .record(Entry::Posted {
                task: task.id,
                transaction: "0x".into(),
            })
            .unwrap();
    }
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    let error = run(LIMITS, &journal, &mut fake).unwrap_err();
    assert_eq!(
        error.downcast_ref::<Irreconcilable>(),
        Some(&Irreconcilable::PostMissing([1; 32]))
    );
}

#[test]
fn every_event_survives_its_own_json() {
    let order = OrderRef {
        digest: [3; 32],
        amount: 250_000,
        order: vault::Order {
            buyer: BUYER,
            seller: SELLER,
            asset: [0x33; 20],
            amount: U256::from(250_000u64).to_be_bytes(),
            verifier: [0x44; 20],
            program: [0x55; 32],
            policy_hash: [0x66; 32],
            base: [0; 32],
            fund_by: 10,
            deliver_by: 20,
            salt: [7; 32],
            context: [8; 32],
        },
    };
    for entry in [
        Entry::Opened(header()),
        Entry::Intent(TaskRef {
            id: [1; 32],
            price: 5,
            fund_by: 6,
            deliver_by: 7,
            salt: Some([4; 32]),
        }),
        Entry::Intent(TaskRef {
            id: [1; 32],
            price: 5,
            fund_by: 6,
            deliver_by: 7,
            salt: None,
        }),
        Entry::Posted {
            task: [1; 32],
            transaction: "0xabc".into(),
        },
        Entry::Signed {
            task: [1; 32],
            order,
        },
        Entry::Settled {
            digest: [3; 32],
            paid: 250_000,
            checked: true,
            block: 9,
        },
        Entry::Refunded {
            digest: [3; 32],
            block: 9,
        },
        Entry::Lapsed {
            digest: [3; 32],
            block: 9,
        },
        Entry::Withdrawn {
            task: [1; 32],
            transaction: "0xdef".into(),
            block: 9,
            reason: Withdrawal::WindowEnded,
        },
        Entry::Withdrawn {
            task: [1; 32],
            transaction: "0xdef".into(),
            block: 9,
            reason: Withdrawal::Unresumable("the statement file is missing".into()),
        },
        Entry::Withdrawn {
            task: [1; 32],
            transaction: "0xdef".into(),
            block: 9,
            reason: Withdrawal::Closed,
        },
        Entry::Withdrawn {
            task: [1; 32],
            transaction: "0xdef".into(),
            block: 9,
            reason: Withdrawal::Unrecorded,
        },
        Entry::Abandoned { task: [1; 32] },
        Entry::Stopped {
            reason: "the task limit is reached".into(),
        },
    ] {
        let line = entry.to_json().to_string();
        assert!(!line.contains('\n'));
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(Entry::from_json(&value).unwrap(), entry, "{line}");
    }
}

#[test]
fn closing_withdraws_an_open_post_and_ends_the_journal() {
    let (path, world) = (scratch(), chain(1_000));
    {
        let journal = open(&path);
        let mut fake = Fake::new(&world, &journal);
        fake.kill = Some(("post", true));
        assert!(run(LIMITS, &journal, &mut fake).is_err());
    }
    assert_eq!(world.borrow().posts, 1);
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    close(&journal, &mut fake).unwrap();
    assert_eq!((world.borrow().withdrawals, world.borrow().posts), (1, 0));
    assert_eq!(journal.lock().unwrap().ledger().open, None);
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"withdrawn\""));
    assert!(
        text.trim_end()
            .lines()
            .last()
            .unwrap()
            .contains("closed by the operator")
    );
    // Closing a journal with nothing open withdraws nothing more.
    close(&journal, &mut fake).unwrap();
    assert_eq!(world.borrow().withdrawals, 1);
}

#[test]
fn a_journal_with_a_signed_order_is_not_closed_over() {
    let (path, world) = (scratch(), chain(1_000));
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    fake.script = Some(Box::new(|fake: &mut Fake| {
        if fake
            .open_task()
            .is_some_and(|task| fake.desks.contains(&task.id))
        {
            fake.sign(100);
            fake.kill = Some(("phase", false));
        }
    }));
    assert!(run(LIMITS, &journal, &mut fake).is_err());
    assert!(matches!(
        journal.lock().unwrap().ledger().open,
        Some(Open::Signed(..))
    ));
    let before = fs::read_to_string(&path).unwrap();
    let refusal = close(&journal, &mut fake).unwrap_err().to_string();
    assert!(refusal.contains("signed for and not finished"), "{refusal}");
    assert_eq!(world.borrow().withdrawals, 0);
    assert_eq!(fs::read_to_string(&path).unwrap(), before);
}

/// R-4 as decided on 2026-11-14: only a settlement uses up a task. A run of
/// posts whose windows end unanswered does not stop the bounty; it keeps
/// posting, and stops at the task limit once that many orders settled.
/// Red under the old rule, which stopped after `tasks` unanswered windows
/// with nothing paid.
#[test]
fn unanswered_windows_do_not_stop_the_bounty_only_settlements_do() {
    let (_path, world) = (scratch(), chain(1_000));
    let journal = open(&_path);
    let limits = Limits { tasks: 2, ..LIMITS };
    let mut fake = Fake::new(&world, &journal);
    // Nobody answers the first five posts; from the sixth on, a seller does.
    fake.script = Some(Box::new(|fake: &mut Fake| {
        let unanswered = fake.world.borrow().withdrawals;
        if unanswered >= 5
            && fake
                .open_task()
                .is_some_and(|task| fake.desks.contains(&task.id))
        {
            fake.trade(100);
        }
    }));
    assert_eq!(run(limits, &journal, &mut fake).unwrap(), Stop::TaskLimit);
    let world = world.borrow();
    assert_eq!(world.withdrawals, 5, "five windows ended unanswered");
    assert_eq!(world.paid, 200, "two tasks settled, the limit");
    assert!(world.peak_exposure <= LIMITS.budget);
}

// The ladder post (`tasks.rs`): the same journal run as a one-shot, with
// gap 3's wallet check. proofs/commerce/LadderPost.lean is the model; each
// test below is one of its theorems seen from outside, through the fake
// chain. Red runs: docs/rfcs/qed-nucleus-merge-ladder-2026-11-14.md,
// section 10, "Gaps 1 to 3: built".

const ONE_SHOT: Limits = Limits {
    price: 100,
    budget: 100,
    tasks: 1,
    pause: 0,
    posts: Some(1),
    gas: Some(1_000),
};
/// A wallet that covers the cap and the gas: 1,000 gas at 1 wei, twice.
fn ladder_chain() -> Chain {
    let world = chain(1_000);
    {
        let mut w = world.borrow_mut();
        w.ether = 2_000;
        w.gas_price = 1;
    }
    world
}

/// Gap 1, a kill between the intent and the post: the restart finds nothing
/// on the board and nothing pending, drops the intent, and posts once.
#[test]
fn a_ladder_post_killed_before_it_was_sent_is_dropped_and_posted_once() {
    let (path, world) = (scratch(), ladder_chain());
    {
        let journal = open(&path);
        let mut fake = Fake::new(&world, &journal);
        fake.kill = Some(("post", false));
        assert!(run(ONE_SHOT, &journal, &mut fake).is_err());
        assert!(matches!(
            journal.lock().unwrap().ledger().open,
            Some(Open::Intent(_))
        ));
    }
    assert_eq!(world.borrow().posts_ever, 0);
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    fake.script = Some(eager());
    assert_eq!(run(ONE_SHOT, &journal, &mut fake).unwrap(), Stop::TaskLimit);
    assert_eq!(world.borrow().posts_ever, 1);
    assert_eq!(world.borrow().paid, 100);
    assert!(fs::read_to_string(&path).unwrap().contains("\"abandoned\""));
}

/// Gap 1, a kill after the post was sent: the restart finds it on the board
/// and journals it posted; nobody answers, so it is withdrawn at its funding
/// deadline, and nothing is ever posted again. Red with `posts: None` (the
/// standing bounty's rule): the run posts again after the window.
#[test]
fn a_ladder_post_killed_after_it_was_sent_is_found_and_never_posted_again() {
    let (path, world) = (scratch(), ladder_chain());
    {
        let journal = open(&path);
        let mut fake = Fake::new(&world, &journal);
        fake.kill = Some(("post", true));
        assert!(run(ONE_SHOT, &journal, &mut fake).is_err());
    }
    assert_eq!(world.borrow().posts_ever, 1);
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    assert_eq!(run(ONE_SHOT, &journal, &mut fake).unwrap(), Stop::PostLimit);
    let w = world.borrow();
    assert_eq!((w.posts_ever, w.withdrawals, w.posts, w.paid), (1, 1, 0, 0));
    // A third run of the same journal posts nothing either.
    drop(w);
    let mut fake = Fake::new(&world, &journal);
    assert_eq!(run(ONE_SHOT, &journal, &mut fake).unwrap(), Stop::PostLimit);
    assert_eq!(world.borrow().posts_ever, 1);
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("found on the board"), "{text}");
}

/// Gap 1, resume: a kill while the post is open, then a restart that
/// reopens the desk; a seller still wins the same post.
#[test]
fn a_ladder_post_resumed_after_a_kill_can_still_settle() {
    let (path, world) = (scratch(), ladder_chain());
    {
        let journal = open(&path);
        let mut fake = Fake::new(&world, &journal);
        fake.kill = Some(("wait", false));
        assert!(run(ONE_SHOT, &journal, &mut fake).is_err());
        assert!(matches!(
            journal.lock().unwrap().ledger().open,
            Some(Open::Posted(_))
        ));
    }
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    fake.script = Some(eager());
    assert_eq!(run(ONE_SHOT, &journal, &mut fake).unwrap(), Stop::TaskLimit);
    let w = world.borrow();
    assert_eq!((w.posts_ever, w.withdrawals, w.paid), (1, 0, 100));
}

/// Gap 1, `task-withdraw`: an orphaned post (its process killed) is
/// withdrawn from the journal, and a later `post-tasks` on that journal
/// posts nothing.
#[test]
fn task_withdraw_ends_an_orphaned_post_and_nothing_is_posted_after() {
    let (path, world) = (scratch(), ladder_chain());
    {
        let journal = open(&path);
        let mut fake = Fake::new(&world, &journal);
        fake.kill = Some(("wait", false));
        assert!(run(ONE_SHOT, &journal, &mut fake).is_err());
    }
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    close(&journal, &mut fake).unwrap();
    assert_eq!((world.borrow().withdrawals, world.borrow().posts), (1, 0));
    let mut fake = Fake::new(&world, &journal);
    assert_eq!(run(ONE_SHOT, &journal, &mut fake).unwrap(), Stop::PostLimit);
    assert_eq!(world.borrow().posts_ever, 1);
}

/// Gap 2, `task-refund`: a funded order is refused a refund before its
/// delivery deadline, with nothing written; after it, refunded and claimed
/// back, journaled, and the journal posts nothing more.
#[test]
fn task_refund_refunds_a_funded_order_only_after_its_delivery_deadline() {
    let (path, world) = (scratch(), ladder_chain());
    {
        let journal = open(&path);
        let mut fake = Fake::new(&world, &journal);
        fake.script = Some(Box::new(|fake: &mut Fake| {
            if fake
                .open_task()
                .is_some_and(|task| fake.desks.contains(&task.id))
            {
                let digest = fake.sign(100);
                fake.world.borrow_mut().fund(digest);
                fake.kill = Some(("phase", false));
            }
        }));
        assert!(run(ONE_SHOT, &journal, &mut fake).is_err());
    }
    let journal = open(&path);
    let deliver_by = match journal.lock().unwrap().ledger().open.clone() {
        Some(Open::Signed(_, order)) => order.order.deliver_by,
        other => panic!("{other:?}"),
    };
    let before = fs::read_to_string(&path).unwrap();
    let mut fake = Fake::new(&world, &journal);
    let early = finish(&journal, &mut fake).unwrap_err();
    assert!(
        matches!(
            early.downcast_ref::<Unfinished>(),
            Some(Unfinished::NotYetRefundable { .. })
        ),
        "{early}"
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), before);
    assert_eq!(world.borrow().refunds, 0);

    world.borrow_mut().clock = deliver_by + 1;
    finish(&journal, &mut fake).unwrap();
    {
        let w = world.borrow();
        assert_eq!((w.refunds, w.owed, w.wallet, w.paid), (1, 0, 1_000, 0));
    }
    assert!(fs::read_to_string(&path).unwrap().contains("\"refunded\""));
    // Nothing more to refund, and nothing is posted again.
    let again = finish(&journal, &mut fake).unwrap_err();
    assert!(matches!(
        again.downcast_ref::<Unfinished>(),
        Some(Unfinished::NoSignedOrder(_))
    ));
    assert_eq!(run(ONE_SHOT, &journal, &mut fake).unwrap(), Stop::Refunds);
    assert_eq!(world.borrow().posts_ever, 1);
}

/// Gap 2, the other end of a signed order: never funded, it lapses at its
/// funding deadline, and the one-shot does not post again.
#[test]
fn a_ladder_order_that_is_never_funded_lapses_and_nothing_is_posted_after() {
    let (path, world) = (scratch(), ladder_chain());
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    fake.script = Some(Box::new(|fake: &mut Fake| {
        if fake
            .open_task()
            .is_some_and(|task| fake.desks.contains(&task.id))
        {
            fake.sign(100);
            fake.world.borrow_mut().posts -= 1;
        }
    }));
    assert_eq!(run(ONE_SHOT, &journal, &mut fake).unwrap(), Stop::PostLimit);
    assert_eq!(world.borrow().posts_ever, 1);
    assert!(fs::read_to_string(&path).unwrap().contains("\"lapsed\""));
}

/// Gap 3: no post from a wallet short of the cap in tokens, or of the gas
/// in ether at twice the price; the typed stop says which and by how much.
/// Red with the ether check removed: the short wallet posts.
#[test]
fn a_ladder_post_refuses_a_wallet_short_of_the_cap_or_the_gas() {
    let (path, world) = (scratch(), ladder_chain());
    world.borrow_mut().wallet = 99;
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    assert_eq!(run(ONE_SHOT, &journal, &mut fake).unwrap(), Stop::Wallet);
    assert_eq!(world.borrow().posts_ever, 0);

    let (path, world) = (scratch(), ladder_chain());
    world.borrow_mut().ether = 1_999;
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    assert_eq!(
        run(ONE_SHOT, &journal, &mut fake).unwrap(),
        Stop::Gas {
            have: 1_999,
            need: 2_000
        }
    );
    assert_eq!(world.borrow().posts_ever, 0);
    assert!(fs::read_to_string(&path).unwrap().contains("\"stopped\""));
    // Funded, the same journal posts.
    world.borrow_mut().ether = 2_000;
    let mut fake = Fake::new(&world, &journal);
    fake.script = Some(eager());
    assert_eq!(run(ONE_SHOT, &journal, &mut fake).unwrap(), Stop::TaskLimit);
    assert_eq!(world.borrow().posts_ever, 1);
    // The standing bounty's limits never ask for ether.
    let (path, world) = (scratch(), chain(1_000));
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    fake.script = Some(eager());
    let limits = Limits { tasks: 1, ..LIMITS };
    assert_eq!(run(limits, &journal, &mut fake).unwrap(), Stop::TaskLimit);
}

// A desk with several rows (`ladder::run`): one process, one wallet, one
// journal per row. One `Fake` per row on one world, as one `Live` per row on
// one hub. proofs/commerce/LadderMulti.lean is the model; the red runs are in
// docs/rfcs/qed-ladder-multi-row-desk-2026-11-27.md, "Red, then green".

/// The ladder's one-shot limits at a row's cap.
fn one_shot(price: u64) -> Limits {
    Limits {
        price,
        budget: price,
        ..ONE_SHOT
    }
}

/// A seller answers row `journal`'s open post at its cap: the desk journals
/// the signature, and the seller funds it.
fn answer_and_fund(world: &Chain, journal: &Shared) -> Option<Hash> {
    let task = match &journal.lock().unwrap().ledger().open {
        Some(Open::Posted(task)) => task.clone(),
        _ => return None,
    };
    let mut digest = task.id;
    digest[0] ^= 0xff;
    let order = vault::Order {
        buyer: BUYER,
        seller: SELLER,
        asset: [0x33; 20],
        amount: U256::from(task.price).to_be_bytes(),
        verifier: [0x44; 20],
        program: [0x55; 32],
        policy_hash: [0x66; 32],
        base: [0; 32],
        fund_by: task.fund_by,
        deliver_by: task.deliver_by,
        salt: [7; 32],
        context: [8; 32],
    };
    journal
        .lock()
        .unwrap()
        .record(Entry::Signed {
            task: task.id,
            order: OrderRef {
                digest,
                amount: task.price,
                order,
            },
        })
        .unwrap();
    let mut world = world.borrow_mut();
    world.amounts.insert(digest, task.price);
    world.phases.insert(digest, Phase::Empty);
    world.fund(digest);
    Some(digest)
}

/// Run the rows as one desk. Between rounds the world's clock moves on and
/// `between` plays the sellers; `Err` from it is a kill.
fn run_desk(
    world: &Chain,
    rows: &mut [(Fake, Limits)],
    mut between: impl FnMut(&Chain) -> Res<()>,
) -> Res<Vec<ladder::Ended>> {
    let mut desk: Vec<ladder::Row> = rows
        .iter_mut()
        .enumerate()
        .map(|(index, (fake, limits))| ladder::Row {
            name: format!("row {index}"),
            limits: *limits,
            journal: fake.journal.clone(),
            market: fake,
        })
        .collect();
    let mut rounds = 0;
    ladder::run(&mut desk, &mut |seconds| {
        {
            let mut w = world.borrow_mut();
            w.clock += seconds;
            w.block += seconds * 4;
            w.pending = w.pending.saturating_sub(1);
        }
        rounds += 1;
        assert!(rounds < 10_000, "the desk never stops");
        between(world)
    })
}

fn desk_chain(wallet: u64) -> Chain {
    let world = ladder_chain();
    {
        let mut w = world.borrow_mut();
        w.wallet = wallet;
        w.rows = 3;
    }
    world
}

/// `no_overcommit`: three rows at 40, 30 and 40 against 100. The first two
/// are posted; the third would commit 110, so it stops at `Wallet` and the
/// others go on to settle. Red with each row checking only its own cap
/// (`mutant_overcommit_breaks_no_overcommit`): the third is posted too, and
/// funding it finds the wallet short.
#[test]
fn a_row_is_not_posted_when_the_wallet_covers_it_only_alone() {
    let world = desk_chain(100);
    let journals = [open(&scratch()), open(&scratch()), open(&scratch())];
    let mut rows: Vec<(Fake, Limits)> = journals
        .iter()
        .zip([40, 30, 40])
        .map(|(journal, price)| (Fake::new(&world, journal), one_shot(price)))
        .collect();
    let answering = journals.clone();
    let ended = run_desk(&world, &mut rows, |world| {
        for journal in &answering {
            if let Some(digest) = answer_and_fund(world, journal) {
                world.borrow_mut().settle(digest);
            }
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(
        ended,
        vec![Ok(Stop::TaskLimit), Ok(Stop::TaskLimit), Ok(Stop::Wallet)]
    );
    let w = world.borrow();
    assert_eq!((w.posts_ever, w.paid, w.wallet), (2, 70, 30));
}

/// `restart_admitted`: S0001's row is funded, then the desk is killed. A
/// one-row process for S0007 refuses to restart over S0001's deposit (rule
/// 8 on one journal, the finding); the desk, checking the union of its rows'
/// journals, restarts, settles S0001 and withdraws S0007 at its deadline.
#[test]
fn a_funded_row_does_not_stop_another_rows_restart() {
    let world = desk_chain(110);
    let (path1, path7) = (scratch(), scratch());
    {
        let (j1, j7) = (open(&path1), open(&path7));
        let mut rows = vec![
            (Fake::new(&world, &j1), one_shot(40)),
            (Fake::new(&world, &j7), one_shot(30)),
        ];
        let error = run_desk(&world, &mut rows, |world| {
            answer_and_fund(world, &j1);
            Err("killed".into())
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "killed");
        assert_eq!(world.borrow().deposits.len(), 1);
    }
    // One process per row, as on 2026-11-19: S0007's refuses.
    let j7 = open(&path7);
    let error = run(one_shot(30), &j7, &mut Fake::new(&world, &j7)).unwrap_err();
    assert!(
        matches!(
            error.downcast_ref::<Irreconcilable>(),
            Some(Irreconcilable::UnknownDeposit(_))
        ),
        "{error}"
    );
    // One desk for both rows restarts.
    let j1 = open(&path1);
    let mut rows = vec![
        (Fake::new(&world, &j1), one_shot(40)),
        (Fake::new(&world, &j7), one_shot(30)),
    ];
    let funded: Vec<Hash> = world.borrow().deposits.iter().map(|(_, d)| *d).collect();
    let ended = run_desk(&world, &mut rows, |world| {
        let mut w = world.borrow_mut();
        if w.phases.get(&funded[0]) == Some(&Phase::Funded) {
            w.settle(funded[0]);
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(ended, vec![Ok(Stop::TaskLimit), Ok(Stop::PostLimit)]);
    let w = world.borrow();
    assert_eq!((w.posts_ever, w.paid, w.withdrawals), (2, 40, 1));
}

/// A deposit no row signed for still stops the whole desk: it is the
/// wallet's, not a row's.
#[test]
fn a_deposit_no_row_signed_for_stops_the_desk() {
    let world = desk_chain(110);
    {
        let mut w = world.borrow_mut();
        w.amounts.insert([0xee; 32], 40);
        w.fund([0xee; 32]);
    }
    let journals = [open(&scratch()), open(&scratch())];
    let mut rows: Vec<(Fake, Limits)> = journals
        .iter()
        .map(|journal| (Fake::new(&world, journal), one_shot(30)))
        .collect();
    let error = run_desk(&world, &mut rows, |_| Ok(())).unwrap_err();
    assert_eq!(
        error.downcast_ref::<Irreconcilable>(),
        Some(&Irreconcilable::UnknownDeposit([0xee; 32]))
    );
    assert_eq!(world.borrow().posts_ever, 0);
}

/// A row that fails leaves the other rows running, and takes its own post
/// off the desk.
#[test]
fn a_row_that_fails_leaves_the_others_running() {
    let world = desk_chain(110);
    let journals = [open(&scratch()), open(&scratch())];
    let mut rows: Vec<(Fake, Limits)> = journals
        .iter()
        .zip([40, 30])
        .map(|(journal, price)| (Fake::new(&world, journal), one_shot(price)))
        .collect();
    let (first, second) = (journals[0].clone(), journals[1].clone());
    let ended = run_desk(&world, &mut rows, |world| {
        // The first row's post vanishes from the board: its journal cannot
        // be reconciled (`PostMissing`); the second row is answered.
        if let Some(Open::Posted(task)) = &first.lock().unwrap().ledger().open {
            world.borrow_mut().board.remove(&task.id);
        }
        if let Some(digest) = answer_and_fund(world, &second) {
            world.borrow_mut().settle(digest);
        }
        Ok(())
    })
    .unwrap();
    assert!(
        matches!(&ended[0], Err(why) if why.contains("the board does not know it")),
        "{ended:?}"
    );
    assert_eq!(ended[1], Ok(Stop::TaskLimit));
    assert!(
        !rows[0].0.desks.iter().any(|_| true),
        "the failed row's post is still on the desk"
    );
}

/// Backward compatibility, one row: the S0001 journal v0.2.4 wrote, run by
/// `post-tasks` with one task file (`bounty::run`, as before), resumes its
/// post and posts nothing new.
#[test]
fn a_v024_journal_resumes_alone_as_before() {
    let path = crate::ladder::tests::scratch("s0001");
    let journal = crate::ladder::tests::reopen(&path, crate::ladder::tests::S0001_V024);
    let task = match &journal.lock().unwrap().ledger().open {
        Some(Open::Posted(task)) => task.clone(),
        other => panic!("{other:?}"),
    };
    let world = ladder_chain();
    {
        let mut w = world.borrow_mut();
        w.wallet = 110_000_000;
        w.board.insert(task.id, false);
        w.posts = 1;
        w.clock = task.fund_by - 100;
    }
    let mut fake = Fake::new(&world, &journal);
    assert_eq!(
        run(one_shot(40_000_000), &journal, &mut fake).unwrap(),
        Stop::PostLimit
    );
    let w = world.borrow();
    assert_eq!((w.posts_ever, w.withdrawals), (0, 1));
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.starts_with(crate::ladder::tests::S0001_V024), "{text}");
    assert_eq!(text.matches("\"intent\"").count(), 1);
}

/// The host desk of 2026-11-27: S0001 and S0007 resumed from the journals
/// v0.2.4 wrote, S0006 new, on one desk and one wallet of 110 USDC. S0006 is
/// posted (40 on top of 70), S0001 and S0007 are not posted again, and each
/// is withdrawn at its own funding deadline.
#[test]
fn the_v024_journals_and_a_new_row_run_as_one_desk() {
    use crate::ladder::tests::{S0001_V024, S0007_V024, reopen, scratch as row};
    let (p1, p7, p6) = (row("s0001"), row("s0007"), row("s0006"));
    let (j1, j7) = (reopen(&p1, S0001_V024), reopen(&p7, S0007_V024));
    let header = replay(S0001_V024).unwrap().header;
    let j6 = Arc::new(Mutex::new(Journal::open(&p6, header).unwrap()));
    let world = desk_chain(110_000_000);
    {
        let mut w = world.borrow_mut();
        for journal in [&j1, &j7] {
            if let Some(Open::Posted(task)) = &journal.lock().unwrap().ledger().open {
                w.board.insert(task.id, false);
            }
        }
        w.posts = 2;
        w.clock = 1_796_286_711 - 100;
    }
    let mut rows = vec![
        (Fake::new(&world, &j1), one_shot(40_000_000)),
        (Fake::new(&world, &j7), one_shot(30_000_000)),
        (Fake::new(&world, &j6), one_shot(40_000_000)),
    ];
    let ended = run_desk(&world, &mut rows, |_| Ok(())).unwrap();
    assert_eq!(ended, vec![Ok(Stop::PostLimit); 3]);
    let w = world.borrow();
    assert_eq!((w.posts_ever, w.withdrawals, w.paid), (1, 3, 0));
    for (path, text) in [(&p1, S0001_V024), (&p7, S0007_V024)] {
        let now = fs::read_to_string(path).unwrap();
        assert!(now.starts_with(text));
        assert_eq!(now.matches("\"intent\"").count(), 1, "{now}");
    }
}

// ---- Savings: the referral line, the payout hook (Payout.lean) ---------------

/// A referred order settled under its cap: the referral is journaled before
/// the signature, the hook sees the post's cap and the referral, its shares
/// are journaled owed before `Settled`, and the next step pays them. The
/// journal replays to the same ledger. Driven red by not calling the hook:
/// no owed line was journaled.
#[test]
fn a_referred_settlement_journals_its_referral_and_pays_its_shares() {
    let (path, world) = (scratch(), chain(1_000));
    let journal = open(&path);
    let mut fake = Fake::new(&world, &journal);
    let referrer = [0xf0; 20];
    let mut traded = false;
    fake.script = Some(Box::new(move |fake: &mut Fake| {
        let Some(task) = fake.open_task() else { return };
        if traded || !fake.desks.contains(&task.id) {
            return;
        }
        traded = true;
        let mut digest = task.id;
        digest[0] ^= 0xff;
        fake.journal
            .lock()
            .unwrap()
            .record(Entry::Referred {
                task: task.id,
                digest,
                referrer,
                nonce: [0x11; 32],
            })
            .unwrap();
        fake.trade(60);
    }));
    let limits = Limits { tasks: 1, ..LIMITS };
    run(limits, &journal, &mut fake).unwrap();
    assert_eq!(fake.savings.len(), 1);
    let (_, cap, referral) = fake.savings[0];
    assert_eq!((cap, referral), (100, Some((referrer, [0x11; 32]))));
    let text = fs::read_to_string(&path).unwrap();
    let events: Vec<String> = text
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["event"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    let at = |e: &str| events.iter().position(|x| x == e).unwrap();
    assert!(at("referred") < at("signed"));
    assert!(at("owed") < at("settled"), "{events:?}");
    assert!(at("paid") > at("settled"));
    // 40 saved: 12 to the referrer (30 %); no authors without a library.
    let ledger = journal.lock().unwrap().ledger().clone();
    assert!(ledger.owed.is_empty());
    assert_eq!(fake.owed_asked.first(), Some(&1));
    let paid: Value = text
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|v| v["event"] == "paid")
        .unwrap();
    assert_eq!(paid["amount"], "12");
    assert_eq!(replay(&text).unwrap(), ledger);
}

/// The new lines: a referral only for the posted task, a share line whose
/// nonce is not its share's is not read, and each survives its JSON.
#[test]
fn savings_lines_are_moves_of_the_diagram_and_read_back() {
    let share = crate::payout::Share {
        order: [6; 32],
        role: crate::payout::Role::Referrer,
        party: [0xf0; 20],
        amount: 12,
    };
    for entry in [
        Entry::Referred {
            task: [1; 32],
            digest: [6; 32],
            referrer: [0xf0; 20],
            nonce: [0x11; 32],
        },
        Entry::Owed {
            share: share.clone(),
        },
        Entry::Paid {
            share: share.clone(),
            transaction: Some("0x01".into()),
        },
        Entry::Paid {
            share: share.clone(),
            transaction: None,
        },
    ] {
        assert_eq!(Entry::from_json(&entry.to_json()).unwrap(), entry);
    }
    let mut forged = Entry::Owed {
        share: share.clone(),
    }
    .to_json();
    forged["amount"] = json!("13");
    assert!(Entry::from_json(&forged).is_err());
    // A referral with no post open is not a move.
    let (path, _) = (scratch(), chain(1_000));
    let journal = open(&path);
    let refused = journal.lock().unwrap().record(Entry::Referred {
        task: [1; 32],
        digest: [6; 32],
        referrer: [0xf0; 20],
        nonce: [0x11; 32],
    });
    assert!(refused.is_err());
}

/// Journals written before this change resume: every file named in
/// `QED_JOURNALS` (colon-separated; the live S0001 and S0007 rows' journals
/// are not in this public repository) replays without error. Ignored when
/// the variable is unset.
#[test]
fn journals_from_before_savings_still_replay() {
    let Ok(paths) = std::env::var("QED_JOURNALS") else {
        return;
    };
    for p in paths.split(':').filter(|p| !p.is_empty()) {
        let text = fs::read_to_string(p).unwrap();
        let ledger = replay(&text).unwrap_or_else(|e| panic!("{p}: {e}"));
        assert!(ledger.referrals.is_empty() && ledger.owed.is_empty());
        println!("{p}: {} lines replay", text.lines().count());
    }
}
