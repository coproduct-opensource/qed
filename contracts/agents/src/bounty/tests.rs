//! The bounty's rules against a market that is a few maps and a clock. A
//! "process" is one `Fake`; the chain it talks to outlives it, and so does
//! the journal file, so a kill and a restart are a dropped `Fake`, a reopened
//! journal and a new `Fake` on the same chain.
//!
//! Each rule was driven red once; the table is in
//! docs/rfcs/proof-commerce-standing-bounty-2026-11-13.md.
use super::*;
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
}
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
        }
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
    fn now(&mut self) -> Res<u64> {
        Ok(self.world.borrow().clock)
    }
    fn block(&mut self) -> Res<u64> {
        Ok(self.world.borrow().block)
    }
    fn wallet(&mut self) -> Res<u64> {
        Ok(self.world.borrow().wallet)
    }
    fn prepare(&mut self, price: u64) -> Res<TaskRef> {
        self.prepared += 1;
        let mut world = self.world.borrow_mut();
        world.block += 1;
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&world.block.to_be_bytes());
        Ok(TaskRef {
            id,
            price,
            fund_by: world.clock + 600,
            deliver_by: world.clock + 3_600,
        })
    }
    fn post(&mut self, task: &TaskRef) -> Res<String> {
        self.killed("post", false)?;
        {
            // Rule 1, seen from outside: never two live posts.
            let mut world = self.world.borrow_mut();
            assert_eq!(
                world.posts, 0,
                "a second task was posted while one was open"
            );
            world.posts += 1;
            world.board.insert(task.id, false);
        }
        self.desks.insert(task.id);
        self.killed("post", true)?;
        Ok("0xpost".into())
    }
    fn on_board(&mut self, task: Hash) -> Res<bool> {
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
        {
            let mut world = self.world.borrow_mut();
            world.clock += seconds;
            world.block += seconds * 4;
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
fn a_post_whose_receipt_was_lost_is_found_and_withdrawn_not_reopened() {
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
    assert_eq!(run(limits, &journal, &mut fake).unwrap(), Stop::TaskLimit);
    // The earlier run's post counts as a post, was withdrawn, and nothing
    // was signed for it by the process that did not hold its desk.
    let world = world.borrow();
    assert_eq!((world.withdrawals, world.posts, world.paid), (1, 0, 0));
    assert_eq!(journal.lock().unwrap().ledger().posted, 1);
    assert!(journal.lock().unwrap().ledger().signed.is_empty());
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
    assert_eq!(run(limits, &journal, &mut fake).unwrap(), Stop::TaskLimit);
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
    assert_eq!(run(limits, &journal, &mut fake).unwrap(), Stop::TaskLimit);
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
        if fake
            .open_task()
            .is_some_and(|task| fake.desks.contains(&task.id))
        {
            fake.sign(100);
            // Nobody funds; the fake counts a live post until it ends.
            fake.world.borrow_mut().posts -= 1;
        }
    }));
    assert_eq!(run(limits, &journal, &mut fake).unwrap(), Stop::TaskLimit);
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
            block: 5
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
