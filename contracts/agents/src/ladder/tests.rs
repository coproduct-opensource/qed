//! The multi-row desk's rules, by value, against proofs/commerce/LadderMulti.lean.
//! The rows run end to end against the fake chain in `bounty/tests.rs`
//! ("A desk with several rows").
use super::*;
use crate::bounty::{Entry, Header, Journal, TaskRef, replay};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
};

/// The two journals v0.2.4 wrote for S0001 and S0007 on Base on 2026-11-19
/// (`OUT_DIR/journal.jsonl`), verbatim: one `opened`, one `intent` with its
/// salt, one `posted`. Every field is public on chain.
pub(crate) const S0001_V024: &str = r#"{"block":59433659,"board":"0xd968d5659b3c63cd74d7b4d09345ff3417711038","buyer":"0xca1f8b498d3df887fe9f0a3cd637b059bb35ad1a","chain":8453,"event":"opened","token":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913","vault":"0x952c31aa208dd129059f6065a26b57c930c6ab3c"}
{"deliverBy":1796459511,"event":"intent","fundBy":1796286711,"price":40000000,"salt":"0xf1020a9b4713a88c359a9f5d7663e3cb8961d5d3781e7ec0a08cb4abe949bb0c","task":"0x2c0d846c983546340c3dbbf950812c09bfea7b87df2c54c58ec153f1e026ec61"}
{"event":"posted","task":"0x2c0d846c983546340c3dbbf950812c09bfea7b87df2c54c58ec153f1e026ec61","transaction":"0x014b6ff0e29089d40a8c9f90876d5085d53a0c494548b89580fa6d0febd0e0a9"}
"#;
pub(crate) const S0007_V024: &str = r#"{"block":59433806,"board":"0xd968d5659b3c63cd74d7b4d09345ff3417711038","buyer":"0xca1f8b498d3df887fe9f0a3cd637b059bb35ad1a","chain":8453,"event":"opened","token":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913","vault":"0x952c31aa208dd129059f6065a26b57c930c6ab3c"}
{"deliverBy":1796459540,"event":"intent","fundBy":1796286740,"price":30000000,"salt":"0x39e3619bbadccd67da503d6384833d3a2d9608c15eebbab664f9f4d569b4f821","task":"0xab261afbc2bbe77a31e1c4f61a04afb48ea66e4618a15832dcbacdd5304545cf"}
{"event":"posted","task":"0xab261afbc2bbe77a31e1c4f61a04afb48ea66e4618a15832dcbacdd5304545cf","transaction":"0x80f21dc55f8f6283f598b4df1d2ccc213213fc99aa4a44e323034e3ee6e0e2a9"}
"#;

pub(crate) fn scratch(name: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "nucleus-ladder-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    fs::create_dir_all(dir.join(name)).unwrap();
    dir.join(name).join("journal.jsonl")
}

/// A journal file holding `text`, opened as a restart opens it.
pub(crate) fn reopen(path: &Path, text: &str) -> Shared {
    fs::write(path, text).unwrap();
    let header = replay(text).unwrap().header;
    Arc::new(Mutex::new(Journal::open(path, header).unwrap()))
}

fn task(id: u8, price: u64, fund_by: u64) -> TaskRef {
    TaskRef {
        id: [id; 32],
        price,
        fund_by,
        deliver_by: fund_by + 172_800,
        salt: Some([0x5a; 32]),
    }
}

fn order(task: &TaskRef, digest: u8) -> OrderRef {
    OrderRef {
        digest: [digest; 32],
        amount: task.price,
        order: vault::Order {
            buyer: [0xb1; 20],
            seller: [0x5e; 20],
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
        },
    }
}

fn signed(task: &TaskRef, digest: u8) -> Signed {
    let order = order(task, digest);
    Signed {
        id: task.id,
        order: order.order,
        digest: order.digest,
        payment: String::new(),
        referral: None,
        policy: Policy {
            statement_sha256: [0; 32],
            claim: "Statements.S0001.claim".into(),
            permitted_axioms: vec![],
            maximum_artifact_bytes: 32_768,
        },
    }
}

/// A fresh journal for row `name` with its post open.
fn posted(name: &str, task: &TaskRef) -> Shared {
    let path = scratch(name);
    let header = Header {
        chain: 8453,
        vault: [0x11; 20],
        board: [0xb0; 20],
        token: [0x33; 20],
        buyer: [0xb1; 20],
        block: 1_000,
    };
    let journal = Arc::new(Mutex::new(Journal::open(&path, header).unwrap()));
    {
        let mut journal = journal.lock().unwrap();
        journal.record(Entry::Intent(task.clone())).unwrap();
        journal
            .record(Entry::Posted {
                task: task.id,
                transaction: "0xpost".into(),
            })
            .unwrap();
    }
    journal
}

fn ledger(journal: &Shared) -> Ledger {
    journal.lock().unwrap().ledger().clone()
}

/// The rows of the model's worked examples: S0001 (task 11), S0007 (task
/// 17) and S0006 (task 16), at their caps, with their funding deadlines.
fn rows() -> (TaskRef, TaskRef, TaskRef) {
    (
        task(11, 40_000_000, 1_796_286_711),
        task(17, 30_000_000, 1_796_286_740),
        task(16, 40_000_000, 1_796_979_600),
    )
}
/// 2026-11-27, when the host desk starts.
const NOW: u64 = 1_795_770_111;
const WALLET: u64 = 110_000_000;

fn all(opens: &[Option<Open>], now: u64, phase: Phase) -> u64 {
    opens
        .iter()
        .map(|open| exposure(open, now, &mut |_| Ok(phase)).unwrap())
        .sum()
}

/// G1 to G8 of proofs/commerce/LadderMulti.lean, "The three rows", in the
/// same numbers. Each assertion names its example.
#[test]
fn the_lean_table() {
    let (s1, s7, s6) = rows();
    let posted1 = Some(Open::Posted(s1.clone()));
    let posted7 = Some(Open::Posted(s7.clone()));
    let posted6 = Some(Open::Posted(s6.clone()));

    // G1: S0001 and S0007 posted commit 70; S0006 at 40 is admitted against
    // 110, and then 110 are committed.
    let two = [posted1.clone(), posted7.clone()];
    assert_eq!(all(&two, NOW, Phase::Empty), 70_000_000);
    assert!(covered(s6.price, 70_000_000, WALLET));
    let three = [posted1.clone(), posted7.clone(), posted6.clone()];
    assert_eq!(all(&three, NOW, Phase::Empty), 110_000_000);

    // G2: one base unit short, S0006 is refused.
    assert!(!covered(s6.price, 70_000_000, WALLET - 1));
    // G3: S0006 one base unit over 40 USDC is refused against 110.
    assert!(!covered(s6.price + 1, 70_000_000, WALLET));

    // G4: an offer for S0001's task routes to S0001's row; one for a task no
    // row holds is refused.
    assert_eq!(route(&three, s1.id), Some(0));
    assert_eq!(route(&three, s6.id), Some(2));
    assert_eq!(route(&three, [99; 32]), None);

    // G5: S0001 signed for, not yet funded, is still committed at its cap.
    let signed1 = Some(Open::Signed(s1.clone(), order(&s1, 101)));
    assert_eq!(
        exposure(&signed1, NOW, &mut |_| Ok(Phase::Empty)).unwrap(),
        40_000_000
    );
    let three_signed = [signed1.clone(), posted7.clone(), posted6.clone()];
    assert_eq!(all(&three_signed, NOW, Phase::Empty), 110_000_000);

    // G6: S0001 funded: it commits nothing more, so 70 are committed against
    // the 70 left; the union of the journals explains the deposit, S0007's
    // journal alone does not.
    assert_eq!(
        exposure(&signed1, NOW, &mut |_| Ok(Phase::Funded)).unwrap(),
        0
    );
    assert_eq!(
        exposure(&signed1, NOW, &mut |_| Ok(Phase::Funded)).unwrap()
            + all(&[posted7.clone(), posted6.clone()], NOW, Phase::Empty),
        70_000_000
    );
    let j1 = posted("s0001", &s1);
    let j7 = posted("s0007", &s7);
    let j6 = posted("s0006", &s6);
    record_signature(&[j1.clone(), j7.clone(), j6.clone()], &signed(&s1, 101)).unwrap();
    let ledgers = [ledger(&j1), ledger(&j7), ledger(&j6)];
    assert_eq!(unexplained(&ledgers, &[[101; 32]]), None);
    assert_eq!(unexplained(&ledgers[1..2], &[[101; 32]]), Some([101; 32]));
    assert_eq!(
        unexplained(&ledgers, &[[101; 32], [0xee; 32]]),
        Some([0xee; 32])
    );

    // G7: a second order for S0001 is refused: the row is signed for.
    let error =
        record_signature(&[j1.clone(), j7.clone(), j6.clone()], &signed(&s1, 102)).unwrap_err();
    assert!(error.contains("no row of this desk holds task"), "{error}");
    assert_eq!(ledger(&j1).signed, vec![[101; 32]]);

    // G8: past S0001's funding deadline unfunded, its order commits nothing,
    // and lapsing it leaves S0007's and S0006's journals as they were.
    assert_eq!(
        exposure(&signed1, s1.fund_by + 1, &mut |_| Ok(Phase::Empty)).unwrap(),
        0
    );
    let before = (ledger(&j7), ledger(&j6));
    j1.lock()
        .unwrap()
        .record(Entry::Lapsed {
            digest: [101; 32],
            block: 2_000,
        })
        .unwrap();
    assert_eq!(ledger(&j1).open, None);
    assert_eq!((ledger(&j7), ledger(&j6)), before);
}

/// `offer_routed`: a signature is journaled in its own row's journal and in
/// no other; `offer_refused`: one for a task no row holds is journaled
/// nowhere and the desk releases nothing.
#[test]
fn a_signature_is_journaled_in_the_row_whose_post_it_is_for() {
    let (s1, s7, s6) = rows();
    let journals = [
        posted("s0001", &s1),
        posted("s0007", &s7),
        posted("s0006", &s6),
    ];
    record_signature(&journals, &signed(&s7, 107)).unwrap();
    let opens: Vec<_> = journals.iter().map(|j| ledger(j).open).collect();
    assert!(matches!(&opens[0], Some(Open::Posted(t)) if t.id == s1.id));
    assert!(
        matches!(&opens[1], Some(Open::Signed(t, o)) if t.id == s7.id && o.digest == [107; 32])
    );
    assert!(matches!(&opens[2], Some(Open::Posted(t)) if t.id == s6.id));
    let before: Vec<_> = journals.iter().map(ledger).collect();
    let unknown = task(99, 40_000_000, s1.fund_by);
    assert!(record_signature(&journals, &signed(&unknown, 199)).is_err());
    let after: Vec<_> = journals.iter().map(ledger).collect();
    assert_eq!(before, after);
}

/// Backward compatibility: the journals v0.2.4 wrote replay to an open,
/// resumable post each, opening them writes nothing, and the two together
/// explain no deposit they did not sign for.
#[test]
fn the_v024_journals_replay_unchanged() {
    for (text, task, price, fund_by) in [
        (
            S0001_V024,
            "2c0d846c983546340c3dbbf950812c09bfea7b87df2c54c58ec153f1e026ec61",
            40_000_000,
            1_796_286_711,
        ),
        (
            S0007_V024,
            "ab261afbc2bbe77a31e1c4f61a04afb48ea66e4618a15832dcbacdd5304545cf",
            30_000_000,
            1_796_286_740,
        ),
    ] {
        let path = scratch("row");
        let journal = reopen(&path, text);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            text,
            "opening wrote to it"
        );
        let ledger = ledger(&journal);
        assert_eq!(
            (ledger.posted, ledger.settled, ledger.signed.len()),
            (1, 0, 0)
        );
        let Some(Open::Posted(posted)) = &ledger.open else {
            panic!("not an open post: {:?}", ledger.open);
        };
        assert_eq!(hex(&posted.id), format!("0x{task}"));
        assert_eq!((posted.price, posted.fund_by), (price, fund_by));
        assert!(
            posted.salt.is_some(),
            "a post without its salt cannot be resumed"
        );
        assert_eq!(
            route(std::slice::from_ref(&ledger.open), posted.id),
            Some(0)
        );
    }
    let ledgers = [replay(S0001_V024).unwrap(), replay(S0007_V024).unwrap()];
    // One buyer, one chain, vault, board and token: one desk can hold both.
    assert_eq!(ledgers[0].header.buyer, ledgers[1].header.buyer);
    assert_eq!(
        (
            ledgers[0].header.vault,
            ledgers[0].header.board,
            ledgers[0].header.token
        ),
        (
            ledgers[1].header.vault,
            ledgers[1].header.board,
            ledgers[1].header.token
        )
    );
    assert_eq!(unexplained(&ledgers, &[]), None);
    assert_eq!(unexplained(&ledgers, &[[1; 32]]), Some([1; 32]));
    // Together they commit 70 USDC; S0006 at 40 fits the 110 the wallet holds.
    let opens: Vec<_> = ledgers.iter().map(|l| l.open.clone()).collect();
    assert_eq!(all(&opens, NOW, Phase::Empty), 70_000_000);
    assert!(covered(40_000_000, 70_000_000, WALLET));
}
