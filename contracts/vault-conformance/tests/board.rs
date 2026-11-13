//! The compiled task board (contracts/board/out, solc 0.8.38) in a local EVM,
//! compared with the Rust reference `nucleus_board_reference` and the model
//! proofs/commerce/Board.lean.
//!
//! Each refusal here was driven red once against a copy of the contract with
//! that check deleted; docs/rfcs/proof-commerce-task-board-2026-11-12.md has
//! the table.
mod common;
use common::*;
use nucleus_board_reference::{self as board, Notice, Task};
use revm::{
    context_interface::result::{ExecutionResult, Output},
    primitives::{Address, TxKind, U256, keccak256},
    state::AccountInfo,
};

const BOARD_BIN: &str = include_str!("../../board/out/NucleusBoard.bin");
const POSTER: Address = Address::new([0xb0; 20]);
const STRANGER: Address = Address::new([0x57; 20]);
const NAMED_VAULT: Address = Address::new([0x7a; 20]);

fn deploy(chain: &mut Chain, vault: Address) -> Address {
    let mut code = unhex(BOARD_BIN);
    code.extend_from_slice(&[0u8; 12]);
    code.extend_from_slice(vault.as_slice());
    chain.create(code)
}
fn task(salt: u8) -> Task {
    Task {
        statement_sha256: [1; 32],
        statement_blake3: [2; 32],
        policy_hash: [3; 32],
        asset: [4; 20],
        maximum_amount: U256::from(250_000u64).to_be_bytes(),
        verifier: [5; 20],
        program: [6; 32],
        fund_by: 1000,
        deliver_by: 2000,
        buyer_node: [7; 32],
        buyer_key_binding: [8; 32],
        salt: [salt; 32],
        buyer_address: "203.0.113.7:4460".into(),
    }
}
fn board_error(selector: &[u8]) -> String {
    for name in [
        "InvalidDeployment()",
        "InvalidTask()",
        "FundingExpired()",
        "AlreadyPosted()",
        "NotPoster()",
        "AlreadyWithdrawn()",
    ] {
        if keccak256(name.as_bytes())[..4] == *selector {
            return name.trim_end_matches("()").to_string();
        }
    }
    format!("unknown error {selector:x?}")
}
/// A call's outcome: the logs it emitted, or the name of its custom error.
fn call(
    chain: &mut Chain,
    from: Address,
    to: Address,
    at: u64,
    data: Vec<u8>,
) -> Result<(Vec<u8>, Vec<Notice>), String> {
    match chain.transact(from, TxKind::Call(to), at, data) {
        ExecutionResult::Success {
            output: Output::Call(bytes),
            logs,
            ..
        } => Ok((
            bytes.to_vec(),
            logs.iter()
                .map(|log| {
                    assert_eq!(log.address, to, "a log from another contract");
                    let topics: Vec<[u8; 32]> = log.data.topics().iter().map(|t| t.0).collect();
                    board::decode_log(&topics, &log.data.data).expect("a board event")
                })
                .collect(),
        )),
        ExecutionResult::Revert { output, .. } => Err(board_error(&output)),
        other => panic!("unexpected EVM outcome: {other:?}"),
    }
}

#[test]
fn the_contract_computes_the_reference_id_and_announces_the_posted_task() {
    let mut chain = Chain::new();
    let b = deploy(&mut chain, NAMED_VAULT);
    let t = task(1);
    let expected = board::id(CHAIN, b.into_array(), POSTER.into_array(), &t);
    let (asked, _) = call(
        &mut chain,
        STRANGER,
        b,
        500,
        board::id_of_call(POSTER.into_array(), &t),
    )
    .unwrap();
    assert_eq!(asked, expected);

    let (returned, notices) = call(&mut chain, POSTER, b, 500, board::post_call(&t)).unwrap();
    assert_eq!(returned, expected);
    let [Notice::Posted(posted)] = notices.as_slice() else {
        panic!("expected one Posted event, got {notices:?}");
    };
    assert_eq!(posted.id, expected);
    assert_eq!(posted.poster, POSTER.into_array());
    assert_eq!(posted.vault, NAMED_VAULT.into_array());
    assert_eq!(posted.task, t);

    let (recorded, _) = call(
        &mut chain,
        STRANGER,
        b,
        500,
        board::poster_of_call(expected),
    )
    .unwrap();
    assert_eq!(&recorded[12..], POSTER.as_slice());
    let (named, _) = call(&mut chain, STRANGER, b, 500, board::vault_call()).unwrap();
    assert_eq!(&named[12..], NAMED_VAULT.as_slice());

    // Another poster, another board or another salt is another task.
    assert_ne!(
        board::id(CHAIN, b.into_array(), STRANGER.into_array(), &t),
        expected
    );
    assert_ne!(
        board::id(CHAIN, b.into_array(), POSTER.into_array(), &task(2)),
        expected
    );
    let (other, _) = call(&mut chain, STRANGER, b, 500, board::post_call(&t)).unwrap();
    assert_eq!(
        other,
        board::id(CHAIN, b.into_array(), STRANGER.into_array(), &t)
    );
}

#[test]
fn a_task_is_posted_at_most_once() {
    let mut chain = Chain::new();
    let b = deploy(&mut chain, NAMED_VAULT);
    let t = task(1);
    call(&mut chain, POSTER, b, 500, board::post_call(&t)).unwrap();
    assert_eq!(
        call(&mut chain, POSTER, b, 501, board::post_call(&t)).unwrap_err(),
        "AlreadyPosted"
    );
    // Withdrawing does not make the ID free again.
    let id = board::id(CHAIN, b.into_array(), POSTER.into_array(), &t);
    call(&mut chain, POSTER, b, 502, board::withdraw_call(id)).unwrap();
    assert_eq!(
        call(&mut chain, POSTER, b, 503, board::post_call(&t)).unwrap_err(),
        "AlreadyPosted"
    );
}

#[test]
fn only_the_poster_withdraws_and_only_once() {
    let mut chain = Chain::new();
    let b = deploy(&mut chain, NAMED_VAULT);
    let t = task(1);
    let id = board::id(CHAIN, b.into_array(), POSTER.into_array(), &t);
    // Nothing to withdraw before it is posted, by anyone.
    assert_eq!(
        call(&mut chain, POSTER, b, 400, board::withdraw_call(id)).unwrap_err(),
        "NotPoster"
    );
    call(&mut chain, POSTER, b, 500, board::post_call(&t)).unwrap();
    assert_eq!(
        call(&mut chain, STRANGER, b, 501, board::withdraw_call(id)).unwrap_err(),
        "NotPoster"
    );
    let (flag, _) = call(&mut chain, STRANGER, b, 501, board::withdrawn_call(id)).unwrap();
    assert_eq!(flag[31], 0);
    let (_, notices) = call(&mut chain, POSTER, b, 502, board::withdraw_call(id)).unwrap();
    assert_eq!(notices, vec![Notice::Withdrawn(id)]);
    let (flag, _) = call(&mut chain, STRANGER, b, 503, board::withdrawn_call(id)).unwrap();
    assert_eq!(flag[31], 1);
    assert_eq!(
        call(&mut chain, POSTER, b, 504, board::withdraw_call(id)).unwrap_err(),
        "AlreadyWithdrawn"
    );
}

#[test]
fn the_contract_refuses_the_posts_the_reference_refuses() {
    let mut chain = Chain::new();
    let b = deploy(&mut chain, NAMED_VAULT);
    type Case = (fn(&mut Task), u64, &'static str);
    let cases: [Case; 13] = [
        (|t| t.statement_sha256 = [0; 32], 500, "InvalidTask"),
        (|t| t.statement_blake3 = [0; 32], 500, "InvalidTask"),
        (|t| t.policy_hash = [0; 32], 500, "InvalidTask"),
        (|t| t.asset = [0; 20], 500, "InvalidTask"),
        (|t| t.maximum_amount = [0; 32], 500, "InvalidTask"),
        (|t| t.verifier = [0; 20], 500, "InvalidTask"),
        (|t| t.program = [0; 32], 500, "InvalidTask"),
        (|t| t.buyer_node = [0; 32], 500, "InvalidTask"),
        (|t| t.buyer_key_binding = [0; 32], 500, "InvalidTask"),
        (|t| t.deliver_by = t.fund_by, 500, "InvalidTask"),
        (|t| t.buyer_address = "x".repeat(129), 500, "InvalidTask"),
        // Its funding deadline has already passed.
        (|_| {}, 1001, "FundingExpired"),
        (|t| t.fund_by = 499, 500, "FundingExpired"),
    ];
    for (change, at, expected) in cases {
        let mut bad = task(9);
        change(&mut bad);
        assert_eq!(bad.refusal(at), Some(expected));
        assert_eq!(
            call(&mut chain, POSTER, b, at, board::post_call(&bad)).unwrap_err(),
            expected
        );
    }
    // The boundaries are accepted: funding deadline now, a 128-byte address.
    let mut edge = task(9);
    edge.buyer_address = "x".repeat(128);
    assert_eq!(edge.refusal(1000), None);
    call(&mut chain, POSTER, b, 1000, board::post_call(&edge)).unwrap();
}

#[test]
fn the_board_takes_no_ether_and_cannot_be_deployed_for_no_vault() {
    let mut chain = Chain::new();
    let b = deploy(&mut chain, NAMED_VAULT);
    chain.db.insert_account_info(
        POSTER,
        AccountInfo {
            balance: U256::from(10u64).pow(U256::from(18u64)),
            ..Default::default()
        },
    );
    for data in [board::post_call(&task(1)), vec![], vec![1, 2, 3, 4]] {
        let outcome =
            chain.transact_with_value(POSTER, TxKind::Call(b), 500, data, U256::from(1u64));
        assert!(
            matches!(outcome, ExecutionResult::Revert { .. }),
            "the board accepted ether: {outcome:?}"
        );
    }
    // The same post without ether goes through, so the refusals above were
    // about the ether.
    call(&mut chain, POSTER, b, 500, board::post_call(&task(1))).unwrap();

    let mut code = unhex(BOARD_BIN);
    code.extend_from_slice(&[0u8; 32]);
    let outcome = chain.transact(ADMIN, TxKind::Create, 1, code);
    let ExecutionResult::Revert { output, .. } = outcome else {
        panic!("a board for the zero vault was deployed");
    };
    assert_eq!(board_error(&output), "InvalidDeployment");
}
