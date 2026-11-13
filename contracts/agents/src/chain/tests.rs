//! R-1 against endpoints that fail on purpose (`fault.rs`). Each test names
//! the failure it drives; the red runs are in
//! docs/rfcs/proof-commerce-standing-bounty-2026-11-13.md.
use super::fault::{QUICK, Reply, Script, serve};
use super::*;
use std::time::{Duration, Instant};

/// Base mainnet's ID, which every scripted endpoint reports unless a test
/// says otherwise.
const ID: &str = "0x2105";

/// Answer `eth_chainId` with `ID`, everything else with `rest`.
fn with_id(mut rest: impl FnMut(&str, &Value, usize) -> Reply + Send + 'static) -> Script {
    Box::new(move |method, params, before| {
        if method == "eth_chainId" {
            Reply::result(json!(ID))
        } else {
            rest(method, params, before)
        }
    })
}
fn chain_of(urls: &[&str]) -> Chain {
    let urls: Vec<String> = urls.iter().map(|url| (*url).to_owned()).collect();
    Chain::connect_any(&urls, QUICK).unwrap()
}

#[test]
fn a_403_that_says_rate_limited_is_waited_out_not_returned() {
    let endpoint = serve(with_id(|_, _, before| {
        // The connect's eth_chainId is request 0.
        if before <= 3 {
            Reply::error(403, -32005, "rate limit exceeded, slow down")
        } else {
            Reply::result(json!("0x10"))
        }
    }));
    let chain = chain_of(&[&endpoint.url]);
    assert_eq!(
        chain.rpc("eth_blockNumber", json!([])).unwrap(),
        json!("0x10")
    );
    assert_eq!(endpoint.count("eth_blockNumber"), 4);
}

#[test]
fn a_retry_after_is_honoured() {
    let endpoint = serve(with_id(|_, _, before| {
        if before == 1 {
            Reply::error(429, -32000, "slow down").header("Retry-After", "1")
        } else {
            Reply::result(json!("0x10"))
        }
    }));
    let chain = chain_of(&[&endpoint.url]);
    chain.rpc("eth_blockNumber", json!([])).unwrap();
    let times = endpoint.times("eth_blockNumber");
    assert_eq!(times.len(), 2);
    // The backoff alone would be 10 to 30 ms.
    assert!(
        times[1] - times[0] >= Duration::from_secs(1),
        "{:?}",
        times[1] - times[0]
    );
}

#[test]
fn a_down_endpoint_fails_over_to_the_next() {
    let down = serve(with_id(|_, _, _| Reply::raw(503, "upstream unavailable")));
    let up = serve(with_id(|_, _, _| Reply::result(json!("0x20"))));
    let chain = chain_of(&[&down.url, &up.url]);
    assert_eq!(
        chain.rpc("eth_blockNumber", json!([])).unwrap(),
        json!("0x20")
    );
    assert_eq!(down.count("eth_blockNumber"), 1);
    // The second endpoint reported the chain's ID before it was used.
    assert_eq!(up.methods(), ["eth_chainId", "eth_blockNumber"]);
    // The down endpoint is backing off, so the next call goes straight on.
    chain.rpc("eth_blockNumber", json!([])).unwrap();
    assert_eq!(down.count("eth_blockNumber"), 1);
}

#[test]
fn publicnodes_403_for_an_unknown_receipt_moves_on_at_once() {
    // The exact reply that crashed the mainnet buyer.
    let archive = serve(with_id(|_, _, _| {
        Reply::error(
            403,
            -32602,
            "Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode",
        )
    }));
    let other = serve(with_id(|_, _, _| Reply::result(Value::Null)));
    let chain = chain_of(&[&archive.url, &other.url]);
    let started = Instant::now();
    let receipt = chain
        .rpc("eth_getTransactionReceipt", json!(["0x01"]))
        .unwrap();
    assert!(receipt.is_null());
    assert!(started.elapsed() < Duration::from_millis(500));
    // Not backed off: the next call asks it first again.
    chain
        .rpc("eth_getTransactionReceipt", json!(["0x01"]))
        .unwrap();
    assert_eq!(archive.count("eth_getTransactionReceipt"), 2);
}

#[test]
fn a_definitive_answer_is_not_retried_anywhere() {
    for message in [
        "nonce too low",
        "insufficient funds for gas * price + value",
        // A revert's own text may say anything, "archive" included.
        "execution reverted: FiatToken: archive request token",
    ] {
        let first = serve(with_id(move |_, _, _| Reply::error(200, -32000, message)));
        let second = serve(with_id(|_, _, _| Reply::result(json!("0x1"))));
        let chain = chain_of(&[&first.url, &second.url]);
        let error = chain.rpc("eth_estimateGas", json!([{}])).unwrap_err();
        assert!(!is_transient(&*error), "{message}: {error}");
        assert!(
            matches!(
                error.downcast_ref::<RpcError>(),
                Some(RpcError::Refused { .. })
            ),
            "{message}: {error}"
        );
        assert_eq!(first.count("eth_estimateGas"), 1, "{message}");
        assert_eq!(second.count("eth_estimateGas"), 0, "{message}");
    }
}

#[test]
fn no_answer_in_time_is_transient_and_bounded() {
    let endpoint = serve(with_id(|_, _, _| Reply::raw(502, "error code: 502")));
    let chain = chain_of(&[&endpoint.url]);
    let started = Instant::now();
    let error = chain.rpc("eth_blockNumber", json!([])).unwrap_err();
    assert!(is_transient(&*error), "{error}");
    assert!(started.elapsed() < QUICK.give_up_after + QUICK.most_backoff * 2);
    assert!(endpoint.count("eth_blockNumber") > 3);
}

#[test]
fn an_endpoint_on_another_chain_is_refused() {
    let down = serve(with_id(|_, _, _| Reply::raw(503, "")));
    let elsewhere = serve(Box::new(|method, _, _| {
        if method == "eth_chainId" {
            Reply::result(json!("0x1"))
        } else {
            Reply::result(json!("0x99"))
        }
    }));
    let chain = chain_of(&[&down.url, &elsewhere.url]);
    let error = chain.rpc("eth_blockNumber", json!([])).unwrap_err();
    assert!(
        matches!(
            error.downcast_ref::<RpcError>(),
            Some(RpcError::WrongChain { found: 1, .. })
        ),
        "{error}"
    );
    assert_eq!(elsewhere.count("eth_blockNumber"), 0);
}

#[test]
fn logs_are_asked_for_in_ranges_the_endpoint_serves_and_paced() {
    let endpoint = serve(with_id(|_, params, _| {
        let number = |field: &str| {
            u64::from_str_radix(
                params[0][field].as_str().unwrap().trim_start_matches("0x"),
                16,
            )
            .unwrap()
        };
        let span = number("toBlock") - number("fromBlock") + 1;
        if span > 1_000 {
            // tenderly's public gateway, word for word but for the number.
            Reply::raw(
                200,
                &json!({"id": 1, "jsonrpc": "2.0", "error": {"code": -32602, "message": "invalid params", "data": format!("Block range too large: maximum 1000 blocks, got {span}")}}).to_string(),
            )
        } else {
            Reply::result(json!([{"blockNumber": params[0]["fromBlock"]}]))
        }
    }));
    let chain = chain_of(&[&endpoint.url]);
    let logs = chain.logs(&json!({"address": "0x00"}), 0, 2_499).unwrap();
    // 2,500 blocks in ranges of 1,000: three answers.
    assert_eq!(logs.len(), 3);
    // The client spaces the moments it sends; the server records when it
    // has read a request, which a busy machine can delay for one request
    // and not the next. On a GitHub runner (2026-11-13, public CI run
    // 43442844200) a gap measured here fell short of the 50 ms spacing, so
    // the check allows 20 ms of that delay. Without spacing the gaps are
    // about a millisecond, so it still fails if the spacing is removed.
    let slack = Duration::from_millis(20);
    let times = endpoint.times("eth_getLogs");
    for pair in times.windows(2) {
        let gap = pair[1] - pair[0];
        assert!(gap + slack >= QUICK.log_spacing, "{gap:?}");
    }
}

/// A node that mines what it is sent: answers what `send` asks, and gives a
/// receipt from the `known`-th time it is asked for one.
fn miner(known: usize) -> impl FnMut(&str, &Value, usize) -> Reply + Send + 'static {
    let mut asked = 0;
    move |method, params, _| match method {
        "eth_getTransactionCount" => Reply::result(json!("0x0")),
        "eth_gasPrice" => Reply::result(json!("0x5f5e100")),
        "eth_estimateGas" => Reply::result(json!("0x5208")),
        "eth_sendRawTransaction" => {
            let raw = unhex(params[0].as_str().unwrap()).unwrap();
            Reply::result(json!(hex(&keccak(&raw))))
        }
        "eth_getTransactionReceipt" => {
            asked += 1;
            if asked < known {
                Reply::result(Value::Null)
            } else {
                Reply::result(
                    json!({"status": "0x1", "gasUsed": "0x5208", "contractAddress": null}),
                )
            }
        }
        _ => Reply::result(Value::Null),
    }
}

#[test]
fn the_crash_loop_receipt_is_found_through_the_next_endpoint() {
    // publicnode: serves everything but a receipt it has not seen.
    let mut serves = miner(1);
    let publicnode = serve(with_id(move |method, params, before| {
        if method == "eth_getTransactionReceipt" {
            Reply::error(
                403,
                -32602,
                "Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode",
            )
        } else {
            serves(method, params, before)
        }
    }));
    let other = serve(with_id(miner(3)));
    let chain = chain_of(&[&publicnode.url, &other.url]);
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let receipt = chain.send(&key, Some([9; 20]), 0, &[]).unwrap();
    assert!(receipt.success);
    // Sent once, to the first endpoint.
    assert_eq!(publicnode.count("eth_sendRawTransaction"), 1);
    assert_eq!(other.count("eth_sendRawTransaction"), 0);
    assert_eq!(other.count("eth_getTransactionReceipt"), 3);
}

#[test]
fn with_only_publicnode_a_missing_receipt_is_transient_not_fatal() {
    let mut serves = miner(1);
    let publicnode = serve(with_id(move |method, params, before| {
        if method == "eth_getTransactionReceipt" {
            Reply::error(
                403,
                -32602,
                "Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode",
            )
        } else {
            serves(method, params, before)
        }
    }));
    let chain = chain_of(&[&publicnode.url]);
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let error = chain.send(&key, Some([9; 20]), 0, &[]).err().unwrap();
    assert!(is_transient(&*error), "{error}");
    assert!(
        matches!(
            error.downcast_ref::<RpcError>(),
            Some(RpcError::NoReceipt { .. })
        ),
        "{error}"
    );
    assert_eq!(publicnode.count("eth_sendRawTransaction"), 1);
}

#[test]
fn the_classes_of_r1() {
    let body = |code: i64, message: &str| {
        json!({"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": message}}).to_string()
    };
    assert!(matches!(
        classify(Some(429), Some("7"), "x"),
        Attempt::Busy { wait: Some(w), .. } if w == Duration::from_secs(7)
    ));
    assert!(matches!(
        classify(Some(403), None, &body(-32005, "limit")),
        Attempt::Busy { .. }
    ));
    assert!(matches!(
        classify(Some(200), None, &body(-32011, "request limit reached")),
        Attempt::Busy { .. }
    ));
    assert!(matches!(classify(Some(525), None, ""), Attempt::Down(_)));
    assert!(matches!(classify(None, None, "refused"), Attempt::Down(_)));
    assert!(matches!(
        classify(Some(200), None, "<html>"),
        Attempt::Down(_)
    ));
    assert!(matches!(
        classify(
            Some(410),
            None,
            "{\"error\":\"This endpoint has been discontinued.\"}"
        ),
        Attempt::Cannot(_)
    ));
    assert!(matches!(
        classify(
            Some(200),
            None,
            &body(
                35,
                "ranges over 10000 blocks are not supported on free plan"
            )
        ),
        Attempt::Cannot(_)
    ));
    assert!(matches!(
        classify(
            Some(200),
            None,
            &body(-32000, "replacement transaction underpriced")
        ),
        Attempt::Refused(_)
    ));
    assert!(matches!(
        classify(Some(200), None, &body(3, "execution reverted")),
        Attempt::Refused(_)
    ));
    assert_eq!(
        classify(
            Some(200),
            None,
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}"
        ),
        Attempt::Answer(Value::Null)
    );
}
