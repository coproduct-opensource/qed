//! How much `settle` calldata a chain's RPC will execute, read-only (QED
//! ladder, build item 11; owner decision D10).
//!
//!   nucleus-vault-ops probe-calldata-read RPC VAULT [MAXIMUM_ARTIFACT_BYTES]
//!
//! Builds third-form `settle(order, artifact, seal)` calldata for the vault
//! with an artifact of N non-zero bytes and a 260-byte seal, and asks the
//! endpoint `eth_call` and `eth_estimateGas` for it. Nothing is signed or
//! sent, and no key or funds are needed.
//!
//! A reply is one of three things:
//!
//! - **executed**: a result, or an execution revert (the order does not exist,
//!   so `settle` reverts). The endpoint took the calldata and ran it;
//! - **refused**: any other JSON-RPC error or HTTP refusal (a request-size
//!   limit, intrinsic gas over the call's gas cap, ...), with its words;
//! - **could not look**: rate limits and network failures, retried a few
//!   times and then reported, never counted as either answer.
//!
//! Then a binary search for the largest N executed. Calldata is mostly
//! non-zero, so this is the costly case for gas.
//!
//! **What this does not measure.** A transaction pool's size limit applies to
//! `eth_sendRawTransaction`, not to `eth_call` or `eth_estimateGas`. Arbitrum
//! Sepolia's refusal at 95,000 bytes ("oversized data") was its pool's, found
//! by sending transactions (`probe-calldata`). This probe finds what the RPC
//! and the EVM accept; whether the pool takes a transaction that large needs
//! a submission, which this command never makes.
use crate::chain::{Attempt, classify, says_reverted};
use crate::prelude::*;
use std::time::Duration;

pub use crate::relay::SEAL_BYTES;

/// One endpoint's answer to one size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Executed: a result, or a revert, whose words follow.
    Executed(String),
    /// Refused, with the endpoint's words.
    Refused(String),
}

/// An answer, or `None` when the exchange decided nothing (busy, down).
pub fn verdict(attempt: &Attempt) -> Option<Verdict> {
    let words = |error: &Value| {
        let mut text = error["message"].as_str().unwrap_or_default().to_owned();
        if let Some(code) = error["code"].as_i64() {
            text = format!("{code}: {text}");
        }
        text
    };
    match attempt {
        Attempt::Answer(_) => Some(Verdict::Executed("result".into())),
        Attempt::Refused(error)
            if says_reverted(
                error["code"].as_i64(),
                error["message"].as_str().unwrap_or(""),
            ) =>
        {
            Some(Verdict::Executed(format!("reverted ({})", words(error))))
        }
        Attempt::Refused(error) => Some(Verdict::Refused(words(error))),
        Attempt::Cannot(text) => Some(Verdict::Refused(text.clone())),
        Attempt::Busy { .. } | Attempt::Down(_) => None,
    }
}

/// The shaped `settle` calldata lives with the relayer, which sizes its gas
/// cap from it (`relay::settle_estimate_bound`); one definition for both.
pub use crate::relay::settle_shaped;

/// What a search found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    /// The largest size executed.
    pub largest_executed: usize,
    /// The smallest size refused, and the words, or `None` if every size up
    /// to the maximum was executed.
    pub smallest_refused: Option<(usize, String)>,
    pub probes: usize,
}

/// Find the boundary in `[1, maximum]`, assuming refusal is monotone in
/// size. `ask` answers one size; `Err` means it could not look, and stops the
/// search.
pub fn search(maximum: usize, ask: &mut dyn FnMut(usize) -> Res<Verdict>) -> Res<Found> {
    let mut probes = 1;
    let mut refused = match ask(maximum)? {
        Verdict::Executed(_) => {
            return Ok(Found {
                largest_executed: maximum,
                smallest_refused: None,
                probes,
            });
        }
        Verdict::Refused(words) => (maximum, words),
    };
    // Invariant: `executed` was executed (0 trivially) and `refused.0` was
    // refused.
    let mut executed = 0;
    while refused.0 - executed > 1 {
        let middle = executed + (refused.0 - executed) / 2;
        probes += 1;
        match ask(middle)? {
            Verdict::Executed(_) => executed = middle,
            Verdict::Refused(words) => refused = (middle, words),
        }
    }
    Ok(Found {
        largest_executed: executed,
        smallest_refused: Some(refused),
        probes,
    })
}

/// One method at one size, with patience for rate limits.
fn ask_once(
    agent: &ureq::Agent,
    rpc: &str,
    method: &str,
    vault: Address,
    bytes: usize,
) -> Res<Verdict> {
    let data = settle_shaped(bytes);
    let call = json!({"from": hex(&[0x99; 20]), "to": hex(&vault), "data": hex(&data)});
    let params = if method == "eth_call" {
        json!([call, "latest"])
    } else {
        json!([call])
    };
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let mut failures = vec![];
    for attempt in 0..6u32 {
        let reply = match agent.post(rpc).send_json(&body) {
            Err(error) => classify(None, None, &error.to_string()),
            Ok(mut response) => {
                let status = response.status().as_u16();
                let text = response.body_mut().read_to_string().unwrap_or_default();
                classify(Some(status), None, &text)
            }
        };
        if let Some(verdict) = verdict(&reply) {
            return Ok(verdict);
        }
        failures.push(format!("{reply:?}"));
        std::thread::sleep(Duration::from_secs(2u64 << attempt.min(4)));
    }
    Err(format!("{method} at {bytes} bytes: could not look: {failures:?}").into())
}

/// `nucleus-vault-ops probe-calldata-read RPC VAULT [MAXIMUM_ARTIFACT_BYTES]`
pub fn probe_calldata_read(args: &[String]) -> Res<()> {
    let (rpc, vault, maximum) = match args {
        [rpc, vault] => (rpc, vault, 4 << 20),
        [rpc, vault, maximum] => (rpc, vault, maximum.parse()?),
        _ => {
            return Err("usage: probe-calldata-read RPC VAULT [MAXIMUM_ARTIFACT_BYTES]".into());
        }
    };
    let vault = crate::world::address_arg(vault)?;
    let chain = Chain::connect(rpc)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(120)))
        .build()
        .into();
    println!(
        "chain {} at {rpc}: settle calldata to {} is {} bytes plus the artifact",
        chain.id,
        hex(&vault),
        settle_shaped(0).len()
    );
    for method in ["eth_call", "eth_estimateGas"] {
        let mut ask = |bytes| {
            let verdict = ask_once(&agent, rpc, method, vault, bytes)?;
            println!("  {method} {bytes:>9} artifact bytes: {verdict:?}");
            Ok(verdict)
        };
        let found = search(maximum, &mut ask)?;
        println!(
            "{method}: largest artifact executed {} bytes ({} bytes of calldata); smallest refused {:?}; {} probes",
            found.largest_executed,
            settle_shaped(found.largest_executed).len(),
            found.smallest_refused,
            found.probes
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Base boundary measured on 2026-11-14 (418,336 executed, 418,337
    /// refused at a 16,777,216-gas allowance) is exactly where a floor of 10
    /// gas per calldata token (zero byte 1, non-zero byte 4) plus 21,000
    /// crosses 2^24.
    #[test]
    fn the_measured_base_boundary_is_the_calldata_floor_at_two_to_the_24() {
        let floor = |bytes: usize| {
            let data = settle_shaped(bytes);
            let zeros = data.iter().filter(|b| **b == 0).count() as u64;
            21_000 + 10 * (zeros + 4 * (data.len() as u64 - zeros))
        };
        assert_eq!((floor(418_336), floor(418_337)), (16_777_060, 16_777_440));
        assert!(floor(418_336) <= 1 << 24 && floor(418_337) > 1 << 24);
    }

    #[test]
    fn the_calldata_is_settle_with_the_artifact_and_seal() {
        let data = settle_shaped(1000);
        let call = crate::world::third::settleCall::abi_decode(&data).unwrap();
        assert_eq!(call.artifact.len(), 1000);
        assert_eq!(call.seal.len(), SEAL_BYTES);
        // Growth is the artifact, padded to a word.
        assert_eq!(settle_shaped(1024).len() - settle_shaped(0).len(), 1024);
    }

    #[test]
    fn replies_are_executed_refused_or_nothing() {
        let reverted = classify(
            Some(200),
            None,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted"}}"#,
        );
        assert!(matches!(verdict(&reverted), Some(Verdict::Executed(_))));
        let answered = classify(Some(200), None, r#"{"jsonrpc":"2.0","id":1,"result":"0x"}"#);
        assert!(matches!(verdict(&answered), Some(Verdict::Executed(_))));
        let gas = classify(
            Some(200),
            None,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"intrinsic gas too high"}}"#,
        );
        assert_eq!(
            verdict(&gas),
            Some(Verdict::Refused("-32000: intrinsic gas too high".into()))
        );
        let too_large = classify(Some(413), None, "Request Entity Too Large");
        assert!(matches!(verdict(&too_large), Some(Verdict::Refused(_))));
        assert_eq!(verdict(&classify(Some(429), None, "slow down")), None);
        assert_eq!(verdict(&classify(None, None, "connection reset")), None);
    }

    fn limit(at: usize) -> impl FnMut(usize) -> Res<Verdict> {
        move |bytes| {
            Ok(if bytes <= at {
                Verdict::Executed("reverted".into())
            } else {
                Verdict::Refused(format!("too big at {bytes}"))
            })
        }
    }

    #[test]
    fn the_search_finds_the_boundary_exactly() {
        for at in [1, 2, 95_000, 131_071, 1_000_000] {
            let found = search(4 << 20, &mut limit(at)).unwrap();
            assert_eq!(found.largest_executed, at, "{at}");
            assert_eq!(
                found.smallest_refused,
                Some((at + 1, format!("too big at {}", at + 1))),
                "{at}"
            );
            assert!(found.probes <= 2 * 23 + 2, "{at}: {} probes", found.probes);
        }
    }

    #[test]
    fn the_search_reports_no_refusal_up_to_the_maximum_and_stops_when_it_cannot_look() {
        let found = search(1 << 20, &mut limit(usize::MAX)).unwrap();
        assert_eq!(found.largest_executed, 1 << 20);
        assert_eq!(found.smallest_refused, None);
        // A size that cannot be asked is not an answer.
        let mut blind = |_| -> Res<Verdict> { Err("down".into()) };
        assert!(search(1 << 20, &mut blind).is_err());
        // Nothing executed at all.
        let found = search(1 << 20, &mut limit(0)).unwrap();
        assert_eq!(found.largest_executed, 0);
        assert_eq!(found.smallest_refused, Some((1, "too big at 1".into())));
    }
}
