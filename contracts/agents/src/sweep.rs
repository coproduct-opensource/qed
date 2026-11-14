//! `nucleus-seller sweep CONFIG.json TO [AMOUNT] [--claim HASH]… [--since
//! BLOCK]`: move what the vault paid this seller to `TO`, with no ETH, by an
//! EIP-3009 authorization the gas relayer sends
//! (docs/rfcs/qed-relayer-2026-11-13.md §15).
//!
//! The seller signs `transferWithAuthorization(from = this seller, TO,
//! AMOUNT, …)` with its wallet key. The relayer can send it or not; it cannot
//! change it. If the relayer refuses or does not deliver, a seller with ETH
//! sends the same signed call itself, so the authorization moves the funds at
//! most once.
use crate::prelude::*;
use crate::relay::{
    Delivered, RelayApi, RelayClient, Submission,
    transfer::{self, Authorization},
};
use crate::world::{World, address_arg};
use std::time::Duration;

/// Without `--since` or `startBlock`, claims are looked for this far back:
/// a week of Base's two-second blocks.
pub const WEEK_OF_BLOCKS: u64 = 302_400;
/// The authorization is valid for this long after the chain's latest block.
pub const VALIDITY: u64 = 900;

struct Args {
    config: String,
    to: Address,
    amount: Option<u128>,
    claims: Vec<String>,
    since: Option<u64>,
}

const USAGE: &str =
    "usage: nucleus-seller sweep CONFIG.json TO [AMOUNT] [--claim HASH]... [--since BLOCK]";

fn args(list: &[String]) -> Res<Args> {
    let mut positional = Vec::new();
    let mut claims = Vec::new();
    let mut since = None;
    let mut rest = list.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--claim" => claims.push(rest.next().ok_or(USAGE)?.clone()),
            "--since" => since = Some(rest.next().ok_or(USAGE)?.parse()?),
            flag if flag.starts_with("--") => return Err(format!("unknown flag {flag}").into()),
            _ => positional.push(arg.clone()),
        }
    }
    let (config, to, amount) = match positional.as_slice() {
        [config, to] => (config, to, None),
        [config, to, amount] => (config, to, Some(amount.parse()?)),
        _ => return Err(USAGE.into()),
    };
    Ok(Args {
        config: config.clone(),
        to: address_arg(to)?,
        amount,
        claims,
        since,
    })
}

fn held(chain: &Chain, token: Address, who: Address) -> Res<u128> {
    let word = chain.call(
        [0; 20],
        token,
        &crate::balanceOfCall {
            account: A::from(who),
        }
        .abi_encode(),
    )?;
    u128::try_from(U256::try_from_be_slice(&word).ok_or("balanceOf reply")?)
        .map_err(|_| "balance out of range".into())
}

fn word_of(address: Address) -> [u8; 32] {
    let mut word = [0; 32];
    word[12..].copy_from_slice(&address);
    word
}

/// This seller's own claims from `vault` in `token` since `since`: the
/// transactions of its `Claimed` logs, newest last, at most
/// `transfer::MAXIMUM_CLAIMS`.
fn find_claims(
    chain: &Chain,
    vault: Address,
    token: Address,
    me: Address,
    since: u64,
) -> Res<Vec<String>> {
    let head = u64::from_str_radix(
        chain
            .rpc("eth_blockNumber", json!([]))?
            .as_str()
            .ok_or("head")?
            .trim_start_matches("0x"),
        16,
    )?;
    let logs = chain.logs(
        &json!({"address": hex(&vault), "topics": [
            hex(&transfer::claimed_topic()), hex(&word_of(me)), hex(&word_of(token))]}),
        since,
        head,
    )?;
    let mut hashes: Vec<String> = Vec::new();
    for log in &logs {
        let hash = log["transactionHash"]
            .as_str()
            .ok_or("log without transaction")?
            .to_owned();
        if !hashes.contains(&hash) {
            hashes.push(hash);
        }
    }
    let keep = hashes.len().saturating_sub(transfer::MAXIMUM_CLAIMS);
    Ok(hashes.split_off(keep))
}

/// The transfer landed: status 1 and a `Transfer(from, to, value)` log from
/// the token in the receipt of `hash`.
pub fn landed(
    chain: &Chain,
    hash: &str,
    token: Address,
    from: Address,
    to: Address,
    value: u128,
) -> Res<()> {
    let receipt = chain.rpc("eth_getTransactionReceipt", json!([hash]))?;
    if receipt["status"].as_str() != Some("0x1") {
        return Err(format!("{hash} has no successful receipt").into());
    }
    let topics = [transfer::transfer_topic(), word_of(from), word_of(to)];
    let amount = U256::from(value).to_be_bytes::<32>();
    let found = receipt["logs"].as_array().into_iter().flatten().any(|log| {
        let address = log["address"].as_str().and_then(|a| unhex(a).ok());
        let listed: Vec<Vec<u8>> = log["topics"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|t| t.as_str().and_then(|t| unhex(t).ok()))
            .collect();
        let data = log["data"].as_str().and_then(|d| unhex(d).ok());
        address.as_deref() == Some(token.as_slice())
            && listed.len() == 3
            && listed.iter().zip(&topics).all(|(a, b)| a == b)
            && data.as_deref() == Some(amount.as_slice())
    });
    if !found {
        return Err(format!(
            "{hash} carries no Transfer of {value} from the seller to {}",
            hex(&to)
        )
        .into());
    }
    Ok(())
}

pub fn sweep(list: &[String]) -> Res<()> {
    let args = args(list)?;
    let config: Value = serde_json::from_slice(&fs::read(&args.config)?)?;
    let keys = Keys::read(config["keys"].as_str().ok_or("keys missing")?)?;
    let world = World::read(config["deployment"].as_str().ok_or("deployment missing")?)?;
    let relayer = match config["relayer"].as_str() {
        Some(url) if !(url.starts_with("https://") || url.starts_with("http://127.0.0.1")) => {
            return Err("a relayer must be https:// (or http://127.0.0.1 for a local test)".into());
        }
        other => other.map(str::to_owned),
    };
    let chain = &world.chain;
    let (token, vault, me, to) = (world.token, world.deployment.vault, keys.address(), args.to);
    if to == me {
        return Err("TO is this seller's own address".into());
    }
    let domain =
        transfer::domain_separator(&world.domain.name, &world.domain.version, chain.id, token);
    if transfer::domain_on_chain(chain, token)? != domain {
        return Err(
            "the token's DOMAIN_SEPARATOR differs from its name, version, chain and address".into(),
        );
    }
    let (me_before, to_before, eth_before) = (
        held(chain, token, me)?,
        held(chain, token, to)?,
        chain.balance(me)?,
    );
    println!(
        "sweep: seller {} holds {me_before} token units and {eth_before} wei; {} holds {to_before}",
        hex(&me),
        hex(&to)
    );
    let amount = args.amount.unwrap_or(me_before);
    if amount == 0 {
        return Err("nothing to sweep".into());
    }
    if amount > me_before {
        return Err(format!("{amount} is more than the {me_before} this seller holds").into());
    }
    let claims = if args.claims.is_empty() {
        let since = match args.since.or(config["startBlock"].as_u64()) {
            Some(since) => since,
            None => u64::from_str_radix(
                chain
                    .rpc("eth_blockNumber", json!([]))?
                    .as_str()
                    .ok_or("head")?
                    .trim_start_matches("0x"),
                16,
            )?
            .saturating_sub(WEEK_OF_BLOCKS),
        };
        find_claims(chain, vault, token, me, since)?
    } else {
        args.claims.clone()
    };
    let relayable = if claims.is_empty() {
        println!("sweep: no claim by this seller found; the relayer would refuse");
        false
    } else {
        match transfer::paid(chain, &[vault], token, me, &claims) {
            Ok(paid) => {
                println!(
                    "sweep: claims {claims:?} paid {} since block {}; {} moved out since; bound {}",
                    paid.claimed,
                    paid.since,
                    paid.out,
                    paid.bound()
                );
                amount <= paid.bound()
            }
            Err((status, why)) => {
                println!("sweep: the bound cannot be read ({status}: {why})");
                false
            }
        }
    };
    if !relayable && eth_before == 0 {
        return Err(
            "the relayer would refuse this amount, and this seller has no ETH to send it itself"
                .into(),
        );
    }
    let now = chain.timestamp()?;
    let authorization = Authorization {
        from: me,
        to,
        value: amount,
        valid_after: 0,
        valid_before: now + VALIDITY,
        nonce: random32()?,
    };
    let signed = authorization.sign(&keys.wallet, &domain);
    if signed.signer(&domain) != Some(me) {
        return Err("the signature does not recover to this seller".into());
    }
    let data = signed.calldata();
    let client = relayer
        .filter(|_| relayable)
        .map(|url| RelayClient::new(&url, keys.possession.clone()));
    let nonce = authorization.nonce;
    let delivered = Submission {
        chain,
        relayer: client.as_ref().map(|c| c as &dyn RelayApi),
        target: token,
        data: &data,
        claims: &claims,
        wait: Duration::from_secs(120),
        until: Some(crate::world::wall_clock()? + VALIDITY - 2 * transfer::LANDING_MARGIN),
        poll: Duration::from_secs(3),
        label: "sweep",
    }
    .run(&|| transfer::nonce_used(chain, token, me, nonce), &|| {
        if chain.balance(me)? == 0 {
            return Err("no ETH to send the transfer with its own gas".into());
        }
        chain.send(&keys.wallet, Some(token), 0, &data)
    })?;
    match &delivered {
        Delivered::Relayed { transaction, .. } | Delivered::OwnGas { transaction, .. } => {
            landed(chain, transaction, token, me, to, amount)?;
        }
        Delivered::AlreadyDone => {
            println!("sweep: the authorization's nonce is used on chain; someone else sent it")
        }
    }
    let (me_after, to_after, eth_after) = (
        held(chain, token, me)?,
        held(chain, token, to)?,
        chain.balance(me)?,
    );
    println!("sweep: {delivered:?}");
    println!(
        "sweep: seller {} now holds {me_after} token units and {eth_after} wei; {} holds {to_after}",
        hex(&me),
        hex(&to)
    );
    if me_before.saturating_sub(me_after) != amount || to_after.saturating_sub(to_before) != amount
    {
        println!(
            "sweep: NOTE the balances moved by other than {amount}; another transfer ran meanwhile"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_take_claims_and_since_anywhere() {
        let list: Vec<String> = [
            "seller.json",
            "--claim",
            "0xaa",
            "0x00000000000000000000000000000000000000bb",
            "5",
            "--since",
            "7",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let parsed = args(&list).unwrap();
        assert_eq!(parsed.config, "seller.json");
        assert_eq!(
            parsed.to,
            [0; 19].iter().chain(&[0xbb]).copied().collect::<Vec<u8>>()[..]
        );
        assert_eq!(parsed.amount, Some(5));
        assert_eq!(parsed.claims, vec!["0xaa".to_owned()]);
        assert_eq!(parsed.since, Some(7));
        assert!(args(&["seller.json".to_owned()]).is_err());
        assert!(args(&["a".into(), "0x00".into(), "1".into(), "--bogus".into()]).is_err());
    }
}
