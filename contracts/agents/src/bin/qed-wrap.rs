//! `qed-wrap CONFIG.json` — the optional Groth16 wrap service (`wrap.rs`).
//!
//! ```json
//! {"listen": "127.0.0.1:4460", "base": "https://wrap.example",
//!  "proofHost": "/usr/local/bin/nucleus-acceptance-host",
//!  "groth16Data": "/var/lib/qed-wrap/risc0-groth16", "workDir": "/var/lib/qed-wrap/work",
//!  "allowed": [{"chainId": 421614, "vault": "0x…"}],
//!  "maximumReceiptBytes": 1048576, "perKeyPerHour": 20, "perAddressPerHour": 60,
//!  "queue": 4, "trustForwardedFor": false}
//! ```
//! `base` is the URL the service is reached at, which every proof must name.
//! Serve it behind TLS; set `trustForwardedFor` only behind a local proxy.
use nucleus_commerce_agents::{
    chain::{Res, unhex},
    wrap::{HostBackend, Policy, Service, serve},
};
use serde_json::Value;
use std::{net::TcpListener, path::PathBuf, process::ExitCode, sync::Arc};

/// `qed-wrap request URL PREFIX RECEIPT HOST SEAL_OUT`: what a seller does,
/// on its own. Asks the service at URL to wrap the succinct RECEIPT, checks
/// the answer with the prover HOST (the receipt's own journal, the returned
/// Groth16 receipt verified for the program, the seal derived from it), and
/// writes the seal as hex.
fn request(args: &[String]) -> Res<()> {
    let [url, prefix, receipt, host, out] = args else {
        return Err("usage: qed-wrap request URL PREFIX RECEIPT HOST SEAL_OUT".into());
    };
    let own = std::process::Command::new(host)
        .arg(format!("{prefix}-verify"))
        .arg(receipt)
        .output()?;
    if !own.status.success() {
        return Err("the receipt does not verify for this program".into());
    }
    let journal = unhex(
        String::from_utf8(own.stdout)?
            .lines()
            .find_map(|l| l.strip_prefix("journal "))
            .ok_or("host printed no journal")?,
    )?;
    let started = std::time::Instant::now();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let key = nucleus_commerce_agents::wrap::WrapKey::fresh()?;
    let answer =
        nucleus_commerce_agents::wrap::request(url, prefix, &std::fs::read(receipt)?, &key, now)?;
    let asked = started.elapsed();
    let work = std::env::temp_dir().join(format!("qed-wrap-request-{}", std::process::id()));
    let seal = nucleus_commerce_agents::wrap::accept_answer(host, prefix, &journal, &answer, &work);
    let _ = std::fs::remove_dir_all(&work);
    let seal = seal?;
    std::fs::write(out, nucleus_commerce_agents::chain::hex(&seal))?;
    println!(
        "seal {} bytes; service answered in {:.1} s; checked locally in {:.1} s",
        seal.len(),
        asked.as_secs_f64(),
        (started.elapsed() - asked).as_secs_f64()
    );
    Ok(())
}

/// `qed-wrap relay CONFIG.json`: the gas relayer (`relay.rs`,
/// docs/rfcs/qed-relayer-2026-11-13.md).
///
/// ```json
/// {"listen": "127.0.0.1:4461", "base": "https://relay.example",
///  "key": "/var/lib/qed-relay/relayer.keys",
///  "chains": [{"chainId": 8453, "rpcs": ["https://mainnet.base.org"],
///              "vaults": ["0x8917c501755f966a5b5f20d6608e297e7066f13b"],
///              "maximumFeePerGasWei": "100000000", "budgetWei": "5000000000000000",
///              "floorWei": "200000000000000",
///              "transfer": {"token": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
///                           "name": "USD Coin", "version": "2",
///                           "perAddressPerDay": 5, "perDay": 100}}],
///  "perKeyPerHour": 20, "perAddressPerHour": 60, "perSellerPerDay": 30,
///  "maximumGasPerCall": 600000, "replaceAfterSeconds": 60, "maximumReplacements": 3,
///  "trustForwardedFor": false}
/// ```
/// The key file is created (mode 0600) on first start if absent; only its
/// address is printed.
fn relay(args: &[String]) -> Res<()> {
    use nucleus_commerce_agents::relay::{Lane, LaneConfig, Limits, Relay, serve, transfer};
    let [config] = args else {
        return Err("usage: qed-wrap relay CONFIG.json".into());
    };
    let value: Value = serde_json::from_slice(&std::fs::read(config)?)?;
    let text = |v: &Value, name: &str| -> Res<String> {
        Ok(v[name]
            .as_str()
            .ok_or_else(|| format!("{name} missing"))?
            .to_owned())
    };
    let wei = |v: &Value, name: &str| -> Res<u128> { Ok(text(v, name)?.parse()?) };
    let defaults = Limits::default();
    let number = |name: &str, default: u64| value[name].as_u64().unwrap_or(default);
    let limits = Limits {
        per_key_per_hour: number("perKeyPerHour", defaults.per_key_per_hour as u64) as usize,
        per_address_per_hour: number("perAddressPerHour", defaults.per_address_per_hour as u64)
            as usize,
        per_seller_per_day: number("perSellerPerDay", defaults.per_seller_per_day as u64) as usize,
        maximum_gas_per_call: u128::from(number(
            "maximumGasPerCall",
            defaults.maximum_gas_per_call as u64,
        )),
        replace_after: std::time::Duration::from_secs(number(
            "replaceAfterSeconds",
            defaults.replace_after.as_secs(),
        )),
        maximum_replacements: number(
            "maximumReplacements",
            u64::from(defaults.maximum_replacements),
        ) as u32,
    };
    let keys = nucleus_commerce_agents::support::Keys::load_or_create(&text(&value, "key")?)?;
    let mut lanes = Vec::new();
    for entry in value["chains"].as_array().ok_or("chains missing")? {
        let rpcs: Vec<String> = entry["rpcs"]
            .as_array()
            .ok_or("chains.rpcs missing")?
            .iter()
            .map(|url| {
                url.as_str()
                    .map(str::to_owned)
                    .ok_or("rpcs entries are URLs")
            })
            .collect::<Result<_, _>>()?;
        let chain = nucleus_commerce_agents::chain::Chain::connect_any(
            &rpcs,
            nucleus_commerce_agents::chain::Patience::DEFAULT,
        )?;
        let expected = entry["chainId"].as_u64().ok_or("chains.chainId missing")?;
        if chain.id != expected {
            return Err(format!("RPC reports chain {}, config says {expected}", chain.id).into());
        }
        let mut vaults = Vec::new();
        for vault in entry["vaults"].as_array().ok_or("chains.vaults missing")? {
            vaults.push(
                unhex(vault.as_str().ok_or("vault")?)?
                    .try_into()
                    .map_err(|_| "vault length")?,
            );
        }
        if vaults.is_empty() {
            return Err("a chain lists no vault".into());
        }
        // T-1: `"transfer": {"token", "name", "version", "perAddressPerDay",
        // "perDay"}`. The domain is computed from the name, version, chain and
        // token, and the relayer refuses to start unless the token reports
        // the same one.
        let transfer = match entry.get("transfer") {
            None | Some(Value::Null) => None,
            Some(t) => {
                let token: [u8; 20] = unhex(&text(t, "token")?)?
                    .try_into()
                    .map_err(|_| "transfer.token length")?;
                let domain = transfer::domain_separator(
                    &text(t, "name")?,
                    &text(t, "version")?,
                    chain.id,
                    token,
                );
                if transfer::domain_on_chain(&chain, token)? != domain {
                    return Err(format!(
                        "token {} reports another EIP-712 domain than its configured name and version",
                        nucleus_commerce_agents::chain::hex(&token)
                    )
                    .into());
                }
                let count = |name: &str| -> Res<usize> {
                    Ok(t[name]
                        .as_u64()
                        .ok_or_else(|| format!("transfer.{name} missing"))?
                        as usize)
                };
                Some(transfer::TransferConfig {
                    token,
                    domain,
                    per_address_per_day: count("perAddressPerDay")?,
                    per_day: count("perDay")?,
                })
            }
        };
        let config = LaneConfig {
            vaults,
            maximum_fee_per_gas: wei(entry, "maximumFeePerGasWei")?,
            budget: wei(entry, "budgetWei")?,
            floor: wei(entry, "floorWei")?,
            transfer,
        };
        println!(
            "qed-wrap relay: chain {} with {} vault(s); balance {} wei; floor {} wei; budget {} wei",
            chain.id,
            config.vaults.len(),
            chain.balance(keys.address())?,
            config.floor,
            config.budget
        );
        if let Some(t) = &config.transfer {
            println!(
                "qed-wrap relay: transfers on chain {}: transferWithAuthorization on token {} (domain {} as the token reports); {} per address and {} in all per day",
                chain.id,
                nucleus_commerce_agents::chain::hex(&t.token),
                nucleus_commerce_agents::chain::hex(&t.domain),
                t.per_address_per_day,
                t.per_day
            );
        }
        lanes.push(Lane::new(chain, config));
    }
    let relay = Relay::new(&text(&value, "base")?, keys.wallet.clone(), limits, lanes)?;
    let listener = TcpListener::bind(text(&value, "listen")?)?;
    println!(
        "qed-wrap relay: listening on {} for {}; relayer address {}",
        listener.local_addr()?,
        relay.base,
        nucleus_commerce_agents::chain::hex(&relay.address())
    );
    serve(
        listener,
        Arc::new(relay),
        value["trustForwardedFor"].as_bool().unwrap_or(false),
    );
    Ok(())
}

fn run(args: &[String]) -> Res<()> {
    if let Some((command, rest)) = args.split_first() {
        if command == "request" {
            return request(rest);
        }
        if command == "relay" {
            return relay(rest);
        }
    }
    let [config] = args else {
        return Err(
            "usage: qed-wrap CONFIG.json | qed-wrap request URL PREFIX RECEIPT HOST SEAL_OUT"
                .into(),
        );
    };
    let value: Value = serde_json::from_slice(&std::fs::read(config)?)?;
    let text = |name: &str| -> Res<String> {
        Ok(value[name]
            .as_str()
            .ok_or_else(|| format!("{name} missing"))?
            .to_owned())
    };
    let number = |name: &str, default: u64| value[name].as_u64().unwrap_or(default) as usize;
    let mut allowed = Vec::new();
    for entry in value["allowed"].as_array().ok_or("allowed missing")? {
        let chain = entry["chainId"].as_u64().ok_or("allowed.chainId")?;
        let vault: [u8; 20] = unhex(entry["vault"].as_str().ok_or("allowed.vault")?)?
            .try_into()
            .map_err(|_| "allowed.vault length")?;
        allowed.push((chain, vault));
    }
    if allowed.is_empty() {
        return Err("allowed lists no vault".into());
    }
    let policy = Policy {
        allowed,
        maximum_receipt: number("maximumReceiptBytes", 1 << 20),
        per_key_per_hour: number("perKeyPerHour", 20),
        per_address_per_hour: number("perAddressPerHour", 60),
        queue: number("queue", 4),
    };
    let backend = HostBackend {
        host: text("proofHost")?,
        data: value["groth16Data"].as_str().map(str::to_owned),
        work: PathBuf::from(text("workDir")?),
    };
    let base = text("base")?;
    let listener = TcpListener::bind(text("listen")?)?;
    println!(
        "qed-wrap: listening on {} for {base}; {} vault(s) allowed",
        listener.local_addr()?,
        policy.allowed.len()
    );
    let service = Arc::new(Service::new(policy, &base, Arc::new(backend)));
    serve(
        listener,
        service,
        value["trustForwardedFor"].as_bool().unwrap_or(false),
    );
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("refused: {error}");
            ExitCode::FAILURE
        }
    }
}
