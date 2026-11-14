//! `nucleus-seller CONFIG.json` — see `seller.rs` for the configuration and
//! the exchange. `nucleus-seller watch CONFIG.json` answers the task board
//! instead of waiting for buyers (`watch.rs`). `nucleus-seller sweep CONFIG.json TO
//! [AMOUNT]` moves what the vault paid to `TO` without ETH (`sweep.rs`). Prints `iroh:<node id>@<ip:port>`, which is what a buyer is
//! given.
use nucleus_commerce_agents::{chain::Res, http, iroh_net, seller};
use std::{
    net::TcpListener,
    sync::{Arc, Mutex},
    time::Duration,
};

fn run(args: &[String]) -> Res<()> {
    if let Some((command, rest)) = args.split_first()
        && command == "watch"
    {
        return nucleus_commerce_agents::watch::watch(rest);
    }
    if let Some((command, rest)) = args.split_first()
        && command == "sweep"
    {
        return nucleus_commerce_agents::sweep::sweep(rest);
    }
    let [config] = args else {
        return Err("usage: nucleus-seller CONFIG.json".into());
    };
    let config = seller::Config::read(config)?;
    if config.iroh_bind.is_none() && config.http_listen.is_none() {
        return Err("configure irohBind, httpListen or both".into());
    }
    let (seller, keys) = seller::from_config(&config)?;
    let jobs = seller.jobs();
    let seller = Arc::new(Mutex::new(seller));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let _router = match &config.iroh_bind {
        None => None,
        Some(bind) => {
            let bind = bind.parse()?;
            let endpoint = runtime.block_on(async {
                iroh_net::endpoint_in(keys.node, bind, &config.relay)
                    .await
                    .map_err(|e| e.to_string())
            })?;
            println!(
                "seller: reachable at {} (relay {:?})",
                iroh_net::address_text_in(&endpoint, &config.relay)?,
                config.relay
            );
            let _guard = runtime.enter();
            // The same handler under both protocols: `nucleus-commerce/1` and
            // A2A 1.0 over iroh (a buyer reaches the latter at `a2a+iroh:…`).
            let card = nucleus_commerce_agents::a2a::card(
                &endpoint.id().to_string(),
                "Lean proof seller",
                "Sells proofs of pinned Lean statements. A contract releases payment when a proof of the check verifies.",
                env!("CARGO_PKG_VERSION"),
            );
            Some(nucleus_commerce_agents::a2a_iroh::serve_seller(
                endpoint,
                seller.clone(),
                &card,
            ))
        }
    };
    if let Some(listen) = &config.http_listen {
        let listener = TcpListener::bind(listen)?;
        println!("seller: also listening for HTTP on {listen}");
        let seller = seller.clone();
        std::thread::spawn(move || http::serve(listener, seller));
    }
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let settled = jobs.lock().map_err(|_| "job table poisoned")?.settled();
        if config.stop_after.is_some_and(|limit| settled >= limit) {
            // Leave time for the buyer to collect the last delivery.
            std::thread::sleep(Duration::from_secs(90));
            return Ok(());
        }
    }
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    nucleus_commerce_agents::exit(run(&args))
}
