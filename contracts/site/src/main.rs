//! nucleus-site build OUT_DIR --input FILE --repository DIR [--site-url URL]
//!         [--ledger input/ledger.json] [--card-key FILE] [--source-commit HASH]
//!     Write the static site for one deployment into OUT_DIR/site, and the
//!     documents its extension identifiers dereference to into OUT_DIR/apex
//!     (they belong on the apex host, https://coproduct.one/). Every option
//!     after --repository may be left out; the site then says what it lacks.
//! nucleus-site snapshot input/ledger.json NOW
//!     Read every settlement the ledger names from its chain (read-only
//!     JSON-RPC) and write input/ledger.snapshot.json and input/artifacts/.
//! nucleus-site snapshot-status input/arbitrum-sepolia.json NOW
//!     Read the main network's bounty, vaults and relayer at the latest
//!     block (read-only JSON-RPC, and one POST without a proof to the
//!     relayer) and write input/status.snapshot.json for the status page.
//! nucleus-site refresh-status INPUT STATE_DIR SITE_URL
//!     The web host's reader, every 10 minutes: the same reads as
//!     snapshot-status, now, then only the status page (HTML and Markdown)
//!     written atomically under STATE_DIR/site/status/. On a failed read,
//!     the last good values are shown with their age, and it exits 1.
//!     Needs no key. docs/rfcs/qed-status-refresh-2026-11-17.md.
//! nucleus-site market-capture INPUT OUT
//!     Scan the main network's board and vaults from their deploy blocks
//!     (read-only JSON-RPC) and write the market index, addresses filtered
//!     for publication, to OUT: the fixture of contracts/site/tests/market.rs.
//!     The authors' wallet list is read from authors-wallets.txt beside INPUT.
//! nucleus-site card-key-create FILE
//!     Make a new ES256 card-signing key file (mode 0600); refuses to overwrite.
//! nucleus-site preview DIR 127.0.0.1:PORT
//!     Serve a built site to a browser on this machine, to look at it.
//! nucleus-site caddy HOST ROOT
//!     Print a Caddyfile site block that serves ROOT for HOST, from the same
//!     serving table the preview and check-live use.
//! nucleus-site check-live URL BUILT_SITE_DIR
//!     After upload: fetch what URL serves and compare it with the built files
//!     and the serving table. Exit 1 on any finding.
//! nucleus-site keccak-hex FILE
//!     Keccak-256 and length of the bytes a hex file holds (the `result` of
//!     `eth_getCode`), for filling in an input file.
use nucleus_site::{
    Input, Options, Res, apex, hex,
    ledger::{self, LedgerInput, Snapshot},
    live, serving, signing, site, unhex,
};
use std::{fs, path::Path, process::ExitCode};

fn write(out: &Path, files: Vec<(String, Vec<u8>)>) -> Res<()> {
    for (path, bytes) in files {
        let target = out.join(&path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, &bytes)?;
        println!("{:>8} bytes  {}", bytes.len(), target.display());
    }
    Ok(())
}

fn run(args: &[String]) -> Res<()> {
    match args {
        [command, file] if command == "keccak-hex" => {
            let bytes = unhex(&fs::read_to_string(file)?)?;
            println!(
                "bytes {} keccak256 0x{}",
                bytes.len(),
                hex(alloy_primitives::keccak256(&bytes).as_slice())
            );
            Ok(())
        }
        [command, out, address] if command == "preview" => {
            nucleus_site::preview::serve(Path::new(out), address)
        }
        [command, host, root] if command == "caddy" => {
            print!("{}", serving::caddy(host, root));
            Ok(())
        }
        [command, url, built] if command == "check-live" => {
            let findings = live::check(url, Path::new(built))?;
            for (path, what) in &findings {
                println!("FAIL {path}: {what}");
            }
            if findings.is_empty() {
                println!(
                    "ok: every checked path matches the built files and the serving table; /status by frame, structure, age and addresses"
                );
                Ok(())
            } else {
                Err(format!("{} finding(s)", findings.len()).into())
            }
        }
        [command, input_file, out] if command == "market-capture" => {
            let path = Path::new(input_file);
            let input = Input::read(path)?;
            let chain = nucleus_site::market::chain_of(&input)?;
            let url = input.mainnet.as_ref().ok_or("main network")?.network.rpc.clone();
            let (index, _) = nucleus_site::market::read(
                &mut |method, params| ledger::rpc(&url, method, params),
                &chain,
                None,
            )?;
            let names = nucleus_site::market::names(&input, path.parent().ok_or("input path")?)?;
            let public = nucleus_site::market::filtered(&index, &names);
            fs::write(out, serde_json::to_string_pretty(&public)? + "\n")?;
            println!(
                "block {}; {} events; {} calls; wrote {out}",
                public.cursor,
                public.events.len(),
                public.scan.calls
            );
            Ok(())
        }
        [command, input_file, now] if command == "snapshot-status" => {
            let path = Path::new(input_file);
            let input = Input::read(path)?;
            let now: u64 = now.parse().map_err(|_| "NOW must be a Unix time in seconds")?;
            // The buyer's signed delivery summary, fetched just before by
            // `nucleus-buyer deliveries-fetch NODE input/deliveries.jws`.
            let deliveries = fs::read_to_string(
                path.parent()
                    .ok_or("input path")?
                    .join(nucleus_site::status::DELIVERIES_FILE),
            )
            .ok();
            // The committed snapshot's index is filtered, so this reads the
            // chain from the deploy blocks; the copy written is filtered again.
            let dir = path.parent().ok_or("input path")?;
            let names = nucleus_site::market::names(&input, dir)?;
            let value = nucleus_site::status::snapshot(&input, now, deliveries.as_deref(), None)?;
            let mut value = nucleus_site::status::public(&value, &names);
            // Without a fresh deliveries.jws, keep the record the committed
            // snapshot carries, with its own read time.
            let out_path = dir.join("status.snapshot.json");
            if deliveries.is_none()
                && let Ok(old) = fs::read(&out_path)
                && let Ok(old) = serde_json::from_slice::<serde_json::Value>(&old)
                && old["deliveries"]["jws"].is_string()
            {
                value["deliveries"] = old["deliveries"].clone();
                println!("no {}: kept the committed delivery record", nucleus_site::status::DELIVERIES_FILE);
            }
            let out = path.parent().ok_or("input path")?.join("status.snapshot.json");
            fs::write(&out, serde_json::to_string_pretty(&value)? + "\n")?;
            println!(
                "block {}; {} posts; wrote {}",
                value["block"],
                value["posts"].as_array().map_or(0, Vec::len),
                out.display()
            );
            Ok(())
        }
        [command, input_file, state, site_url] if command == "refresh-status" => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let pass = nucleus_site::status::refresh(
                Path::new(input_file),
                Path::new(state),
                site_url,
                now,
            )?;
            if let Some(snap) = &pass.snapshot {
                println!(
                    "block {} (timestamp {}); wrote {}",
                    snap["block"],
                    snap["blockTimestamp"],
                    Path::new(state).join(nucleus_site::status::LAST_GOOD).display()
                );
            }
            if pass.pages.is_some() {
                println!(
                    "wrote {} and {}",
                    Path::new(state).join(nucleus_site::status::SERVED_MD).display(),
                    Path::new(state).join(nucleus_site::status::SERVED_HTML).display()
                );
            }
            match (pass.failure, pass.pages.is_some()) {
                (None, _) => Ok(()),
                (Some(why), true) => Err(format!(
                    "the read failed ({why}); the page shows the last good values and their age"
                )
                .into()),
                (Some(why), false) => Err(format!(
                    "the read failed ({why}) and there is no earlier read; nothing written, the release's page is served"
                )
                .into()),
            }
        }
        [command, ledger_file, now] if command == "snapshot" => {
            let path = Path::new(ledger_file);
            let input = LedgerInput::read(path)?;
            let now: u64 = now.parse().map_err(|_| "NOW must be a Unix time in seconds")?;
            let count = ledger::snapshot(&input, path.parent().ok_or("ledger path")?, now)?;
            println!("{count} settlements read; wrote ledger.snapshot.json and artifacts/");
            Ok(())
        }
        [command, path] if command == "card-key-create" => {
            signing::create_key(Path::new(path))?;
            let key = signing::load_key(Path::new(path))?;
            println!("kid {}", signing::thumbprint(key.verifying_key()));
            Ok(())
        }
        [command, out, rest @ ..] if command == "build" => {
            let (mut input, mut repository, mut site_url) = (None, None, None);
            let (mut ledger_file, mut card_key, mut commit) = (None, None, None);
            let mut rest = rest.iter();
            while let Some(flag) = rest.next() {
                let value = rest.next().ok_or_else(|| format!("{flag} needs a value"))?;
                match flag.as_str() {
                    "--input" => input = Some(value),
                    "--repository" => repository = Some(value),
                    "--site-url" => site_url = Some(value),
                    "--ledger" => ledger_file = Some(value),
                    "--card-key" => card_key = Some(value),
                    "--source-commit" => commit = Some(value),
                    other => return Err(format!("unknown option {other}").into()),
                }
            }
            let input = Input::read(Path::new(input.ok_or("--input FILE is required")?))?;
            let repository = Path::new(repository.ok_or("--repository DIR is required")?);
            if site_url.is_some_and(|url| !url.starts_with("https://")) {
                return Err("--site-url must be an https URL".into());
            }
            let site_url = site_url.map(String::as_str);
            let ledger = match ledger_file {
                Some(file) => {
                    let path = Path::new(file);
                    let snapshot = Snapshot::read(
                        &path.parent().ok_or("ledger path")?.join("ledger.snapshot.json"),
                    )?;
                    Some((LedgerInput::read(path)?, snapshot))
                }
                None => None,
            };
            let key = card_key.map(|k| signing::load_key(Path::new(k))).transpose()?;
            let options = Options {
                site_url,
                ledger: ledger.as_ref().map(|(i, s)| (i, s)),
                card_key: key.as_ref(),
                source_commit: commit.map(String::as_str),
            };
            let out = Path::new(out);
            write(&out.join("site"), site(&input, repository, &options)?)?;
            write(&out.join("apex"), apex(repository, site_url)?)?;
            if site_url.is_none() {
                println!("built without --site-url: no canonical links, sitemap or card documentation link");
            }
            if key.is_none() {
                println!("built without --card-key: the card is not signed");
            }
            if ledger.is_none() {
                println!("built without --ledger: no receipts or transaction pages");
            }
            Ok(())
        }
        _ => Err("usage: nucleus-site build OUT_DIR --input FILE --repository DIR [--site-url URL] [--ledger input/ledger.json] [--card-key FILE] [--source-commit HASH] | snapshot input/ledger.json NOW | snapshot-status input/arbitrum-sepolia.json NOW | refresh-status INPUT STATE_DIR SITE_URL | card-key-create FILE | preview DIR 127.0.0.1:PORT | caddy HOST ROOT | check-live URL BUILT_SITE_DIR | keccak-hex FILE".into()),
    }
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
