//! qed-analytics serve STATE_DIR [ADDRESS]
//!
//! Count beacons forwarded by Caddy on `ADDRESS` (default `127.0.0.1:4462`),
//! keep the state in `STATE_DIR`, and publish each finished week there.
//! contracts/analytics/README.md.
use qed_analytics::{noise::Coins, server, store::Collector};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

pub const DEFAULT_ADDRESS: &str = "127.0.0.1:4462";

fn run(args: &[String]) -> std::io::Result<()> {
    let (dir, address) = match args {
        [cmd, dir] if cmd == "serve" => (PathBuf::from(dir), DEFAULT_ADDRESS),
        [cmd, dir, address] if cmd == "serve" => (PathBuf::from(dir), address.as_str()),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: qed-analytics serve STATE_DIR [ADDRESS]",
            ));
        }
    };
    let collector = Collector::open(&dir, Coins::system()?, server::now_ms())?;
    let listener = TcpListener::bind(address)?;
    eprintln!("qed-analytics: listening on {address}");
    server::serve(listener, Arc::new(Mutex::new(collector)))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("qed-analytics: {e}");
            ExitCode::FAILURE
        }
    }
}
