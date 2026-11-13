//! `nucleus-buyer DEPLOYMENT KEYFILE SELLER STATEMENT PROGRAM_HEX MAXIMUM_PRICE OUT_DIR`
//!   asks one seller directly (`buyer.rs`).
//! `nucleus-buyer post DEPLOYMENT BOARD KEYFILE STATEMENT PROGRAM_HEX MAXIMUM_PRICE BIND OUT_DIR`
//!   posts a task on the board and waits at its desk (`post.rs`).
//! `nucleus-buyer post-tasks DEPLOYMENT BOARD KEYFILE BIND OUT_DIR TASK.json...`
//!   posts several tasks from task files and waits at one desk (`tasks.rs`).
fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    nucleus_commerce_agents::exit(match args.split_first() {
        Some((command, rest)) if command == "post" => nucleus_commerce_agents::post::post(rest),
        Some((command, rest)) if command == "post-tasks" => {
            nucleus_commerce_agents::tasks::post_tasks(rest)
        }
        Some((command, rest)) if command == "bounty" => {
            nucleus_commerce_agents::bounty::bounty(rest)
        }
        Some((command, rest)) if command == "bounty-close" => {
            nucleus_commerce_agents::bounty::bounty_close(rest)
        }
        Some((command, rest)) if command == "bounty-ledger" => {
            nucleus_commerce_agents::bounty::bounty_ledger(rest)
        }
        _ => nucleus_commerce_agents::buyer::buyer(&args),
    })
}
