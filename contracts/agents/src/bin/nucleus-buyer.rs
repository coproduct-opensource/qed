//! `nucleus-buyer DEPLOYMENT KEYFILE SELLER STATEMENT PROGRAM_HEX MAXIMUM_PRICE OUT_DIR`
//!   asks one seller directly (`buyer.rs`).
//! `nucleus-buyer post DEPLOYMENT BOARD KEYFILE STATEMENT PROGRAM_HEX MAXIMUM_PRICE BIND OUT_DIR`
//!   posts a task on the board and waits at its desk (`post.rs`).
//! `nucleus-buyer post-tasks DEPLOYMENT BOARD KEYFILE BIND OUT_DIR TASK.json`
//!   posts one task, journaled in OUT_DIR, and follows it to its end (`tasks.rs`).
//! `nucleus-buyer task-withdraw DEPLOYMENT BOARD KEYFILE BIND OUT_DIR TASK.json`
//!   withdraws that journal's post if nobody was signed for it.
//! `nucleus-buyer task-refund DEPLOYMENT BOARD KEYFILE BIND OUT_DIR TASK.json`
//!   refunds and claims back that journal's funded order past its delivery deadline.
//! `nucleus-buyer deliveries-fetch NODE_ID OUT [BINDING]`
//!   fetches a desk's signed summary of delivery attempts (`deliveries.rs`).
fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    nucleus_commerce_agents::exit(match args.split_first() {
        Some((command, rest)) if command == "post" => nucleus_commerce_agents::post::post(rest),
        Some((command, rest)) if command == "post-tasks" => {
            nucleus_commerce_agents::tasks::post_tasks(rest)
        }
        Some((command, rest)) if command == "task-withdraw" => {
            nucleus_commerce_agents::tasks::task_withdraw(rest)
        }
        Some((command, rest)) if command == "task-refund" => {
            nucleus_commerce_agents::tasks::task_refund(rest)
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
        Some((command, rest)) if command == "deliveries-fetch" => {
            nucleus_commerce_agents::deliveries::deliveries_fetch(rest)
        }
        _ => nucleus_commerce_agents::buyer::buyer(&args),
    })
}
