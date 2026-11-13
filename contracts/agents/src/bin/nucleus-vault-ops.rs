//! Operations on a vault deployment. See `ops.rs`.
use nucleus_commerce_agents::{ops, support};

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.split_first() {
        Some((command, rest)) if command == "deploy" => ops::deploy(rest),
        Some((command, rest)) if command == "prepare" => ops::prepare(rest),
        Some((command, rest)) if command == "preflight" => ops::preflight(rest),
        Some((command, rest)) if command == "sweep" => ops::sweep(rest),
        Some((command, rest)) if command == "deploy3" => ops::deploy3(rest),
        Some((command, rest)) if command == "claim" => ops::claim(rest),
        Some((command, rest)) if command == "send-gas" => ops::send_gas(rest),
        Some((command, rest)) if command == "send-token" => ops::send_token(rest),
        Some((command, rest)) if command == "probe-calldata" => ops::probe_calldata(rest),
        Some((command, rest)) if command == "swap-native" => ops::swap_native(rest),
        Some((command, rest)) if command == "keys" => support::keys(rest),
        Some((command, rest)) if command == "board-deploy" => ops::board_deploy(rest),
        Some((command, rest)) if command == "registry-deploy" => ops::registry_deploy(rest),
        Some((command, rest)) if command == "registry-register" => ops::registry_register(rest),
        _ => Err(
            "usage: deploy | deploy3 | prepare | preflight | sweep | claim | send-gas | send-token | probe-calldata | swap-native | keys | board-deploy | registry-deploy | registry-register (see src/ops.rs)"
                .into(),
        ),
    };
    nucleus_commerce_agents::exit(result)
}
