//! A `RUSTC_WRAPPER` for the guest build. It runs the compiler it is given
//! with one more `--remap-path-prefix` per line of `NUCLEUS_GUEST_REMAP`, so
//! the source paths rustc records in panic locations do not name the machine,
//! the user or the checkout that built the program. `build.rs` compiles this
//! file and sets both variables; nothing else runs it.
use std::{env, process::Command, process::ExitCode};

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(rustc) = args.next() else {
        eprintln!("guest-rustc: no compiler given");
        return ExitCode::FAILURE;
    };
    let mut command = Command::new(rustc);
    command.args(args);
    for mapping in env::var("NUCLEUS_GUEST_REMAP").unwrap_or_default().lines() {
        if !mapping.is_empty() {
            command.arg(format!("--remap-path-prefix={mapping}"));
        }
    }
    match command.status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => ExitCode::from(u8::try_from(status.code().unwrap_or(1)).unwrap_or(1)),
        Err(error) => {
            eprintln!("guest-rustc: cannot run the compiler: {error}");
            ExitCode::FAILURE
        }
    }
}
