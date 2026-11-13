//! `verify-programs`: rebuild every guest named in a recipe file with the
//! pinned builder image and compare the result with the recorded image IDs.
//!
//!   nucleus-acceptance-host verify-programs [--recipe FILE] [--runtime docker|container]
//!       [--commit REV | --worktree] [--work DIR] [--keep] [--cpus N] [--memory SIZE]
//!
//! The statement it checks (docs/rfcs/qed-reproducible-programs-2026-11-13.md):
//! for each `program` line of the recipe, the source tree at REV (or the tracked
//! files of the working tree), built inside the image named by digest, at
//! `/src`, with the recipe's environment and RISC Zero's build command, gives
//! a user ELF whose program binary (that ELF with RISC Zero's v1compat kernel,
//! encoded as `risc0-build` encodes it) has the image ID in the recipe's ID
//! file. Exit 0 when every program matches, 1 when any does not, 2 when the
//! check could not be run.
//!
//! The build mirrors `risc0-build` 3.0.7's own Docker route (`docker.rs`):
//! the same image, working directory, environment and two cargo commands,
//! one fresh source tree per guest. It runs the image with `run` and a
//! mounted directory instead of `docker build`, so that Apple `container`
//! (which has no BuildKit `--output`) can run it too. The image is published
//! for linux/amd64 only; under `container` on a Mac it runs translated by
//! Rosetta, which this command says when it does.
use risc0_binfmt::ProgramBinary;
use risc0_zkvm::sha::{Impl, Sha256};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

const DEFAULT_RECIPE: &str = "contracts/proof-acceptance/program/REPRODUCIBLE";
const TARGET: &str = "riscv32im-risc0-zkvm-elf";

/// One guest: where its manifest lives, its binary's name, and the files that
/// record what it must build to.
struct Program {
    name: String,
    guest_dir: String,
    binary: String,
    id_file: String,
    published: Option<String>,
}

struct Recipe {
    image: String,
    platform: String,
    rustflags: Vec<String>,
    env: Vec<(String, String)>,
    programs: Vec<Program>,
    /// Directory of the recipe file, relative to the repository root; ID and
    /// binary file names are relative to it.
    dir: PathBuf,
}

fn parse_recipe(text: &str, dir: PathBuf) -> Result<Recipe, Box<dyn Error>> {
    let mut image = None;
    let mut platform = None;
    let mut rustflags = Vec::new();
    let mut env = Vec::new();
    let mut programs = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, rest) = line.split_once(' ').unwrap_or((line, ""));
        match key {
            "image" => image = Some(rest.trim().to_owned()),
            "platform" => platform = Some(rest.trim().to_owned()),
            "rustflags" => rustflags = rest.split_whitespace().map(str::to_owned).collect(),
            // `env KEY VALUE`, the value being the rest of the line (it may be
            // empty or contain spaces).
            "env" => {
                let (name, value) = rest.split_once(' ').unwrap_or((rest, ""));
                env.push((name.to_owned(), value.to_owned()));
            }
            "program" => {
                let fields: Vec<&str> = rest.split_whitespace().collect();
                let [name, guest_dir, binary, id_file, more @ ..] = fields.as_slice() else {
                    return Err(format!(
                        "recipe line {}: program NAME GUEST_DIR BINARY ID_FILE [PUBLISHED_BIN]",
                        number + 1
                    )
                    .into());
                };
                programs.push(Program {
                    name: (*name).to_owned(),
                    guest_dir: (*guest_dir).to_owned(),
                    binary: (*binary).to_owned(),
                    id_file: (*id_file).to_owned(),
                    published: more.first().map(|s| (*s).to_owned()),
                });
            }
            other => {
                return Err(format!("recipe line {}: unknown key {other:?}", number + 1).into())
            }
        }
    }
    let image = image.ok_or("recipe: no image line")?;
    if !image.contains("@sha256:") {
        return Err("recipe: the image must be named by digest (…@sha256:…)".into());
    }
    Ok(Recipe {
        image,
        platform: platform.ok_or("recipe: no platform line")?,
        rustflags,
        env,
        programs,
        dir,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> String {
    hex(Impl::hash_bytes(bytes).as_bytes())
}

fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>, Box<dyn Error>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()?;
    if !out.status.success() {
        return Err(format!("git {args:?}: {}", String::from_utf8_lossy(&out.stderr)).into());
    }
    Ok(out.stdout)
}

enum Source {
    Commit(String),
    Worktree,
}

/// Put the source tree in `dest`: the files of a commit (`git archive`), or
/// the tracked files of the working tree as they are on disk.
fn stage(repo: &Path, source: &Source, dest: &Path, work: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(dest)?;
    match source {
        Source::Commit(rev) => {
            let tar = work.join("source.tar");
            git(
                repo,
                &[
                    "archive",
                    "--format=tar",
                    "-o",
                    tar.to_str().ok_or("path")?,
                    rev,
                ],
            )?;
            let status = Command::new("tar")
                .arg("-xf")
                .arg(&tar)
                .arg("-C")
                .arg(dest)
                .status()?;
            if !status.success() {
                return Err("tar -x of the source failed".into());
            }
        }
        Source::Worktree => {
            let listed = git(repo, &["ls-files", "-z", "--cached"])?;
            for path in listed.split(|b| *b == 0).filter(|p| !p.is_empty()) {
                let relative = Path::new(std::str::from_utf8(path)?);
                let from = repo.join(relative);
                // A tracked file deleted in the working tree is not part of it.
                let Ok(meta) = fs::symlink_metadata(&from) else {
                    continue;
                };
                let to = dest.join(relative);
                if let Some(parent) = to.parent() {
                    fs::create_dir_all(parent)?;
                }
                if meta.file_type().is_symlink() {
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(fs::read_link(&from)?, &to)?;
                } else if meta.is_file() {
                    fs::copy(&from, &to)?;
                }
            }
        }
    }
    Ok(())
}

struct Runtime {
    kind: String,
    cpus: String,
    memory: String,
}

impl Runtime {
    /// `<runtime> run` of the pinned image with `dir` at /src, running `script`.
    fn command(
        &self,
        recipe: &Recipe,
        dir: &Path,
        env: &[(String, String)],
        script: &str,
    ) -> Command {
        let mut command = Command::new(&self.kind);
        command.arg("run").arg("--rm");
        match self.kind.as_str() {
            "container" => {
                command.args(["--platform", &recipe.platform]);
                if recipe.platform.ends_with("amd64") && cfg!(target_arch = "aarch64") {
                    command.arg("--rosetta");
                }
                command.args(["-c", &self.cpus, "-m", &self.memory]);
            }
            _ => {
                command.args(["--platform", &recipe.platform]);
            }
        }
        command
            .arg("-v")
            .arg(format!("{}:/src", dir.display()))
            .args(["-w", "/src"]);
        for (key, value) in env {
            command.arg("-e").arg(format!("{key}={value}"));
        }
        // The image's entrypoint is /bin/sh.
        command.arg(&recipe.image).arg("-c").arg(script);
        command
    }
}

struct Outcome {
    name: String,
    expected: String,
    built: String,
    matches: bool,
}

pub fn run(args: &[String]) -> Result<bool, Box<dyn Error>> {
    let mut recipe_path = None;
    let mut runtime = Runtime {
        kind: "docker".into(),
        cpus: "8".into(),
        memory: "16g".into(),
    };
    let mut source = Source::Commit("HEAD".into());
    let mut work = None;
    let mut keep = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let mut value = || iter.next().cloned().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--recipe" => recipe_path = Some(value()?),
            "--runtime" => runtime.kind = value()?,
            "--commit" => source = Source::Commit(value()?),
            "--worktree" => source = Source::Worktree,
            "--work" => work = Some(PathBuf::from(value()?)),
            "--cpus" => runtime.cpus = value()?,
            "--memory" => runtime.memory = value()?,
            "--keep" => keep = true,
            other => return Err(format!("verify-programs: unknown argument {other:?}").into()),
        }
    }
    if !matches!(runtime.kind.as_str(), "docker" | "container") {
        return Err("--runtime is docker or container".into());
    }
    let cwd = std::env::current_dir()?;
    let repo =
        PathBuf::from(String::from_utf8(git(&cwd, &["rev-parse", "--show-toplevel"])?)?.trim());
    let recipe_rel = PathBuf::from(recipe_path.unwrap_or_else(|| DEFAULT_RECIPE.into()));
    let recipe_text = fs::read_to_string(repo.join(&recipe_rel))?;
    let recipe = parse_recipe(
        &recipe_text,
        recipe_rel
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default(),
    )?;
    let work = work.unwrap_or_else(|| repo.join("target/reproduce"));
    if work.exists() {
        return Err(format!(
            "work directory {} exists; remove it or pass --work",
            work.display()
        )
        .into());
    }
    fs::create_dir_all(&work)?;
    let work = work.canonicalize()?;

    let described = match &source {
        Source::Commit(rev) => {
            let commit =
                String::from_utf8(git(&repo, &["rev-parse", &format!("{rev}^{{commit}}")])?)?;
            format!("commit {}", commit.trim())
        }
        Source::Worktree => {
            let head = String::from_utf8(git(&repo, &["rev-parse", "HEAD"])?)?;
            let dirty = !git(&repo, &["status", "--porcelain", "--untracked-files=no"])?.is_empty();
            format!(
                "working tree at {}{}",
                head.trim(),
                if dirty { " with changes" } else { "" }
            )
        }
    };
    println!("source {described}");
    println!("image {}", recipe.image);
    println!("runtime {} platform {}", runtime.kind, recipe.platform);
    if runtime.kind == "container"
        && recipe.platform.ends_with("amd64")
        && cfg!(target_arch = "aarch64")
    {
        println!("translation rosetta (the image is linux/amd64; this host is arm64)");
    }

    let mut outcomes = Vec::new();
    for program in &recipe.programs {
        let dir = work.join(&program.name);
        stage(&repo, &source, &dir, &work)?;
        let manifest = format!("{}/Cargo.toml", program.guest_dir);
        let mut env = vec![
            ("CARGO_MANIFEST_PATH".to_owned(), manifest),
            (
                "CARGO_ENCODED_RUSTFLAGS".to_owned(),
                recipe.rustflags.join("\u{1f}"),
            ),
        ];
        env.extend(recipe.env.iter().cloned());
        // risc0-build 3.0.7's two commands, as its Dockerfile runs them.
        let common = format!("--locked --target {TARGET} --manifest-path $CARGO_MANIFEST_PATH");
        let script = format!(
            "set -e; rustc +risc0 -vV >&2; cargo +risc0 fetch {common}; cargo +risc0 build --release {common}"
        );
        let started = Instant::now();
        let status = runtime.command(&recipe, &dir, &env, &script).status()?;
        let seconds = started.elapsed().as_secs_f64();
        if !status.success() {
            return Err(format!(
                "{}: the build in the container failed ({status})",
                program.name
            )
            .into());
        }
        let elf_path = dir
            .join("target")
            .join(TARGET)
            .join("release")
            .join(&program.binary);
        let elf = fs::read(&elf_path)?;
        let kernel = risc0_zkos_v1compat::V1COMPAT_ELF;
        let binary = ProgramBinary::new(&elf, kernel).encode();
        let built = hex(risc0_zkvm::compute_image_id(&binary)?.as_bytes());
        let expected = fs::read_to_string(repo.join(&recipe.dir).join(&program.id_file))?
            .trim()
            .to_owned();
        let out = work.join("out");
        fs::create_dir_all(&out)?;
        fs::write(out.join(format!("{}.elf", program.name)), &elf)?;
        fs::write(out.join(format!("{}.bin", program.name)), &binary)?;
        println!("program {}", program.name);
        println!("  guest {}", program.guest_dir);
        println!("  seconds {seconds:.1}");
        println!("  elf_sha256 {} ({} bytes)", sha256(&elf), elf.len());
        println!("  bin_sha256 {} ({} bytes)", sha256(&binary), binary.len());
        if let Some(published) = &program.published {
            let file = fs::read(repo.join(&recipe.dir).join(published))?;
            let same = if file == binary {
                "identical"
            } else {
                "different"
            };
            println!("  published {published}: {same} (sha256 {})", sha256(&file));
        }
        println!("  image_id {built}");
        println!("  expected {expected} ({})", program.id_file);
        let matches = built == expected;
        println!("  {}", if matches { "MATCH" } else { "MISMATCH" });
        if !keep {
            // Files the container wrote may belong to its root user; let the
            // container remove its own target directory first.
            let _ = runtime
                .command(&recipe, &dir, &[], "rm -rf /src/target")
                .status();
            let _ = fs::remove_dir_all(&dir);
        }
        outcomes.push(Outcome {
            name: program.name.clone(),
            expected,
            built,
            matches,
        });
    }
    let _ = fs::remove_file(work.join("source.tar"));
    println!("outputs {}", work.join("out").display());
    let all = outcomes.iter().all(|o| o.matches);
    for o in outcomes.iter().filter(|o| !o.matches) {
        eprintln!(
            "verify-programs: {} built {} but the recipe records {}",
            o.name, o.built, o.expected
        );
    }
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recipe_requires_a_digest_and_reads_every_line() {
        let text = "image docker.io/x/y:t\nplatform linux/amd64\n";
        assert!(parse_recipe(text, PathBuf::new()).is_err());
        let text = "# c\nimage docker.io/x/y@sha256:00\nplatform linux/amd64\nrustflags -C a --cfg b=\"c\"\nenv EMPTY \nenv CFLAGS -march=rv32im -nostdlib\nprogram base g/base nucleus-base-guest ID B.bin\n";
        let recipe = parse_recipe(text, PathBuf::from("p")).expect("parses");
        assert_eq!(recipe.rustflags, ["-C", "a", "--cfg", "b=\"c\""]);
        assert_eq!(
            recipe.env,
            [
                ("EMPTY".to_owned(), String::new()),
                ("CFLAGS".to_owned(), "-march=rv32im -nostdlib".to_owned())
            ]
        );
        assert_eq!(recipe.programs[0].published.as_deref(), Some("B.bin"));
        assert!(parse_recipe("bogus line\n", PathBuf::new()).is_err());
    }
}
