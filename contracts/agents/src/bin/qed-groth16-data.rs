//! `qed-groth16-data DIR` — fetch the circuit data a local Groth16 wrap needs.
//!
//! Downloads RISC Zero's `risc0-groth16` 0.2.0 archive (2,406,044,780 bytes)
//! from the address `rzup` uses, refuses it unless its SHA-256 is the one
//! RISC Zero's signed distribution manifest names, and extracts only the two
//! files the native wrap reads, each checked against its own SHA-256. A
//! seller who wraps through a wrap service does not need this.
//!
//! The archive hash is pinned here, not read from the manifest at run time:
//! this tool does not check the manifest's RSA signature (`rzup` does), so the
//! pin is the trust anchor, recorded with how it was obtained in
//! docs/rfcs/proof-commerce-native-groth16-2026-11-12.md.
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufReader, Read, Write},
    path::Path,
    process::ExitCode,
};

const ARCHIVE: &str = "https://artifacts.risczero.net/rzup/components/risc0-groth16/sha256/173354ab0bd18417ba1080a0094b4398098a62b9c7460ba1dc34988b2baa57e5";
const ARCHIVE_SHA256: &str = "173354ab0bd18417ba1080a0094b4398098a62b9c7460ba1dc34988b2baa57e5";
const ARCHIVE_BYTES: u64 = 2_406_044_780;
/// The two files the wrap reads, by name inside the archive, with their hashes.
const WANTED: [(&str, &str); 2] = [
    (
        "stark_verify_graph.bin",
        "887aa345d6adc25773723e30ea66eb769efb35e4c22c4cc9a4ee9a4e2b66302a",
    ),
    (
        "stark_verify_final.zkey",
        "2da7b0932f2a9f11500346351ddac71189ffe349bbb1bdf7ed7401fd43cf3c6d",
    ),
];

type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Copy `from` to `to`, returning the SHA-256 of what passed.
fn copy_hashing(mut from: impl Read, to: &mut impl Write) -> Res<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = from.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        to.write_all(&buffer[..n])?;
        total += n as u64;
    }
    Ok((hex(&hasher.finalize()), total))
}

fn complete(dir: &Path) -> Res<bool> {
    for (name, sha) in WANTED {
        let path = dir.join(name);
        if !path.exists() {
            return Ok(false);
        }
        let (got, _) = copy_hashing(BufReader::new(fs::File::open(&path)?), &mut std::io::sink())?;
        if got != sha {
            return Ok(false);
        }
    }
    Ok(true)
}

fn run(args: &[String]) -> Res<()> {
    let [dir] = args else {
        return Err("usage: qed-groth16-data DIR".into());
    };
    let dir = Path::new(dir);
    fs::create_dir_all(dir)?;
    if complete(dir)? {
        println!(
            "circuit data already present and checked in {}",
            dir.display()
        );
        return Ok(());
    }
    let archive = dir.join("risc0-groth16-0.2.0.tar.xz.part");
    println!("downloading {ARCHIVE_BYTES} bytes from {ARCHIVE}");
    let mut response = ureq::get(ARCHIVE).call()?;
    let mut file = fs::File::create(&archive)?;
    let (sha, bytes) = copy_hashing(response.body_mut().as_reader(), &mut file)?;
    file.sync_all()?;
    if sha != ARCHIVE_SHA256 || bytes != ARCHIVE_BYTES {
        let _ = fs::remove_file(&archive);
        return Err(format!("archive refused: {bytes} bytes, SHA-256 {sha}").into());
    }
    println!("archive checked: SHA-256 {sha}");
    // Decompress on one thread into a pipe; read the tar from the other end.
    let (reader, mut writer) = std::io::pipe()?;
    let source = archive.clone();
    let decompress = std::thread::spawn(move || -> Res<()> {
        let mut input = BufReader::new(fs::File::open(source)?);
        lzma_rs::xz_decompress(&mut input, &mut writer).map_err(|e| format!("xz: {e:?}"))?;
        Ok(())
    });
    let mut found = 0;
    let mut tar = tar::Archive::new(reader);
    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some((_, want)) = WANTED.iter().find(|(n, _)| *n == name) else {
            // Drain the entries not wanted so the stream moves on.
            std::io::copy(&mut entry, &mut std::io::sink())?;
            continue;
        };
        let partial = dir.join(format!("{name}.part"));
        let mut out = fs::File::create(&partial)?;
        let (got, _) = copy_hashing(&mut entry, &mut out)?;
        out.sync_all()?;
        if got != *want {
            let _ = fs::remove_file(&partial);
            return Err(format!("{name} refused: SHA-256 {got}").into());
        }
        fs::rename(&partial, dir.join(name))?;
        println!("  ok   {name}");
        found += 1;
    }
    decompress.join().map_err(|_| "decompression thread")??;
    let _ = fs::remove_file(&archive);
    if found != WANTED.len() {
        return Err(format!("archive held {found} of the {} files", WANTED.len()).into());
    }
    println!("circuit data ready in {}", dir.display());
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
