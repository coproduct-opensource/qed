//! Reads a guest profile written by RISC Zero's profiler (`RISC0_PPROF_OUT`,
//! an uncompressed pprof `Profile` message whose one sample value is cycles)
//! and prints where the cycles went. No dependencies: the few protobuf fields
//! used are decoded here.
//!
//!   pprof_summary FILE top N            N functions by self and by cumulative cycles
//!   pprof_summary FILE any PATTERN...   each sample goes to the first pattern found in ANY frame
//!   pprof_summary FILE leaf PATTERN...  each sample goes to the first pattern found in its LEAF frame
//!   pprof_summary FILE under ROOT N     N functions by self cycles among samples with ROOT in a frame
//!   pprof_summary FILE callers LEAF N   for samples whose leaf matches LEAF, the nearest frame that does not
//!
//! A pattern is a substring of a demangled function name; `a|b` matches
//! either. "Self" is cycles spent in a function's own instructions;
//! "cumulative" counts a sample once for every distinct function on its stack.
use std::{collections::HashMap, error::Error, fs, process::ExitCode};

/// One protobuf field: its number, its varint value (or 0), and its
/// length-delimited bytes (or empty).
type Field<'a> = (u64, u64, &'a [u8]);

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn varint(&mut self) -> Result<u64, Box<dyn Error>> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let (&byte, rest) = self.0.split_first().ok_or("truncated varint")?;
            self.0 = rest;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err("varint too long".into())
    }
    fn bytes(&mut self) -> Result<&'a [u8], Box<dyn Error>> {
        let length = usize::try_from(self.varint()?)?;
        let (head, rest) = self.0.split_at_checked(length).ok_or("truncated field")?;
        self.0 = rest;
        Ok(head)
    }
    /// The next field as (number, varint value or 0, length-delimited bytes or empty).
    fn field(&mut self) -> Result<Option<Field<'a>>, Box<dyn Error>> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let key = self.varint()?;
        let (number, wire) = (key >> 3, key & 7);
        Ok(Some(match wire {
            0 => (number, self.varint()?, &[][..]),
            2 => (number, 0, self.bytes()?),
            1 => {
                let (_, rest) = self.0.split_at_checked(8).ok_or("truncated fixed64")?;
                self.0 = rest;
                (number, 0, &[][..])
            }
            5 => {
                let (_, rest) = self.0.split_at_checked(4).ok_or("truncated fixed32")?;
                self.0 = rest;
                (number, 0, &[][..])
            }
            other => return Err(format!("unsupported wire type {other}").into()),
        }))
    }
}

/// A repeated integer field, packed or not.
fn push_ints(into: &mut Vec<u64>, value: u64, packed: &[u8]) -> Result<(), Box<dyn Error>> {
    if packed.is_empty() {
        into.push(value);
    } else {
        let mut reader = Reader(packed);
        while !reader.0.is_empty() {
            into.push(reader.varint()?);
        }
    }
    Ok(())
}

struct Profile {
    /// Function names of each sample's stack, leaf first, and its cycles.
    samples: Vec<(Vec<u32>, u64)>,
    names: Vec<String>,
}

fn read(bytes: &[u8]) -> Result<Profile, Box<dyn Error>> {
    let mut strings: Vec<String> = Vec::new();
    let mut raw_samples: Vec<(Vec<u64>, u64)> = Vec::new();
    // location id -> function ids of its lines, innermost first
    let mut locations: HashMap<u64, Vec<u64>> = HashMap::new();
    // function id -> string index of its name
    let mut functions: HashMap<u64, u64> = HashMap::new();
    let mut top = Reader(bytes);
    while let Some((number, _, body)) = top.field()? {
        match number {
            2 => {
                let (mut stack, mut values) = (Vec::new(), Vec::new());
                let mut reader = Reader(body);
                while let Some((n, v, b)) = reader.field()? {
                    match n {
                        1 => push_ints(&mut stack, v, b)?,
                        2 => push_ints(&mut values, v, b)?,
                        _ => {}
                    }
                }
                raw_samples.push((stack, values.first().copied().unwrap_or(0)));
            }
            4 => {
                let (mut id, mut lines) = (0, Vec::new());
                let mut reader = Reader(body);
                while let Some((n, v, b)) = reader.field()? {
                    match n {
                        1 => id = v,
                        4 => {
                            let mut line = Reader(b);
                            while let Some((ln, lv, _)) = line.field()? {
                                if ln == 1 {
                                    lines.push(lv);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                locations.insert(id, lines);
            }
            5 => {
                let (mut id, mut name) = (0, 0);
                let mut reader = Reader(body);
                while let Some((n, v, _)) = reader.field()? {
                    match n {
                        1 => id = v,
                        2 => name = v,
                        _ => {}
                    }
                }
                functions.insert(id, name);
            }
            6 => strings.push(String::from_utf8_lossy(body).into_owned()),
            _ => {}
        }
    }
    // Intern function names so a stack is a list of small integers.
    let mut index: HashMap<u64, u32> = HashMap::new();
    let mut names: Vec<String> = Vec::new();
    let mut samples = Vec::with_capacity(raw_samples.len());
    for (stack, cycles) in raw_samples {
        let mut frames = Vec::new();
        for location in stack {
            for function in locations.get(&location).map(Vec::as_slice).unwrap_or(&[]) {
                let next = u32::try_from(names.len())?;
                let slot = *index.entry(*function).or_insert_with(|| {
                    let name = functions
                        .get(function)
                        .and_then(|s| strings.get(usize::try_from(*s).ok()?))
                        .cloned()
                        .unwrap_or_else(|| format!("function {function}"));
                    names.push(name);
                    next
                });
                frames.push(slot);
            }
        }
        samples.push((frames, cycles));
    }
    Ok(Profile { samples, names })
}

fn matches(name: &str, pattern: &str) -> bool {
    pattern.split('|').any(|part| name.contains(part))
}
fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 * 100.0 / whole as f64
    }
}
fn ranked(counts: &HashMap<u32, u64>, names: &[String], total: u64, limit: usize) {
    let mut rows: Vec<(&u32, &u64)> = counts.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (function, cycles) in rows.into_iter().take(limit) {
        let name = names.get(*function as usize).map_or("?", String::as_str);
        println!("{cycles:>14} {:>6.2}%  {name}", percent(*cycles, total));
    }
}
fn self_counts<'a>(samples: impl Iterator<Item = &'a (Vec<u32>, u64)>) -> HashMap<u32, u64> {
    let mut counts = HashMap::new();
    for (stack, cycles) in samples {
        if let Some(leaf) = stack.first() {
            *counts.entry(*leaf).or_insert(0) += cycles;
        }
    }
    counts
}

fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    let usage = "usage: pprof_summary FILE top N | any PATTERN... | leaf PATTERN... | under ROOT N | callers LEAF N";
    let [file, mode, rest @ ..] = args else {
        return Err(usage.into());
    };
    let profile = read(&fs::read(file)?)?;
    let total: u64 = profile.samples.iter().map(|(_, cycles)| cycles).sum();
    println!("samples {} cycles {total}", profile.samples.len());
    match (mode.as_str(), rest) {
        ("top", [limit]) => {
            let limit: usize = limit.parse()?;
            println!("-- self");
            ranked(
                &self_counts(profile.samples.iter()),
                &profile.names,
                total,
                limit,
            );
            let mut cumulative: HashMap<u32, u64> = HashMap::new();
            for (stack, cycles) in &profile.samples {
                let mut seen = stack.clone();
                seen.sort_unstable();
                seen.dedup();
                for function in seen {
                    *cumulative.entry(function).or_insert(0) += cycles;
                }
            }
            println!("-- cumulative");
            ranked(&cumulative, &profile.names, total, limit);
        }
        ("any" | "leaf", patterns) if !patterns.is_empty() => {
            let mut counts = vec![0u64; patterns.len() + 1];
            for (stack, cycles) in &profile.samples {
                let frames: &[u32] = if mode == "leaf" {
                    stack.get(..1).unwrap_or(&[])
                } else {
                    stack
                };
                let slot = patterns
                    .iter()
                    .position(|pattern| {
                        frames.iter().any(|f| {
                            profile
                                .names
                                .get(*f as usize)
                                .is_some_and(|name| matches(name, pattern))
                        })
                    })
                    .unwrap_or(patterns.len());
                if let Some(count) = counts.get_mut(slot) {
                    *count += cycles;
                }
            }
            for (pattern, cycles) in patterns
                .iter()
                .map(String::as_str)
                .chain(["(none)"])
                .zip(&counts)
            {
                println!("{cycles:>14} {:>6.2}%  {pattern}", percent(*cycles, total));
            }
        }
        ("callers", [leaf, limit]) => {
            let limit: usize = limit.parse()?;
            let is_leaf = |f: &u32| {
                profile
                    .names
                    .get(*f as usize)
                    .is_some_and(|name| matches(name, leaf))
            };
            let mut counts: HashMap<u32, u64> = HashMap::new();
            let mut part = 0u64;
            for (stack, cycles) in &profile.samples {
                if stack.first().is_some_and(is_leaf) {
                    part += cycles;
                    if let Some(caller) = stack.iter().find(|f| !is_leaf(f)) {
                        *counts.entry(*caller).or_insert(0) += cycles;
                    }
                }
            }
            println!(
                "leaf {leaf}: {part} cycles, {:.2}% of all",
                percent(part, total)
            );
            ranked(&counts, &profile.names, total, limit);
        }
        ("under", [root, limit]) => {
            let limit: usize = limit.parse()?;
            let inside: Vec<&(Vec<u32>, u64)> = profile
                .samples
                .iter()
                .filter(|(stack, _)| {
                    stack.iter().any(|f| {
                        profile
                            .names
                            .get(*f as usize)
                            .is_some_and(|name| matches(name, root))
                    })
                })
                .collect();
            let part: u64 = inside.iter().map(|(_, cycles)| cycles).sum();
            println!(
                "under {root}: {part} cycles, {:.2}% of all",
                percent(part, total)
            );
            ranked(
                &self_counts(inside.into_iter()),
                &profile.names,
                total,
                limit,
            );
        }
        _ => return Err(usage.into()),
    }
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
