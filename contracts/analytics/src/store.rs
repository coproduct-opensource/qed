//! The collector's state on disk, its rate limit, and the daily publication.
//!
//! Two files in the state directory, and nothing else:
//!
//! - `today.json`: the day being counted, `{"record":"qed-visits-today/1",
//!   "day":N,"cells":[…34 counts…]}`. Replaced whole (write, sync, rename) at
//!   most once a minute while beacons arrive, and at each new day. Not
//!   append-only on purpose: a log of minute-by-minute checkpoints would keep
//!   the order in which cells grew, which the published days do not reveal.
//!   A crash loses at most a minute of counts.
//! - `published.jsonl`: one line per finished day, appended once and synced
//!   (`nucleus_jsonl::append_line_synced`), never rewritten. A day's noise is
//!   drawn once, when its line is written; a restart never publishes a day
//!   again, so the noise cannot be averaged away by asking twice.
//!
//! True counts of a finished day are never written: they exist in memory and
//! in `today.json` only until the day's line is published.
//!
//! **Rate limit.** A token bucket for all beacons together, [`BURST`] deep,
//! refilled at [`PER_SECOND`]: no address or other identifier is stored, so a
//! single sender can use the whole budget, and beacons refused by the limit
//! are counted in the `limited` cell. Whether a beacon is refused depends only
//! on arrival times, never on its fields.
//!
//! The native Olog store is not available to this public tree (it lives in the
//! private olog repository), so this is the synced JSON-lines file the bounty
//! buyer's journal and delivery record use. No SQLite.
use crate::core::{self, CELLS, Cell, Day, K, LIMITED, MALFORMED, PATHS, Request};
use crate::noise::Coins;
use crate::paths::ALLOWED;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const CHECKPOINT: &str = "today.json";
pub const PUBLISHED: &str = "published.jsonl";
pub const RECORD_TODAY: &str = "qed-visits-today/1";
pub const RECORD_DAY: &str = "qed-visits/1";
/// About eleven years of days; past it nothing more is published.
pub const MAX_PUBLISHED: usize = 4000;
/// Days with no beacons between two days with beacons are published as all
/// suppressed, at most this many in a row.
pub const MAX_GAP_DAYS: u32 = 31;
/// Seconds between checkpoints while beacons arrive.
pub const SAVE_EVERY: u64 = 60;
pub const BURST: u64 = 600;
pub const PER_SECOND: u64 = 5;
/// Days the published view returns.
pub const SHOWN_DAYS: usize = 7;
const MS_PER_DAY: u64 = 86_400_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Counted,
    Malformed,
    Limited,
}

/// What the shell read from one connection, besides the body.
#[derive(Clone, Copy, Debug)]
pub struct Connection {
    pub peer: [u8; 16],
    pub peer_port: u16,
    pub head_bytes: u32,
    pub body_bytes: u32,
}

pub struct Collector<R> {
    dir: PathBuf,
    state: Day,
    coins: Coins<R>,
    dirty: bool,
    saved_ms: u64,
    last_published: Option<u32>,
    published_lines: usize,
    recent: VecDeque<Value>,
    tokens_milli: u64,
    refilled_ms: u64,
}

pub fn day_of(now_ms: u64) -> u32 {
    u32::try_from(now_ms / MS_PER_DAY).unwrap_or(u32::MAX)
}

/// `YYYY-MM-DD` of a day number (days since 1970-01-01).
pub fn date(day: u32) -> String {
    // Howard Hinnant's civil_from_days.
    let z = i64::from(day) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn bad(what: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

fn cell_json(cell: Cell) -> Value {
    match cell {
        Cell::Suppressed => Value::Null,
        Cell::Count(v) => json!(v),
    }
}

impl<R: Read> Collector<R> {
    /// Open the state directory: read the published days and the checkpoint.
    /// An unreadable line or checkpoint stops the collector rather than
    /// being read as nothing.
    pub fn open(dir: &Path, coins: Coins<R>, now_ms: u64) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let mut last_published = None;
        let mut published_lines = 0;
        let mut recent = VecDeque::new();
        match fs::read_to_string(dir.join(PUBLISHED)) {
            Ok(text) => {
                for (n, line) in text.lines().enumerate() {
                    let value: Value = serde_json::from_str(line)
                        .map_err(|e| bad(format!("{PUBLISHED} line {}: {e}", n + 1)))?;
                    let day = value["day"]
                        .as_u64()
                        .and_then(|d| u32::try_from(d).ok())
                        .filter(|_| value["record"] == RECORD_DAY)
                        .ok_or_else(|| bad(format!("{PUBLISHED} line {}: not a day", n + 1)))?;
                    last_published = last_published.max(Some(day));
                    published_lines += 1;
                    recent.push_back(value);
                    if recent.len() > SHOWN_DAYS {
                        recent.pop_front();
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let today = day_of(now_ms);
        let state = match fs::read(dir.join(CHECKPOINT)) {
            Ok(bytes) => {
                let saved = read_checkpoint(&bytes)?;
                // A day already published is not counted again.
                if last_published.is_some_and(|p| saved.day <= p) {
                    core::fresh(today.max(saved.day))
                } else {
                    saved
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => core::fresh(today),
            Err(e) => return Err(e),
        };
        let mut collector = Collector {
            dir: dir.to_path_buf(),
            state,
            coins,
            dirty: false,
            saved_ms: now_ms,
            last_published,
            published_lines,
            recent,
            tokens_milli: BURST * 1000,
            refilled_ms: now_ms,
        };
        collector.save()?;
        collector.tick(now_ms)?;
        Ok(collector)
    }

    pub fn state(&self) -> &Day {
        &self.state
    }

    /// Roll to a new day when the clock has passed midnight (UTC): publish
    /// the finished day and any empty days since, then start the new day.
    /// Otherwise save a checkpoint if one is due.
    pub fn tick(&mut self, now_ms: u64) -> io::Result<()> {
        let today = day_of(now_ms);
        if today > self.state.day {
            let finished = self.state;
            self.publish(finished)?;
            let gap_end = today.min(finished.day.saturating_add(1 + MAX_GAP_DAYS));
            for day in finished.day + 1..gap_end {
                self.publish(core::fresh(day))?;
            }
            self.state = core::fresh(today);
            self.save()?;
            self.saved_ms = now_ms;
            self.dirty = false;
        } else if self.dirty && now_ms.saturating_sub(self.saved_ms) >= SAVE_EVERY * 1000 {
            self.save()?;
            self.saved_ms = now_ms;
            self.dirty = false;
        }
        Ok(())
    }

    fn take_token(&mut self, now_ms: u64) -> bool {
        let elapsed = now_ms.saturating_sub(self.refilled_ms);
        self.tokens_milli = (self.tokens_milli + elapsed * PER_SECOND).min(BURST * 1000);
        self.refilled_ms = now_ms.max(self.refilled_ms);
        if self.tokens_milli >= 1000 {
            self.tokens_milli -= 1000;
            true
        } else {
            false
        }
    }

    /// One beacon. `path` and `first` come from `paths::parse` of the body;
    /// the connection's fields go into the request record and nowhere else.
    pub fn beacon(
        &mut self,
        path: usize,
        first: bool,
        connection: Connection,
        now_ms: u64,
    ) -> io::Result<Outcome> {
        self.tick(now_ms)?;
        let day = day_of(now_ms);
        let outcome = if !self.take_token(now_ms) {
            self.state = core::limit(self.state, day);
            Outcome::Limited
        } else {
            let request = Request {
                path,
                first,
                day,
                second_of_day: ((now_ms % MS_PER_DAY) / 1000) as u32,
                peer: connection.peer,
                peer_port: connection.peer_port,
                head_bytes: connection.head_bytes,
                body_bytes: connection.body_bytes,
            };
            self.state = core::handle(self.state, &request);
            if path < PATHS {
                Outcome::Counted
            } else {
                Outcome::Malformed
            }
        };
        self.dirty = true;
        self.tick(now_ms)?;
        Ok(outcome)
    }

    fn save(&self) -> io::Result<()> {
        let body = json!({
            "record": RECORD_TODAY,
            "day": self.state.day,
            "cells": self.state.cells.to_vec(),
        });
        let path = self.dir.join(CHECKPOINT);
        let tmp = self.dir.join(format!("{CHECKPOINT}.new"));
        {
            let mut file = fs::File::create(&tmp)?;
            file.write_all(body.to_string().as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        fs::File::open(&self.dir)?.sync_all()
    }

    /// Publish one finished day, once: each cell through `core::publish_cell`
    /// with a fresh pair of fair-coin counts.
    fn publish(&mut self, day: Day) -> io::Result<()> {
        if self.last_published.is_some_and(|p| day.day <= p) {
            return Ok(());
        }
        if self.published_lines >= MAX_PUBLISHED {
            eprintln!("qed-analytics: {MAX_PUBLISHED} days published; publishing stopped");
            return Ok(());
        }
        let mut cells = [Cell::Suppressed; CELLS];
        for (i, cell) in cells.iter_mut().enumerate() {
            let (g1, g2) = self.coins.pair()?;
            *cell = core::publish_cell(day.cells[i], g1, g2);
        }
        let paths: Vec<Value> = ALLOWED
            .iter()
            .enumerate()
            .map(|(p, label)| json!([label, cell_json(cells[2 * p]), cell_json(cells[2 * p + 1])]))
            .collect();
        let line = json!({
            "record": RECORD_DAY,
            "day": day.day,
            "date": date(day.day),
            "k": K,
            "noise": "g1 - g2, each a count of fair-coin heads before the first tail",
            "columns": ["path", "returning", "first visit today"],
            "paths": paths,
            "malformed": cell_json(cells[MALFORMED]),
            "limited": cell_json(cells[LIMITED]),
        });
        // Synced before the day counts as published: a crash before this
        // returns leaves the day unpublished, never published twice.
        let _durable =
            nucleus_jsonl::append_line_synced(&self.dir.join(PUBLISHED), &line.to_string())?;
        eprintln!("qed-analytics: published {}", date(day.day));
        self.last_published = Some(day.day);
        self.published_lines += 1;
        self.recent.push_back(line);
        if self.recent.len() > SHOWN_DAYS {
            self.recent.pop_front();
        }
        Ok(())
    }

    /// The last published days, newest last: what `GET /analytics/published`
    /// returns.
    pub fn published_view(&self) -> Value {
        json!({
            "record": "qed-visits-published/1",
            "counting": date(self.state.day),
            "days": self.recent.iter().collect::<Vec<_>>(),
        })
    }
}

fn read_checkpoint(bytes: &[u8]) -> io::Result<Day> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| bad(format!("{CHECKPOINT}: {e}")))?;
    if value["record"] != RECORD_TODAY {
        return Err(bad(format!("{CHECKPOINT}: not a {RECORD_TODAY} record")));
    }
    let object = value.as_object().map(|o| o.len()).unwrap_or(0);
    let day = value["day"].as_u64().and_then(|d| u32::try_from(d).ok());
    let cells: Option<Vec<u32>> = value["cells"].as_array().and_then(|a| {
        a.iter()
            .map(|c| c.as_u64().and_then(|c| u32::try_from(c).ok()))
            .collect()
    });
    match (object, day, cells) {
        (3, Some(day), Some(cells)) if cells.len() == CELLS => {
            let mut out = core::fresh(day);
            out.cells.copy_from_slice(&cells);
            Ok(out)
        }
        _ => Err(bad(format!("{CHECKPOINT}: unreadable"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY_MS: u64 = MS_PER_DAY;

    fn coins() -> Coins<std::io::Repeat> {
        // Every flip tails: each count is 0, so published values are exact.
        Coins::new(std::io::repeat(0))
    }

    fn connection() -> Connection {
        Connection {
            peer: [0; 16],
            peer_port: 1,
            head_bytes: 100,
            body_bytes: 9,
        }
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("qed-analytics-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn dates_are_civil() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(20_407), "2025-11-15");
        assert_eq!(date(20_772), "2026-11-15");
        assert_eq!(date(11_016), "2000-02-29");
    }

    #[test]
    fn a_day_is_published_once_with_suppression_and_the_disk_holds_only_counts() {
        let dir = temp("once");
        let t0 = 20_772 * DAY_MS + 3_600_000;
        let mut c = Collector::open(&dir, coins(), t0).unwrap();
        for n in 0..12 {
            c.beacon(14, n == 0, connection(), t0 + n * 1000).unwrap();
        }
        c.beacon(2, true, connection(), t0 + 20_000).unwrap();
        assert_eq!(
            c.beacon(PATHS, false, connection(), t0 + 21_000).unwrap(),
            Outcome::Malformed
        );
        c.tick(t0 + 120_000).unwrap();
        let saved: Value =
            serde_json::from_slice(&fs::read(dir.join(CHECKPOINT)).unwrap()).unwrap();
        let keys: Vec<&String> = saved.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["cells", "day", "record"]);
        assert_eq!(saved["cells"][28], 11);
        assert_eq!(saved["cells"][29], 1);
        // Next day: the finished day is published; status (14) returning has
        // 11, first 1 (suppressed); specification first 1 (suppressed).
        c.tick(t0 + DAY_MS).unwrap();
        let text = fs::read_to_string(dir.join(PUBLISHED)).unwrap();
        assert_eq!(text.lines().count(), 1);
        let day: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(day["date"], "2026-11-15");
        assert_eq!(day["paths"][14], json!(["/status", 11, null]));
        assert_eq!(
            day["paths"][2],
            json!(["/protocol/specification", null, null])
        );
        assert_eq!(day["malformed"], Value::Null);
        // Reopening does not publish the day again.
        drop(c);
        let c = Collector::open(&dir, coins(), t0 + DAY_MS + 5000).unwrap();
        assert_eq!(
            fs::read_to_string(dir.join(PUBLISHED))
                .unwrap()
                .lines()
                .count(),
            1
        );
        assert_eq!(c.state().day, 20_773);
        assert_eq!(c.published_view()["days"].as_array().unwrap().len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn empty_days_between_are_published_suppressed_and_bounded() {
        let dir = temp("gap");
        let t0 = 20_772 * DAY_MS;
        let mut c = Collector::open(&dir, coins(), t0).unwrap();
        c.beacon(0, true, connection(), t0).unwrap();
        c.tick(t0 + 40 * DAY_MS).unwrap();
        let text = fs::read_to_string(dir.join(PUBLISHED)).unwrap();
        assert_eq!(text.lines().count(), 1 + MAX_GAP_DAYS as usize);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_limit_refuses_past_the_burst_and_counts_it() {
        let dir = temp("limit");
        let t0 = 20_772 * DAY_MS;
        let mut c = Collector::open(&dir, coins(), t0).unwrap();
        let mut limited = 0;
        for _ in 0..BURST + 10 {
            if c.beacon(0, false, connection(), t0).unwrap() == Outcome::Limited {
                limited += 1;
            }
        }
        assert_eq!(limited, 10);
        assert_eq!(c.state().cells[LIMITED], 10);
        assert_eq!(c.state().cells[0], BURST as u32);
        // A second later, PER_SECOND more are admitted.
        let mut admitted = 0;
        for _ in 0..PER_SECOND + 3 {
            if c.beacon(0, false, connection(), t0 + 1000).unwrap() == Outcome::Counted {
                admitted += 1;
            }
        }
        assert_eq!(admitted, PER_SECOND);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unreadable_checkpoint_stops_the_collector() {
        let dir = temp("bad");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(CHECKPOINT),
            b"{\"record\":\"qed-visits-today/1\",\"day\":1,\"cells\":[1],\"ip\":\"x\"}",
        )
        .unwrap();
        assert!(Collector::open(&dir, coins(), 0).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
