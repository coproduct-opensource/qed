//! The collector's state on disk, its rate limit, and the weekly publication.
//!
//! Since 2026-11-18 a published window is a week starting Monday 00:00 UTC
//! (`core::week`); until then it was a UTC day. Each beacon is counted in one
//! cell of one window and each window is published once, so a beacon reaches
//! exactly one published cell (the spec's `one_window`, `publication_dp`).
//! Daily and weekly cells are never published side by side: that would put a
//! beacon in two cells.
//!
//! Two files in the state directory, and nothing else:
//!
//! - `window.json`: the window being counted, `{"record":"qed-visits-window/1",
//!   "window":W,"from":D,"cells":[…34 counts…]}`, where `from` is the first
//!   day counted in it (the window's Monday, or a later day when earlier days
//!   of that week were already published day by day). Replaced whole (write,
//!   sync, rename) at most once a minute while beacons arrive, and at each
//!   new window. Not append-only on purpose: a log of minute-by-minute
//!   checkpoints would keep the order in which cells grew, which the
//!   published windows do not reveal. A crash loses at most a minute of
//!   counts.
//! - `published.jsonl`: one line per finished window, appended once and
//!   synced (`nucleus_jsonl::append_line_synced`), never rewritten. A
//!   window's noise is drawn once, when its line is written; a restart never
//!   publishes a window again, so the noise cannot be averaged away by asking
//!   twice. Lines written before 2026-11-18 are days (`qed-visits/1`) and stay
//!   as history.
//!
//! **From days to weeks.** The daily collector kept the day being counted in
//! `today.json`. At start, if `window.json` does not exist and `today.json`
//! does, its counts (of one unpublished day `D`) become the counts of `D`'s
//! week with `from = D`; `window.json` is written and synced, then
//! `today.json` is removed. The earlier days of that week were published as
//! days and are not counted again. If both files exist, `window.json` is the
//! later one (it is written before `today.json` is removed) and `today.json`
//! is removed.
//!
//! True counts of a finished window are never written: they exist in memory
//! and in `window.json` only until the window's line is published.
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
use crate::core::{self, CELLS, Cell, K, LIMITED, MALFORMED, PATHS, Request, Window};
use crate::noise::Coins;
use crate::paths::ALLOWED;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const CHECKPOINT: &str = "window.json";
pub const RECORD_WINDOW: &str = "qed-visits-window/1";
/// The daily collector's checkpoint, read once to carry its counts over.
pub const LEGACY_CHECKPOINT: &str = "today.json";
pub const RECORD_TODAY: &str = "qed-visits-today/1";
pub const PUBLISHED: &str = "published.jsonl";
/// A published day: the lines written until 2026-11-18, kept as history.
pub const RECORD_DAY: &str = "qed-visits/1";
/// A published week.
pub const RECORD_WEEK: &str = "qed-visits-week/1";
/// What `GET /analytics/published` answers ([`Collector::published_view`]);
/// `/1` was the daily collector's, with `days` in place of `lines`.
pub const RECORD_PUBLISHED: &str = "qed-visits-published/2";
/// Lines in the published file past which nothing more is published.
pub const MAX_PUBLISHED: usize = 4000;
/// Weeks with no beacons between two weeks with beacons are published from
/// zero counts like any other week (each cell shown with probability
/// 1/1536, `shown_zero`), at most this many in a row.
pub const MAX_GAP_WEEKS: u32 = 5;
/// Seconds between checkpoints while beacons arrive.
pub const SAVE_EVERY: u64 = 60;
pub const BURST: u64 = 600;
pub const PER_SECOND: u64 = 5;
/// Published lines the view returns, newest last.
pub const SHOWN_LINES: usize = 8;
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
    state: Window,
    /// The first day counted in `state`.
    from: u32,
    coins: Coins<R>,
    dirty: bool,
    saved_ms: u64,
    /// The last window published as a week, and the last day published as a
    /// day (history).
    last_week: Option<u32>,
    last_day: Option<u32>,
    published_lines: usize,
    recent: VecDeque<Value>,
    tokens_milli: u64,
    refilled_ms: u64,
}

pub fn day_of(now_ms: u64) -> u32 {
    u32::try_from(now_ms / MS_PER_DAY).unwrap_or(u32::MAX)
}

/// The first day of window `w`: its Monday (window 0 starts on day 0).
pub fn first_day(w: u32) -> u32 {
    (u64::from(w) * 7)
        .saturating_sub(3)
        .min(u64::from(u32::MAX)) as u32
}

/// The last day of window `w`: its Sunday.
pub fn last_day(w: u32) -> u32 {
    (u64::from(w) * 7 + 3).min(u64::from(u32::MAX)) as u32
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

/// A line of `published.jsonl`, by its record.
enum Line {
    Day(u32),
    Week(u32),
}

fn read_line(value: &Value) -> Option<Line> {
    let number = |key: &str| value[key].as_u64().and_then(|d| u32::try_from(d).ok());
    if value["record"] == RECORD_DAY {
        number("day").map(Line::Day)
    } else if value["record"] == RECORD_WEEK {
        number("week").map(Line::Week)
    } else {
        None
    }
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

impl<R: Read> Collector<R> {
    /// Open the state directory: read the published lines and the
    /// checkpoint (or the daily collector's, once). An unreadable line or
    /// checkpoint stops the collector rather than being read as nothing.
    pub fn open(dir: &Path, coins: Coins<R>, now_ms: u64) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let mut last_week = None;
        let mut last_day = None;
        let mut published_lines = 0;
        let mut recent = VecDeque::new();
        match fs::read_to_string(dir.join(PUBLISHED)) {
            Ok(text) => {
                for (n, line) in text.lines().enumerate() {
                    let value: Value = serde_json::from_str(line)
                        .map_err(|e| bad(format!("{PUBLISHED} line {}: {e}", n + 1)))?;
                    match read_line(&value) {
                        Some(Line::Day(d)) => last_day = last_day.max(Some(d)),
                        Some(Line::Week(w)) => last_week = last_week.max(Some(w)),
                        None => {
                            return Err(bad(format!(
                                "{PUBLISHED} line {}: not a day or a week",
                                n + 1
                            )));
                        }
                    }
                    published_lines += 1;
                    recent.push_back(value);
                    if recent.len() > SHOWN_LINES {
                        recent.pop_front();
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let now = core::week(day_of(now_ms));
        let start = |w: u32| first_day(w).max(last_day.map_or(0, |d| d.saturating_add(1)));
        let published = |w: u32| last_week.is_some_and(|p| w <= p);
        let read = |name: &str| match fs::read(dir.join(name)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        };
        let (state, from) = match (read(CHECKPOINT)?, read(LEGACY_CHECKPOINT)?) {
            (Some(bytes), _) => {
                let (saved, from) = read_checkpoint(&bytes)?;
                // A window already published is not counted again.
                if published(saved.window) {
                    let w = now.max(saved.window);
                    (core::fresh(w), start(w))
                } else {
                    (saved, from)
                }
            }
            (None, Some(bytes)) => {
                let (day, cells) = read_legacy(&bytes)?;
                let w = core::week(day);
                if last_day.is_some_and(|d| day <= d) || published(w) {
                    let w = now.max(w);
                    (core::fresh(w), start(w))
                } else {
                    // The unpublished day's counts start its week.
                    let mut state = core::fresh(w);
                    state.cells = cells;
                    (state, day)
                }
            }
            (None, None) => (core::fresh(now), start(now)),
        };
        let mut collector = Collector {
            dir: dir.to_path_buf(),
            state,
            from,
            coins,
            dirty: false,
            saved_ms: now_ms,
            last_week,
            last_day,
            published_lines,
            recent,
            tokens_milli: BURST * 1000,
            refilled_ms: now_ms,
        };
        collector.save()?;
        // Only once `window.json` holds its counts.
        remove_if_present(&dir.join(LEGACY_CHECKPOINT))?;
        fs::File::open(dir)?.sync_all()?;
        collector.tick(now_ms)?;
        Ok(collector)
    }

    pub fn state(&self) -> &Window {
        &self.state
    }

    /// The first day counted in the window being counted.
    pub fn from(&self) -> u32 {
        self.from
    }

    fn start(&self, w: u32) -> u32 {
        first_day(w).max(self.last_day.map_or(0, |d| d.saturating_add(1)))
    }

    /// Roll to a new window when the clock has passed Monday 00:00 UTC:
    /// publish the finished window and any empty windows since, then start
    /// the new one. Otherwise save a checkpoint if one is due.
    pub fn tick(&mut self, now_ms: u64) -> io::Result<()> {
        let now = core::week(day_of(now_ms));
        if now > self.state.window {
            let finished = self.state;
            self.publish(finished, self.from)?;
            let gap_end = now.min(finished.window.saturating_add(1 + MAX_GAP_WEEKS));
            for w in finished.window + 1..gap_end {
                self.publish(core::fresh(w), self.start(w))?;
            }
            self.state = core::fresh(now);
            self.from = self.start(now);
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
            "record": RECORD_WINDOW,
            "window": self.state.window,
            "from": self.from,
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

    /// Publish one finished window, once: each cell through
    /// `core::publish_cell` with a fresh pair of fair-coin counts.
    fn publish(&mut self, window: Window, from: u32) -> io::Result<()> {
        if self.last_week.is_some_and(|p| window.window <= p) {
            return Ok(());
        }
        if self.published_lines >= MAX_PUBLISHED {
            eprintln!("qed-analytics: {MAX_PUBLISHED} lines published; publishing stopped");
            return Ok(());
        }
        let mut cells = [Cell::Suppressed; CELLS];
        for (i, cell) in cells.iter_mut().enumerate() {
            let (g1, g2) = self.coins.pair()?;
            *cell = core::publish_cell(window.cells[i], g1, g2);
        }
        let paths: Vec<Value> = ALLOWED
            .iter()
            .enumerate()
            .map(|(p, label)| json!([label, cell_json(cells[2 * p]), cell_json(cells[2 * p + 1])]))
            .collect();
        let to = last_day(window.window);
        let line = json!({
            "record": RECORD_WEEK,
            "week": window.window,
            "from": date(from),
            "to": date(to),
            "days": to.saturating_sub(from) + 1,
            "k": K,
            "suppressed": "count plus noise under k",
            "noise": "g1 - g2, each a count of fair-coin heads before the first tail",
            "columns": ["path", "returning", "first visit that day"],
            "paths": paths,
            "malformed": cell_json(cells[MALFORMED]),
            "limited": cell_json(cells[LIMITED]),
        });
        // Synced before the window counts as published: a crash before this
        // returns leaves the window unpublished, never published twice.
        let _durable =
            nucleus_jsonl::append_line_synced(&self.dir.join(PUBLISHED), &line.to_string())?;
        eprintln!(
            "qed-analytics: published the week {} to {}",
            date(from),
            date(to)
        );
        self.last_week = Some(window.window);
        self.published_lines += 1;
        self.recent.push_back(line);
        if self.recent.len() > SHOWN_LINES {
            self.recent.pop_front();
        }
        Ok(())
    }

    /// The last published lines, newest last, and the window being counted:
    /// what `GET /analytics/published` returns.
    pub fn published_view(&self) -> Value {
        json!({
            "record": RECORD_PUBLISHED,
            "counting": {
                "from": date(self.from),
                "to": date(last_day(self.state.window)),
            },
            "lines": self.recent.iter().collect::<Vec<_>>(),
        })
    }
}

fn cells_of(value: &Value) -> Option<[u32; CELLS]> {
    let cells: Vec<u32> = value["cells"]
        .as_array()?
        .iter()
        .map(|c| c.as_u64().and_then(|c| u32::try_from(c).ok()))
        .collect::<Option<_>>()?;
    cells.try_into().ok()
}

fn read_checkpoint(bytes: &[u8]) -> io::Result<(Window, u32)> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| bad(format!("{CHECKPOINT}: {e}")))?;
    if value["record"] != RECORD_WINDOW {
        return Err(bad(format!("{CHECKPOINT}: not a {RECORD_WINDOW} record")));
    }
    let keys = value.as_object().map(|o| o.len()).unwrap_or(0);
    let number = |key: &str| value[key].as_u64().and_then(|d| u32::try_from(d).ok());
    match (keys, number("window"), number("from"), cells_of(&value)) {
        (4, Some(window), Some(from), Some(cells))
            if from >= first_day(window) && from <= last_day(window) =>
        {
            Ok((Window { window, cells }, from))
        }
        _ => Err(bad(format!("{CHECKPOINT}: unreadable"))),
    }
}

fn read_legacy(bytes: &[u8]) -> io::Result<(u32, [u32; CELLS])> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| bad(format!("{LEGACY_CHECKPOINT}: {e}")))?;
    if value["record"] != RECORD_TODAY {
        return Err(bad(format!(
            "{LEGACY_CHECKPOINT}: not a {RECORD_TODAY} record"
        )));
    }
    let keys = value.as_object().map(|o| o.len()).unwrap_or(0);
    let day = value["day"].as_u64().and_then(|d| u32::try_from(d).ok());
    match (keys, day, cells_of(&value)) {
        (3, Some(day), Some(cells)) => Ok((day, cells)),
        _ => Err(bad(format!("{LEGACY_CHECKPOINT}: unreadable"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY_MS: u64 = MS_PER_DAY;
    /// Monday 2026-11-16.
    const MONDAY: u64 = 20_773;

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

    fn lines(dir: &Path) -> Vec<Value> {
        fs::read_to_string(dir.join(PUBLISHED))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn dates_are_civil_and_weeks_run_monday_to_sunday() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(20_407), "2025-11-15");
        assert_eq!(date(20_772), "2026-11-15");
        assert_eq!(date(11_016), "2000-02-29");
        let w = core::week(MONDAY as u32);
        assert_eq!(date(first_day(w)), "2026-11-16");
        assert_eq!(date(last_day(w)), "2026-11-22");
        assert_eq!((first_day(0), last_day(0), first_day(1)), (0, 3, 4));
        for d in [0u32, 3, 4, 20_772, 20_773, 20_779, 20_780] {
            let w = core::week(d);
            assert!(first_day(w) <= d && d <= last_day(w), "{d}");
        }
    }

    #[test]
    fn a_week_is_published_once_with_every_day_in_one_line() {
        let dir = temp("once");
        let t0 = MONDAY * DAY_MS + 3_600_000;
        let mut c = Collector::open(&dir, coins(), t0).unwrap();
        // Six beacons on Monday, six on Sunday: one cell, one window.
        for n in 0..12 {
            let at = if n < 6 { t0 } else { t0 + 6 * DAY_MS };
            c.beacon(14, n == 0, connection(), at + n * 1000).unwrap();
        }
        c.beacon(2, true, connection(), t0 + 20_000).unwrap();
        assert_eq!(
            c.beacon(PATHS, false, connection(), t0 + 21_000).unwrap(),
            Outcome::Malformed
        );
        c.tick(t0 + 6 * DAY_MS + 120_000).unwrap();
        let saved: Value =
            serde_json::from_slice(&fs::read(dir.join(CHECKPOINT)).unwrap()).unwrap();
        let keys: Vec<&String> = saved.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["cells", "from", "record", "window"]);
        assert_eq!(saved["cells"][28], 11);
        assert_eq!(saved["cells"][29], 1);
        assert_eq!(saved["from"], MONDAY);
        assert!(
            lines(&dir).is_empty(),
            "nothing is published within the week"
        );
        // Next Monday: the finished week is published.
        c.tick((MONDAY + 7) * DAY_MS).unwrap();
        let published = lines(&dir);
        assert_eq!(published.len(), 1);
        let week = &published[0];
        assert_eq!(week["record"], RECORD_WEEK);
        assert_eq!(
            (&week["from"], &week["to"], &week["days"]),
            (&json!("2026-11-16"), &json!("2026-11-22"), &json!(7))
        );
        assert_eq!(week["suppressed"], "count plus noise under k");
        assert_eq!(week["paths"][14], json!(["/status", 11, null]));
        assert_eq!(
            week["paths"][2],
            json!(["/protocol/specification", null, null])
        );
        assert_eq!(week["malformed"], Value::Null);
        // Reopening does not publish the week again.
        drop(c);
        let c = Collector::open(&dir, coins(), (MONDAY + 7) * DAY_MS + 5000).unwrap();
        assert_eq!(lines(&dir).len(), 1);
        assert_eq!(c.state().window, core::week(MONDAY as u32) + 1);
        assert_eq!(c.published_view()["lines"].as_array().unwrap().len(), 1);
        assert_eq!(c.published_view()["counting"]["from"], "2026-11-23");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_daily_checkpoint_starts_its_week_and_published_days_stay() {
        let dir = temp("legacy");
        fs::create_dir_all(&dir).unwrap();
        // The daily collector published Monday and Tuesday and was counting
        // Wednesday 2026-11-18 (day 20_775).
        let day_line = |d: u32| {
            json!({"record": RECORD_DAY, "day": d, "date": date(d), "k": 10,
                   "suppressed": "count plus noise under k", "paths": [],
                   "malformed": null, "limited": null})
            .to_string()
        };
        fs::write(
            dir.join(PUBLISHED),
            format!("{}\n{}\n", day_line(20_773), day_line(20_774)),
        )
        .unwrap();
        let mut cells = [0u32; CELLS];
        cells[28] = 4;
        fs::write(
            dir.join(LEGACY_CHECKPOINT),
            json!({"record": RECORD_TODAY, "day": 20_775, "cells": cells.to_vec()}).to_string(),
        )
        .unwrap();
        let t = 20_775 * DAY_MS + 50_000_000;
        let mut c = Collector::open(&dir, coins(), t).unwrap();
        assert!(!dir.join(LEGACY_CHECKPOINT).exists());
        assert_eq!(c.state().window, core::week(20_775));
        assert_eq!(c.state().cells[28], 4);
        assert_eq!(c.from(), 20_775);
        c.beacon(14, false, connection(), t + 1000).unwrap();
        c.tick(t + 120_000).unwrap();
        // Reopened before the week ends: the counts survive, the daily file
        // is not read again.
        drop(c);
        let mut c = Collector::open(&dir, coins(), t + DAY_MS).unwrap();
        assert_eq!(c.state().cells[28], 5);
        assert_eq!(c.from(), 20_775);
        c.tick(20_780 * DAY_MS).unwrap();
        let published = lines(&dir);
        assert_eq!(published.len(), 3);
        let week = &published[2];
        assert_eq!(
            (&week["from"], &week["to"], &week["days"]),
            (&json!("2026-11-18"), &json!("2026-11-22"), &json!(5))
        );
        // The next week starts on its Monday.
        assert_eq!(c.from(), 20_780);
        let view = c.published_view();
        assert_eq!(view["lines"][0]["record"], RECORD_DAY);
        assert_eq!(view["lines"][2]["record"], RECORD_WEEK);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_daily_checkpoint_of_a_published_day_is_not_counted_again() {
        let dir = temp("legacy-done");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(PUBLISHED),
            json!({"record": RECORD_DAY, "day": 20_775}).to_string() + "\n",
        )
        .unwrap();
        let mut cells = [0u32; CELLS];
        cells[0] = 9;
        fs::write(
            dir.join(LEGACY_CHECKPOINT),
            json!({"record": RECORD_TODAY, "day": 20_775, "cells": cells.to_vec()}).to_string(),
        )
        .unwrap();
        let c = Collector::open(&dir, coins(), 20_776 * DAY_MS).unwrap();
        assert_eq!(c.state().cells.iter().sum::<u32>(), 0);
        assert_eq!(c.from(), 20_776);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn empty_weeks_between_are_published_and_bounded() {
        let dir = temp("gap");
        let t0 = MONDAY * DAY_MS;
        let mut c = Collector::open(&dir, coins(), t0).unwrap();
        c.beacon(0, true, connection(), t0).unwrap();
        c.tick(t0 + 70 * DAY_MS).unwrap();
        assert_eq!(lines(&dir).len(), 1 + MAX_GAP_WEEKS as usize);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_limit_refuses_past_the_burst_and_counts_it() {
        let dir = temp("limit");
        let t0 = MONDAY * DAY_MS;
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
        for (name, file, body) in [
            (
                "bad",
                CHECKPOINT,
                "{\"record\":\"qed-visits-window/1\",\"window\":1,\"from\":4,\"cells\":[1],\"ip\":\"x\"}",
            ),
            (
                "bad-from",
                CHECKPOINT,
                "{\"record\":\"qed-visits-window/1\",\"window\":1,\"from\":20,\"cells\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}",
            ),
            (
                "bad-legacy",
                LEGACY_CHECKPOINT,
                "{\"record\":\"qed-visits-today/1\",\"day\":1,\"cells\":[1],\"ip\":\"x\"}",
            ),
        ] {
            let dir = temp(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(file), body).unwrap();
            assert!(Collector::open(&dir, coins(), 0).is_err(), "{name}");
            // Nothing was removed.
            assert!(dir.join(file).exists(), "{name}");
            fs::remove_dir_all(&dir).unwrap();
        }
    }
}
