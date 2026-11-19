//! The collector's core, in the subset of Rust that Charon and Aeneas
//! translate: integers, booleans, fixed arrays, two structs and one enum. No
//! I/O, strings, floats, loops or allocation.
//!
//! `lean/generated/` is this module's translation, and
//! `lean/QedAnalytics/Refines.lean` proves that the translation computes the
//! functions of `lean/QedAnalytics/Spec.lean`, where the theorems are. The rest
//! of the crate is the shell: it reads the socket, the clock, the random bytes
//! and the disk, and changes the counts or publishes them only by calling
//! [`handle`], [`limit`] and [`publish_cell`].
//!
//! Each function here mirrors the spec's definition of the same name. A
//! change to one is a change to the other, and `Refines.lean` stops compiling
//! until both agree.

/// Site paths on the allow-list (`paths::ALLOWED`).
pub const PATHS: usize = 16;
/// Cells per window: per path, returning visits at `2 * path` and first
/// visits that day at `2 * path + 1`; then malformed beacons; then beacons
/// refused by the rate limit.
pub const CELLS: usize = 2 * PATHS + 2;
pub const MALFORMED: usize = 2 * PATHS;
pub const LIMITED: usize = 2 * PATHS + 1;
/// A cell whose count plus noise is under `K` is published as suppressed.
pub const K: u32 = 10;

/// The whole state: the window being counted ([`week`] of its days) and its
/// cells. Until 2026-11-18 the window was a UTC day.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub window: u32,
    pub cells: [u32; CELLS],
}

/// Everything the shell holds about one beacon when it calls the core: the
/// path as an index into the allow-list (`PATHS` or more: malformed), the
/// first-visit bit, the day (days since 1970-01-01, UTC), and what it read
/// from the connection. Only [`project`] reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub path: usize,
    pub first: bool,
    pub day: u32,
    pub second_of_day: u32,
    pub peer: [u8; 16],
    pub peer_port: u16,
    pub head_bytes: u32,
    pub body_bytes: u32,
}

/// One published cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cell {
    Suppressed,
    Count(i64),
}

/// The window of a day: weeks starting Monday 00:00 UTC. Day 0
/// (1970-01-01) was a Thursday and day 4 the first Monday, so window `w >= 1`
/// holds days `7w - 3` to `7w + 3`; the spec's `week d = (d + 3) / 7`,
/// written so that it cannot overflow.
pub fn week(day: u32) -> u32 {
    let w = day / 7;
    if day % 7 >= 4 { w + 1 } else { w }
}

pub fn fresh(window: u32) -> Window {
    Window {
        window,
        cells: [0; CELLS],
    }
}

pub fn cell(path: usize, first: bool) -> usize {
    if path < PATHS {
        if first { 2 * path + 1 } else { 2 * path }
    } else {
        MALFORMED
    }
}

pub fn bump(c: u32) -> u32 {
    if c < u32::MAX { c + 1 } else { c }
}

/// Count one beacon in cell `i` (which must be under `CELLS`) in `window`. A
/// beacon of a window before the one being counted changes nothing; one of
/// a later window starts that window from zero.
pub fn count(s: Window, i: usize, window: u32) -> Window {
    if window < s.window {
        s
    } else {
        let mut t = if s.window < window { fresh(window) } else { s };
        t.cells[i] = bump(t.cells[i]);
        t
    }
}

/// The only fields of a request the core uses.
pub fn project(r: &Request) -> (usize, bool, u32) {
    (r.path, r.first, r.day)
}

/// A beacon dated `day` is counted in that day's window.
pub fn step(s: Window, path: usize, first: bool, day: u32) -> Window {
    count(s, cell(path, first), week(day))
}

/// A beacon the rate limit refused, counted in the window of `day`.
pub fn limit(s: Window, day: u32) -> Window {
    count(s, LIMITED, week(day))
}

pub fn handle(s: Window, r: &Request) -> Window {
    let (path, first, day) = project(r);
    step(s, path, first, day)
}

/// Publish one cell: the true count plus the noise `g1 - g2` (two fair-coin
/// counts, `noise::Coins::geometric`), suppressed when that noisy value is
/// under `K`. Suppression reads only the noisy value (the spec's
/// `publish_is_post`), so the differential-privacy theorem holds for every
/// window. Until 2026-11-15 it read the true count (`lean/QedAnalytics/History.lean`).
pub fn publish_cell(count: u32, g1: u32, g2: u32) -> Cell {
    let noisy = count as i64 + g1 as i64 - g2 as i64;
    if noisy < K as i64 {
        Cell::Suppressed
    } else {
        Cell::Count(noisy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(path: usize, first: bool, day: u32) -> Request {
        Request {
            path,
            first,
            day,
            second_of_day: 0,
            peer: [0; 16],
            peer_port: 0,
            head_bytes: 0,
            body_bytes: 0,
        }
    }

    /// 2026-11-18, a Wednesday; its week runs from Monday 2026-11-16 (day
    /// 20_773) to Sunday 2026-11-22 (day 20_779).
    const D: u32 = 20_775;

    #[test]
    fn the_connection_never_changes_the_state() {
        let s = step(fresh(week(D)), 3, true, D);
        let a = request(5, false, D);
        let mut b = a;
        b.second_of_day = 86_399;
        b.peer = [0xff; 16];
        b.peer_port = 65_535;
        b.head_bytes = 4096;
        b.body_bytes = 64;
        assert_eq!(handle(s, &a), handle(s, &b));
    }

    #[test]
    fn one_beacon_moves_one_cell_by_one() {
        let s = step(fresh(week(D)), 3, true, D);
        let t = handle(s, &request(5, false, D));
        let moved: Vec<usize> = (0..CELLS).filter(|&j| s.cells[j] != t.cells[j]).collect();
        assert_eq!(moved, [10]);
        assert_eq!(t.cells[10], s.cells[10] + 1);
        assert_eq!(handle(s, &request(PATHS, true, D)).cells[MALFORMED], 1);
        assert_eq!(limit(s, D).cells[LIMITED], 1);
    }

    #[test]
    fn weeks_start_on_monday_utc() {
        // 1970-01-01 (day 0) was a Thursday; 1970-01-05 (day 4) a Monday.
        assert_eq!(
            (week(0), week(3), week(4), week(10), week(11)),
            (0, 0, 1, 1, 2)
        );
        // Sunday 2026-11-15 and Monday 2026-11-16 are in different weeks;
        // Monday to Sunday share one.
        assert_eq!(week(20_772) + 1, week(20_773));
        assert!((20_773..=20_779).all(|d| week(d) == week(D)));
        assert_eq!(week(20_780), week(D) + 1);
        for d in [0, 1, 6, 7, 20_775, u32::MAX - 7, u32::MAX] {
            assert_eq!(u64::from(week(d)), (u64::from(d) + 3) / 7, "{d}");
        }
    }

    #[test]
    fn every_day_of_a_week_counts_in_it_and_weeks_never_go_back() {
        let s = step(fresh(week(D)), 3, true, D);
        // Sunday of the same week: the same window.
        let sunday = step(s, 1, false, 20_779);
        assert_eq!(sunday.window, week(D));
        assert_eq!(sunday.cells.iter().sum::<u32>(), 2);
        // Next Monday: a new window from zero.
        let later = step(sunday, 1, false, 20_780);
        assert_eq!(later.window, week(D) + 1);
        assert_eq!(later.cells.iter().sum::<u32>(), 1);
        assert_eq!(step(later, 1, false, D), later);
    }

    #[test]
    fn a_cell_saturates() {
        assert_eq!(bump(u32::MAX), u32::MAX);
        assert_eq!(bump(u32::MAX - 1), u32::MAX);
    }

    #[test]
    fn suppression_reads_the_noisy_value() {
        // 9 lifted to 10 by its noise is shown; 12 lowered to 9 is not.
        assert_eq!(publish_cell(9, 1, 0), Cell::Count(10));
        assert_eq!(publish_cell(0, 10, 0), Cell::Count(10));
        assert_eq!(publish_cell(12, 0, 3), Cell::Suppressed);
        assert_eq!(publish_cell(K, 0, 0), Cell::Count(K as i64));
        assert_eq!(publish_cell(K, 3, 1), Cell::Count(K as i64 + 2));
        assert_eq!(publish_cell(u32::MAX, 0, u32::MAX), Cell::Suppressed);
        assert_eq!(
            publish_cell(u32::MAX, u32::MAX, 0),
            Cell::Count(2 * u32::MAX as i64)
        );
    }

    #[test]
    fn nothing_under_k_is_shown() {
        for c in 0..3 * K {
            for g1 in 0..2 * K {
                for g2 in 0..2 * K {
                    let noisy = c as i64 + g1 as i64 - g2 as i64;
                    match publish_cell(c, g1, g2) {
                        Cell::Count(v) => assert!(v >= K as i64 && v == noisy),
                        Cell::Suppressed => assert!(noisy < K as i64),
                    }
                }
            }
        }
    }
}
