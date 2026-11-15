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
/// Cells per day: per path, returning visits at `2 * path` and first visits
/// today at `2 * path + 1`; then malformed beacons; then beacons refused by
/// the rate limit.
pub const CELLS: usize = 2 * PATHS + 2;
pub const MALFORMED: usize = 2 * PATHS;
pub const LIMITED: usize = 2 * PATHS + 1;
/// A cell whose true count is under `K` is published as suppressed.
pub const K: u32 = 10;

/// The whole state: the day being counted (days since 1970-01-01, UTC) and
/// its cells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Day {
    pub day: u32,
    pub cells: [u32; CELLS],
}

/// Everything the shell holds about one beacon when it calls the core: the
/// path as an index into the allow-list (`PATHS` or more: malformed), the
/// first-visit bit, the day, and what it read from the connection. Only
/// [`project`] reads it.
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

pub fn fresh(day: u32) -> Day {
    Day {
        day,
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

/// Count one beacon in cell `i` (which must be under `CELLS`) on `day`. A
/// beacon dated before the day being counted changes nothing; one dated
/// later starts a new day from zero.
pub fn count(s: Day, i: usize, day: u32) -> Day {
    if day < s.day {
        s
    } else {
        let mut t = if s.day < day { fresh(day) } else { s };
        t.cells[i] = bump(t.cells[i]);
        t
    }
}

/// The only fields of a request the core uses.
pub fn project(r: &Request) -> (usize, bool, u32) {
    (r.path, r.first, r.day)
}

pub fn step(s: Day, path: usize, first: bool, day: u32) -> Day {
    count(s, cell(path, first), day)
}

/// A beacon the rate limit refused, counted on `day`.
pub fn limit(s: Day, day: u32) -> Day {
    count(s, LIMITED, day)
}

pub fn handle(s: Day, r: &Request) -> Day {
    let (path, first, day) = project(r);
    step(s, path, first, day)
}

/// Publish one cell: suppressed under `K`, otherwise the true count plus the
/// noise `g1 - g2` (two fair-coin counts, `noise::Coins::geometric`).
pub fn publish_cell(count: u32, g1: u32, g2: u32) -> Cell {
    if count < K {
        Cell::Suppressed
    } else {
        Cell::Count(count as i64 + g1 as i64 - g2 as i64)
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

    #[test]
    fn the_connection_never_changes_the_state() {
        let s = step(fresh(9), 3, true, 9);
        let a = request(5, false, 9);
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
        let s = step(fresh(9), 3, true, 9);
        let t = handle(s, &request(5, false, 9));
        let moved: Vec<usize> = (0..CELLS).filter(|&j| s.cells[j] != t.cells[j]).collect();
        assert_eq!(moved, [10]);
        assert_eq!(t.cells[10], s.cells[10] + 1);
        assert_eq!(handle(s, &request(PATHS, true, 9)).cells[MALFORMED], 1);
        assert_eq!(limit(s, 9).cells[LIMITED], 1);
    }

    #[test]
    fn days_roll_forward_and_never_back() {
        let s = step(fresh(9), 3, true, 9);
        let later = step(s, 1, false, 10);
        assert_eq!(later.day, 10);
        assert_eq!(later.cells.iter().sum::<u32>(), 1);
        assert_eq!(step(later, 1, false, 9), later);
    }

    #[test]
    fn a_cell_saturates() {
        assert_eq!(bump(u32::MAX), u32::MAX);
        assert_eq!(bump(u32::MAX - 1), u32::MAX);
    }

    #[test]
    fn under_k_is_suppressed_whatever_the_noise() {
        for c in 0..K {
            for (g1, g2) in [(0, 0), (u32::MAX, 0), (0, u32::MAX)] {
                assert_eq!(publish_cell(c, g1, g2), Cell::Suppressed);
            }
        }
        assert_eq!(publish_cell(K, 3, 1), Cell::Count(K as i64 + 2));
        assert_eq!(
            publish_cell(u32::MAX, u32::MAX, 0),
            Cell::Count(2 * u32::MAX as i64)
        );
    }
}
