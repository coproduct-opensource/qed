//! The one-pass export reader (statement format v2, stage 1;
//! docs/rfcs/proof-commerce-statement-format-v2-2026-11-13.md): reading
//! segments in place gives what reading their concatenation gives, and lines
//! no exporter writes are refused.
use nanoda_lib::acceptance::{inspect, inspect_after, inspect_after_segments, inspect_segments};

const STATEMENT: &[u8] = include_bytes!("fixtures/task.ndjson");
const ARTIFACT: &[u8] = include_bytes!("fixtures/suffix.ndjson");

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

#[test]
fn segments_read_in_place_are_their_concatenation() {
    let whole = concat(&[STATEMENT, ARTIFACT]);
    assert_eq!(
        inspect_segments(&[STATEMENT, ARTIFACT], &[], true),
        inspect(&whole, &[], true)
    );
    assert!(inspect_segments(&[STATEMENT, ARTIFACT], &[], true).is_ok());
    // Marks are offsets into the concatenation, across the segment boundary.
    let marks = [STATEMENT.len(), whole.len()];
    assert_eq!(
        inspect_after_segments(&[STATEMENT, ARTIFACT], &[], &marks),
        inspect_after(&whole, &[], &marks)
    );
}

#[test]
fn a_segment_before_the_last_must_end_at_a_line_end() {
    // Split inside the last line. Read line by line per segment, both halves
    // would also fail as JSON; the refusal must name the boundary rule.
    let cut = STATEMENT.len() - 10;
    let (head, tail) = STATEMENT.split_at(cut);
    let refused = inspect_segments(&[head, tail], &[], false).unwrap_err();
    assert!(refused.contains("does not end at a line end"), "{refused}");
    // An empty segment anywhere is no line at all.
    assert_eq!(
        inspect_segments(&[STATEMENT, b"", ARTIFACT], &[], true),
        inspect_segments(&[STATEMENT, ARTIFACT], &[], true)
    );
}

/// The statement with one line appended. The line's back-reference is the
/// next free name index, so only the line's shape is at issue.
fn with_line(line: &str) -> Vec<u8> {
    let mut out = STATEMENT.to_vec();
    out.extend_from_slice(line.as_bytes());
    out.push(b'\n');
    out
}

fn next_name_index() -> usize {
    std::str::from_utf8(STATEMENT)
        .unwrap()
        .lines()
        .filter(|l| l.contains("\"in\":"))
        .count()
        + 1
}

#[test]
fn a_well_formed_appended_line_reads() {
    let n = next_name_index();
    let line = format!(r#"{{"in":{n},"str":{{"pre":0,"str":"Probe"}}}}"#);
    assert!(inspect(&with_line(&line), &[], false).is_ok());
    // Key order does not matter.
    let line = format!(r#"{{"str":{{"pre":0,"str":"Probe"}},"in":{n}}}"#);
    assert!(inspect(&with_line(&line), &[], false).is_ok());
}

#[test]
fn lines_no_exporter_writes_are_refused() {
    let n = next_name_index();
    for line in [
        // an unknown key beside a value and a back-reference
        format!(r#"{{"in":{n},"str":{{"pre":0,"str":"Probe"}},"zz":1}}"#),
        // two value keys
        format!(r#"{{"in":{n},"str":{{"pre":0,"str":"Probe"}},"num":{{"pre":0,"i":1}}}}"#),
        // two back-reference keys
        format!(r#"{{"in":{n},"ie":{n},"str":{{"pre":0,"str":"Probe"}}}}"#),
        // the same back-reference key twice
        format!(r#"{{"in":{n},"in":{n},"str":{{"pre":0,"str":"Probe"}}}}"#),
        // no value key
        format!(r#"{{"in":{n}}}"#),
        // not an object
        "[1,2]".to_string(),
    ] {
        assert!(
            inspect(&with_line(&line), &[], false).is_err(),
            "accepted: {line}"
        );
    }
}

#[test]
fn a_line_that_is_not_utf8_is_refused() {
    let mut bytes = STATEMENT.to_vec();
    bytes.extend_from_slice(b"{\"in\":1,\"str\":{\"pre\":0,\"str\":\"\xff\"}}\n");
    assert!(inspect(&bytes, &[], false).is_err());
}

#[test]
fn a_last_line_without_a_newline_is_still_read() {
    let trimmed = &STATEMENT[..STATEMENT.len() - 1];
    assert_eq!(inspect(trimmed, &[], false), inspect(STATEMENT, &[], false));
}
