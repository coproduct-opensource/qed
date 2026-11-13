//! Nucleus addition; not part of upstream nanoda_lib.
//!
//! In-memory, single-thread checking of an export, and the one inspection a
//! caller needs to bind a checked declaration to a pinned claim: for each
//! declaration, its name, its kind, and whether its type is exactly a
//! universe-monomorphic constant that names another declaration.
//!
//! Nothing here weakens a kernel check. Parsing and checking go through the
//! same `parse_export_file` and `check_declar` as the upstream binary.
use crate::env::Declar;
use crate::expr::Expr;
use crate::name::Name;

/// Export v2, the binary form of an export (statement format v2): its header,
/// the NDJSON-to-v2 encoder, and checks used by tests and tools.
pub use crate::parser::v2::{
    MAGIC as EXPORT_V2_MAGIC, decode_all as export_v2_decode_all, encode_ndjson as export_v2_from_ndjson,
    round_trip as export_v2_round_trip,
};

/// Whether `export` ends where the reader can end it: a v2 export always does
/// (its records delimit themselves; a cut record fails to decode), an NDJSON
/// export when its last byte is a newline.
pub fn ends_at_a_record_end(export: &[u8]) -> bool {
    export.starts_with(&EXPORT_V2_MAGIC) || export.last() == Some(&b'\n')
}
use crate::util::{Config, ExportFile, NamePtr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Axiom,
    Quot,
    Theorem,
    Definition,
    Opaque,
    Inductive,
    Constructor,
    Recursor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Dotted rendering. Two different names can render alike; compare
    /// declarations by position, not by this string, across trust boundaries.
    pub name: String,
    pub kind: Kind,
    /// Number of universe parameters of this declaration.
    pub universe_parameters: usize,
    /// `Some(i)` when this declaration's type is the constant declared at
    /// position `i`, applied to no universe levels.
    pub type_is_declaration: Option<usize>,
}

fn name_string(file: &ExportFile<'_>, n: NamePtr<'_>) -> String {
    match file.dag.names.get_index(n.idx()).copied() {
        None | Some(Name::Anon) => String::new(),
        Some(Name::Str(prefix, suffix, _)) => {
            let mut s = name_string(file, prefix);
            if !s.is_empty() {
                s.push('.');
            }
            match file.dag.strings.get_index(suffix.idx()) {
                Some(text) => s + text,
                None => s,
            }
        }
        Some(Name::Num(prefix, suffix, _)) => {
            let mut s = name_string(file, prefix);
            if !s.is_empty() {
                s.push('.');
            }
            s + suffix.to_string().as_str()
        }
    }
}

fn config(permitted_axioms: &[String]) -> Result<Config, String> {
    serde_json::from_value(serde_json::json!({
        "use_stdin": true,
        "permitted_axioms": permitted_axioms,
        "unpermitted_axiom_hard_error": true,
        "num_threads": 1,
        "nat_extension": true,
        "string_extension": true,
        "print_success_message": false,
        "print_axioms": false,
    }))
    .map_err(|e| e.to_string())
}

/// Parse `export`, admitting only the named axioms, and, when `check` is set,
/// type-check every declaration on the calling thread. Returns one entry per
/// declaration in the order the export declares them.
///
/// A kernel refusal is a panic, as in upstream. The caller decides whether to
/// catch it; inside a proof guest it must abort.
pub fn inspect(export: &[u8], permitted_axioms: &[String], check: bool) -> Result<Vec<Entry>, String> {
    inspect_segments(&[export], permitted_axioms, check)
}

/// As `inspect`, on the concatenation of `segments`, read in place. Every
/// segment but the last must be empty or end with a newline.
pub fn inspect_segments(segments: &[&[u8]], permitted_axioms: &[String], check: bool) -> Result<Vec<Entry>, String> {
    let (file, skipped, _) =
        crate::parser::parse_export_segments_marked(segments, config(permitted_axioms)?, &[])
            .map_err(|e| e.to_string())?;
    if !skipped.is_empty() {
        return Err(format!("unpermitted axioms were skipped: {skipped:?}"));
    }
    if check {
        file.check_all_declars_serial();
    }
    Ok(entries(&file))
}

fn entries(file: &ExportFile<'_>) -> Vec<Entry> {
    let mut entries = Vec::with_capacity(file.declars.len());
    for declar in file.declars.values() {
        let info = declar.info();
        let kind = match declar {
            Declar::Axiom { .. } => Kind::Axiom,
            Declar::Quot { .. } => Kind::Quot,
            Declar::Theorem { .. } => Kind::Theorem,
            Declar::Definition { .. } => Kind::Definition,
            Declar::Opaque { .. } => Kind::Opaque,
            Declar::Inductive(..) => Kind::Inductive,
            Declar::Constructor(..) => Kind::Constructor,
            Declar::Recursor(..) => Kind::Recursor,
        };
        let type_is_declaration = match file.dag.exprs.get_index(info.ty.idx()) {
            Some(Expr::Const { name, levels, .. })
                if file.dag.uparams.get_index(levels.idx()).is_some_and(|l| l.is_empty()) =>
            {
                file.declars.get_index_of(name)
            }
            _ => None,
        };
        let universe_parameters =
            file.dag.uparams.get_index(info.uparams.idx()).map_or(usize::MAX, |l| l.len());
        entries.push(Entry { name: name_string(file, info.name), kind, universe_parameters, type_is_declaration });
    }
    entries
}

/// What `inspect_after` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marked {
    /// One entry per declaration, in export order.
    pub entries: Vec<Entry>,
    /// For each mark given, the number of declarations made by the bytes
    /// before it. Derived from the bytes by the parser.
    pub counts: Vec<usize>,
}

/// Parse `export` once and type-check every declaration made after the first
/// mark, on the calling thread. The declarations made before the first mark
/// are NOT checked here: the caller must hold other evidence that those bytes,
/// as a complete export of their own, checked under the same permitted axioms
/// with this same checker.
///
/// `marks` are ascending byte offsets at line ends; at least one is required.
///
/// One whole-file table links declarations across the first mark: an
/// inductive type's check compares the recursors the file attaches to it with
/// the ones it derives. That check belongs to the inductive, so for an
/// inductive before the mark it is not run here. This function therefore
/// refuses any constructor or recursor after the mark that names an inductive
/// declared before it, which keeps every earlier inductive's recursor set
/// what it was when those bytes were checked alone.
///
/// Every check that is run is the upstream `check_declar`, unchanged.
pub fn inspect_after(export: &[u8], permitted_axioms: &[String], marks: &[usize]) -> Result<Marked, String> {
    inspect_after_segments(&[export], permitted_axioms, marks)
}

/// As `inspect_after`, on the concatenation of `segments`, read in place.
/// Marks are offsets into the concatenation.
pub fn inspect_after_segments(
    segments: &[&[u8]],
    permitted_axioms: &[String],
    marks: &[usize],
) -> Result<Marked, String> {
    if marks.is_empty() {
        return Err("at least one mark is required".into());
    }
    let (file, skipped, counts) =
        crate::parser::parse_export_segments_marked(segments, config(permitted_axioms)?, marks)
            .map_err(|e| e.to_string())?;
    if !skipped.is_empty() {
        return Err(format!("unpermitted axioms were skipped: {skipped:?}"));
    }
    let first = counts.first().copied().ok_or("no count for the first mark")?;
    refuse_attached_after(&file, first, "the checked prefix")?;
    for declar in file.declars.values().skip(first) {
        file.check_declar(declar);
    }
    Ok(Marked { entries: entries(&file), counts })
}

/// Refuse any constructor or recursor at position `first` or later that names
/// an inductive type declared before `first`. Keeps the recursor set the file
/// attaches to each earlier inductive what those earlier bytes alone give it.
fn refuse_attached_after(file: &ExportFile<'_>, first: usize, what: &str) -> Result<(), String> {
    let before = |name: &NamePtr<'_>| file.declars.get_index_of(name).is_some_and(|index| index < first);
    for declar in file.declars.values().skip(first) {
        let attached = match declar {
            Declar::Constructor(data) => before(&data.inductive_name),
            Declar::Recursor(data) => data.all_inductives.iter().any(before),
            _ => false,
        };
        if attached {
            return Err(format!(
                "{} is attached to an inductive type declared before {what}",
                name_string(file, declar.info().name)
            ));
        }
    }
    Ok(())
}

/// Nucleus addition (statement format v2, one parse without a base). Parse
/// the concatenation of `segments` once, type-check EVERY declaration, and
/// report how many declarations the bytes before each mark made.
///
/// This is what the base-less acceptance rule needs from a statement and an
/// artifact in one parse instead of two (statement alone, then statement and
/// artifact). The statement's declarations are the first `counts[0]` of the
/// whole parse, because parsing is a function of the bytes read so far. The
/// one thing the separate parse of the statement also did is the end-of-file
/// link between inductive types and their constructors and recursors, over
/// the statement alone; so, as for a checked base, any constructor or
/// recursor after the first mark that names an inductive declared before it
/// is refused, and the whole-file links of the statement's inductives are the
/// statement's own. Every declaration, the statement's included, is checked
/// with the upstream `check_declar`.
pub fn inspect_all_marked_segments(
    segments: &[&[u8]],
    permitted_axioms: &[String],
    marks: &[usize],
) -> Result<Marked, String> {
    if marks.is_empty() {
        return Err("at least one mark is required".into());
    }
    let (file, skipped, counts) =
        crate::parser::parse_export_segments_marked(segments, config(permitted_axioms)?, marks)
            .map_err(|e| e.to_string())?;
    if !skipped.is_empty() {
        return Err(format!("unpermitted axioms were skipped: {skipped:?}"));
    }
    let first = counts.first().copied().ok_or("no count for the first mark")?;
    refuse_attached_after(&file, first, "the end of the statement")?;
    file.check_all_declars_serial();
    Ok(Marked { entries: entries(&file), counts })
}
