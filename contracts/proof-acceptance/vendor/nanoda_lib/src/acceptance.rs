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

/// Nucleus change (VENDOR.md, item 12). Whether `name` (dotted, as
/// `Entry::name` renders it) is one the checker treats specially by name: a
/// `NameCache` name (`util.rs`, generated from one list) or one `quot.rs`
/// looks `Eq` up by. The checker reduces, or builds terms with, the constant
/// of that name whatever the export defines under it.
///
/// A declaration whose name *is* a cached name renders to exactly that string
/// (`find_name` splits on `.`, `name_string` joins on `.`, and no listed name
/// has a numeric component), so a test on the rendering never misses one. It
/// can also match a different name that renders alike (one component holding
/// a dot); that errs toward refusing.
pub fn is_kernel_reserved(name: &str) -> bool {
    crate::util::NAME_CACHE_NAMES.contains(&name)
        || name == crate::quot::EQ
        || name.strip_prefix(crate::quot::EQ).and_then(|rest| rest.strip_prefix('.')) == Some(crate::quot::EQ_REFL)
}

/// Every name `is_kernel_reserved` holds for. For tests and tools.
pub fn kernel_reserved_names() -> Vec<String> {
    let mut names: Vec<String> = crate::util::NAME_CACHE_NAMES.iter().map(|n| (*n).to_string()).collect();
    names.push(crate::quot::EQ.to_string());
    names.push(format!("{}.{}", crate::quot::EQ, crate::quot::EQ_REFL));
    names
}

/// Nucleus addition (VENDOR.md, item 13; proof-carrying savings,
/// `docs/rfcs/qed-proof-carrying-savings-2026-11-28.md`). One declaration
/// the walk reached: its position in the export, its dotted name, and the
/// digests of its type and of its value (`None` for a declaration without a
/// value: an axiom, an inductive type, a constructor or a recursor).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Used {
    pub position: usize,
    pub name: String,
    pub ty: [u8; 32],
    pub value: Option<[u8; 32]>,
}

/// What `used_constants` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Walked {
    /// Every declaration reached from the root, the root included, in
    /// export order, less kernel-reserved names.
    pub used: Vec<Used>,
    /// For each mark given, the number of declarations made by the bytes
    /// before it, as `inspect_after` reports them.
    pub counts: Vec<usize>,
}

/// Nucleus addition (VENDOR.md, item 13). Parse the concatenation of
/// `segments` once, with no kernel check, and walk from the declaration
/// named `root` (dotted, as `Entry::name` renders it) through the type and
/// the value of every constant reached, transitively. Kernel-reserved names
/// (`is_kernel_reserved`) are left out of the result, and the walk does not
/// go through them: the checker treats them by name, so whoever exported
/// them authored nothing it reads.
///
/// The digests are a Merkle hash over the expression tree with `hash` at
/// each node, binder names and binder styles left out and constants named
/// by their dotted names: two exports of the same term give the same
/// digest whatever their back-references. Nothing here is a kernel check;
/// it is for attributing reuse of a declaration an accepted artifact made.
pub fn used_constants(
    segments: &[&[u8]],
    permitted_axioms: &[String],
    marks: &[usize],
    root: &str,
    hash: &mut dyn FnMut(&[u8]) -> [u8; 32],
) -> Result<Walked, String> {
    let (file, skipped, counts) =
        crate::parser::parse_export_segments_marked(segments, config(permitted_axioms)?, marks)
            .map_err(|e| e.to_string())?;
    if !skipped.is_empty() {
        return Err(format!("unpermitted axioms were skipped: {skipped:?}"));
    }
    let start = file
        .declars
        .values()
        .position(|d| name_string(&file, d.info().name) == root)
        .ok_or_else(|| format!("no declaration named {root}"))?;
    let mut digests = Digests { file: &file, hash, exprs: Default::default(), names: Default::default(), levels: Default::default() };
    let mut seen = vec![false; file.declars.len()];
    let mut stack = vec![start];
    let mut used = Vec::new();
    while let Some(position) = stack.pop() {
        if seen.get(position).copied().unwrap_or(true) {
            continue;
        }
        if let Some(s) = seen.get_mut(position) {
            *s = true;
        }
        let Some((_, declar)) = file.declars.get_index(position) else { continue };
        let name = name_string(&file, declar.info().name);
        if is_kernel_reserved(&name) {
            continue;
        }
        let value = match declar {
            Declar::Theorem { val, .. } | Declar::Definition { val, .. } | Declar::Opaque { val, .. } => Some(*val),
            _ => None,
        };
        let mut reached = Vec::new();
        constants(&file, declar.info().ty, &mut reached);
        if let Some(v) = value {
            constants(&file, v, &mut reached);
        }
        for n in reached {
            if let Some(i) = file.declars.get_index_of(&n) {
                stack.push(i);
            }
        }
        let ty = digests.expr(declar.info().ty)?;
        let value = value.map(|v| digests.expr(v)).transpose()?;
        used.push(Used { position, name, ty, value });
    }
    used.sort_by_key(|u| u.position);
    Ok(Walked { used, counts })
}

/// The names of the constants `e` mentions, each subterm visited once.
fn constants<'p>(file: &ExportFile<'p>, e: crate::util::ExprPtr<'p>, out: &mut Vec<NamePtr<'p>>) {
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![e];
    while let Some(e) = stack.pop() {
        if !seen.insert(e.idx()) {
            continue;
        }
        let Some(expr) = file.dag.exprs.get_index(e.idx()) else { continue };
        match *expr {
            Expr::Const { name, .. } => out.push(name),
            Expr::App { fun, arg, .. } => stack.extend([fun, arg]),
            Expr::Pi { binder_type, body, .. } | Expr::Lambda { binder_type, body, .. } => {
                stack.extend([binder_type, body])
            }
            Expr::Let { binder_type, val, body, .. } => stack.extend([binder_type, val, body]),
            Expr::Proj { ty_name, structure, .. } => {
                out.push(ty_name);
                stack.push(structure)
            }
            Expr::Local { binder_type, .. } => stack.push(binder_type),
            Expr::Var { .. } | Expr::Sort { .. } | Expr::NatLit { .. } | Expr::StringLit { .. } => {}
        }
    }
}

/// Memoised Merkle digests of names, levels and expressions of one export.
struct Digests<'f, 'p, 'h> {
    file: &'f ExportFile<'p>,
    hash: &'h mut dyn FnMut(&[u8]) -> [u8; 32],
    exprs: std::collections::HashMap<usize, [u8; 32]>,
    names: std::collections::HashMap<usize, [u8; 32]>,
    levels: std::collections::HashMap<usize, [u8; 32]>,
}

impl<'p> Digests<'_, 'p, '_> {
    fn name(&mut self, n: NamePtr<'p>) -> [u8; 32] {
        if let Some(d) = self.names.get(&n.idx()) {
            return *d;
        }
        // The dotted rendering, length-prefixed: a constant is named as the
        // checker's tables name it, not by its position in this export.
        let text = name_string(self.file, n);
        let mut bytes = vec![b'N'];
        bytes.extend_from_slice(&(text.len() as u64).to_be_bytes());
        bytes.extend_from_slice(text.as_bytes());
        let d = (self.hash)(&bytes);
        self.names.insert(n.idx(), d);
        d
    }

    fn level(&mut self, l: crate::util::LevelPtr<'p>) -> Result<[u8; 32], String> {
        if let Some(d) = self.levels.get(&l.idx()) {
            return Ok(*d);
        }
        let level = *self.file.dag.levels.get_index(l.idx()).ok_or("level index out of range")?;
        let mut bytes = Vec::with_capacity(65);
        match level {
            crate::level::Level::Zero => bytes.push(0),
            crate::level::Level::Succ(a, _) => {
                bytes.push(1);
                bytes.extend_from_slice(&self.level(a)?);
            }
            crate::level::Level::Max(a, b, _) => {
                bytes.push(2);
                bytes.extend_from_slice(&self.level(a)?);
                bytes.extend_from_slice(&self.level(b)?);
            }
            crate::level::Level::IMax(a, b, _) => {
                bytes.push(3);
                bytes.extend_from_slice(&self.level(a)?);
                bytes.extend_from_slice(&self.level(b)?);
            }
            crate::level::Level::Param(n, _) => {
                bytes.push(4);
                bytes.extend_from_slice(&self.name(n));
            }
        }
        let d = (self.hash)(&bytes);
        self.levels.insert(l.idx(), d);
        Ok(d)
    }

    fn expr(&mut self, e: crate::util::ExprPtr<'p>) -> Result<[u8; 32], String> {
        if let Some(d) = self.exprs.get(&e.idx()) {
            return Ok(*d);
        }
        let expr = *self.file.dag.exprs.get_index(e.idx()).ok_or("expression index out of range")?;
        let mut bytes = Vec::with_capacity(97);
        match expr {
            Expr::Var { dbj_idx, .. } => {
                bytes.push(0);
                bytes.extend_from_slice(&dbj_idx.to_be_bytes());
            }
            Expr::Sort { level, .. } => {
                bytes.push(1);
                bytes.extend_from_slice(&self.level(level)?);
            }
            Expr::Const { name, levels, .. } => {
                bytes.push(2);
                bytes.extend_from_slice(&self.name(name));
                let levels = self.file.dag.uparams.get_index(levels.idx()).ok_or("levels index out of range")?.clone();
                bytes.extend_from_slice(&(levels.len() as u64).to_be_bytes());
                for l in levels.iter() {
                    bytes.extend_from_slice(&self.level(*l)?);
                }
            }
            Expr::App { fun, arg, .. } => {
                bytes.push(3);
                bytes.extend_from_slice(&self.expr(fun)?);
                bytes.extend_from_slice(&self.expr(arg)?);
            }
            Expr::Pi { binder_type, body, .. } => {
                bytes.push(4);
                bytes.extend_from_slice(&self.expr(binder_type)?);
                bytes.extend_from_slice(&self.expr(body)?);
            }
            Expr::Lambda { binder_type, body, .. } => {
                bytes.push(5);
                bytes.extend_from_slice(&self.expr(binder_type)?);
                bytes.extend_from_slice(&self.expr(body)?);
            }
            Expr::Let { binder_type, val, body, .. } => {
                bytes.push(6);
                bytes.extend_from_slice(&self.expr(binder_type)?);
                bytes.extend_from_slice(&self.expr(val)?);
                bytes.extend_from_slice(&self.expr(body)?);
            }
            Expr::NatLit { ptr, .. } => {
                bytes.push(7);
                let n = self
                    .file
                    .dag
                    .bignums
                    .as_ref()
                    .and_then(|b| b.get_index(ptr.idx()))
                    .ok_or("natural literal index out of range")?;
                bytes.extend_from_slice(&n.to_bytes_be());
            }
            Expr::StringLit { ptr, .. } => {
                bytes.push(8);
                let s = self.file.dag.strings.get_index(ptr.idx()).ok_or("string index out of range")?;
                bytes.extend_from_slice(s.as_bytes());
            }
            Expr::Proj { ty_name, idx, structure, .. } => {
                bytes.push(9);
                bytes.extend_from_slice(&self.name(ty_name));
                bytes.extend_from_slice(&(idx as u64).to_be_bytes());
                bytes.extend_from_slice(&self.expr(structure)?);
            }
            Expr::Local { .. } => return Err("a free variable in an exported term".into()),
        }
        let d = (self.hash)(&bytes);
        self.exprs.insert(e.idx(), d);
        Ok(d)
    }
}

/// Nucleus addition (VENDOR.md, item 14). Parse the concatenation of
/// `segments` once, with no kernel check, and give every declaration with
/// the digests `used_constants` gives it, in export order, kernel-reserved
/// names included. For building the exclusion set of a library export:
/// the same digests, so the same keys.
pub fn declaration_digests(
    segments: &[&[u8]],
    permitted_axioms: &[String],
    hash: &mut dyn FnMut(&[u8]) -> [u8; 32],
) -> Result<Vec<Used>, String> {
    let (file, skipped, _) =
        crate::parser::parse_export_segments_marked(segments, config(permitted_axioms)?, &[])
            .map_err(|e| e.to_string())?;
    if !skipped.is_empty() {
        return Err(format!("unpermitted axioms were skipped: {skipped:?}"));
    }
    let mut digests = Digests { file: &file, hash, exprs: Default::default(), names: Default::default(), levels: Default::default() };
    let mut out = Vec::with_capacity(file.declars.len());
    for (position, declar) in file.declars.values().enumerate() {
        let value = match declar {
            Declar::Theorem { val, .. } | Declar::Definition { val, .. } | Declar::Opaque { val, .. } => Some(*val),
            _ => None,
        };
        let ty = digests.expr(declar.info().ty)?;
        let value = value.map(|v| digests.expr(v)).transpose()?;
        out.push(Used { position, name: name_string(&file, declar.info().name), ty, value });
    }
    Ok(out)
}
