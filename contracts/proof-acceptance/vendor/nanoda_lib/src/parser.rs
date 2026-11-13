use crate::env::{
    ConstructorData, Declar, DeclarInfo, InductiveData, Notation, RecursorData, ReducibilityHint,
};
use crate::expr::{BinderStyle, Expr};
use crate::hash64;
use crate::level::Level;
use crate::name::Name;
use crate::util::{
    new_fx_hash_map, new_fx_index_map, new_fx_hash_set, BigUintPtr, Config, DagMarker, ExprPtr, FxHashMap, FxHashSet, FxIndexMap,
    LeanDag, LevelPtr, LevelsPtr, NamePtr, StringPtr,
};
use num_bigint::BigUint;
use serde::{ Deserialize, Deserializer };
use serde::de::{Error as DeError, Visitor};
use std::error::Error;
use std::io::BufRead;
use std::sync::Arc;
use std::borrow::Cow;
use std::fmt;

/// Nucleus addition: the binary export form (statement format v2).
pub mod v2;

fn check_semver<'a>(meta: &FileMeta<'a>) -> Result<(), Box<dyn Error>> {
    const MIN_SEMVER : semver::Version = semver::Version::new(3, 1, 0);
    const MAX_SEMVER : semver::Version = semver::Version::new(3, 2, 0);
    let export_file_semver = semver::Version::parse(&meta.format.version)?;
    if export_file_semver < MIN_SEMVER {
        return Err(Box::from(format!(
            "export format version is less than the minimum supported version. Found {}, but min supported is {}",
            export_file_semver, MIN_SEMVER
        )))
    } else if export_file_semver >= MAX_SEMVER {
        return Err(Box::from(format!(
            "export format version is greater than the maximum supported version. Found {}, but max (exclusive) supported is {}",
            export_file_semver, MAX_SEMVER
        )))
    } else {
        Ok(())
    }
}

pub struct Parser<'a, R: BufRead> {
    buf_reader: R,
    line_num: usize,
    dag: LeanDag<'a>,
    declars: FxIndexMap<NamePtr<'a>, Declar<'a>>,
    notations: FxHashMap<NamePtr<'a>, Notation<'a>>,
    config: Config,
    /// Tracks axiom names that were found in the export file, but not white-listed,
    /// for use when `unpermitted_axiom_hard_error: false`
    skipped: Vec<String>,
    mutual_block_sizes: FxHashMap<NamePtr<'a>, (usize, usize)>
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
struct LeanMeta<'a> {
    version: Cow<'a, str>,
    githash: Cow<'a, str>
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
struct ExporterMeta<'a> {
    name: Cow<'a, str>,
    version: Cow<'a, str>
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
struct FormatMeta<'a> {
    version: Cow<'a, str>
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct FileMeta<'a> {
    lean: LeanMeta<'a>,
    exporter: ExporterMeta<'a>,
    format: FormatMeta<'a>
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
enum BackRef {
    #[serde(alias = "in")]
    In(u32),
    #[serde(alias = "il")]
    Il(u32),
    #[serde(alias = "ie")]
    Ie(u32),
}

impl BackRef {
    fn assert_in(self, (idx, inserted): (usize, bool)) {
        if !inserted {
            panic!("Attempted to insert duplicate Name");
        }
        let lhs = u32::try_from(idx).unwrap();
        if self != BackRef::In(lhs) {
            // Nucleus change: upstream prints this and calls std::process::exit(2).
            // A library must not end its host on untrusted input; refuse by panic
            // like every other parser and kernel refusal here.
            panic!(
                "Declined: Name back-reference mismatch, expected {:?}, found {:?}. Back-refs must be continuous.",
                BackRef::In(lhs),
                self
            );
        }
    }

    fn assert_il(self, (idx, inserted): (usize, bool)) {
        if !inserted {
            panic!("Attempted to insert duplicate Level");
        }
        let lhs = u32::try_from(idx).unwrap();
        if self != BackRef::Il(lhs) {
            // Nucleus change: upstream prints this and calls std::process::exit(2).
            // A library must not end its host on untrusted input; refuse by panic
            // like every other parser and kernel refusal here.
            panic!(
                "Declined: Level back-reference mismatch, expected {:?}, found {:?}. Back-refs must be continuous.",
                BackRef::Il(lhs),
                self
            );
        }
    }

    fn assert_ie(self, (idx, inserted): (usize, bool)) {
        if !inserted {
            panic!("Attempted to insert duplicate Expr");
        }
        let lhs = u32::try_from(idx).unwrap();
        if self != BackRef::Ie(lhs) {
            // Nucleus change: upstream prints this and calls std::process::exit(2).
            // A library must not end its host on untrusted input; refuse by panic
            // like every other parser and kernel refusal here.
            panic!(
                "Declined: Expr back-reference mismatch, expected {:?}, found {:?}. Back-refs must be continuous.",
                BackRef::Ie(lhs),
                self
            );
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExportJsonObject<'a> {
    val: ExportJsonVal<'a>,
    i: Option<BackRef>
}

// Nucleus change (statement format v2, stage 1). Upstream derives this type
// with two `#[serde(flatten)]` fields. serde implements flatten by buffering
// the whole object into its generic `Content` tree (owned copies of every
// string) and deserialising that tree once per flattened field; on the
// Nucleus base library that cost 141 million of 617 million cycles in a proof
// guest. This reads the object's keys once: `in`, `il` and `ie` are the
// back-reference, and the one other key selects the variant of the derived
// `ExportJsonVal`, whose value is deserialised in place through `Tagged`
// below. The derived field rules are unchanged. A line with an unknown key,
// two value keys or two back-reference keys is refused (upstream ignored
// unknown keys); lean4export writes none of these.
impl<'de: 'a, 'a> Deserialize<'de> for ExportJsonObject<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(ObjectVisitor(std::marker::PhantomData))
    }
}

enum Key<'de> {
    Borrowed(&'de str),
    Owned(String),
}

impl Key<'_> {
    fn as_str(&self) -> &str {
        match self {
            Key::Borrowed(s) => s,
            Key::Owned(s) => s.as_str(),
        }
    }
}

struct KeySeed;

impl<'de> serde::de::DeserializeSeed<'de> for KeySeed {
    type Value = Key<'de>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Key<'de>, D::Error> {
        deserializer.deserialize_str(KeyVisitor)
    }
}

struct KeyVisitor;

impl<'de> Visitor<'de> for KeyVisitor {
    type Value = Key<'de>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object key")
    }
    fn visit_borrowed_str<E: DeError>(self, v: &'de str) -> Result<Key<'de>, E> {
        Ok(Key::Borrowed(v))
    }
    fn visit_str<E: DeError>(self, v: &str) -> Result<Key<'de>, E> {
        Ok(Key::Owned(v.to_owned()))
    }
    fn visit_string<E: DeError>(self, v: String) -> Result<Key<'de>, E> {
        Ok(Key::Owned(v))
    }
}

struct ObjectVisitor<'a>(std::marker::PhantomData<ExportJsonObject<'a>>);

impl<'de: 'a, 'a> Visitor<'de> for ObjectVisitor<'a> {
    type Value = ExportJsonObject<'a>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an export line object")
    }
    fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut val: Option<ExportJsonVal<'a>> = None;
        let mut i: Option<BackRef> = None;
        while let Some(key) = map.next_key_seed(KeySeed)? {
            let backref: Option<fn(u32) -> BackRef> = match key.as_str() {
                "in" => Some(BackRef::In),
                "il" => Some(BackRef::Il),
                "ie" => Some(BackRef::Ie),
                _ => None,
            };
            match backref {
                Some(make) => {
                    if i.is_some() {
                        return Err(M::Error::custom("two back-reference keys"));
                    }
                    i = Some(make(map.next_value::<u32>()?));
                }
                None => {
                    if val.is_some() {
                        return Err(M::Error::custom("two value keys"));
                    }
                    val = Some(map.next_value_seed(ValueSeed {
                        key: key.as_str(),
                        marker: std::marker::PhantomData,
                    })?);
                }
            }
        }
        let val = val.ok_or_else(|| M::Error::custom("no value key"))?;
        Ok(ExportJsonObject { val, i })
    }
}

struct ValueSeed<'k, 'a> {
    key: &'k str,
    marker: std::marker::PhantomData<ExportJsonVal<'a>>,
}

impl<'de: 'a, 'k, 'a> serde::de::DeserializeSeed<'de> for ValueSeed<'k, 'a> {
    type Value = ExportJsonVal<'a>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        ExportJsonVal::deserialize(Tagged { key: self.key, value: deserializer })
    }
}

/// An externally tagged enum whose tag was already read: the key, and a
/// deserializer positioned at its value.
struct Tagged<'k, D> {
    key: &'k str,
    value: D,
}

impl<'de, 'k, D: Deserializer<'de>> Deserializer<'de> for Tagged<'k, D> {
    type Error = D::Error;
    fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, D::Error> {
        Err(D::Error::custom("expected an export line value"))
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        visitor.visit_enum(self)
    }
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf
        option unit unit_struct newtype_struct seq tuple tuple_struct map struct identifier
        ignored_any
    }
}

impl<'de, 'k, D: Deserializer<'de>> serde::de::EnumAccess<'de> for Tagged<'k, D> {
    type Error = D::Error;
    type Variant = TaggedValue<D>;
    fn variant_seed<V: serde::de::DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, TaggedValue<D>), D::Error> {
        use serde::de::IntoDeserializer;
        let variant = seed.deserialize(IntoDeserializer::<D::Error>::into_deserializer(self.key))?;
        Ok((variant, TaggedValue(self.value)))
    }
}

struct TaggedValue<D>(D);

impl<'de, D: Deserializer<'de>> serde::de::VariantAccess<'de> for TaggedValue<D> {
    type Error = D::Error;
    fn unit_variant(self) -> Result<(), D::Error> {
        Err(D::Error::custom("no export line value is a unit"))
    }
    fn newtype_variant_seed<T: serde::de::DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, D::Error> {
        seed.deserialize(self.0)
    }
    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, D::Error> {
        self.0.deserialize_tuple(len, visitor)
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.0.deserialize_struct("", fields, visitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
enum DefinitionSafety {
    #[serde(rename = "unsafe")]
    Unsafe,
    #[serde(rename = "safe")]
    Safe,
    #[serde(rename = "partial")]
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
enum QuotKind {
    #[serde(rename = "type")]
    Ty,
    #[serde(rename = "ctor")]
    Ctor,
    #[serde(rename = "lift")]
    Lift,
    #[serde(rename = "ind")]
    Ind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
struct RecursorRule {
    ctor: u32,
    nfields: u16,
    rhs: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
struct IndInfo {
    name: u32,
    #[serde(rename = "levelParams")]
    uparams: Vec<u32>,
    #[serde(rename = "type")]
    ty: u32,
    all: Vec<u32>,
    ctors: Vec<u32>,
    #[serde(rename = "isRec")]
    is_rec: bool,
    #[serde(rename = "isReflexive")]
    is_reflexive: bool,
    #[serde(rename = "numIndices")]
    num_indices: u16,
    #[serde(rename = "numNested")]
    num_nested: u16,
    #[serde(rename = "numParams")]
    num_params: u16,
    #[serde(rename = "isUnsafe")]
    is_unsafe: bool
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
struct Constructor {
    name: u32,
    #[serde(rename = "levelParams")]
    uparams: Vec<u32>,
    #[serde(rename = "type")]
    ty: u32,
    #[serde(rename = "isUnsafe")]
    is_unsafe: bool,
    cidx: u16,
    #[serde(rename = "numParams")]
    num_params: u16,
    #[serde(rename = "numFields")]
    num_fields: u16,
    induct: u32
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
struct Recursor {
    name: u32,
    #[serde(rename = "levelParams")]
    uparams: Vec<u32>,
    #[serde(rename = "type")]
    ty: u32,
    #[serde(rename = "isUnsafe")]
    is_unsafe: bool,
    #[serde(rename = "numParams")]
    num_params: u16,
    #[serde(rename = "numIndices")]
    num_indices: u16,
    #[serde(rename = "numMotives")]
    num_motives: u16,
    #[serde(rename = "numMinors")]
    num_minors: u16,
    rules: Vec<RecursorRule>,
    all: Vec<u32>,
    k: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
enum ExportJsonVal<'a> {
    // The exporter metadata, incl. info about the lean, exporter, and format versions used
    // to create the export file.
    // Nucleus change (statement format v2, optimization pass): boxed, so the
    // one metadata line per export does not make every line's value as large
    // as five strings; each line's value is moved several times.
    #[serde(rename = "meta")]
    Metadata(Box<FileMeta<'a>>),
    #[serde(rename = "str")]
    NameStr {
        pre: u32,
        str: Cow<'a, str>
    },
    #[serde(rename = "num")]
    NameNum {
        pre: u32,
        i: u32
    },
    #[serde(rename = "succ")]
    LevelSucc(u32),
    #[serde(rename = "max")]
    LevelMax([u32; 2]),
    #[serde(rename = "imax")]
    LevelIMax([u32; 2]),
    #[serde(rename = "param")]
    LevelParam(u32),
    #[serde(rename = "natVal", deserialize_with = "deserialize_biguint_from_string")]
    NatLit(BigUint),
    #[serde(rename = "strVal")]
    StrLit(Cow<'a, str>),
    #[serde(rename = "mdata")]
    ExprMData {
        expr: u32,
        data: serde_json::Value
    },
    #[serde(rename = "letE")]
    ExprLet {
        name: u32,
        #[serde(rename = "type")]
        ty: u32,
        value: u32,
        body: u32,
        nondep: bool
    },
    #[serde(rename = "const")]
    ExprConst {
        name: u32,
        #[serde(rename = "us")]
        levels: Vec<u32>
    },
    #[serde(rename = "app")]
    ExprApp {
        #[serde(rename = "fn")]
        fun: u32,
        arg: u32 
    },
    #[serde(rename = "forallE")]
    ExprPi {
        #[serde(rename = "name")]
        binder_name: u32,
        #[serde(rename = "type")]
        binder_type: u32,
        body: u32,
        #[serde(rename = "binderInfo")]
        binder_info: BinderStyle

    },
    #[serde(rename = "lam")]
    ExprLambda {
        #[serde(rename = "name")]
        binder_name: u32,
        #[serde(rename = "type")]
        binder_type: u32,
        body: u32,
        #[serde(rename = "binderInfo")]
        binder_info: BinderStyle
    },
    #[serde(rename = "proj")]
    ExprProj {
        #[serde(rename = "typeName")]
        type_name: u32,
        idx: usize,
        #[serde(rename = "struct")]
        structure: u32,
    },
    #[serde(rename = "sort")]
    ExprSort(u32),
    #[serde(rename = "bvar")]
    ExprBVar(u16),
    #[serde(rename = "axiom")]
    Axiom {
        name: u32,
        #[serde(rename = "levelParams")]
        uparams: Vec<u32>,
        #[serde(rename = "type")]
        ty: u32,
        #[serde(rename = "isUnsafe")]
        is_unsafe: bool
    },
    #[serde(rename = "thm")]
    Thm {
        name: u32,
        #[serde(rename = "levelParams")]
        uparams: Vec<u32>,
        #[serde(rename = "type")]
        ty: u32,
        value: u32,
    },
    #[serde(rename = "def")]
    Defn {
        name: u32,
        #[serde(rename = "levelParams")]
        uparams: Vec<u32>,
        #[serde(rename = "type")]
        ty: u32,
        value: u32,
        #[serde(rename = "hints")]
        hint: ReducibilityHint,
        //all: Vec<usize>,
        safety: DefinitionSafety
    },
    #[serde(rename = "opaque")]
    Opaque {
        name: u32,
        #[serde(rename = "levelParams")]
        uparams: Vec<u32>,
        #[serde(rename = "type")]
        ty: u32,
        value: u32,
        #[serde(rename = "isUnsafe")]
        is_unsafe: bool
    },
    #[serde(rename = "quot")]
    Quot {
        name: u32,
        #[serde(rename = "levelParams")]
        uparams: Vec<u32>,
        #[serde(rename = "type")]
        ty: u32,
        #[serde(rename = "kind")]
        kind: QuotKind
    },
    #[serde(rename = "inductive")]
    Inductive {
        #[serde(rename = "types")]
        ind_vals: Vec<IndInfo>,
        #[serde(rename = "ctors")]
        ctor_vals: Vec<Constructor>,
        #[serde(rename = "recs")]
        rec_vals: Vec<Recursor>
    },
}

pub(crate) fn parse_export_file<'p, R: BufRead>(
    buf_reader: R,
    config: Config,

) -> Result<(crate::util::ExportFile<'p>, Vec<String>), Box<dyn Error>> {
    let (file, skipped, _) = parse_export_file_marked(buf_reader, config, &[])?;
    Ok((file, skipped))
}

/// Nucleus addition. As `parse_export_file`, and additionally reports, for
/// each byte offset in `marks` (ascending), how many declarations had been
/// made when exactly that many bytes had been consumed. A mark that does not
/// fall at a line end, or lies beyond the input, is an error. The lines are
/// read and interpreted exactly as without marks.
pub(crate) fn parse_export_file_marked<'p, R: BufRead>(
    buf_reader: R,
    config: Config,
    marks: &[usize],
) -> Result<(crate::util::ExportFile<'p>, Vec<String>, Vec<usize>), Box<dyn Error>> {
    let mut parser = Parser::new(buf_reader, config);
    let mut line_buffer = String::new();
    let mut consumed = 0usize;
    let mut counts = Vec::with_capacity(marks.len());

    loop {
        record_marks(&mut counts, marks, consumed, parser.declars.len())?;
        let amt = parser.buf_reader.read_line(&mut line_buffer)?;
        if amt == 0 {
            break
        }
        consumed = consumed.checked_add(amt).ok_or("export too long")?;
        parser.go1(line_buffer.as_str())?;
        parser.line_num += 1;
        line_buffer.clear();
    }
    finish(parser, marks, counts)
}

/// Nucleus addition (statement format v2, stage 1). For each mark not yet
/// recorded: record the declaration count if `consumed` is exactly at it,
/// refuse it if `consumed` has passed it (it is not at a line end).
fn record_marks(
    counts: &mut Vec<usize>,
    marks: &[usize],
    consumed: usize,
    declared: usize,
) -> Result<(), Box<dyn Error>> {
    while let Some(mark) = marks.get(counts.len()).copied() {
        if mark == consumed {
            counts.push(declared);
        } else if mark < consumed {
            return Err(Box::from(format!("mark at byte {} is not at a line end", mark)))
        } else {
            break
        }
    }
    Ok(())
}

/// Nucleus addition (statement format v2, stage 1). As
/// `parse_export_file_marked` over the concatenation of `segments`, without
/// copying: each line is a slice of the input, checked to be UTF-8 as
/// `read_line` checks it, and handed to the same `go1`. Every segment but the
/// last must be empty or end with a newline, so no line spans two segments.
pub(crate) fn parse_export_segments_marked<'p>(
    segments: &[&[u8]],
    config: Config,
    marks: &[usize],
) -> Result<(crate::util::ExportFile<'p>, Vec<String>, Vec<usize>), Box<dyn Error>> {
    let mut parser = Parser::new(std::io::empty(), config);
    let mut consumed = 0usize;
    let mut counts = Vec::with_capacity(marks.len());
    let last = segments.len().saturating_sub(1);
    // Export v2: the first non-empty segment begins with the v2 header. Then
    // every segment is v2 records (the first after its header), each
    // decoded and applied as the NDJSON line it encodes would be. A record
    // cannot span segments: each segment is decoded on its own.
    let first = segments.iter().find(|s| !s.is_empty());
    if first.is_some_and(|s| s.starts_with(&v2::MAGIC)) {
        // Capacity only, no effect on what is read: size the expression and
        // name tables for the input up front, so they are not grown and
        // rehashed while parsing. Measured exports average about 11 to 12
        // bytes per expression record and 44 or more per name record; one
        // expression per 13 bytes and one name per 100 measured fewest total
        // cycles of the hints tried (1/10, 1/13). The hints are proportional
        // to the input's length, so they cannot exceed what the input could
        // hold; a table that needs more grows as it did before.
        let total: usize = segments.iter().map(|s| s.len()).sum();
        parser.dag.exprs.reserve(total / 13);
        parser.dag.names.reserve(total / 100);
        let mut header = true;
        for segment in segments {
            let mut input = v2::In { rest: segment };
            if header && !segment.is_empty() {
                input.rest = &segment[v2::MAGIC.len()..];
                consumed = v2::MAGIC.len();
                header = false;
            }
            while !input.rest.is_empty() {
                record_marks(&mut counts, marks, consumed, parser.declars.len())?;
                let before = input.rest.len();
                let object = v2::decode_record(&mut input).map_err(|e| {
                    format!("export v2 record {}: {e}", parser.line_num + 1)
                })?;
                consumed = consumed.checked_add(before - input.rest.len()).ok_or("export too long")?;
                parser.apply(object, "(export v2 record)")?;
                parser.line_num += 1;
            }
        }
        record_marks(&mut counts, marks, consumed, parser.declars.len())?;
        return finish(parser, marks, counts)
    }
    for (k, segment) in segments.iter().enumerate() {
        if k != last && !segment.is_empty() && segment.last() != Some(&b'\n') {
            return Err(Box::from("a segment before the last does not end at a line end"))
        }
        let mut rest: &[u8] = segment;
        while !rest.is_empty() {
            record_marks(&mut counts, marks, consumed, parser.declars.len())?;
            let end = rest.iter().position(|&b| b == b'\n').map_or(rest.len(), |i| i + 1);
            let (line, tail) = rest.split_at(end);
            rest = tail;
            let line = std::str::from_utf8(line)?;
            consumed = consumed.checked_add(line.len()).ok_or("export too long")?;
            parser.go1(line)?;
            parser.line_num += 1;
        }
    }
    record_marks(&mut counts, marks, consumed, parser.declars.len())?;
    finish(parser, marks, counts)
}

#[allow(unused_mut)]
fn finish<'p, R: BufRead>(
    mut parser: Parser<'p, R>,
    marks: &[usize],
    counts: Vec<usize>,
) -> Result<(crate::util::ExportFile<'p>, Vec<String>, Vec<usize>), Box<dyn Error>> {
    if counts.len() != marks.len() {
        return Err(Box::from("a mark lies beyond the end of the export"))
    }

    // If the execution config has `unknown_pp_declar_hard_error: true`, and a `pp_declars` 
    // that includes `foo`, then we return early with an error if no `foo` declaration is present 
    // in the export file.
    if parser.config.unknown_pp_declar_hard_error {
        if let Some(pp_declars) = parser.config.pp_declars.as_ref() {
            let mut pp_declar_names = pp_declars.iter().map(|s| s.as_str()).collect::<crate::util::FxHashSet<&str>>();
            for declar_name in parser.declars.keys() {
                let n = parser.name_to_string(*declar_name);
                pp_declar_names.remove(n.as_str());
            }
            if pp_declar_names.len() > 0 {
                let list = pp_declar_names.into_iter().collect::<Vec<&str>>();
                return Err(Box::from(format!("these pp_declars were not found in the exported environment: {:#?}", list)))
            }
        }
    }
    
    let name_cache = parser.dag.mk_name_cache();
    // Maps inductive names to exported recursor names. This is later reused in the inductive
    // module to require that the set of derived recursors matches the set of exported recursors,
    // so that additional "unassociated" recursors cannot be added to the environment.
    let mut ind_name_to_recursor_names = new_fx_hash_map();
    for declar in parser.declars.values() {
        match declar {
            Declar::Constructor(ConstructorData {inductive_name, info, ..}) => {
                match parser.declars.get(inductive_name).unwrap() {
                    Declar::Inductive(InductiveData {all_ctor_names, ..}) => {
                        assert!(all_ctor_names.contains(&info.name))
                    },
                    _ => panic!("failed to find inductive {:?}", parser.name_to_string(*inductive_name))
                }
            }
            Declar::Recursor(RecursorData {all_inductives, info, ..}) => {
                for ind_name in all_inductives.iter().copied() {
                    ind_name_to_recursor_names.entry(ind_name).or_insert(new_fx_hash_set()).insert(info.name);
                }
            },
            _ => continue
        }
    }
    
    let export_file = crate::util::ExportFile {
        dag: parser.dag,
        declars: parser.declars,
        notations: parser.notations,
        name_cache,
        config: parser.config,
        mutual_block_sizes: parser.mutual_block_sizes,
        ind_name_to_recursor_names,
    };
    Ok((export_file, parser.skipped, counts))
}

impl<'a, R: BufRead> Parser<'a, R> {
    pub fn new(buf_reader: R, config: Config) -> Self {
        Self {
            buf_reader,
            line_num: 0usize,
            dag: LeanDag::new(&config),
            declars: new_fx_index_map(),
            notations: new_fx_hash_map(),
            config,
            skipped: Vec::new(),
            mutual_block_sizes: new_fx_hash_map()
        }
    }
    
    fn axiom_permitted(&self, n: NamePtr<'a>) -> bool {
        self.config.unsafe_permit_all_axioms ||
            self.config.permitted_axioms.as_ref().map(|v| v.contains(&self.name_to_string(n))).unwrap_or(false)
    }

    fn num_loose_bvars(&self, e: ExprPtr<'a>) -> u16 {
        self.dag.exprs.get_index(e.idx()).unwrap().num_loose_bvars()
    }

    fn has_fvars(&self, e: ExprPtr<'a>) -> bool { self.dag.exprs.get_index(e.idx()).unwrap().has_fvars() }

    fn get_name_ptr(&self, idx: u32) -> NamePtr<'a> {
        let out = crate::util::Ptr::from(DagMarker::ExportFile, idx as usize);
        assert!((idx as usize) < self.dag.names.len());
        out
    }

    fn get_level_ptr(&self, idx: u32) -> LevelPtr<'a> {
        let out = crate::util::Ptr::from(DagMarker::ExportFile, idx as usize);
        assert!((idx as usize) < self.dag.levels.len(), "level back-reference {} must refer to an earlier level", idx);
        out
    }
    fn get_names(&self, idxs: &[u32]) -> Vec<NamePtr<'a>> {
        let mut names = Vec::new();
        for idx in idxs.iter().copied() {
            assert!(self.dag.names.get_index(idx as usize).is_some());
            names.push(NamePtr::from(DagMarker::ExportFile, idx as usize));
        }
        names
    }

    fn get_uparams_ptr(&mut self, name_idxs: &[u32]) -> LevelsPtr<'a> {
        let mut levels = Vec::new();
        for name_idx in name_idxs.iter().copied() {
            let name_ptr = self.get_name_ptr(name_idx);
            let hash = hash64!(crate::level::PARAM_HASH, name_ptr);
            // Has to already exist
            let idx = self.dag.levels.get_index_of(&Level::Param(name_ptr, hash)).unwrap();
            levels.push(LevelPtr::from(DagMarker::ExportFile, idx as usize));
        }
        LevelsPtr::from(DagMarker::ExportFile, self.dag.uparams.insert_full(Arc::from(levels)).0)
    }

    fn get_levels_ptr(&mut self, idxs: &[u32]) -> LevelsPtr<'a> {
        let mut levels = Vec::new();
        for idx in idxs.iter().copied() {
            levels.push(self.get_level_ptr(idx));
        }
        LevelsPtr::from(DagMarker::ExportFile, self.dag.uparams.insert_full(Arc::from(levels)).0)
    }

    /// Check ownership before flattening a block into the declaration map. The
    /// reconstruction checks follow the exported `all` and `ctors` lists, so
    /// those lists must cover exactly the declarations actually in this block.
    fn check_inductive_block(
        &self,
        types: &[IndInfo],
        ctors: &[Constructor],
        recs: &[Recursor],
    ) -> Result<(), Box<dyn Error>> {
        fn same_names(names: &[u32], expected: &FxHashSet<u32>) -> bool {
            names.len() == expected.len() && names.iter().copied().collect::<FxHashSet<_>>() == *expected
        }

        let error = |message: String| -> Box<dyn Error> {
            format!("invalid inductive block at line {}: {}", self.line_num + 1, message).into()
        };
        if types.is_empty() {
            return Err(error("expected at least one inductive type".to_owned()))
        }

        let mut member_names = new_fx_hash_set();
        for name in types.iter().map(|t| t.name)
            .chain(ctors.iter().map(|c| c.name))
            .chain(recs.iter().map(|r| r.name))
        {
            if !member_names.insert(name) {
                return Err(error(format!("duplicate declaration name index {}", name)))
            }
        }

        let type_names = types.iter().map(|t| t.name).collect::<FxHashSet<_>>();
        let mut ctors_by_type = new_fx_hash_map();
        for ctor in ctors {
            if !type_names.contains(&ctor.induct) {
                return Err(error(format!("constructor {} must belong to an inductive in the same block", ctor.name)))
            }
            ctors_by_type.entry(ctor.induct).or_insert_with(new_fx_hash_set).insert(ctor.name);
        }

        let empty = new_fx_hash_set();
        for ty in types {
            if !same_names(&ty.all, &type_names) {
                return Err(error(format!("inductive {} must list exactly the block's types without duplicates", ty.name)))
            }
            let expected_ctors = ctors_by_type.get(&ty.name).unwrap_or(&empty);
            if !same_names(&ty.ctors, expected_ctors) {
                return Err(error(format!("inductive {} must list exactly its constructors in this block without duplicates", ty.name)))
            }
        }

        for rec in recs {
            if !same_names(&rec.all, &type_names) {
                return Err(error(format!("recursor {} must list exactly the block's types without duplicates", rec.name)))
            }
            // Rule constructors may belong to earlier container types for a
            // nested inductive. Reconstruction validates those associations.
        }
        Ok(())
    }

    fn get_expr_ptr(&self, idx: u32) -> ExprPtr<'a> {
        let out = crate::util::Ptr::from(DagMarker::ExportFile, idx as usize);
        assert!((idx as usize) < self.dag.exprs.len());
        out
    }

    // Used for the axiom whitelist feature.
    fn name_to_string(&self, n: NamePtr<'a>) -> String {
        match self.dag.names.get_index(n.idx()).copied().unwrap() {
            Name::Anon => String::new(),
            Name::Str(pfx, sfx, _) => {
                let mut s = self.name_to_string(pfx);
                if !s.is_empty() {
                    s.push('.');
                }
                s + self.dag.strings.get_index(sfx.idx()).unwrap()
            }
            Name::Num(pfx, sfx, _) => {
                let mut s = self.name_to_string(pfx);
                if !s.is_empty() {
                    s.push('.');
                }
                s + format!("{}", sfx).as_str()
            }
        }
    }

    fn go1(&mut self, line: &str) -> Result<(), Box<dyn Error>> {
        let object = serde_json::from_str::<ExportJsonObject>(line)?;
        self.apply(object, line)
    }

    /// Nucleus change (statement format v2): the body of upstream `go1`, from
    /// the parsed line object on. Reached from an NDJSON line (`go1`) or a
    /// binary record (`v2::decode_record`) with the same values. `line` is
    /// only used in error messages.
    fn apply<'l>(&mut self, object: ExportJsonObject<'l>, line: &str) -> Result<(), Box<dyn Error>> {
        use ExportJsonVal::*;
        let ExportJsonObject {val, i: assigned_idx} = object;
        match val {
            Metadata(json_val) => {
                let _ = check_semver(&json_val)?;
            }
            NameStr {pre, str} => {
                let pfx = self.get_name_ptr(pre);
                let sfx = StringPtr::from(
                    DagMarker::ExportFile, 
                    self.dag.strings.insert_full(std::borrow::Cow::Owned(str.to_string())).0
                );

                let insert_result = {
                    let hash = hash64!(crate::name::STR_HASH, pfx, sfx);
                    self.dag.names.insert_full(Name::Str(pfx, sfx, hash))
                };
                assigned_idx.unwrap().assert_in(insert_result);
            }
            NameNum {pre, i} => {
                let pfx = self.get_name_ptr(pre);
                let sfx = i as u64;
                let insert_result = {
                    let hash = hash64!(crate::name::NUM_HASH, pfx, sfx);
                    self.dag.names.insert_full(Name::Num(pfx, sfx, hash))
                };
                assigned_idx.unwrap().assert_in(insert_result);
            }
            NatLit(big_uint) => {
                if !self.config.nat_extension {
                    return Err(Box::<dyn Error>::from(
                        format!("Nat lit extension disallowed by checker execution config, but export file contains a nat literal {:?}", line)
                    ))
                }
                let num_ptr = BigUintPtr::from(DagMarker::ExportFile, self.dag.bignums.as_mut().unwrap().insert_full(big_uint).0);
                let insert_result = {
                    let hash = hash64!(crate::expr::NAT_LIT_HASH, num_ptr);
                    self.dag.exprs.insert_full(Expr::NatLit { ptr: num_ptr, hash })
                };
                if !self.config.nat_extension {
                    return Err(Box::<dyn Error>::from(
                        format!("Nat lit extension disallowed by checker execution config, found {:?}", line)
                    ))
                }
                assigned_idx.unwrap().assert_ie(insert_result);
            }
            StrLit(cow_str) => {
                if !self.config.string_extension {
                    return Err(Box::<dyn Error>::from(
                        format!("String lit extension disallowed by checker execution config, but export file contains a string literal {:?}", line)
                    ))
                }
                let s = cow_str.to_string();
                let string_ptr = StringPtr::from(
                    DagMarker::ExportFile,
                    self.dag.strings.insert_full(crate::util::CowStr::Owned(s)).0
                );
                let insert_result = {
                    let hash = hash64!(crate::expr::STRING_LIT_HASH, string_ptr);
                    self.dag.exprs.insert_full(Expr::StringLit { ptr: string_ptr, hash })
                };
                assigned_idx.unwrap().assert_ie(insert_result);
            }
            LevelSucc(l) => {
                let l = self.get_level_ptr(l);
                let insert_result = {
                    let hash = hash64!(crate::level::SUCC_HASH, l);
                    self.dag.levels.insert_full(Level::Succ(l, hash))
                };
                assigned_idx.unwrap().assert_il(insert_result);
            }
            LevelMax([l, r]) => {
                let l = self.get_level_ptr(l);
                let r = self.get_level_ptr(r);
                let insert_result = {
                    let hash = hash64!(crate::level::MAX_HASH, l, r);
                    self.dag.levels.insert_full(Level::Max(l, r, hash))
                };
                assigned_idx.unwrap().assert_il(insert_result);
            }
            LevelIMax([l, r]) => {
                let l = self.get_level_ptr(l);
                let r = self.get_level_ptr(r);
                let insert_result = {
                    let hash = hash64!(crate::level::IMAX_HASH, l, r);
                    self.dag.levels.insert_full(Level::IMax(l, r, hash))
                };
                assigned_idx.unwrap().assert_il(insert_result);
            }
            LevelParam(var_idx) => {
                 let n = self.get_name_ptr(var_idx);
                 let insert_result = {
                     let hash = hash64!(crate::level::PARAM_HASH, n);
                     self.dag.levels.insert_full(Level::Param(n, hash))
                 };
                assigned_idx.unwrap().assert_il(insert_result);
            }
            ExprSort(level) => {
                let level = self.get_level_ptr(level);
                let insert_result = {
                    let hash = hash64!(crate::expr::SORT_HASH, level);
                    self.dag.exprs.insert_full(Expr::Sort { level, hash })
                };
                assigned_idx.unwrap().assert_ie(insert_result);
            }
            ExprMData {..} => {
                panic!("Expr.mdata not supported");
            }
            ExprConst {name, levels} => {
                let name = self.get_name_ptr(name);
                let levels = self.get_levels_ptr(&levels);
                let insert_result = {
                    let hash = hash64!(crate::expr::CONST_HASH, name, levels);
                    self.dag.exprs.insert_full(Expr::Const { name, levels, hash })
                };
                assigned_idx.unwrap().assert_ie(insert_result);
            }
            ExprApp {fun, arg} => {
                let fun = self.get_expr_ptr(fun);
                let arg = self.get_expr_ptr(arg);
                let insert_result = {
                    let hash = hash64!(crate::expr::APP_HASH, fun, arg);
                    let num_bvars = self.num_loose_bvars(fun).max(self.num_loose_bvars(arg));
                    let locals = self.has_fvars(fun) || self.has_fvars(arg);
                    self.dag.exprs.insert_full(Expr::App { fun, arg, num_loose_bvars: num_bvars, has_fvars: locals, hash })
                };
                assigned_idx.unwrap().assert_ie(insert_result);
            }
            ExprBVar(dbj_idx) => {
                let insert_result = {
                    let hash = hash64!(crate::expr::VAR_HASH, dbj_idx);
                    self.dag.exprs.insert_full(Expr::Var { dbj_idx, hash })
                };
                assigned_idx.unwrap().assert_ie(insert_result);
            }
            ExprLambda {binder_name, binder_type, binder_info, body} => {
                let binder_name = self.get_name_ptr(binder_name);
                let binder_type = self.get_expr_ptr(binder_type);
                let body = self.get_expr_ptr(body);
                let insert_result = {
                    let hash = hash64!(crate::expr::LAMBDA_HASH, binder_name, binder_info, binder_type, body);
                    let num_bvars = self.num_loose_bvars(binder_type).max(self.num_loose_bvars(body).saturating_sub(1));
                    let locals = self.has_fvars(binder_type) || self.has_fvars(body);
                    self.dag.exprs.insert_full(Expr::Lambda {
                        binder_name,
                        binder_style: binder_info,
                        binder_type,
                        body,
                        num_loose_bvars: num_bvars,
                        has_fvars: locals,
                        hash,
                    })
                };
                assigned_idx.unwrap().assert_ie(insert_result);
            }
            ExprPi {binder_name, binder_type, binder_info, body} => {
                let binder_name = self.get_name_ptr(binder_name);
                let binder_type = self.get_expr_ptr(binder_type);
                let body = self.get_expr_ptr(body);
                let insert_result = {
                    let hash = hash64!(crate::expr::PI_HASH, binder_name, binder_info, binder_type, body);
                    let num_bvars = self.num_loose_bvars(binder_type).max(self.num_loose_bvars(body).saturating_sub(1));
                    let locals = self.has_fvars(binder_type) || self.has_fvars(body);
                    self.dag.exprs.insert_full(Expr::Pi {
                        binder_name,
                        binder_style: binder_info,
                        binder_type,
                        body,
                        num_loose_bvars: num_bvars,
                        has_fvars: locals,
                        hash,
                    })
                };
                assigned_idx.unwrap().assert_ie(insert_result);
            }
            ExprLet {name, ty, value, body, nondep} => {
                let binder_name = self.get_name_ptr(name);
                let binder_type = self.get_expr_ptr(ty);
                let val = self.get_expr_ptr(value);
                let body = self.get_expr_ptr(body);
                let insert_result = {
                    let hash = hash64!(crate::expr::LET_HASH, binder_name, binder_type, val, body, nondep);
                    let num_bvars = self
                        .num_loose_bvars(binder_type)
                        .max(self.num_loose_bvars(val).max(self.num_loose_bvars(body).saturating_sub(1)));
                    let locals = self.has_fvars(binder_type) || self.has_fvars(val) || self.has_fvars(body);
                    self.dag.exprs.insert_full(Expr::Let {
                        binder_name,
                        binder_type,
                        val,
                        body,
                        num_loose_bvars: num_bvars,
                        has_fvars: locals,
                        hash,
                        nondep
                    })
                };
                assigned_idx.unwrap().assert_ie(insert_result);
            }
            ExprProj {type_name, idx, structure: struct_} => {
                let ty_name = self.get_name_ptr(type_name);
                let structure = self.get_expr_ptr(struct_);
                let insert_result = {
                    let hash = hash64!(crate::expr::PROJ_HASH, ty_name, idx, structure);
                    let num_bvars = self.num_loose_bvars(structure);
                    let locals = self.has_fvars(structure);
                    self.dag.exprs.insert_full(Expr::Proj {
                        ty_name,
                        idx,
                        structure,
                        num_loose_bvars: num_bvars,
                        has_fvars: locals,
                        hash,
                    })
                };
                assigned_idx.unwrap().assert_ie(insert_result);
            }
            Axiom {name, ty, uparams, is_unsafe} => {
                assert!(!is_unsafe);
                let name = self.get_name_ptr(name);
                let uparams = self.get_uparams_ptr(&uparams);
                let ty = self.get_expr_ptr(ty);
                let info = DeclarInfo { name, ty, uparams };
                let axiom = Declar::Axiom { info };
                if self.axiom_permitted(name) {
                    assert!(self.declars.insert(name, axiom).is_none());
                } else {
                    let name_string = self.name_to_string(name);
                    if self.config.unpermitted_axiom_hard_error {
                        return Err(Box::from(format!("export file declares unpermitted axiom {:?}", name_string)))
                    } else {
                        self.skipped.push(name_string)
                    }
                }
            }
            Defn {name, ty, uparams, value, hint, safety} => {
                assert!(!matches!(safety, DefinitionSafety::Unsafe | DefinitionSafety::Partial));
                let name = self.get_name_ptr(name);
                let ty = self.get_expr_ptr(ty);
                let val = self.get_expr_ptr(value);
                let uparams = self.get_uparams_ptr(&uparams);
                let info = DeclarInfo { name, ty, uparams };
                let definition = Declar::Definition { info, val, hint };
                assert!(self.declars.insert(name, definition).is_none());
            }
            Thm {name, ty, uparams, value} => {
                let name = self.get_name_ptr(name);
                let ty = self.get_expr_ptr(ty);
                let val = self.get_expr_ptr(value);
                let uparams = self.get_uparams_ptr(&uparams);
                let info = DeclarInfo { name, ty, uparams };
                let theorem = Declar::Theorem { info, val };
                assert!(self.declars.insert(name, theorem).is_none());
            }
            Opaque {name, ty, uparams, value, is_unsafe} => {
                assert!(!is_unsafe);
                let name = self.get_name_ptr(name);
                let ty = self.get_expr_ptr(ty);
                let val = self.get_expr_ptr(value);
                let uparams = self.get_uparams_ptr(&uparams);
                let info = DeclarInfo { name, ty, uparams };
                let definition = Declar::Opaque { info, val };
                assert!(self.declars.insert(name, definition).is_none());
            }
            Quot {name, ty, uparams, ..} => {
                let name = self.get_name_ptr(name);
                let ty = self.get_expr_ptr(ty);
                let uparams = self.get_uparams_ptr(&uparams);
                let info = DeclarInfo { name, ty, uparams };
                let quot = Declar::Quot { info };
                assert!(self.declars.insert(name, quot).is_none());
            }
            Inductive {ind_vals, ctor_vals, rec_vals} => {
                self.check_inductive_block(&ind_vals, &ctor_vals, &rec_vals)?;
                let block_start = self.declars.len();
                let block_size = ind_vals.len() + ctor_vals.len() + rec_vals.len();
                for IndInfo {name, ty, uparams, all, ctors, is_rec, num_nested, num_params, num_indices, is_unsafe, ..} in ind_vals {
                    assert!(!is_unsafe);
                    let name = self.get_name_ptr(name);
                    self.mutual_block_sizes.insert(name, (block_start, block_size));
                    let uparams = self.get_uparams_ptr(&uparams);
                    let ty = self.get_expr_ptr(ty);
                    let all_ind_names =  Arc::from(self.get_names(&all)); 
                    let all_ctor_names = Arc::from(self.get_names(&ctors)); 
                    let inductive = Declar::Inductive(InductiveData {
                        info: DeclarInfo { name, uparams, ty },
                        is_recursive: is_rec,
                        is_nested: num_nested > 0,
                        num_params,
                        num_indices,
                        all_ind_names,
                        all_ctor_names,
                    });
                    assert!(self.declars.insert(name, inductive).is_none());
                }
                for Constructor {name, uparams, ty, is_unsafe, induct, cidx, num_params, num_fields, ..}  in ctor_vals {
                    assert!(!is_unsafe);
                    let name = self.get_name_ptr(name);
                    let ty = self.get_expr_ptr(ty);
                    let uparams = self.get_uparams_ptr(&uparams);
                    let info = DeclarInfo { name, ty, uparams };
                    let parent_inductive = self.get_name_ptr(induct);
                    let ctor_idx = cidx;
                    let ctor = Declar::Constructor(ConstructorData {
                        info,
                        inductive_name: parent_inductive,
                        ctor_idx,
                        num_params,
                        num_fields,
                    });
                    assert!(self.declars.insert(name, ctor).is_none());
                }
                for Recursor {name, uparams, ty, rules, is_unsafe, num_params, num_indices, num_motives, num_minors, k, all, ..} in rec_vals {
                    assert!(!is_unsafe);
                    let name = self.get_name_ptr(name);
                    let ty = self.get_expr_ptr(ty);
                    let uparams = self.get_uparams_ptr(&uparams);
                    let info = DeclarInfo { name, ty, uparams };
                    let rules = rules.into_iter().map(|RecursorRule {rhs, ctor, nfields}| 
                        crate::env::RecRule {
                            val: self.get_expr_ptr(rhs),
                            ctor_name: self.get_name_ptr(ctor),
                            ctor_telescope_size_wo_params: nfields
                        }
                    ).collect::<Vec<_>>();
                    let all_inductives = self.get_names(&all);
                    let recursor = Declar::Recursor(RecursorData {
                        info,
                        all_inductives: Arc::from(all_inductives),
                        num_params,
                        num_indices,
                        num_motives,
                        num_minors,
                        rec_rules: Arc::from(rules),
                        is_k: k,
                    });
                    assert!(self.declars.insert(name, recursor).is_none())
                }
            }
        }
        Ok(())
    }
}

/// Decimal string -> BigUint in sub-quadratic time. `BigUint::from_str` is quadratic in the digit count,
/// which makes nat literals with millions of digits (as in large `decide`/`norm_num` proofs) take days.
/// This splits the digit string by 10^(BASE_DIGITS * 2^j) and combines with big multiplications
/// (Karatsuba/Toom-3), so cost is that of multiplication times a log factor. Same value as `from_str`.
pub(crate) fn parse_decimal_fast(s: &str) -> Result<BigUint, String> {
    use std::str::FromStr;
    const BASE_DIGITS: usize = 2048;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err("expected a non-empty string of ASCII digits".to_string());
    }
    let s = s.trim_start_matches('0');
    if s.is_empty() {
        return Ok(BigUint::ZERO);
    }
    fn go(s: &str, pows: &mut Vec<BigUint>) -> BigUint {
        if s.len() <= 2 * BASE_DIGITS {
            return BigUint::from_str(s).expect("validated nonempty ASCII digits");
        }
        // largest j with BASE_DIGITS * 2^j < s.len()
        let mut j = 0usize;
        while BASE_DIGITS << (j + 1) < s.len() { j += 1; }
        while pows.len() <= j {
            let next = match pows.last() {
                None => num_traits::pow::pow(BigUint::from(10u8), BASE_DIGITS),
                Some(last) => last * last,
            };
            pows.push(next);
        }
        let m = BASE_DIGITS << j;
        let (hi, lo) = s.split_at(s.len() - m);
        let hi_v = go(hi, pows);
        let lo_v = go(lo, pows);
        hi_v * &pows[j] + lo_v
    }
    let mut pows: Vec<BigUint> = Vec::new();
    Ok(go(s, &mut pows))
}

#[cfg(test)]
mod parse_decimal_fast_tests {
    use super::*;
    use std::str::FromStr;
    #[test]
    fn matches_from_str() {
        let mut x: u64 = 88172645463325252;
        let mut next = || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
        let lens = [1usize, 2, 9, 4095, 4096, 4097, 4098, 6144, 8191, 8192, 8193, 12345, 40000, 100_000, 300_001];
        for &l in &lens {
            for trial in 0..3 {
                let mut st = String::with_capacity(l);
                for i in 0..l {
                    let d = if trial == 1 && i < l / 2 { 0 } else { (next() % 10) as u8 }; // leading zeros too
                    st.push((b'0' + d) as char);
                }
                assert_eq!(parse_decimal_fast(&st).unwrap(), BigUint::from_str(&st).unwrap(), "len {l} trial {trial}");
            }
        }
        assert_eq!(parse_decimal_fast("0").unwrap(), BigUint::from(0u8));
        let nines = "9".repeat(20000);
        assert_eq!(parse_decimal_fast(&nines).unwrap(), BigUint::from_str(&nines).unwrap());
        assert!(parse_decimal_fast("").is_err());
        assert!(parse_decimal_fast("12a").is_err());
    }
}

/// Needed because the lean4export format serializes nat literals as strings: 
/// https://github.com/leanprover/lean4export/blob/ddeb0869b0b5679b0104e16291ffd929fbaa6a48/format_ndjson.md?plain=1#L186
fn deserialize_biguint_from_string<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where D: Deserializer<'de> {
    struct BigUintStringVisitor;

    impl<'de> Visitor<'de> for BigUintStringVisitor {
        type Value = BigUint;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string containing a natural number")
        }

        fn visit_str<E>(self, v: &str) -> Result<BigUint, E> where E: DeError {
            parse_decimal_fast(v).map_err(|e| E::custom(format!("invalid BigUint decimal string: {e}")))
        }

        fn visit_string<E>(self, v: String) -> Result<BigUint, E> where E: DeError {
            self.visit_str(&v)
        }
    }
    deserializer.deserialize_str(BigUintStringVisitor)
}

mod semver_tests {
    use super::*;
    #[allow(dead_code)]
    fn mk_meta(s: &'static str) -> FileMeta<'static> {
        FileMeta {
            lean: LeanMeta { version: Cow::Borrowed(""), githash: Cow::Borrowed("") },
            exporter: ExporterMeta { version: Cow::Borrowed(""), name: Cow::Borrowed("") },
            format :FormatMeta { version: Cow::Borrowed(s) }
        }
    }

    #[test]
    fn test_ng() {
        let too_small = [
            "2.9.9",
            "2.9.99",
        ];
        let too_big = [
            "4.0.0",
            "4.1.0",
            "3.2.0",
            "3.2.1",
        ];

        for v in too_small {
            assert!(check_semver(&mk_meta(v)).is_err())
        }
        for v in too_big {
            assert!(check_semver(&mk_meta(v)).is_err())
        }
    }

    #[test]
    fn test_ok() {
        let ok = [
            "3.1.0",
            "3.1.9",
        ];
        for v in ok {
            assert!(check_semver(&mk_meta(v)).is_ok())
        }
    }
}
