//! Nucleus addition: "export v2", a binary form of a lean4export NDJSON export
//! (docs/rfcs/proof-commerce-statement-format-v2-2026-11-13.md).
//!
//! An export in v2 is `MAGIC` followed by one record per NDJSON line, in the
//! same order. A continuation (an artifact that extends a statement) is
//! records only. A record is a tag byte naming the line's value variant, its
//! fields in declaration order, then the line's back-reference. Integers are
//! unsigned LEB128 in their shortest form and within their field's width;
//! booleans are one byte, 0 or 1; strings are a length and UTF-8 bytes; lists
//! are a count and their elements; big naturals are their little-endian bytes
//! with no trailing zero byte (zero is the empty string).
//!
//! The decoder yields exactly the `ExportJsonObject` the NDJSON reader yields
//! for the same line, and the parser applies it with the same code. Every
//! length is checked against the bytes left; malformed input is an error.
//! There is one encoding per value: the decoder refuses non-shortest
//! integers, booleans other than 0 and 1, trailing zero bytes in a natural,
//! and unknown tags.
use super::{
    BackRef, Constructor, DefinitionSafety, ExportJsonObject, ExportJsonVal, ExporterMeta, FileMeta,
    FormatMeta, IndInfo, LeanMeta, QuotKind, Recursor, RecursorRule,
};
use crate::env::ReducibilityHint;
use crate::expr::BinderStyle;
use num_bigint::BigUint;
use std::borrow::Cow;

/// First bytes of a v2 export. No NDJSON export starts with a zero byte.
pub const MAGIC: [u8; 4] = [0x00, b'L', b'E', b'2'];

pub type Error = String;

mod tag {
    pub const META: u8 = 0;
    pub const NAME_STR: u8 = 1;
    pub const NAME_NUM: u8 = 2;
    pub const SUCC: u8 = 3;
    pub const MAX: u8 = 4;
    pub const IMAX: u8 = 5;
    pub const PARAM: u8 = 6;
    pub const NAT: u8 = 7;
    pub const STR: u8 = 8;
    pub const LET: u8 = 10;
    pub const CONST: u8 = 11;
    pub const APP: u8 = 12;
    pub const PI: u8 = 13;
    pub const LAM: u8 = 14;
    pub const PROJ: u8 = 15;
    pub const SORT: u8 = 16;
    pub const BVAR: u8 = 17;
    pub const AXIOM: u8 = 18;
    pub const THM: u8 = 19;
    pub const DEF: u8 = 20;
    pub const OPAQUE: u8 = 21;
    pub const QUOT: u8 = 22;
    pub const INDUCTIVE: u8 = 23;
}

// ---------------------------------------------------------------- encoding

struct Out(Vec<u8>);

impl Out {
    fn byte(&mut self, b: u8) {
        self.0.push(b);
    }
    fn uint(&mut self, mut v: u64) {
        loop {
            let low = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.0.push(low);
                return;
            }
            self.0.push(low | 0x80);
        }
    }
    fn u32(&mut self, v: u32) {
        self.uint(u64::from(v))
    }
    fn u16(&mut self, v: u16) {
        self.uint(u64::from(v))
    }
    fn bool(&mut self, v: bool) {
        self.0.push(u8::from(v))
    }
    fn bytes(&mut self, b: &[u8]) {
        self.uint(b.len() as u64);
        self.0.extend_from_slice(b);
    }
    fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes())
    }
    fn u32s(&mut self, v: &[u32]) {
        self.uint(v.len() as u64);
        for x in v {
            self.u32(*x);
        }
    }
    fn list<T>(&mut self, v: &[T], mut each: impl FnMut(&mut Self, &T)) {
        self.uint(v.len() as u64);
        for x in v {
            each(self, x);
        }
    }
}

fn binder(b: BinderStyle) -> u8 {
    match b {
        BinderStyle::Default => 0,
        BinderStyle::Implicit => 1,
        BinderStyle::StrictImplicit => 2,
        BinderStyle::InstanceImplicit => 3,
    }
}

/// One record for one parsed line.
pub(crate) fn encode_object(object: &ExportJsonObject<'_>, out: &mut Vec<u8>) -> Result<(), Error> {
    use ExportJsonVal::*;
    let mut o = Out(std::mem::take(out));
    match &object.val {
        Metadata(m) => {
            o.byte(tag::META);
            o.str(&m.lean.version);
            o.str(&m.lean.githash);
            o.str(&m.exporter.name);
            o.str(&m.exporter.version);
            o.str(&m.format.version);
        }
        NameStr { pre, str } => {
            o.byte(tag::NAME_STR);
            o.u32(*pre);
            o.str(str);
        }
        NameNum { pre, i } => {
            o.byte(tag::NAME_NUM);
            o.u32(*pre);
            o.u32(*i);
        }
        LevelSucc(x) => {
            o.byte(tag::SUCC);
            o.u32(*x);
        }
        LevelMax([a, b]) => {
            o.byte(tag::MAX);
            o.u32(*a);
            o.u32(*b);
        }
        LevelIMax([a, b]) => {
            o.byte(tag::IMAX);
            o.u32(*a);
            o.u32(*b);
        }
        LevelParam(x) => {
            o.byte(tag::PARAM);
            o.u32(*x);
        }
        NatLit(n) => {
            o.byte(tag::NAT);
            let bytes = if *n == BigUint::ZERO { Vec::new() } else { n.to_bytes_le() };
            o.bytes(&bytes);
        }
        StrLit(s) => {
            o.byte(tag::STR);
            o.str(s);
        }
        ExprMData { .. } => {
            *out = o.0;
            return Err("export v2 has no form for Expr.mdata, which the checker refuses".into());
        }
        ExprLet { name, ty, value, body, nondep } => {
            o.byte(tag::LET);
            o.u32(*name);
            o.u32(*ty);
            o.u32(*value);
            o.u32(*body);
            o.bool(*nondep);
        }
        ExprConst { name, levels } => {
            o.byte(tag::CONST);
            o.u32(*name);
            o.u32s(levels);
        }
        ExprApp { fun, arg } => {
            o.byte(tag::APP);
            o.u32(*fun);
            o.u32(*arg);
        }
        ExprPi { binder_name, binder_type, body, binder_info } => {
            o.byte(tag::PI);
            o.u32(*binder_name);
            o.u32(*binder_type);
            o.u32(*body);
            o.byte(binder(*binder_info));
        }
        ExprLambda { binder_name, binder_type, body, binder_info } => {
            o.byte(tag::LAM);
            o.u32(*binder_name);
            o.u32(*binder_type);
            o.u32(*body);
            o.byte(binder(*binder_info));
        }
        ExprProj { type_name, idx, structure } => {
            o.byte(tag::PROJ);
            o.u32(*type_name);
            match u32::try_from(*idx) {
                Ok(idx) => o.u32(idx),
                Err(_) => {
                    *out = o.0;
                    return Err("projection index wider than 32 bits".into());
                }
            }
            o.u32(*structure);
        }
        ExprSort(x) => {
            o.byte(tag::SORT);
            o.u32(*x);
        }
        ExprBVar(x) => {
            o.byte(tag::BVAR);
            o.u16(*x);
        }
        Axiom { name, uparams, ty, is_unsafe } => {
            o.byte(tag::AXIOM);
            o.u32(*name);
            o.u32s(uparams);
            o.u32(*ty);
            o.bool(*is_unsafe);
        }
        Thm { name, uparams, ty, value } => {
            o.byte(tag::THM);
            o.u32(*name);
            o.u32s(uparams);
            o.u32(*ty);
            o.u32(*value);
        }
        Defn { name, uparams, ty, value, hint, safety } => {
            o.byte(tag::DEF);
            o.u32(*name);
            o.u32s(uparams);
            o.u32(*ty);
            o.u32(*value);
            match hint {
                ReducibilityHint::Opaque => o.byte(0),
                ReducibilityHint::Regular(h) => {
                    o.byte(1);
                    o.u16(*h);
                }
                ReducibilityHint::Abbrev => o.byte(2),
            }
            o.byte(match safety {
                DefinitionSafety::Unsafe => 0,
                DefinitionSafety::Safe => 1,
                DefinitionSafety::Partial => 2,
            });
        }
        Opaque { name, uparams, ty, value, is_unsafe } => {
            o.byte(tag::OPAQUE);
            o.u32(*name);
            o.u32s(uparams);
            o.u32(*ty);
            o.u32(*value);
            o.bool(*is_unsafe);
        }
        Quot { name, uparams, ty, kind } => {
            o.byte(tag::QUOT);
            o.u32(*name);
            o.u32s(uparams);
            o.u32(*ty);
            o.byte(match kind {
                QuotKind::Ty => 0,
                QuotKind::Ctor => 1,
                QuotKind::Lift => 2,
                QuotKind::Ind => 3,
            });
        }
        Inductive { ind_vals, ctor_vals, rec_vals } => {
            o.byte(tag::INDUCTIVE);
            o.list(ind_vals, |o, t| {
                o.u32(t.name);
                o.u32s(&t.uparams);
                o.u32(t.ty);
                o.u32s(&t.all);
                o.u32s(&t.ctors);
                o.bool(t.is_rec);
                o.bool(t.is_reflexive);
                o.u16(t.num_indices);
                o.u16(t.num_nested);
                o.u16(t.num_params);
                o.bool(t.is_unsafe);
            });
            o.list(ctor_vals, |o, c| {
                o.u32(c.name);
                o.u32s(&c.uparams);
                o.u32(c.ty);
                o.bool(c.is_unsafe);
                o.u16(c.cidx);
                o.u16(c.num_params);
                o.u16(c.num_fields);
                o.u32(c.induct);
            });
            o.list(rec_vals, |o, r| {
                o.u32(r.name);
                o.u32s(&r.uparams);
                o.u32(r.ty);
                o.bool(r.is_unsafe);
                o.u16(r.num_params);
                o.u16(r.num_indices);
                o.u16(r.num_motives);
                o.u16(r.num_minors);
                o.list(&r.rules, |o, rule| {
                    o.u32(rule.ctor);
                    o.u16(rule.nfields);
                    o.u32(rule.rhs);
                });
                o.u32s(&r.all);
                o.bool(r.k);
            });
        }
    }
    match object.i {
        None => o.byte(0),
        Some(BackRef::In(x)) => {
            o.byte(1);
            o.u32(x)
        }
        Some(BackRef::Il(x)) => {
            o.byte(2);
            o.u32(x)
        }
        Some(BackRef::Ie(x)) => {
            o.byte(3);
            o.u32(x)
        }
    }
    *out = o.0;
    Ok(())
}

/// Encode NDJSON lines as v2 records. With `header`, the result starts with
/// `MAGIC` (a statement, a base); without, it is records only (a continuation).
/// Each line is parsed by the same reader the checker uses.
pub fn encode_ndjson(ndjson: &[u8], header: bool) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(ndjson.len() / 3);
    if header {
        out.extend_from_slice(&MAGIC);
    }
    for (n, line) in ndjson.split_inclusive(|&b| b == b'\n').enumerate() {
        let line = std::str::from_utf8(line).map_err(|e| format!("line {}: {e}", n + 1))?;
        let object = serde_json::from_str::<ExportJsonObject>(line).map_err(|e| format!("line {}: {e}", n + 1))?;
        encode_object(&object, &mut out).map_err(|e| format!("line {}: {e}", n + 1))?;
    }
    Ok(out)
}

// ---------------------------------------------------------------- decoding

pub(crate) struct In<'b> {
    pub(crate) rest: &'b [u8],
}

impl<'b> In<'b> {
    #[inline(always)]
    fn byte(&mut self) -> Result<u8, Error> {
        let (&b, tail) = self.rest.split_first().ok_or("record truncated")?;
        self.rest = tail;
        Ok(b)
    }
    /// Shortest-form LEB128 no wider than `bits` (at most 32).
    ///
    /// A one-byte integer (below 128) is returned at once; that is most of the
    /// integers in an export. Longer ones accumulate in 64 bits: at most five
    /// bytes of seven bits each, 35 bits, so nothing is lost before the width
    /// check. The rules are the same as for one byte at a time: a final byte
    /// of zero after the first is not shortest form, and a value of `bits` or
    /// more bits, or a sixth byte, is wider than the field.
    #[inline(always)]
    fn uint(&mut self, bits: u32) -> Result<u32, Error> {
        debug_assert!(bits <= 32);
        let rest = self.rest;
        let &first = rest.first().ok_or("record truncated")?;
        if first & 0x80 == 0 {
            self.rest = &rest[1..];
            return Ok(u32::from(first));
        }
        let max_bytes = bits.div_ceil(7) as usize;
        let mut v = u64::from(first & 0x7f);
        for k in 1..max_bytes {
            let &b = rest.get(k).ok_or("record truncated")?;
            v |= u64::from(b & 0x7f) << (7 * k);
            if b & 0x80 == 0 {
                if b == 0 {
                    return Err("integer not in shortest form".into());
                }
                if v >> bits != 0 {
                    return Err("integer wider than its field".into());
                }
                self.rest = &rest[k + 1..];
                return Ok(v as u32);
            }
        }
        Err("integer wider than its field".into())
    }
    #[inline(always)]
    fn u32(&mut self) -> Result<u32, Error> {
        self.uint(32)
    }
    #[inline(always)]
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(self.uint(16)? as u16)
    }
    fn bool(&mut self) -> Result<bool, Error> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("boolean other than 0 or 1".into()),
        }
    }
    fn len(&mut self) -> Result<usize, Error> {
        let n = usize::try_from(self.uint(32)?).map_err(|_| "length too large")?;
        if n > self.rest.len() {
            return Err("length past the end of the input".into());
        }
        Ok(n)
    }
    fn bytes(&mut self) -> Result<&'b [u8], Error> {
        let n = self.len()?;
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }
    fn str(&mut self) -> Result<Cow<'b, str>, Error> {
        Ok(Cow::Borrowed(std::str::from_utf8(self.bytes()?).map_err(|e| e.to_string())?))
    }
    fn u32s(&mut self) -> Result<Vec<u32>, Error> {
        let n = self.len()?; // each element takes at least one byte
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.u32()?);
        }
        Ok(v)
    }
    fn list<T>(&mut self, mut each: impl FnMut(&mut Self) -> Result<T, Error>) -> Result<Vec<T>, Error> {
        let n = self.len()?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(each(self)?);
        }
        Ok(v)
    }
    fn binder(&mut self) -> Result<BinderStyle, Error> {
        Ok(match self.byte()? {
            0 => BinderStyle::Default,
            1 => BinderStyle::Implicit,
            2 => BinderStyle::StrictImplicit,
            3 => BinderStyle::InstanceImplicit,
            _ => return Err("unknown binder style".into()),
        })
    }
}

/// Decode one record from the front of `input.rest`, advancing it.
pub(crate) fn decode_record<'b>(input: &mut In<'b>) -> Result<ExportJsonObject<'b>, Error> {
    use ExportJsonVal::*;
    let r = input;
    let val = match r.byte()? {
        tag::META => Metadata(Box::new(FileMeta {
            lean: LeanMeta { version: r.str()?, githash: r.str()? },
            exporter: ExporterMeta { name: r.str()?, version: r.str()? },
            format: FormatMeta { version: r.str()? },
        })),
        tag::NAME_STR => NameStr { pre: r.u32()?, str: r.str()? },
        tag::NAME_NUM => NameNum { pre: r.u32()?, i: r.u32()? },
        tag::SUCC => LevelSucc(r.u32()?),
        tag::MAX => LevelMax([r.u32()?, r.u32()?]),
        tag::IMAX => LevelIMax([r.u32()?, r.u32()?]),
        tag::PARAM => LevelParam(r.u32()?),
        tag::NAT => {
            let bytes = r.bytes()?;
            if bytes.last() == Some(&0) {
                return Err("natural with a trailing zero byte".into());
            }
            NatLit(BigUint::from_bytes_le(bytes))
        }
        tag::STR => StrLit(r.str()?),
        tag::LET => ExprLet { name: r.u32()?, ty: r.u32()?, value: r.u32()?, body: r.u32()?, nondep: r.bool()? },
        tag::CONST => ExprConst { name: r.u32()?, levels: r.u32s()? },
        tag::APP => ExprApp { fun: r.u32()?, arg: r.u32()? },
        tag::PI => ExprPi { binder_name: r.u32()?, binder_type: r.u32()?, body: r.u32()?, binder_info: r.binder()? },
        tag::LAM => ExprLambda { binder_name: r.u32()?, binder_type: r.u32()?, body: r.u32()?, binder_info: r.binder()? },
        tag::PROJ => ExprProj {
            type_name: r.u32()?,
            idx: usize::try_from(r.uint(32)?).map_err(|_| "projection index too large")?,
            structure: r.u32()?,
        },
        tag::SORT => ExprSort(r.u32()?),
        tag::BVAR => ExprBVar(r.u16()?),
        tag::AXIOM => Axiom { name: r.u32()?, uparams: r.u32s()?, ty: r.u32()?, is_unsafe: r.bool()? },
        tag::THM => Thm { name: r.u32()?, uparams: r.u32s()?, ty: r.u32()?, value: r.u32()? },
        tag::DEF => Defn {
            name: r.u32()?,
            uparams: r.u32s()?,
            ty: r.u32()?,
            value: r.u32()?,
            hint: match r.byte()? {
                0 => ReducibilityHint::Opaque,
                1 => ReducibilityHint::Regular(r.u16()?),
                2 => ReducibilityHint::Abbrev,
                _ => return Err("unknown reducibility hint".into()),
            },
            safety: match r.byte()? {
                0 => DefinitionSafety::Unsafe,
                1 => DefinitionSafety::Safe,
                2 => DefinitionSafety::Partial,
                _ => return Err("unknown definition safety".into()),
            },
        },
        tag::OPAQUE => Opaque { name: r.u32()?, uparams: r.u32s()?, ty: r.u32()?, value: r.u32()?, is_unsafe: r.bool()? },
        tag::QUOT => Quot {
            name: r.u32()?,
            uparams: r.u32s()?,
            ty: r.u32()?,
            kind: match r.byte()? {
                0 => QuotKind::Ty,
                1 => QuotKind::Ctor,
                2 => QuotKind::Lift,
                3 => QuotKind::Ind,
                _ => return Err("unknown quotient kind".into()),
            },
        },
        tag::INDUCTIVE => Inductive {
            ind_vals: r.list(|r| {
                Ok(IndInfo {
                    name: r.u32()?,
                    uparams: r.u32s()?,
                    ty: r.u32()?,
                    all: r.u32s()?,
                    ctors: r.u32s()?,
                    is_rec: r.bool()?,
                    is_reflexive: r.bool()?,
                    num_indices: r.u16()?,
                    num_nested: r.u16()?,
                    num_params: r.u16()?,
                    is_unsafe: r.bool()?,
                })
            })?,
            ctor_vals: r.list(|r| {
                Ok(Constructor {
                    name: r.u32()?,
                    uparams: r.u32s()?,
                    ty: r.u32()?,
                    is_unsafe: r.bool()?,
                    cidx: r.u16()?,
                    num_params: r.u16()?,
                    num_fields: r.u16()?,
                    induct: r.u32()?,
                })
            })?,
            rec_vals: r.list(|r| {
                Ok(Recursor {
                    name: r.u32()?,
                    uparams: r.u32s()?,
                    ty: r.u32()?,
                    is_unsafe: r.bool()?,
                    num_params: r.u16()?,
                    num_indices: r.u16()?,
                    num_motives: r.u16()?,
                    num_minors: r.u16()?,
                    rules: r.list(|r| Ok(RecursorRule { ctor: r.u32()?, nfields: r.u16()?, rhs: r.u32()? }))?,
                    all: r.u32s()?,
                    k: r.bool()?,
                })
            })?,
        },
        _ => return Err("unknown record tag".into()),
    };
    let i = match r.byte()? {
        0 => None,
        1 => Some(BackRef::In(r.u32()?)),
        2 => Some(BackRef::Il(r.u32()?)),
        3 => Some(BackRef::Ie(r.u32()?)),
        _ => return Err("unknown back-reference kind".into()),
    };
    Ok(ExportJsonObject { val, i })
}

/// Decode every record of `bytes` (after `MAGIC` if `header`), for tests and
/// tools; the parser decodes record by record instead.
pub fn decode_all(bytes: &[u8], header: bool) -> Result<usize, Error> {
    let mut rest = bytes;
    if header {
        rest = rest.strip_prefix(&MAGIC[..]).ok_or("missing v2 header")?;
    }
    let mut input = In { rest };
    let mut n = 0;
    while !input.rest.is_empty() {
        decode_record(&mut input)?;
        n += 1;
    }
    Ok(n)
}

/// Encode every line of `ndjson`, decode the records, and compare with the
/// objects the NDJSON reader produced. `Ok(n)` is the number of lines.
pub fn round_trip(ndjson: &[u8]) -> Result<usize, Error> {
    let mut n = 0;
    for line in ndjson.split_inclusive(|&b| b == b'\n') {
        let line = std::str::from_utf8(line).map_err(|e| e.to_string())?;
        let object = serde_json::from_str::<ExportJsonObject>(line).map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        encode_object(&object, &mut bytes)?;
        let mut input = In { rest: &bytes };
        let back = decode_record(&mut input)?;
        if !input.rest.is_empty() {
            return Err(format!("line {}: record has trailing bytes", n + 1));
        }
        if back != object {
            return Err(format!("line {}: decoded record differs from the line", n + 1));
        }
        n += 1;
    }
    Ok(n)
}
