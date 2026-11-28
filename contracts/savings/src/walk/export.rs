//! A reader of lean4export exports (NDJSON 3.1.0, and the binary "export v2"
//! the acceptance rule also reads) for attribution only, and the walk and
//! digests over it.
//!
//! Why it is here and not in the vendored checker: the checker is compiled
//! into the proof guests, and any change to its sources moved the published
//! programs' image IDs (`verify-programs`, 2026-11-28). This reader shares no
//! code with the guests. It checks nothing: the artifacts it reads were
//! accepted by the acceptance rule first (`walk::declarations`).
//!
//! The digests are the Merkle hash the walk has always used: binder names
//! and styles left out, constants named by their dotted names, `mdata`
//! transparent. A whole export's keys reproduce the committed library set
//! byte for byte (`library/README.md`), which is how this reader was checked
//! against the checker's tables it replaced.
use std::collections::HashMap;

/// First bytes of a v2 export.
pub const V2_MAGIC: [u8; 4] = [0x00, b'L', b'E', b'2'];

#[derive(Clone, Debug)]
enum Name {
    Str(u32, String),
    Num(u32, u64),
}

#[derive(Clone, Copy, Debug)]
enum Level {
    Succ(u32),
    Max(u32, u32),
    IMax(u32, u32),
    Param(u32),
}

#[derive(Clone, Debug)]
enum Expr {
    BVar(u16),
    Sort(u32),
    Const(u32, Vec<u32>),
    App(u32, u32),
    Pi(u32, u32),
    Lam(u32, u32),
    Let(u32, u32, u32),
    /// Big-endian bytes; zero is `[0]`.
    Nat(Vec<u8>),
    Str(String),
    Proj(u32, u64, u32),
    MData(u32),
}

/// One declaration: its name, type and value (theorems, definitions and
/// opaque constants have one).
#[derive(Clone, Debug)]
struct Decl {
    name: u32,
    ty: u32,
    value: Option<u32>,
}

/// The tables of one export, read segment by segment.
#[derive(Default)]
pub struct Export {
    names: HashMap<u32, Name>,
    levels: HashMap<u32, Level>,
    exprs: HashMap<u32, Expr>,
    decls: Vec<Decl>,
    v2: bool,
}

/// A declaration the walk reached: its position, dotted name, and the
/// digests of its type and value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Used {
    pub position: usize,
    pub name: String,
    pub ty: [u8; 32],
    pub value: Option<[u8; 32]>,
}

type R<T> = Result<T, String>;

fn u32_of(v: &serde_json::Value) -> R<u32> {
    v.as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| format!("index expected, not {v}"))
}
fn u32s_of(v: &serde_json::Value) -> R<Vec<u32>> {
    v.as_array()
        .ok_or("list expected")?
        .iter()
        .map(u32_of)
        .collect()
}

/// A decimal natural as big-endian bytes; zero is `[0]`.
fn decimal_be(text: &str) -> R<Vec<u8>> {
    let mut out: Vec<u8> = vec![0];
    for c in text.bytes() {
        if !c.is_ascii_digit() {
            return Err(format!("natural literal {text:?}"));
        }
        let mut carry = u32::from(c - b'0');
        for b in out.iter_mut().rev() {
            let v = u32::from(*b) * 10 + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            out.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    while out.len() > 1 && out.first() == Some(&0) {
        out.remove(0);
    }
    Ok(out)
}

struct In<'b> {
    rest: &'b [u8],
}

impl<'b> In<'b> {
    fn byte(&mut self) -> R<u8> {
        let (&b, tail) = self.rest.split_first().ok_or("record truncated")?;
        self.rest = tail;
        Ok(b)
    }
    fn uint(&mut self) -> R<u64> {
        let mut v = 0u64;
        for k in 0..10 {
            let b = self.byte()?;
            v |= u64::from(b & 0x7f) << (7 * k);
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err("integer too long".into())
    }
    fn u32(&mut self) -> R<u32> {
        u32::try_from(self.uint()?).map_err(|_| "integer wider than 32 bits".into())
    }
    fn bytes(&mut self) -> R<&'b [u8]> {
        let n = usize::try_from(self.uint()?).map_err(|_| "length")?;
        if n > self.rest.len() {
            return Err("length past the end".into());
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }
    fn str(&mut self) -> R<String> {
        Ok(std::str::from_utf8(self.bytes()?)
            .map_err(|e| e.to_string())?
            .to_owned())
    }
    fn u32s(&mut self) -> R<Vec<u32>> {
        let n = self.uint()?;
        (0..n).map(|_| self.u32()).collect()
    }
    fn skip_list(&mut self, mut each: impl FnMut(&mut Self) -> R<()>) -> R<u64> {
        let n = self.uint()?;
        for _ in 0..n {
            each(self)?;
        }
        Ok(n)
    }
}

impl Export {
    /// Read one more segment: the whole export, or a statement then its
    /// artifact. A v2 export starts with `V2_MAGIC`; its continuation does
    /// not.
    pub fn read(&mut self, segment: &[u8]) -> R<()> {
        if let Some(rest) = segment.strip_prefix(&V2_MAGIC[..]) {
            self.v2 = true;
            return self.read_v2(rest);
        }
        if self.v2 {
            return self.read_v2(segment);
        }
        for (n, line) in segment.split(|b| *b == b'\n').enumerate() {
            if line.is_empty() {
                continue;
            }
            let v: serde_json::Value =
                serde_json::from_slice(line).map_err(|e| format!("line {}: {e}", n + 1))?;
            self.line(&v).map_err(|e| format!("line {}: {e}", n + 1))?;
        }
        Ok(())
    }

    /// How many declarations have been read.
    pub fn declarations(&self) -> usize {
        self.decls.len()
    }

    fn line(&mut self, v: &serde_json::Value) -> R<()> {
        let o = v.as_object().ok_or("object expected")?;
        let at = |k: &str| o.get(k).map(u32_of).transpose();
        if let Some(i) = at("in")? {
            let name = if let Some(s) = o.get("str") {
                Name::Str(
                    u32_of(&s["pre"])?,
                    s["str"].as_str().ok_or("str")?.to_owned(),
                )
            } else if let Some(s) = o.get("num") {
                Name::Num(u32_of(&s["pre"])?, s["i"].as_u64().ok_or("num")?)
            } else {
                return Err("a name line of no known kind".into());
            };
            self.names.insert(i, name);
        } else if let Some(i) = at("il")? {
            let level = if let Some(x) = o.get("succ") {
                Level::Succ(u32_of(x)?)
            } else if let Some(x) = o.get("max") {
                Level::Max(u32_of(&x[0])?, u32_of(&x[1])?)
            } else if let Some(x) = o.get("imax") {
                Level::IMax(u32_of(&x[0])?, u32_of(&x[1])?)
            } else if let Some(x) = o.get("param") {
                Level::Param(u32_of(x)?)
            } else {
                return Err("a level line of no known kind".into());
            };
            self.levels.insert(i, level);
        } else if let Some(i) = at("ie")? {
            let e = if let Some(x) = o.get("bvar") {
                Expr::BVar(u16::try_from(x.as_u64().ok_or("bvar")?).map_err(|_| "bvar")?)
            } else if let Some(x) = o.get("sort") {
                Expr::Sort(u32_of(x)?)
            } else if let Some(x) = o.get("const") {
                Expr::Const(u32_of(&x["name"])?, u32s_of(&x["us"])?)
            } else if let Some(x) = o.get("app") {
                Expr::App(u32_of(&x["fn"])?, u32_of(&x["arg"])?)
            } else if let Some(x) = o.get("forallE") {
                Expr::Pi(u32_of(&x["type"])?, u32_of(&x["body"])?)
            } else if let Some(x) = o.get("lam") {
                Expr::Lam(u32_of(&x["type"])?, u32_of(&x["body"])?)
            } else if let Some(x) = o.get("letE") {
                Expr::Let(
                    u32_of(&x["type"])?,
                    u32_of(&x["value"])?,
                    u32_of(&x["body"])?,
                )
            } else if let Some(x) = o.get("natVal") {
                Expr::Nat(decimal_be(x.as_str().ok_or("natVal")?)?)
            } else if let Some(x) = o.get("strVal") {
                Expr::Str(x.as_str().ok_or("strVal")?.to_owned())
            } else if let Some(x) = o.get("proj") {
                Expr::Proj(
                    u32_of(&x["typeName"])?,
                    x["idx"].as_u64().ok_or("idx")?,
                    u32_of(&x["struct"])?,
                )
            } else if let Some(x) = o.get("mdata") {
                Expr::MData(u32_of(&x["expr"])?)
            } else {
                return Err("an expression line of no known kind".into());
            };
            self.exprs.insert(i, e);
        } else if o.contains_key("meta") {
        } else {
            for (k, x) in o {
                match k.as_str() {
                    "thm" | "def" | "opaque" => self.decls.push(Decl {
                        name: u32_of(&x["name"])?,
                        ty: u32_of(&x["type"])?,
                        value: Some(u32_of(&x["value"])?),
                    }),
                    "axiom" | "quot" => self.decls.push(Decl {
                        name: u32_of(&x["name"])?,
                        ty: u32_of(&x["type"])?,
                        value: None,
                    }),
                    "inductive" => {
                        for part in ["types", "ctors", "recs"] {
                            for d in x[part].as_array().ok_or("inductive part")? {
                                self.decls.push(Decl {
                                    name: u32_of(&d["name"])?,
                                    ty: u32_of(&d["type"])?,
                                    value: None,
                                });
                            }
                        }
                    }
                    other => return Err(format!("unknown line kind {other:?}")),
                }
            }
        }
        Ok(())
    }

    /// The v2 records, in the field order of the vendored codec
    /// (`nanoda_lib/src/parser/v2.rs`, `decode_record`).
    fn read_v2(&mut self, bytes: &[u8]) -> R<()> {
        let mut r = In { rest: bytes };
        while !r.rest.is_empty() {
            let tag = r.byte()?;
            enum Got {
                None,
                Name(Name),
                Level(Level),
                Expr(Expr),
            }
            let got = match tag {
                0 => {
                    for _ in 0..5 {
                        r.str()?;
                    }
                    Got::None
                }
                1 => Got::Name(Name::Str(r.u32()?, r.str()?)),
                2 => Got::Name(Name::Num(r.u32()?, u64::from(r.u32()?))),
                3 => Got::Level(Level::Succ(r.u32()?)),
                4 => Got::Level(Level::Max(r.u32()?, r.u32()?)),
                5 => Got::Level(Level::IMax(r.u32()?, r.u32()?)),
                6 => Got::Level(Level::Param(r.u32()?)),
                7 => {
                    let le = r.bytes()?;
                    let mut be: Vec<u8> = le.iter().rev().copied().collect();
                    if be.is_empty() {
                        be.push(0);
                    }
                    Got::Expr(Expr::Nat(be))
                }
                8 => Got::Expr(Expr::Str(r.str()?)),
                10 => {
                    let _name = r.u32()?;
                    let (ty, value, body) = (r.u32()?, r.u32()?, r.u32()?);
                    r.byte()?;
                    Got::Expr(Expr::Let(ty, value, body))
                }
                11 => Got::Expr(Expr::Const(r.u32()?, r.u32s()?)),
                12 => Got::Expr(Expr::App(r.u32()?, r.u32()?)),
                13 | 14 => {
                    let _name = r.u32()?;
                    let (ty, body) = (r.u32()?, r.u32()?);
                    r.byte()?;
                    Got::Expr(if tag == 13 {
                        Expr::Pi(ty, body)
                    } else {
                        Expr::Lam(ty, body)
                    })
                }
                15 => Got::Expr(Expr::Proj(r.u32()?, r.uint()?, r.u32()?)),
                16 => Got::Expr(Expr::Sort(r.u32()?)),
                17 => Got::Expr(Expr::BVar(u16::try_from(r.uint()?).map_err(|_| "bvar")?)),
                18 => {
                    let (name, _, ty) = (r.u32()?, r.u32s()?, r.u32()?);
                    r.byte()?;
                    self.decls.push(Decl {
                        name,
                        ty,
                        value: None,
                    });
                    Got::None
                }
                19 => {
                    let (name, _, ty, value) = (r.u32()?, r.u32s()?, r.u32()?, r.u32()?);
                    self.decls.push(Decl {
                        name,
                        ty,
                        value: Some(value),
                    });
                    Got::None
                }
                20 => {
                    let (name, _, ty, value) = (r.u32()?, r.u32s()?, r.u32()?, r.u32()?);
                    if r.byte()? == 1 {
                        r.uint()?;
                    }
                    r.byte()?;
                    self.decls.push(Decl {
                        name,
                        ty,
                        value: Some(value),
                    });
                    Got::None
                }
                21 => {
                    let (name, _, ty, value) = (r.u32()?, r.u32s()?, r.u32()?, r.u32()?);
                    r.byte()?;
                    self.decls.push(Decl {
                        name,
                        ty,
                        value: Some(value),
                    });
                    Got::None
                }
                22 => {
                    let (name, _, ty) = (r.u32()?, r.u32s()?, r.u32()?);
                    r.byte()?;
                    self.decls.push(Decl {
                        name,
                        ty,
                        value: None,
                    });
                    Got::None
                }
                23 => {
                    let push = |name: u32, ty: u32, decls: &mut Vec<Decl>| {
                        decls.push(Decl {
                            name,
                            ty,
                            value: None,
                        })
                    };
                    let mut types = Vec::new();
                    r.skip_list(|r| {
                        let (name, _, ty) = (r.u32()?, r.u32s()?, r.u32()?);
                        r.u32s()?;
                        r.u32s()?;
                        r.byte()?;
                        r.byte()?;
                        r.uint()?;
                        r.uint()?;
                        r.uint()?;
                        r.byte()?;
                        types.push((name, ty));
                        Ok(())
                    })?;
                    let mut ctors = Vec::new();
                    r.skip_list(|r| {
                        let (name, _, ty) = (r.u32()?, r.u32s()?, r.u32()?);
                        r.byte()?;
                        r.uint()?;
                        r.uint()?;
                        r.uint()?;
                        r.u32()?;
                        ctors.push((name, ty));
                        Ok(())
                    })?;
                    let mut recs = Vec::new();
                    r.skip_list(|r| {
                        let (name, _, ty) = (r.u32()?, r.u32s()?, r.u32()?);
                        r.byte()?;
                        for _ in 0..4 {
                            r.uint()?;
                        }
                        r.skip_list(|r| {
                            r.u32()?;
                            r.uint()?;
                            r.u32()?;
                            Ok(())
                        })?;
                        r.u32s()?;
                        r.byte()?;
                        recs.push((name, ty));
                        Ok(())
                    })?;
                    for (name, ty) in types.into_iter().chain(ctors).chain(recs) {
                        push(name, ty, &mut self.decls);
                    }
                    Got::None
                }
                other => return Err(format!("unknown record tag {other}")),
            };
            let kind = r.byte()?;
            let i = if kind == 0 { None } else { Some(r.u32()?) };
            match (got, kind, i) {
                (Got::Name(n), 1, Some(i)) => {
                    self.names.insert(i, n);
                }
                (Got::Level(l), 2, Some(i)) => {
                    self.levels.insert(i, l);
                }
                (Got::Expr(e), 3, Some(i)) => {
                    self.exprs.insert(i, e);
                }
                (Got::None, 0, None) => {}
                _ => return Err("a record with the wrong back-reference".into()),
            }
        }
        Ok(())
    }

    /// The dotted rendering of name `n` (index 0 is the anonymous name).
    pub fn name(&self, n: u32) -> String {
        match self.names.get(&n) {
            None => String::new(),
            Some(Name::Str(pre, s)) => {
                let mut p = self.name(*pre);
                if !p.is_empty() {
                    p.push('.');
                }
                p + s
            }
            Some(Name::Num(pre, i)) => {
                let mut p = self.name(*pre);
                if !p.is_empty() {
                    p.push('.');
                }
                p + &i.to_string()
            }
        }
    }

    fn expr(&self, e: u32) -> R<&Expr> {
        self.exprs
            .get(&e)
            .ok_or_else(|| format!("expression {e} not in the export"))
    }

    /// The constants `e` names, `mdata` looked through, each subterm once.
    fn constants(&self, e: u32, out: &mut Vec<u32>) -> R<()> {
        let mut seen = std::collections::HashSet::new();
        let mut stack = vec![e];
        while let Some(e) = stack.pop() {
            if !seen.insert(e) {
                continue;
            }
            match self.expr(e)? {
                Expr::Const(n, _) => out.push(*n),
                Expr::App(a, b) | Expr::Pi(a, b) | Expr::Lam(a, b) => stack.extend([*a, *b]),
                Expr::Let(a, b, c) => stack.extend([*a, *b, *c]),
                Expr::Proj(n, _, s) => {
                    out.push(*n);
                    stack.push(*s);
                }
                Expr::MData(x) => stack.push(*x),
                Expr::BVar(_) | Expr::Sort(_) | Expr::Nat(_) | Expr::Str(_) => {}
            }
        }
        Ok(())
    }
}

/// Memoised Merkle digests over one export.
pub struct Digests<'a> {
    x: &'a Export,
    hash: &'a mut dyn FnMut(&[u8]) -> [u8; 32],
    exprs: HashMap<u32, [u8; 32]>,
    names: HashMap<u32, [u8; 32]>,
    levels: HashMap<u32, [u8; 32]>,
}

impl<'a> Digests<'a> {
    pub fn new(x: &'a Export, hash: &'a mut dyn FnMut(&[u8]) -> [u8; 32]) -> Self {
        Self {
            x,
            hash,
            exprs: HashMap::new(),
            names: HashMap::new(),
            levels: HashMap::new(),
        }
    }
    fn name(&mut self, n: u32) -> [u8; 32] {
        if let Some(d) = self.names.get(&n) {
            return *d;
        }
        let text = self.x.name(n);
        let mut bytes = vec![b'N'];
        bytes.extend_from_slice(&(text.len() as u64).to_be_bytes());
        bytes.extend_from_slice(text.as_bytes());
        let d = (self.hash)(&bytes);
        self.names.insert(n, d);
        d
    }
    fn level(&mut self, l: u32) -> R<[u8; 32]> {
        if let Some(d) = self.levels.get(&l) {
            return Ok(*d);
        }
        let mut bytes = Vec::with_capacity(65);
        match (l, self.x.levels.get(&l).copied()) {
            (0, _) => bytes.push(0),
            (_, Some(Level::Succ(a))) => {
                bytes.push(1);
                bytes.extend_from_slice(&self.level(a)?);
            }
            (_, Some(Level::Max(a, b))) => {
                bytes.push(2);
                bytes.extend_from_slice(&self.level(a)?);
                bytes.extend_from_slice(&self.level(b)?);
            }
            (_, Some(Level::IMax(a, b))) => {
                bytes.push(3);
                bytes.extend_from_slice(&self.level(a)?);
                bytes.extend_from_slice(&self.level(b)?);
            }
            (_, Some(Level::Param(n))) => {
                bytes.push(4);
                bytes.extend_from_slice(&self.name(n));
            }
            (_, None) => return Err(format!("level {l} not in the export")),
        }
        let d = (self.hash)(&bytes);
        self.levels.insert(l, d);
        Ok(d)
    }
    /// The digest of expression `e`.
    pub fn expr(&mut self, e: u32) -> R<[u8; 32]> {
        if let Some(d) = self.exprs.get(&e) {
            return Ok(*d);
        }
        let expr = self.x.expr(e)?.clone();
        let mut bytes = Vec::with_capacity(97);
        match expr {
            Expr::MData(inner) => {
                let d = self.expr(inner)?;
                self.exprs.insert(e, d);
                return Ok(d);
            }
            Expr::BVar(i) => {
                bytes.push(0);
                bytes.extend_from_slice(&i.to_be_bytes());
            }
            Expr::Sort(l) => {
                bytes.push(1);
                bytes.extend_from_slice(&self.level(l)?);
            }
            Expr::Const(n, ls) => {
                bytes.push(2);
                bytes.extend_from_slice(&self.name(n));
                bytes.extend_from_slice(&(ls.len() as u64).to_be_bytes());
                for l in ls {
                    bytes.extend_from_slice(&self.level(l)?);
                }
            }
            Expr::App(a, b) => {
                bytes.push(3);
                bytes.extend_from_slice(&self.expr(a)?);
                bytes.extend_from_slice(&self.expr(b)?);
            }
            Expr::Pi(a, b) => {
                bytes.push(4);
                bytes.extend_from_slice(&self.expr(a)?);
                bytes.extend_from_slice(&self.expr(b)?);
            }
            Expr::Lam(a, b) => {
                bytes.push(5);
                bytes.extend_from_slice(&self.expr(a)?);
                bytes.extend_from_slice(&self.expr(b)?);
            }
            Expr::Let(a, b, c) => {
                bytes.push(6);
                bytes.extend_from_slice(&self.expr(a)?);
                bytes.extend_from_slice(&self.expr(b)?);
                bytes.extend_from_slice(&self.expr(c)?);
            }
            Expr::Nat(be) => {
                bytes.push(7);
                bytes.extend_from_slice(&be);
            }
            Expr::Str(s) => {
                bytes.push(8);
                bytes.extend_from_slice(s.as_bytes());
            }
            Expr::Proj(n, idx, s) => {
                bytes.push(9);
                bytes.extend_from_slice(&self.name(n));
                bytes.extend_from_slice(&idx.to_be_bytes());
                bytes.extend_from_slice(&self.expr(s)?);
            }
        }
        let d = (self.hash)(&bytes);
        self.exprs.insert(e, d);
        Ok(d)
    }
}

/// Every declaration reachable from the one named `root`, through types and
/// values, root included, in export order, kernel-reserved names left out
/// and not walked through (`nanoda_lib::acceptance::is_kernel_reserved`,
/// unchanged public API).
pub fn used_constants(
    x: &Export,
    root: &str,
    hash: &mut dyn FnMut(&[u8]) -> [u8; 32],
) -> R<Vec<Used>> {
    let mut by_name: HashMap<String, usize> = HashMap::new();
    for (i, d) in x.decls.iter().enumerate() {
        by_name.entry(x.name(d.name)).or_insert(i);
    }
    let start = *by_name
        .get(root)
        .ok_or_else(|| format!("no declaration named {root}"))?;
    let mut digests = Digests::new(x, hash);
    let mut seen = vec![false; x.decls.len()];
    let mut stack = vec![start];
    let mut used = Vec::new();
    while let Some(position) = stack.pop() {
        if seen.get(position).copied().unwrap_or(true) {
            continue;
        }
        if let Some(s) = seen.get_mut(position) {
            *s = true;
        }
        let Some(d) = x.decls.get(position) else {
            continue;
        };
        let name = x.name(d.name);
        if nanoda_lib::acceptance::is_kernel_reserved(&name) {
            continue;
        }
        let mut reached = Vec::new();
        x.constants(d.ty, &mut reached)?;
        if let Some(v) = d.value {
            x.constants(v, &mut reached)?;
        }
        for n in reached {
            if let Some(i) = by_name.get(&x.name(n)) {
                stack.push(*i);
            }
        }
        let ty = digests.expr(d.ty)?;
        let value = d.value.map(|v| digests.expr(v)).transpose()?;
        used.push(Used {
            position,
            name,
            ty,
            value,
        });
    }
    used.sort_by_key(|u| u.position);
    Ok(used)
}

/// Every declaration of the export with its digests, in export order.
pub fn all_declarations(x: &Export, hash: &mut dyn FnMut(&[u8]) -> [u8; 32]) -> R<Vec<Used>> {
    let mut digests = Digests::new(x, hash);
    let mut out = Vec::with_capacity(x.decls.len());
    for (position, d) in x.decls.iter().enumerate() {
        let ty = digests.expr(d.ty)?;
        let value = d.value.map(|v| digests.expr(v)).transpose()?;
        out.push(Used {
            position,
            name: x.name(d.name),
            ty,
            value,
        });
    }
    Ok(out)
}
