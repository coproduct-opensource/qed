//! The witness of RISC Zero's `stark_verify` circuit, computed from its
//! published witness graph (`stark_verify_graph.bin`).
//!
//! The file format and the arithmetic are those of iden3's `circom-witnesscalc`
//! 0.2.1 (MIT OR Apache-2.0), which RISC Zero's own non-container prover
//! uses: `src/storage/proto_deserializer.rs` for the layout, `src/field.rs`
//! for what each operation means on a 254-bit value, `src/graph.rs` for the
//! evaluation order. This is a reimplementation of the parts that file needs,
//! not a copy; that crate's build needs `protoc` and `libclang`, and this one
//! needs neither.
//!
//! A wrong witness cannot produce an accepted proof: the Groth16 verifier
//! checks the result. So this code is in the proving path, not the trusted
//! base.
use ruint::Uint;
use std::collections::HashMap;

/// A value of the graph: an integer below 2^254, as `circom-witnesscalc` holds
/// it. Shifts drop bits above bit 253, which the circuit's semantics rely on.
pub type Value = Uint<254, 4>;

const MAGIC: &[u8] = b"wtns.graph.001";
/// The BN254 scalar field modulus.
const PRIME: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";

#[derive(Debug)]
pub enum Error {
    Malformed(&'static str),
    UnknownOperation(u32),
    UnsupportedField,
    Input(String),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Malformed(what) => write!(f, "witness graph malformed: {what}"),
            Error::UnknownOperation(op) => write!(f, "witness graph names unknown operation {op}"),
            Error::UnsupportedField => {
                write!(f, "witness graph is not over the BN254 scalar field")
            }
            Error::Input(what) => write!(f, "witness input: {what}"),
        }
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy)]
enum Node {
    Input(u32),
    Constant(u32),
    Uno(u8, u32),
    Duo(u8, u32, u32),
    Tres(u32, u32, u32),
}

pub struct Graph {
    nodes: Vec<Node>,
    constants: Vec<Value>,
    /// Node index of each witness signal, in witness order.
    witness: Vec<u32>,
    /// Name -> (offset, length) in the input buffer.
    inputs: HashMap<String, (usize, usize)>,
}

fn varint(bytes: &[u8], at: &mut usize) -> Result<u64, Error> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *bytes.get(*at).ok_or(Error::Malformed("truncated varint"))?;
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Ok(value);
        }
    }
    Err(Error::Malformed("varint too long"))
}

/// One protobuf field: number, and either a varint or a length-delimited slice.
enum Field<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}
fn field<'a>(bytes: &'a [u8], at: &mut usize) -> Result<(u32, Field<'a>), Error> {
    let tag = varint(bytes, at)?;
    let number = u32::try_from(tag >> 3).map_err(|_| Error::Malformed("field number"))?;
    match tag & 7 {
        0 => Ok((number, Field::Varint(varint(bytes, at)?))),
        2 => {
            let length = usize::try_from(varint(bytes, at)?)
                .map_err(|_| Error::Malformed("field length"))?;
            let end = at
                .checked_add(length)
                .ok_or(Error::Malformed("field length"))?;
            let slice = bytes
                .get(*at..end)
                .ok_or(Error::Malformed("truncated field"))?;
            *at = end;
            Ok((number, Field::Bytes(slice)))
        }
        _ => Err(Error::Malformed("unexpected wire type")),
    }
}
fn index(value: u64) -> Result<u32, Error> {
    u32::try_from(value).map_err(|_| Error::Malformed("node index"))
}
/// The varint fields 1..=4 of a node body; absent fields are zero (proto3).
fn operands(body: &[u8]) -> Result<[u32; 4], Error> {
    let mut out = [0u32; 4];
    let mut at = 0;
    while at < body.len() {
        match field(body, &mut at)? {
            (n @ 1..=4, Field::Varint(v)) => out[n as usize - 1] = index(v)?,
            _ => return Err(Error::Malformed("node field")),
        }
    }
    Ok(out)
}
/// `BigUInt { bytes valueLE = 1; }`, reduced below the modulus.
fn big(body: &[u8], prime: Value) -> Result<Value, Error> {
    let mut at = 0;
    let mut value = Value::ZERO;
    while at < body.len() {
        match field(body, &mut at)? {
            (1, Field::Bytes(le)) => {
                value = Value::try_from_le_slice(le).ok_or(Error::Malformed("constant too wide"))?
            }
            _ => return Err(Error::Malformed("big integer field")),
        }
    }
    Ok(if value > prime { value % prime } else { value })
}

impl Graph {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let prime: Value = PRIME.parse().map_err(|_| Error::Malformed("modulus"))?;
        if bytes.len() < MAGIC.len() + 16 || &bytes[..MAGIC.len()] != MAGIC {
            return Err(Error::Malformed("magic"));
        }
        let mut at = MAGIC.len();
        let word = |at: usize| -> Result<usize, Error> {
            let raw: [u8; 8] = bytes
                .get(at..at + 8)
                .and_then(|s| s.try_into().ok())
                .ok_or(Error::Malformed("truncated header"))?;
            usize::try_from(u64::from_le_bytes(raw)).map_err(|_| Error::Malformed("header value"))
        };
        let count = word(at)?;
        at += 8;
        let metadata_at = word(bytes.len() - 8)?;

        let mut nodes = Vec::with_capacity(count);
        let mut constants: Vec<Value> = Vec::new();
        let mut seen: HashMap<Value, ()> = HashMap::new();
        for _ in 0..count {
            let length = usize::try_from(varint(bytes, &mut at)?)
                .map_err(|_| Error::Malformed("node length"))?;
            let end = at
                .checked_add(length)
                .ok_or(Error::Malformed("node length"))?;
            let message = bytes
                .get(at..end)
                .ok_or(Error::Malformed("truncated node"))?;
            at = end;
            let mut inner = 0;
            let (kind, body) = match field(message, &mut inner)? {
                (kind, Field::Bytes(body)) if inner == message.len() => (kind, body),
                _ => return Err(Error::Malformed("node envelope")),
            };
            match kind {
                1 => nodes.push(Node::Input(operands(body)?[0])),
                2 => {
                    let mut inner = 0;
                    let value = match field(body, &mut inner)? {
                        (1, Field::Bytes(value)) if inner == body.len() => big(value, prime)?,
                        _ => return Err(Error::Malformed("constant node")),
                    };
                    // As the reference loader does: a constant value that was
                    // already seen adds no node.
                    if seen.insert(value, ()).is_none() {
                        constants.push(value);
                        nodes.push(Node::Constant(index(constants.len() as u64 - 1)?));
                    }
                }
                3 => {
                    let [op, a, _, _] = operands(body)?;
                    if op > 3 {
                        return Err(Error::UnknownOperation(op));
                    }
                    nodes.push(Node::Uno(op as u8, a));
                }
                4 => {
                    let [op, a, b, _] = operands(body)?;
                    if op > 19 {
                        return Err(Error::UnknownOperation(op));
                    }
                    nodes.push(Node::Duo(op as u8, a, b));
                }
                5 => {
                    let [op, a, b, c] = operands(body)?;
                    if op != 0 {
                        return Err(Error::UnknownOperation(op));
                    }
                    nodes.push(Node::Tres(a, b, c));
                }
                _ => return Err(Error::Malformed("node kind")),
            }
        }

        // Metadata: one length-delimited `GraphMetadata` message.
        let mut at = metadata_at;
        let length = usize::try_from(varint(bytes, &mut at)?)
            .map_err(|_| Error::Malformed("metadata length"))?;
        let metadata = bytes
            .get(
                at..at
                    .checked_add(length)
                    .ok_or(Error::Malformed("metadata length"))?,
            )
            .ok_or(Error::Malformed("truncated metadata"))?;
        let mut witness = Vec::new();
        let mut inputs = HashMap::new();
        let mut at = 0;
        while at < metadata.len() {
            match field(metadata, &mut at)? {
                (1, Field::Varint(v)) => witness.push(index(v)?),
                (1, Field::Bytes(packed)) => {
                    let mut inner = 0;
                    while inner < packed.len() {
                        witness.push(index(varint(packed, &mut inner)?)?);
                    }
                }
                (2, Field::Bytes(entry)) => {
                    let (mut name, mut span) = (String::new(), (0usize, 0usize));
                    let mut inner = 0;
                    while inner < entry.len() {
                        match field(entry, &mut inner)? {
                            (1, Field::Bytes(key)) => {
                                name = String::from_utf8(key.to_vec())
                                    .map_err(|_| Error::Malformed("input name"))?
                            }
                            (2, Field::Bytes(description)) => {
                                let mut i = 0;
                                while i < description.len() {
                                    match field(description, &mut i)? {
                                        (1, Field::Varint(v)) => span.0 = index(v)? as usize,
                                        (2, Field::Varint(v)) => span.1 = index(v)? as usize,
                                        _ => return Err(Error::Malformed("signal description")),
                                    }
                                }
                            }
                            _ => return Err(Error::Malformed("input entry")),
                        }
                    }
                    inputs.insert(name, span);
                }
                (3, Field::Bytes(value)) => {
                    if big(value, Value::MAX)? != prime {
                        return Err(Error::UnsupportedField);
                    }
                }
                (4, Field::Bytes(_)) => {}
                _ => return Err(Error::Malformed("metadata field")),
            }
        }
        let limit = nodes.len();
        if witness.iter().any(|&i| i as usize >= limit) {
            return Err(Error::Malformed("witness signal out of range"));
        }
        Ok(Self {
            nodes,
            constants,
            witness,
            inputs,
        })
    }

    pub fn nodes(&self) -> usize {
        self.nodes.len()
    }

    /// Lay the named inputs of `input.json` out in the graph's input buffer.
    /// Slot 0 is the constant one.
    fn input_buffer(&self, json: &str) -> Result<Vec<Value>, Error> {
        let prime: Value = PRIME.parse().map_err(|_| Error::Malformed("modulus"))?;
        let parsed: serde_json::Value =
            serde_json::from_str(json).map_err(|e| Error::Input(e.to_string()))?;
        let object = parsed
            .as_object()
            .ok_or(Error::Input("inputs must be an object".into()))?;
        let size = self
            .inputs
            .values()
            .map(|(offset, length)| offset + length)
            .max()
            .unwrap_or(0);
        let mut buffer = vec![Value::ZERO; size + 1];
        buffer[0] = Value::from(1u64);
        fn flatten(
            value: &serde_json::Value,
            prime: Value,
            out: &mut Vec<Value>,
        ) -> Result<(), Error> {
            match value {
                serde_json::Value::String(text) => {
                    let (digits, negative) = match text.strip_prefix('-') {
                        Some(rest) => (rest, true),
                        None => (text.as_str(), false),
                    };
                    let mut v: Value = digits
                        .parse()
                        .map_err(|_| Error::Input(format!("not a number: {text}")))?;
                    if v >= prime {
                        v %= prime;
                    }
                    out.push(if negative && v != Value::ZERO {
                        prime - v
                    } else {
                        v
                    });
                }
                serde_json::Value::Number(number) => out.push(Value::from(
                    number
                        .as_u64()
                        .ok_or(Error::Input("not a non-negative integer".into()))?,
                )),
                serde_json::Value::Array(items) => {
                    for item in items {
                        flatten(item, prime, out)?;
                    }
                }
                _ => return Err(Error::Input("unsupported value".into())),
            }
            Ok(())
        }
        for (name, value) in object {
            let &(offset, length) = self
                .inputs
                .get(name)
                .ok_or_else(|| Error::Input(format!("the circuit has no input named {name}")))?;
            let mut values = Vec::with_capacity(length);
            flatten(value, prime, &mut values)?;
            if values.len() != length {
                return Err(Error::Input(format!(
                    "input {name} has {} values, the circuit takes {length}",
                    values.len()
                )));
            }
            buffer[offset..offset + length].copy_from_slice(&values);
        }
        Ok(buffer)
    }

    /// The full witness, little-endian 32-byte values in witness order.
    pub fn witness(&self, input_json: &str) -> Result<Vec<Value>, Error> {
        let prime: Value = PRIME.parse().map_err(|_| Error::Malformed("modulus"))?;
        let half = prime >> 1;
        let inputs = self.input_buffer(input_json)?;
        let one = Value::from(1u64);
        let truth = |b: bool| if b { one } else { Value::ZERO };
        // A shift amount as a signed machine integer, when it fits.
        let signed = |v: Value| -> Option<isize> {
            if v > half {
                isize::try_from(prime - v).ok().map(|n| -n)
            } else {
                isize::try_from(v).ok()
            }
        };
        let shift = |value: Value, by: Value, left: bool| -> Value {
            match signed(by) {
                Some(n) => {
                    let leftward = (n >= 0) == left;
                    let amount = n.unsigned_abs();
                    let r = if leftward {
                        value << amount
                    } else {
                        value >> amount
                    };
                    if r > prime {
                        r % prime
                    } else {
                        r
                    }
                }
                None => Value::ZERO,
            }
        };
        let ordered = |a: Value, b: Value, same: fn(&Value, &Value) -> bool, a_negative: bool| {
            let (an, bn) = (half < a, half < b);
            if an == bn {
                truth(same(&a, &b))
            } else {
                truth(an == a_negative)
            }
        };

        let mut values: Vec<Value> = Vec::with_capacity(self.nodes.len());
        let get = |values: &Vec<Value>, i: u32| -> Result<Value, Error> {
            values
                .get(i as usize)
                .copied()
                .ok_or(Error::Malformed("forward reference"))
        };
        for node in &self.nodes {
            let value = match *node {
                Node::Input(i) => *inputs
                    .get(i as usize)
                    .ok_or(Error::Malformed("input index out of range"))?,
                Node::Constant(i) => self.constants[i as usize],
                Node::Uno(op, a) => {
                    let a = get(&values, a)?;
                    match op {
                        0 => {
                            if a == Value::ZERO {
                                a
                            } else {
                                prime - a
                            }
                        }
                        1 => a,
                        2 => truth(a == Value::ZERO),
                        _ => {
                            // Bitwise not over the modulus's 254 bits.
                            let r = !a;
                            if r >= prime {
                                r % prime
                            } else {
                                r
                            }
                        }
                    }
                }
                Node::Duo(op, a, b) => {
                    let (a, b) = (get(&values, a)?, get(&values, b)?);
                    match op {
                        0 => a.mul_mod(b, prime),
                        1 => match b.inv_mod(prime) {
                            Some(inverse) if b != Value::ZERO => a.mul_mod(inverse, prime),
                            _ => Value::ZERO,
                        },
                        2 => a.add_mod(b, prime),
                        3 => a.add_mod(prime - b, prime),
                        4 => a.pow_mod(b, prime),
                        5 => {
                            if b == Value::ZERO {
                                Value::ZERO
                            } else {
                                a / b
                            }
                        }
                        6 => {
                            if b == Value::ZERO {
                                return Err(Error::Malformed("remainder by zero"));
                            } else {
                                a % b
                            }
                        }
                        7 => truth(a == b),
                        8 => truth(a != b),
                        9 => ordered(a, b, |x, y| x < y, true),
                        10 => ordered(a, b, |x, y| x > y, false),
                        11 => ordered(a, b, |x, y| x <= y, true),
                        12 => ordered(a, b, |x, y| x >= y, false),
                        13 => truth(a != Value::ZERO && b != Value::ZERO),
                        14 => truth(a != Value::ZERO || b != Value::ZERO),
                        15 => shift(a, b, true),
                        16 => shift(a, b, false),
                        17 => {
                            let r = a | b;
                            if r >= prime {
                                r % prime
                            } else {
                                r
                            }
                        }
                        18 => a & b,
                        _ => {
                            let r = a ^ b;
                            if r >= prime {
                                r % prime
                            } else {
                                r
                            }
                        }
                    }
                }
                Node::Tres(a, b, c) => {
                    if get(&values, a)? == Value::ZERO {
                        get(&values, c)?
                    } else {
                        get(&values, b)?
                    }
                }
            };
            values.push(value);
        }
        Ok(self.witness.iter().map(|&i| values[i as usize]).collect())
    }
}
