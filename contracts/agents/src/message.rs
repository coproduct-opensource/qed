//! What a buyer asks and a seller answers, independent of how the bytes
//! travel. The same `Request` and `Reply` go over iroh and over HTTP, so one
//! handler serves both.
//!
//! Frame, used on an iroh stream (one request and one reply per stream):
//!
//!   u32 big-endian length of the head, at most `MAXIMUM_HEAD`
//!   head: JSON, `{"method","path","headers"}` or `{"status","headers"}`
//!   u32 big-endian length of the body, at most `MAXIMUM_BODY`
//!   body: raw bytes
use crate::chain::Res;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const MAXIMUM_HEAD: usize = 64 * 1024;
/// Room for an 8 MiB statement in base64 inside a JSON body.
pub const MAXIMUM_BODY: usize = 12 * 1024 * 1024;
/// Largest statement a seller takes inline.
pub const MAXIMUM_STATEMENT: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    /// Header names are lower case.
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
impl Reply {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: vec![],
            body: vec![],
        }
    }
    pub fn text(status: u16, text: &str) -> Self {
        Self {
            status,
            headers: vec![],
            body: text.as_bytes().to_vec(),
        }
    }
    pub fn with(mut self, name: &str, value: String) -> Self {
        self.headers.push((name.to_owned(), value));
        self
    }
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// How a request arrived. The adapter fills this in; the request cannot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Via {
    /// What the caller's proof of possession must name before the path:
    /// `iroh://<this node's id>` or `http://<host>`.
    pub base: String,
    /// The caller's node ID as the transport authenticated it. `None` over
    /// plain HTTP, which authenticates no one.
    pub peer: Option<String>,
    /// The possession key's thumbprint, when the adapter has already verified
    /// a fresh proof for this request under its own binding's naming
    /// (`dpop::possession`). `None` for the adapters whose proof names the
    /// request's own method and path: the handler then verifies it itself.
    /// An adapter is trusted code: one that sets this without checking a
    /// proof has removed the check.
    pub owner: Option<[u8; 32]>,
}

fn frame(head: &Value, body: &[u8]) -> Res<Vec<u8>> {
    let head = serde_json::to_vec(head)?;
    if head.len() > MAXIMUM_HEAD || body.len() > MAXIMUM_BODY {
        return Err("message too large".into());
    }
    let mut out = Vec::with_capacity(8 + head.len() + body.len());
    out.extend_from_slice(&u32::try_from(head.len())?.to_be_bytes());
    out.extend_from_slice(&head);
    out.extend_from_slice(&u32::try_from(body.len())?.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}
fn headers_of(head: &Value) -> Res<Vec<(String, String)>> {
    head["headers"]
        .as_object()
        .ok_or("headers missing")?
        .iter()
        .map(|(name, value)| {
            Ok((
                name.to_ascii_lowercase(),
                value.as_str().ok_or("header value")?.to_owned(),
            ))
        })
        .collect()
}

impl Request {
    pub fn encode(&self) -> Res<Vec<u8>> {
        frame(
            &json!({"method": self.method, "path": self.path, "headers": self.headers}),
            &self.body,
        )
    }
    pub fn from_parts(head: &[u8], body: Vec<u8>) -> Res<Self> {
        let head: Value = serde_json::from_slice(head)?;
        Ok(Self {
            method: head["method"].as_str().ok_or("method missing")?.to_owned(),
            path: head["path"].as_str().ok_or("path missing")?.to_owned(),
            headers: headers_of(&head)?.into_iter().collect(),
            body,
        })
    }
}
impl Reply {
    pub fn encode(&self) -> Res<Vec<u8>> {
        let headers: BTreeMap<&str, &str> = self
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        frame(
            &json!({"status": self.status, "headers": headers}),
            &self.body,
        )
    }
    pub fn from_parts(head: &[u8], body: Vec<u8>) -> Res<Self> {
        let head: Value = serde_json::from_slice(head)?;
        Ok(Self {
            status: u16::try_from(head["status"].as_u64().ok_or("status missing")?)?,
            headers: headers_of(&head)?,
            body,
        })
    }
}

/// Whoever answers requests: the seller's harness, or a buyer's desk. One
/// handler serves every adapter.
pub trait Handler: Send {
    /// Answer one request. Must not panic on what a caller sends.
    fn handle(&mut self, via: &Via, request: &Request) -> Reply;
}

/// How a caller reaches a handler.
pub trait Transport {
    /// The prefix the seller expects in the proof's `htu`.
    fn base(&self) -> String;
    /// This caller's node ID, when the transport has one.
    fn node(&self) -> Option<String>;
    fn send(&self, request: &Request) -> Res<Reply>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(bytes: &[u8]) -> (&[u8], Vec<u8>) {
        let head = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        let body_at = 4 + head + 4;
        (&bytes[4..4 + head], bytes[body_at..].to_vec())
    }

    #[test]
    fn a_request_and_a_reply_survive_the_frame() {
        let request = Request {
            method: "POST".into(),
            path: "/work".into(),
            headers: [("dpop".to_owned(), "a.b.c".to_owned())].into(),
            body: vec![0, 255, 10],
        };
        let bytes = request.encode().unwrap();
        let (head, body) = split(&bytes);
        assert_eq!(Request::from_parts(head, body).unwrap(), request);

        let reply = Reply::text(402, "{}").with("PAYMENT-REQUIRED", "abc".into());
        let bytes = reply.encode().unwrap();
        let (head, body) = split(&bytes);
        let back = Reply::from_parts(head, body).unwrap();
        assert_eq!(back.status, 402);
        assert_eq!(back.header("payment-required"), Some("abc"));
        assert_eq!(back.body, b"{}");
    }

    #[test]
    fn an_oversize_body_is_not_framed() {
        let request = Request {
            method: "POST".into(),
            path: "/work".into(),
            headers: BTreeMap::new(),
            body: vec![0; MAXIMUM_BODY + 1],
        };
        assert!(request.encode().is_err());
    }
}
