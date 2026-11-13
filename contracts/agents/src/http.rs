//! The optional HTTP adapter: the same handler behind a plain HTTP/1.1
//! listener, and a client for it. Plain HTTP authenticates no node, so here
//! the DPoP proof is the only thing that identifies a caller; put TLS in
//! front of it before using it across a network.
use crate::chain::Res;
use crate::message::{MAXIMUM_BODY, MAXIMUM_HEAD, Reply, Request, Transport, Via};
use crate::seller::Seller;
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    time::Duration,
};

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        410 => "Gone",
        413 => "Content Too Large",
        422 => "Unprocessable Content",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

fn read_request(stream: &mut TcpStream) -> Result<Request, Reply> {
    let bad = |why: &str| Reply::text(400, why);
    let mut reader = BufReader::new(stream).take((MAXIMUM_HEAD + MAXIMUM_BODY) as u64);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|_| bad("request line"))?;
    let mut first = line.split_whitespace();
    let (Some(method), Some(path)) = (first.next(), first.next()) else {
        return Err(bad("request line"));
    };
    let (method, path) = (method.to_owned(), path.to_owned());
    let mut headers = BTreeMap::new();
    let mut head_bytes = line.len();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|_| bad("header"))?;
        head_bytes += line.len();
        if head_bytes > MAXIMUM_HEAD {
            return Err(Reply::text(413, "request head too large"));
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let length: usize = headers
        .get("content-length")
        .map_or(Ok(0), |v| v.parse())
        .map_err(|_| bad("content-length"))?;
    if length > MAXIMUM_BODY {
        return Err(Reply::text(413, "request body too large"));
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).map_err(|_| bad("body"))?;
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn respond(stream: &mut TcpStream, reply: &Reply) -> Res<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        reply.status,
        reason(reply.status),
        reply.body.len()
    );
    for (name, value) in &reply.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&reply.body)?;
    Ok(())
}

/// Serve the seller over HTTP until the process ends. One request per
/// connection, one connection at a time.
pub fn serve(listener: TcpListener, seller: Arc<Mutex<Seller>>) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
        let reply = match read_request(&mut stream) {
            Err(reply) => reply,
            Ok(request) => match request.headers.get("host") {
                None => Reply::text(400, "Host header missing"),
                Some(host) => {
                    let via = Via {
                        base: format!("http://{host}"),
                        peer: None,
                        owner: None,
                    };
                    match seller.lock() {
                        Ok(mut seller) => seller.handle(&via, &request),
                        Err(_) => Reply::text(500, "seller state poisoned"),
                    }
                }
            },
        };
        let _ = respond(&mut stream, &reply);
    }
}

/// A buyer's HTTP client for one seller.
pub struct HttpTransport {
    base: String,
    agent: ureq::Agent,
}
impl HttpTransport {
    /// `base` is `http://host:port` with no trailing slash.
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_owned(),
            agent: ureq::Agent::config_builder()
                .http_status_as_error(false)
                .build()
                .into(),
        }
    }
}
impl Transport for HttpTransport {
    fn base(&self) -> String {
        self.base.clone()
    }
    fn node(&self) -> Option<String> {
        None
    }
    fn send(&self, request: &Request) -> Res<Reply> {
        let url = format!("{}{}", self.base, request.path);
        let mut response = match request.method.as_str() {
            "POST" => {
                let mut call = self.agent.post(&url);
                for (name, value) in &request.headers {
                    call = call.header(name, value);
                }
                call.send(&request.body[..])?
            }
            "GET" => {
                let mut call = self.agent.get(&url);
                for (name, value) in &request.headers {
                    call = call.header(name, value);
                }
                call.call()?
            }
            other => return Err(format!("method {other} not supported").into()),
        };
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                Some((
                    name.as_str().to_ascii_lowercase(),
                    value.to_str().ok()?.to_owned(),
                ))
            })
            .collect();
        Ok(Reply {
            status: response.status().as_u16(),
            headers,
            body: response
                .body_mut()
                .with_config()
                .limit(MAXIMUM_BODY as u64)
                .read_to_vec()?,
        })
    }
}
