//! The loopback HTTP endpoint Caddy forwards to. HTTP/1.1, one request per
//! connection, `Connection: close`.
//!
//! - `POST /analytics/beacon`: the body (at most `paths::MAX_BODY` bytes) is
//!   the beacon. 204 counted, 400 malformed (counted as malformed), 429
//!   refused by the rate limit (counted as limited).
//! - `GET /analytics/published`: the last published lines (weeks, and days
//!   published before 2026-11-18), JSON.
//! - anything else: 404, not counted.
//!
//! The only header read is `Content-Length`. Nothing about a request is
//! written to the log or the disk; the connection's peer address and port and
//! the request's sizes go into `core::Request`, where `core::project` drops
//! them (`core_handle_noninterference` in `lean/QedAnalytics/Refines.lean`).
//! Caddy strips the client's address and headers before forwarding
//! (contracts/host), so the peer is Caddy on loopback.
use crate::paths::{self, MAX_BODY};
use crate::store::{Collector, Connection, Outcome};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The longest request head read.
pub const MAX_HEAD: usize = 4096;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct Head {
    method: String,
    target: String,
    content_length: Option<usize>,
    chunked: bool,
    len: usize,
}

fn parse_head(bytes: &[u8]) -> Option<Head> {
    let end = bytes.windows(4).position(|w| w == b"\r\n\r\n")?;
    let text = std::str::from_utf8(&bytes[..end]).ok()?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target, version) = (first.next()?, first.next()?, first.next()?);
    if !version.starts_with("HTTP/1.") || first.next().is_some() {
        return None;
    }
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(value.trim().parse().ok()?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = true;
        }
    }
    Some(Head {
        method: method.to_string(),
        target: target.to_string(),
        content_length,
        chunked,
        len: end + 4,
    })
}

fn respond(stream: &mut TcpStream, status: &str, body: Option<&str>) {
    let (kind, text) = match body {
        Some(text) => ("application/json", text),
        None => ("text/plain; charset=utf-8", ""),
    };
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    let _ = stream.write_all(reply.as_bytes());
}

fn peer(stream: &TcpStream) -> ([u8; 16], u16) {
    match stream.peer_addr() {
        Ok(addr) => {
            let ip = match addr.ip() {
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                IpAddr::V6(v6) => v6,
            };
            (ip.octets(), addr.port())
        }
        Err(_) => ([0; 16], 0),
    }
}

/// Handle one connection.
pub fn handle<R: Read>(mut stream: TcpStream, collector: &Mutex<Collector<R>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    let head = loop {
        if let Some(head) = parse_head(&buf) {
            break head;
        }
        if buf.len() > MAX_HEAD {
            return respond(&mut stream, "431 Request Header Fields Too Large", None);
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    match (head.method.as_str(), head.target.as_str()) {
        ("GET", "/analytics/published") => {
            let view = match collector.lock() {
                Ok(c) => c.published_view().to_string(),
                Err(_) => return respond(&mut stream, "500 Internal Server Error", None),
            };
            respond(&mut stream, "200 OK", Some(&view));
        }
        ("POST", "/analytics/beacon") => {
            let length = match (head.content_length, head.chunked) {
                (Some(n), false) => n,
                _ => return respond(&mut stream, "411 Length Required", None),
            };
            // An oversized body is not read: it is malformed by length.
            let body = if length > MAX_BODY {
                None
            } else {
                let mut body = buf[head.len.min(buf.len())..].to_vec();
                while body.len() < length {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => body.extend_from_slice(&chunk[..n]),
                    }
                }
                body.truncate(length);
                Some(body)
            };
            let (path, first) = match &body {
                Some(body) => paths::parse(body),
                None => (crate::core::PATHS, false),
            };
            let (peer, peer_port) = peer(&stream);
            let connection = Connection {
                peer,
                peer_port,
                head_bytes: head.len as u32,
                body_bytes: length.min(u32::MAX as usize) as u32,
            };
            let outcome = match collector.lock() {
                Ok(mut c) => c.beacon(path, first, connection, now_ms()),
                Err(_) => return respond(&mut stream, "500 Internal Server Error", None),
            };
            match outcome {
                Ok(Outcome::Counted) => respond(&mut stream, "204 No Content", None),
                Ok(Outcome::Malformed) => respond(&mut stream, "400 Bad Request", None),
                Ok(Outcome::Limited) => respond(&mut stream, "429 Too Many Requests", None),
                Err(e) => {
                    eprintln!("qed-analytics: state directory: {e}");
                    respond(&mut stream, "503 Service Unavailable", None)
                }
            }
        }
        _ => respond(&mut stream, "404 Not Found", None),
    }
}

/// Serve until the process is stopped; a second thread rolls the window over
/// at Monday 00:00 UTC even when no beacon arrives.
pub fn serve<R: Read + Send + 'static>(
    listener: TcpListener,
    collector: Arc<Mutex<Collector<R>>>,
) -> std::io::Result<()> {
    let ticker = Arc::clone(&collector);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(20));
            if let Ok(mut c) = ticker.lock()
                && let Err(e) = c.tick(now_ms())
            {
                eprintln!("qed-analytics: state directory: {e}");
            }
        }
    });
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => handle(stream, &collector),
            Err(e) => eprintln!("qed-analytics: accept: {e}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::Coins;

    fn exchange(addr: std::net::SocketAddr, request: &[u8]) -> String {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(request).unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn beacons_are_counted_refused_or_not_found_over_loopback() {
        let dir = std::env::temp_dir().join(format!("qed-analytics-srv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let collector = Arc::new(Mutex::new(
            Collector::open(&dir, Coins::new(std::io::repeat(0)), now_ms()).unwrap(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = Arc::clone(&collector);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                handle(stream, &server);
            }
        });
        let ok = exchange(
            addr,
            b"POST /analytics/beacon HTTP/1.1\r\nHost: x\r\nContent-Length: 9\r\n\r\n/status\n1",
        );
        assert!(ok.starts_with("HTTP/1.1 204"), "{ok}");
        let bad = exchange(
            addr,
            b"POST /analytics/beacon HTTP/1.1\r\nContent-Length: 6\r\n\r\n/x\nyes",
        );
        assert!(bad.starts_with("HTTP/1.1 400"), "{bad}");
        let big = exchange(
            addr,
            b"POST /analytics/beacon HTTP/1.1\r\nContent-Length: 100000\r\n\r\n",
        );
        assert!(big.starts_with("HTTP/1.1 400"), "{big}");
        let other = exchange(addr, b"GET /analytics/beacon HTTP/1.1\r\n\r\n");
        assert!(other.starts_with("HTTP/1.1 404"), "{other}");
        let view = exchange(addr, b"GET /analytics/published HTTP/1.1\r\n\r\n");
        assert!(view.starts_with("HTTP/1.1 200"), "{view}");
        assert!(view.contains("\"lines\":[]"), "{view}");
        let state = *collector.lock().unwrap().state();
        assert_eq!(state.cells[29], 1);
        assert_eq!(state.cells[crate::core::MALFORMED], 2);
        assert_eq!(state.cells.iter().sum::<u32>(), 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
