//! A JSON-RPC endpoint for tests that answers from a script, so every class
//! of failure R-1 names is driven in-process, without the internet.
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

/// Short enough for a test, in the same proportions as the default.
pub(crate) const QUICK: super::Patience = super::Patience {
    first_backoff: Duration::from_millis(20),
    most_backoff: Duration::from_millis(200),
    most_retry_after: Duration::from_secs(3),
    give_up_after: Duration::from_millis(1_500),
    log_spacing: Duration::from_millis(50),
    receipt_poll: Duration::from_millis(10),
    receipt_wait: Duration::from_millis(600),
    request_timeout: Duration::from_secs(2),
};

pub(crate) struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}
impl Reply {
    pub fn result(value: Value) -> Self {
        Self {
            status: 200,
            headers: vec![],
            body: json!({"jsonrpc": "2.0", "id": 1, "result": value}).to_string(),
        }
    }
    pub fn error(status: u16, code: i64, message: &str) -> Self {
        Self {
            status,
            headers: vec![],
            body: json!({"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": message}})
                .to_string(),
        }
    }
    pub fn raw(status: u16, body: &str) -> Self {
        Self {
            status,
            headers: vec![],
            body: body.to_owned(),
        }
    }
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

/// Answers one request: its method, its params, and how many requests this
/// endpoint saw before it.
pub(crate) type Script = Box<dyn FnMut(&str, &Value, usize) -> Reply + Send>;

pub(crate) struct Endpoint {
    pub url: String,
    /// Every request's arrival and method, in order.
    pub seen: Arc<Mutex<Vec<(Instant, String)>>>,
}
impl Endpoint {
    pub fn methods(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|(_, method)| method.clone())
            .collect()
    }
    pub fn count(&self, method: &str) -> usize {
        self.methods().iter().filter(|m| *m == method).count()
    }
    pub fn times(&self, method: &str) -> Vec<Instant> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, m)| m == method)
            .map(|(at, _)| *at)
            .collect()
    }
}

/// Serve `script` on a fresh local port, one request per connection.
pub(crate) fn serve(mut script: Script) -> Endpoint {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(vec![]));
    let log = seen.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Ok(clone) = stream.try_clone() else {
                continue;
            };
            let mut reader = BufReader::new(clone);
            let mut length = 0;
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let line = line.trim_end();
                if line.is_empty() {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0; length];
            if reader.read_exact(&mut body).is_err() {
                continue;
            }
            let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let method = request["method"].as_str().unwrap_or_default().to_owned();
            let before = {
                let mut log = log.lock().unwrap();
                log.push((Instant::now(), method.clone()));
                log.len() - 1
            };
            let reply = script(&method, &request["params"], before);
            let mut head = format!(
                "HTTP/1.1 {} Scripted\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
                reply.status,
                reply.body.len()
            );
            for (name, value) in &reply.headers {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(reply.body.as_bytes());
        }
    });
    Endpoint { url, seen }
}
