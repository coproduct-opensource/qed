//! A local preview of a built site, for looking at it in a browser and for
//! the tests. One request at a time, GET only, files under one directory.
//! Not a way to host the site.
//!
//! It answers routes and sends the headers the serving table
//! (`serving.rs`) says the host must send, except HSTS (plain HTTP), so
//! `check-live` and the agent-readability tests can run against it.
use crate::{Res, hex, serving};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    path::{Component, Path, PathBuf},
};

/// A file under `root`, if `relative` stays inside it.
fn inside(root: &Path, relative: &str) -> Option<PathBuf> {
    let rel = Path::new(relative);
    if rel
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return None;
    }
    Some(root.join(rel))
}

/// The file a request names, and its path relative to `root`.
pub fn resolve(root: &Path, request: &str, markdown: bool) -> Option<(String, PathBuf)> {
    serving::candidates(request, markdown)
        .into_iter()
        .find_map(|candidate| {
            let file = inside(root, &candidate)?;
            file.is_file().then_some((candidate, file))
        })
}

pub fn serve(root: &Path, address: &str) -> Res<()> {
    if !address.starts_with("127.0.0.1:") {
        return Err("the preview binds 127.0.0.1 only".into());
    }
    let listener = TcpListener::bind(address)?;
    println!("preview of {} at http://{address}/", root.display());
    serve_on(root, listener)
}

/// Serve `root` on a listener already bound to a loopback address.
pub fn serve_on(root: &Path, listener: TcpListener) -> Res<()> {
    if !listener.local_addr()?.ip().is_loopback() {
        return Err("the preview serves loopback only".into());
    }
    // One thread per connection, each with a read timeout: a browser opens
    // connections it may never send a request on, and one such connection
    // must not stop the others.
    for stream in listener.incoming() {
        let stream = stream?;
        let root = root.to_path_buf();
        std::thread::spawn(move || {
            let _ = answer(&root, stream);
        });
    }
    Ok(())
}

fn answer(root: &Path, mut stream: std::net::TcpStream) -> Res<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut accept = String::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 || header.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.trim().eq_ignore_ascii_case("accept")
        {
            accept = value.trim().to_owned();
        }
    }
    let mut parts = line.split_whitespace();
    let found = match (parts.next(), parts.next()) {
        (Some("GET"), Some(path)) => resolve(root, path, serving::wants_markdown(&accept))
            .and_then(|(rel, file)| fs::read(&file).ok().map(|body| (rel, body))),
        _ => None,
    };
    let reply = match found {
        Some((rel, body)) => {
            let mut head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: {}\r\ncontent-length: {}\r\netag: \"{}\"\r\n",
                serving::media_type(&rel),
                body.len(),
                hex(&Sha256::digest(&body)[..16]),
            );
            for (name, value) in serving::headers(&rel, false) {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("connection: close\r\n\r\n");
            [head.into_bytes(), body].concat()
        }
        None => b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nvary: Accept\r\nconnection: close\r\n\r\n".to_vec(),
    };
    // A browser that hangs up early is not an error worth stopping for.
    let _ = stream.write_all(&reply);
    Ok(())
}
