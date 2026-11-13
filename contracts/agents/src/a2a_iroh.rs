//! A2A 1.0 JSON-RPC over iroh: the transport binding of
//! docs/specs/a2a-iroh-transport-binding.md, version 0.1.
//!
//! One operation per bidirectional stream. The caller writes two frames, a
//! header object (service parameters and the possession proof) and the
//! JSON-RPC request, then finishes its side. The agent answers with one frame
//! (a JSON-RPC response) or, for the two streaming operations, one frame per
//! event, and finishes. A frame is a 4-byte big-endian length and that many
//! bytes of UTF-8 JSON.
//!
//! The agent behind this adapter is the same `Handler` the other adapters
//! serve. This file verifies the proof this binding defines (with the one
//! verifier in `dpop.rs`), translates with `a2a.rs`, and keeps the list of
//! task IDs each key opened here, which `ListTasks` needs and the handler
//! does not offer. It decides nothing else.
use crate::a2a::{self, Fault, Kind};
use crate::chain::Res;
use crate::iroh_net::Shared;
use crate::message::{Reply, Request, Transport, Via};
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::{Connection, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

/// The ALPN protocol identifier: a draft name under no one else's prefix. It
/// names the wire format, unchanged since binding version 0.1.
pub const ALPN: &[u8] = nucleus_a2a_iroh_card::ALPN.as_bytes();
/// Largest header frame.
pub const MAXIMUM_HEADER: usize = 16 * 1024;
/// Largest request or response frame.
pub const MAXIMUM_FRAME: usize = 24 * 1024 * 1024;
/// Header key of the possession proof. Reserved by the binding.
pub const PROOF: &str = "a2a-iroh-proof";
/// Header key of a well-known document request. Reserved by the binding.
pub const WELL_KNOWN: &str = "a2a-iroh-well-known";
/// The well-known document that is the Agent Card.
pub const CARD: &str = "agent-card.json";
/// How long a caller may take to send its frames, and one reply to be read.
const EXCHANGE: Duration = Duration::from_secs(60);
/// How often a stream looks at its task.
const WATCH: Duration = Duration::from_millis(500);
/// Stream error code: a frame was larger than the limit.
const TOO_LARGE: u32 = 1;

/// What a proof under this binding names as its target for `node`.
pub fn target(node: &str) -> String {
    format!("iroh://{node}/{}", String::from_utf8_lossy(ALPN))
}

enum Read {
    Frame(Vec<u8>),
    /// The stream ended cleanly before a length.
    End,
    TooLarge,
    Broken,
}
async fn read_frame(recv: &mut RecvStream, limit: usize) -> Read {
    let mut length = [0u8; 4];
    let mut filled = 0;
    while filled < 4 {
        match recv.read(&mut length[filled..]).await {
            Ok(Some(n)) => filled += n,
            Ok(None) if filled == 0 => return Read::End,
            _ => return Read::Broken,
        }
    }
    let length = u32::from_be_bytes(length) as usize;
    if length > limit {
        return Read::TooLarge;
    }
    let mut bytes = vec![0; length];
    match recv.read_exact(&mut bytes).await {
        Ok(()) => Read::Frame(bytes),
        Err(_) => Read::Broken,
    }
}
async fn write_frame(send: &mut SendStream, bytes: &[u8]) -> bool {
    let Ok(length) = u32::try_from(bytes.len()) else {
        return false;
    };
    send.write_all(&length.to_be_bytes()).await.is_ok() && send.write_all(bytes).await.is_ok()
}
fn response(id: &Value, outcome: Result<Value, Fault>) -> Vec<u8> {
    let body = match outcome {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(fault) => json!({"jsonrpc": "2.0", "id": id, "error": fault.json()}),
    };
    serde_json::to_vec(&body).unwrap_or_default()
}

/// The task IDs each possession key opened through this adapter.
type Opened = Arc<Mutex<BTreeMap<[u8; 32], Vec<String>>>>;

/// A handler as an A2A agent on iroh.
#[derive(Clone)]
pub struct A2a {
    handler: Shared,
    /// This endpoint's node ID.
    node: String,
    card: Arc<Vec<u8>>,
    seen: Arc<Mutex<HashSet<String>>>,
    opened: Opened,
    clock: fn() -> u64,
}
impl std::fmt::Debug for A2a {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "A2a({})", self.node)
    }
}
fn wall() -> u64 {
    crate::world::wall_clock().unwrap_or_default()
}

impl A2a {
    pub fn new(handler: Shared, node: String, card: &Value) -> Self {
        Self {
            handler,
            node,
            card: Arc::new(serde_json::to_vec(card).unwrap_or_default()),
            seen: Arc::default(),
            opened: Arc::default(),
            clock: wall,
        }
    }

    /// One call to the handler, as the key that proved possession.
    async fn ask(&self, peer: &str, owner: [u8; 32], request: Request) -> Reply {
        let via = Via {
            base: format!("iroh://{}", self.node),
            peer: Some(peer.to_owned()),
            owner: Some(owner),
        };
        let handler = self.handler.clone();
        tokio::task::spawn_blocking(move || match handler.lock() {
            Ok(mut handler) => handler.handle(&via, &request),
            Err(_) => Reply::text(500, "handler state poisoned"),
        })
        .await
        .unwrap_or_else(|_| Reply::text(500, "handler failed"))
    }
    async fn task(&self, peer: &str, owner: [u8; 32], id: &str) -> Result<Value, Fault> {
        let call = a2a::call("GetTask", &json!({"id": id}))?;
        let reply = self.ask(peer, owner, call.request).await;
        a2a::task_of(Kind::Read, Some(id), &reply)
    }
    async fn send(&self, peer: &str, owner: [u8; 32], params: &Value) -> Result<Value, Fault> {
        let call = a2a::call("SendMessage", params)?;
        let named = params["message"]["taskId"].as_str().map(str::to_owned);
        let reply = self.ask(peer, owner, call.request).await;
        let task = a2a::task_of(call.kind, named.as_deref(), &reply)?;
        if call.kind == Kind::Open
            && let (Some(id), Ok(mut opened)) = (task["id"].as_str(), self.opened.lock())
        {
            let mine = opened.entry(owner).or_default();
            if !mine.iter().any(|known| known == id) {
                mine.push(id.to_owned());
            }
        }
        Ok(task)
    }

    /// The unary operations.
    async fn unary(
        &self,
        peer: &str,
        owner: [u8; 32],
        method: &str,
        params: &Value,
    ) -> Result<Value, Fault> {
        match method {
            "SendMessage" => Ok(json!({"task": self.send(peer, owner, params).await?})),
            "GetTask" => {
                let id = params["id"].as_str().unwrap_or_default();
                self.task(peer, owner, id).await
            }
            "ListTasks" => {
                let mine = self
                    .opened
                    .lock()
                    .map(|opened| opened.get(&owner).cloned().unwrap_or_default())
                    .unwrap_or_default();
                let mut tasks = vec![];
                for id in mine {
                    if let Ok(task) = self.task(peer, owner, &id).await
                        && (params["status"].is_null()
                            || params["status"] == task["status"]["state"])
                        && (params["contextId"].is_null()
                            || params["contextId"] == task["contextId"])
                    {
                        tasks.push(task);
                    }
                }
                let count = tasks.len();
                Ok(
                    json!({"tasks": tasks, "nextPageToken": "", "pageSize": count, "totalSize": count}),
                )
            }
            // The agent has no way to abandon work it has started.
            "CancelTask" => {
                let id = params["id"].as_str().unwrap_or_default();
                self.task(peer, owner, id).await?;
                Err(Fault::new(
                    a2a::TASK_NOT_CANCELABLE,
                    "TASK_NOT_CANCELABLE",
                    "Task cannot be canceled",
                ))
            }
            "CreateTaskPushNotificationConfig"
            | "GetTaskPushNotificationConfig"
            | "ListTaskPushNotificationConfigs"
            | "DeleteTaskPushNotificationConfig" => Err(Fault::new(
                a2a::PUSH_NOT_SUPPORTED,
                "PUSH_NOTIFICATION_NOT_SUPPORTED",
                "Push Notification is not supported",
            )),
            "GetExtendedAgentCard" => Err(Fault::new(
                a2a::EXTENDED_CARD_NOT_CONFIGURED,
                "EXTENDED_AGENT_CARD_NOT_CONFIGURED",
                "Extended Agent Card is not configured",
            )),
            _ => Err(Fault::new(
                a2a::METHOD_NOT_FOUND,
                "METHOD_NOT_FOUND",
                "Method not found",
            )),
        }
    }

    /// The two streaming operations: the task as it is, then each change, in
    /// order, until it is terminal or waits on the caller, or the caller
    /// stops reading.
    async fn stream(
        &self,
        send: &mut SendStream,
        peer: &str,
        owner: [u8; 32],
        id: &Value,
        first: Value,
    ) {
        let task_id = first["id"].as_str().unwrap_or_default().to_owned();
        let mut last = first["status"].clone();
        if !write_frame(send, &response(id, Ok(json!({"task": first})))).await {
            return;
        }
        loop {
            let state = last["state"].as_str().unwrap_or_default();
            if a2a::terminal(state) || a2a::interrupted(state) {
                return;
            }
            tokio::time::sleep(WATCH).await;
            let now = match self.task(peer, owner, &task_id).await {
                Ok(task) => task,
                Err(fault) => {
                    write_frame(send, &response(id, Err(fault))).await;
                    return;
                }
            };
            if now["status"] == last {
                continue;
            }
            last = now["status"].clone();
            if let Some(artifact) = now["artifacts"].get(0) {
                let event = json!({"artifactUpdate": {
                    "taskId": task_id, "contextId": task_id, "artifact": artifact, "lastChunk": true,
                }});
                if !write_frame(send, &response(id, Ok(event))).await {
                    return;
                }
            }
            let event = json!({"statusUpdate": {
                "taskId": task_id, "contextId": task_id, "status": last,
            }});
            // A caller that stopped reading has cancelled the stream, not the task.
            if !write_frame(send, &response(id, Ok(event))).await {
                return;
            }
        }
    }

    async fn serve(&self, peer: String, mut send: SendStream, mut recv: RecvStream) {
        let header =
            match tokio::time::timeout(EXCHANGE, read_frame(&mut recv, MAXIMUM_HEADER)).await {
                Ok(Read::Frame(bytes)) => bytes,
                Ok(Read::TooLarge) => {
                    let _ = send.reset(TOO_LARGE.into());
                    return;
                }
                _ => return,
            };
        let null = Value::Null;
        let refuse = |code, reason, why: &str| response(&null, Err(Fault::new(code, reason, why)));
        let Ok(header) = serde_json::from_slice::<Value>(&header) else {
            write_frame(
                &mut send,
                &refuse(a2a::PARSE_ERROR, "PARSE_ERROR", "Invalid JSON payload"),
            )
            .await;
            let _ = send.finish();
            return;
        };
        // A well-known document: the Agent Card. Public; no proof.
        if let Some(document) = header.get(WELL_KNOWN) {
            if document == CARD {
                write_frame(&mut send, &self.card).await;
            }
            let _ = send.finish();
            return;
        }
        let frame = match tokio::time::timeout(EXCHANGE, read_frame(&mut recv, MAXIMUM_FRAME)).await
        {
            Ok(Read::Frame(bytes)) => bytes,
            Ok(Read::TooLarge) => {
                let _ = send.reset(TOO_LARGE.into());
                return;
            }
            _ => return,
        };
        let outcome = self.answer(&peer, &header, &frame, &mut send).await;
        if let Some(bytes) = outcome {
            write_frame(&mut send, &bytes).await;
        }
        let _ = send.finish();
    }

    /// Checks in the order the specification gives them (§9): well-formed
    /// request, version, proof, then the operation. `None` when a stream was
    /// written.
    async fn answer(
        &self,
        peer: &str,
        header: &Value,
        frame: &[u8],
        send: &mut SendStream,
    ) -> Option<Vec<u8>> {
        let null = Value::Null;
        let Ok(request) = serde_json::from_slice::<Value>(frame) else {
            return Some(response(
                &null,
                Err(Fault::new(
                    a2a::PARSE_ERROR,
                    "PARSE_ERROR",
                    "Invalid JSON payload",
                )),
            ));
        };
        let id = &request["id"];
        let (Some("2.0"), Some(method), true) = (
            request["jsonrpc"].as_str(),
            request["method"].as_str(),
            id.is_string() || id.is_number(),
        ) else {
            return Some(response(
                &null,
                Err(Fault::new(
                    a2a::INVALID_REQUEST,
                    "INVALID_REQUEST",
                    "Request payload validation error",
                )),
            ));
        };
        if header["a2a-version"] != a2a::VERSION {
            return Some(response(
                id,
                Err(Fault::new(
                    a2a::VERSION_NOT_SUPPORTED,
                    "VERSION_NOT_SUPPORTED",
                    "A2A version not supported",
                )),
            ));
        }
        let Some(proof) = header[PROOF].as_str() else {
            return Some(response(
                id,
                Err(Fault::new(
                    a2a::SERVER_ERROR,
                    "POSSESSION_PROOF_REQUIRED",
                    "possession proof missing",
                )),
            ));
        };
        let proved = match self.seen.lock() {
            Ok(mut seen) => crate::dpop::possession(
                peer,
                proof,
                method,
                &target(&self.node),
                frame,
                (self.clock)(),
                &mut seen,
            ),
            Err(_) => Err("replay store poisoned".to_owned()),
        };
        let owner = match proved {
            Ok(owner) => owner,
            Err(why) => {
                return Some(response(
                    id,
                    Err(Fault::new(
                        a2a::SERVER_ERROR,
                        "POSSESSION_PROOF_INVALID",
                        why,
                    )),
                ));
            }
        };
        let params = &request["params"];
        match method {
            "SendStreamingMessage" => match self.send(peer, owner, params).await {
                Ok(task) => {
                    self.stream(send, peer, owner, id, task).await;
                    None
                }
                Err(fault) => Some(response(id, Err(fault))),
            },
            "SubscribeToTask" => {
                let task = params["id"].as_str().unwrap_or_default();
                match self.task(peer, owner, task).await {
                    Ok(task)
                        if a2a::terminal(task["status"]["state"].as_str().unwrap_or_default()) =>
                    {
                        Some(response(
                            id,
                            Err(Fault::new(
                                a2a::UNSUPPORTED_OPERATION,
                                "UNSUPPORTED_OPERATION",
                                "This operation is not supported",
                            )),
                        ))
                    }
                    Ok(task) => {
                        self.stream(send, peer, owner, id, task).await;
                        None
                    }
                    Err(fault) => Some(response(id, Err(fault))),
                }
            }
            _ => Some(response(id, self.unary(peer, owner, method, params).await)),
        }
    }
}

impl ProtocolHandler for A2a {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // The node iroh authenticated at the other end of this connection.
        let peer = connection.remote_id().to_string();
        while let Ok((send, recv)) = connection.accept_bi().await {
            let (agent, peer) = (self.clone(), peer.clone());
            tokio::spawn(async move { agent.serve(peer, send, recv).await });
        }
        Ok(())
    }
}

// ---- Client.

/// The header frame of a request: service parameters and the proof.
pub fn header(proof: &str) -> Value {
    json!({"a2a-version": a2a::VERSION, "a2a-extensions": format!("{},{}", a2a::POSSESSION_EXTENSION, a2a::X402_EXTENSION), PROOF: proof})
}

/// Write `frames` on a new stream of a new connection and collect every
/// frame of the answer, up to `limit` of them. For tests and the client.
pub async fn exchange(
    endpoint: &Endpoint,
    agent: &EndpointAddr,
    frames: &[Vec<u8>],
    limit: usize,
) -> Res<Vec<Vec<u8>>> {
    let work = async {
        let connection = endpoint.connect(agent.clone(), ALPN).await?;
        let (mut send, mut recv) = connection.open_bi().await?;
        for frame in frames {
            if !write_frame(&mut send, frame).await {
                return Err("stream refused".into());
            }
        }
        send.finish()?;
        let mut answers = vec![];
        while answers.len() < limit {
            match read_frame(&mut recv, MAXIMUM_FRAME).await {
                Read::Frame(bytes) => answers.push(bytes),
                Read::End => break,
                Read::TooLarge => return Err("answer too large".into()),
                Read::Broken => return Err("stream reset".into()),
            }
        }
        // Stop reading: cancels a stream that has more to say.
        let _ = recv.stop(0u32.into());
        connection.close(0u32.into(), b"done");
        Ok(answers)
    };
    tokio::time::timeout(Duration::from_secs(300), work)
        .await
        .map_err(|_| "exchange timed out")?
}

/// One JSON-RPC request with a fresh proof; every answer frame, parsed.
pub async fn rpc(
    endpoint: &Endpoint,
    agent: &EndpointAddr,
    key: &p256::ecdsa::SigningKey,
    method: &str,
    params: &Value,
    limit: usize,
) -> Res<Vec<Value>> {
    let request = serde_json::to_vec(
        &json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
    )?;
    let proof = crate::dpop::proof_make(
        key,
        crate::dpop::BINDING_TYP,
        method,
        &target(&agent.id.to_string()),
        crate::world::wall_clock()?,
        Some(&endpoint.id().to_string()),
        Some(&request),
    )?;
    let frames = [serde_json::to_vec(&header(&proof))?, request];
    exchange(endpoint, agent, &frames, limit)
        .await?
        .iter()
        .map(|frame| Ok(serde_json::from_slice(frame)?))
        .collect()
}

/// The Agent Card of the agent at `agent`, fetched over iroh.
pub async fn fetch_card(endpoint: &Endpoint, agent: &EndpointAddr) -> Res<Value> {
    let frames = [serde_json::to_vec(&json!({WELL_KNOWN: CARD}))?];
    let answers = exchange(endpoint, agent, &frames, 1).await?;
    let card: Value = serde_json::from_slice(answers.first().ok_or("no card")?)?;
    named_in(&card, &agent.id.to_string())?;
    Ok(card)
}

/// A buyer's client for one seller over this binding. Blocking, and a
/// `Transport`: the buyer's flow is the same code over every adapter.
pub struct A2aTransport {
    runtime: tokio::runtime::Runtime,
    endpoint: Endpoint,
    seller: EndpointAddr,
    key: p256::ecdsa::SigningKey,
}
impl A2aTransport {
    /// `seller` is `iroh:<node id>[@<ip:port>]`, as for the other iroh adapter.
    pub fn new_in(
        node_key: [u8; 32],
        key: p256::ecdsa::SigningKey,
        seller: &str,
        relay: &crate::iroh_net::Relay,
    ) -> Res<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let seller = crate::iroh_net::parse_address_in(seller, relay)?;
        let endpoint = runtime
            .block_on(async {
                crate::iroh_net::endpoint_in(node_key, "0.0.0.0:0".parse()?, relay).await
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            runtime,
            endpoint,
            seller,
            key,
        })
    }
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    pub fn seller(&self) -> &EndpointAddr {
        &self.seller
    }
    pub fn runtime(&self) -> &tokio::runtime::Runtime {
        &self.runtime
    }
}
impl Transport for A2aTransport {
    fn base(&self) -> String {
        format!("iroh://{}", self.seller.id)
    }
    fn node(&self) -> Option<String> {
        Some(self.endpoint.id().to_string())
    }
    /// The request's own `dpop` header, made for another adapter's naming, is
    /// not sent: this binding's proof replaces it.
    fn send(&self, request: &Request) -> Res<Reply> {
        let (method, params) = a2a::outgoing(request)?;
        let answers = self
            .runtime
            .block_on(async {
                rpc(&self.endpoint, &self.seller, &self.key, method, &params, 1)
                    .await
                    .map_err(|e| e.to_string())
            })
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        let answer = answers.first().ok_or("no answer")?;
        if !answer["error"].is_null() {
            return Ok(a2a::reply_of_error(&answer["error"]));
        }
        let result = &answer["result"];
        a2a::reply_of(if method == "SendMessage" {
            &result["task"]
        } else {
            result
        })
    }
}

/// Serve a seller's handler on this endpoint under both protocols: the
/// existing `nucleus-commerce/1` and this binding. One handler, two adapters.
pub fn serve_seller(endpoint: Endpoint, handler: Shared, card: &Value) -> iroh::protocol::Router {
    let node = endpoint.id().to_string();
    iroh::protocol::Router::builder(endpoint)
        .accept(
            crate::iroh_net::ALPN,
            crate::iroh_net::Commerce::new(handler.clone(), node.clone()),
        )
        .accept(ALPN, A2a::new(handler, node, card))
        .spawn()
}

/// A card fetched from `node` must list an interface of this binding whose
/// URL names that node (specification §3.4): otherwise it describes some
/// other agent.
pub fn named_in(card: &Value, node: &str) -> Res<()> {
    let mine = format!("iroh://{node}");
    let listed = card["supportedInterfaces"]
        .as_array()
        .is_some_and(|interfaces| {
            interfaces.iter().any(|interface| {
                interface["protocolBinding"] == a2a::BINDING
                    && interface["url"].as_str().is_some_and(|url| {
                        url == mine
                            || url
                                .strip_prefix(&mine)
                                .is_some_and(|rest| rest.starts_with('?'))
                    })
            })
        });
    if listed {
        Ok(())
    } else {
        Err("the card does not list this node under this binding".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_card_is_taken_only_if_it_names_the_node_it_came_from() {
        let node = "ab".repeat(32);
        let card = a2a::card(&node, "n", "d", "1");
        named_in(&card, &node).unwrap();
        // Hints after the node ID do not change which node is named.
        let mut hinted = card.clone();
        hinted["supportedInterfaces"][0]["url"] =
            json!(format!("iroh://{node}?addr=203.0.113.7%3A1"));
        named_in(&hinted, &node).unwrap();
        // Another node's card, a longer ID with this one as its prefix, and
        // this node under another binding are all refused.
        assert!(named_in(&card, &"cd".repeat(32)).is_err());
        let mut longer = card.clone();
        longer["supportedInterfaces"][0]["url"] = json!(format!("iroh://{node}00"));
        assert!(named_in(&longer, &node).is_err());
        let mut other = card.clone();
        other["supportedInterfaces"][0]["protocolBinding"] = json!("JSONRPC");
        assert!(named_in(&other, &node).is_err());
    }
}
