//! A2A 1.0 operations over the seller's one handler, independent of transport.
//!
//! Nothing here decides anything. An A2A call is translated into the same
//! `message::Request` the other adapters send, the one `Handler` answers it,
//! and its `Reply` is translated into an A2A `Task`. The client half is the
//! exact inverse, so the buyer's existing flow runs over A2A unchanged
//! (`a2a_iroh::A2aTransport`).
//!
//! Wire names and state names are A2A 1.0's (ProtoJSON: camelCase fields,
//! `TASK_STATE_*` and `ROLE_*` enum strings, `bytes` as standard base64).
//! Payment objects are x402's, carried under the metadata keys of the A2A
//! x402 extension, v0.2.
//!
//! Specification of the transport that carries this:
//! docs/specs/a2a-iroh-transport-binding.md.
use crate::message::{Reply, Request};
use crate::prelude::*;
use nucleus_proof_commerce::x402::wire::{
    BUYER_HEADER, REQUIRED_HEADER, RESPONSE_HEADER, SIGNATURE_HEADER,
};

/// The binding's identifiers and media types, from the one crate the static
/// site also builds its example card from (contracts/a2a-iroh-card). The work
/// request's media type names the same bytes the other adapters send as the
/// body of `POST /work`.
pub use nucleus_a2a_iroh_card::{
    ARTIFACT_MEDIA_TYPE, BINDING, POSSESSION_EXTENSION, VERSION, WORK_MEDIA_TYPE, X402_EXTENSION,
};

const PAYMENT_STATUS: &str = "x402.payment.status";
const PAYMENT_REQUIRED: &str = "x402.payment.required";
const PAYMENT_PAYLOAD: &str = "x402.payment.payload";
const PAYMENT_RECEIPTS: &str = "x402.payment.receipts";
const PAYMENT_ERROR: &str = "x402.payment.error";
/// Message metadata key for the buyer's wallet and key declaration.
const BUYER: &str = "nucleus.buyer";
/// Status metadata key for the seller's own step name.
const JOB: &str = "nucleus.job";

/// A JSON-RPC error: an A2A error type or a JSON-RPC one, with the reason
/// and, where one adapter's status code exists, that code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fault {
    pub code: i64,
    pub message: String,
    pub reason: &'static str,
    /// The status the handler answered with, when it answered.
    pub status: Option<u16>,
}
impl Fault {
    pub fn new(code: i64, reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            reason,
            status: None,
        }
    }
    fn with(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }
    /// The `error` member of a JSON-RPC response (A2A §9.5).
    pub fn json(&self) -> Value {
        let mut metadata = json!({});
        if let Some(status) = self.status {
            metadata["status"] = json!(status.to_string());
        }
        json!({
            "code": self.code,
            "message": self.message,
            "data": [{
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "reason": self.reason,
                "domain": BINDING,
                "metadata": metadata,
            }],
        })
    }
}

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;
/// JSON-RPC's implementation-defined server error. Used for a refused or
/// missing possession proof; A2A defines no code for authentication.
pub const SERVER_ERROR: i64 = -32000;
pub const TASK_NOT_FOUND: i64 = -32001;
pub const TASK_NOT_CANCELABLE: i64 = -32002;
pub const PUSH_NOT_SUPPORTED: i64 = -32003;
pub const UNSUPPORTED_OPERATION: i64 = -32004;
pub const EXTENDED_CARD_NOT_CONFIGURED: i64 = -32007;
pub const VERSION_NOT_SUPPORTED: i64 = -32009;

/// What a call asks the handler to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Open,
    Read,
    Pay,
}

/// An A2A call as the request every adapter sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub kind: Kind,
    pub request: Request,
}

fn invalid(why: &str) -> Fault {
    Fault::new(INVALID_PARAMS, "INVALID_PARAMS", why)
}
fn x402_header(object: &Value) -> Res<String> {
    Ok(B64.encode(serde_json::to_vec(object)?))
}
fn x402_object(header: &str) -> Res<Value> {
    Ok(serde_json::from_slice(&B64.decode(header)?)?)
}
fn job_path(id: &str) -> Result<String, Fault> {
    // A task ID is the handler's job ID: `0x` and 64 hex characters. Anything
    // else names no job, and is kept out of the path.
    if id
        .strip_prefix("0x")
        .is_some_and(|digits| digits.len() == 64 && digits.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        Ok(format!("/work/{id}"))
    } else {
        Err(Fault::new(
            TASK_NOT_FOUND,
            "TASK_NOT_FOUND",
            "Task not found",
        ))
    }
}

/// The handler request for `SendMessage` or `GetTask`.
pub fn call(method: &str, params: &Value) -> Result<Call, Fault> {
    match method {
        "GetTask" => Ok(Call {
            kind: Kind::Read,
            request: Request {
                method: "GET".into(),
                path: job_path(params["id"].as_str().ok_or_else(|| invalid("id missing"))?)?,
                headers: [].into(),
                body: vec![],
            },
        }),
        "SendMessage" => {
            let message = &params["message"];
            if message["role"] != "ROLE_USER" {
                return Err(invalid("message.role must be ROLE_USER"));
            }
            if message["messageId"].as_str().is_none_or(str::is_empty) {
                return Err(invalid("message.messageId missing"));
            }
            let parts = message["parts"]
                .as_array()
                .filter(|parts| !parts.is_empty())
                .ok_or_else(|| invalid("message.parts: at least one part is required"))?;
            let metadata = &message["metadata"];
            match message["taskId"].as_str() {
                // A continuation: the only one this agent takes is a payment.
                Some(task) => {
                    if metadata[PAYMENT_STATUS] != "payment-submitted" {
                        return Err(invalid(
                            "a message for an existing task must submit a payment",
                        ));
                    }
                    let payload = x402_header(&metadata[PAYMENT_PAYLOAD])
                        .map_err(|_| invalid("payment payload malformed"))?;
                    Ok(Call {
                        kind: Kind::Pay,
                        request: Request {
                            method: "POST".into(),
                            path: job_path(task)?,
                            headers: [(SIGNATURE_HEADER.to_ascii_lowercase(), payload)].into(),
                            body: vec![],
                        },
                    })
                }
                None => {
                    let work = parts
                        .iter()
                        .find(|part| part["mediaType"] == WORK_MEDIA_TYPE)
                        .and_then(|part| part["raw"].as_str())
                        .ok_or_else(|| invalid("no work-request part"))?;
                    let body = B64
                        .decode(work)
                        .map_err(|_| invalid("work-request part is not base64"))?;
                    let buyer = metadata[BUYER]
                        .as_str()
                        .ok_or_else(|| invalid("buyer declaration missing"))?;
                    Ok(Call {
                        kind: Kind::Open,
                        request: Request {
                            method: "POST".into(),
                            path: "/work".into(),
                            headers: [(BUYER_HEADER.to_ascii_lowercase(), buyer.to_owned())].into(),
                            body,
                        },
                    })
                }
            }
        }
        _ => Err(Fault::new(
            METHOD_NOT_FOUND,
            "METHOD_NOT_FOUND",
            "Method not found",
        )),
    }
}

fn status(task: &str, state: &str, text: &str, metadata: Value) -> Value {
    json!({
        "state": state,
        "message": {
            "messageId": format!("{task}-{state}"),
            "taskId": task,
            "contextId": task,
            "role": "ROLE_AGENT",
            "parts": [{"text": text}],
            "metadata": metadata,
        },
    })
}
fn task(id: &str, status: Value) -> Value {
    json!({"id": id, "contextId": id, "status": status})
}
fn refusal(reply: &Reply) -> String {
    String::from_utf8_lossy(&reply.body).into_owned()
}

/// The A2A `Task` for the handler's reply to `call`. `id` is the task the
/// call named; for `Kind::Open` it is read from the reply.
pub fn task_of(kind: Kind, id: Option<&str>, reply: &Reply) -> Result<Value, Fault> {
    let named = || id.unwrap_or_default().to_owned();
    let located = || -> Result<String, Fault> {
        reply
            .header("location")
            .and_then(|path| path.strip_prefix("/work/"))
            .map(str::to_owned)
            .ok_or_else(|| Fault::new(INTERNAL_ERROR, "INTERNAL", "handler named no job"))
    };
    match (kind, reply.status) {
        (Kind::Open, 202) => {
            let id = located()?;
            let state = status(
                &id,
                "TASK_STATE_SUBMITTED",
                "Request taken; looking for a proof.",
                json!({JOB: "quoting"}),
            );
            Ok(task(&id, state))
        }
        (Kind::Pay, 202) => {
            let id = located()?;
            let state = status(
                &id,
                "TASK_STATE_WORKING",
                "Payment authorization taken.",
                json!({PAYMENT_STATUS: "payment-submitted", JOB: "funding"}),
            );
            Ok(task(&id, state))
        }
        (Kind::Read, 202) => {
            let id = named();
            let step = reply.header("nucleus-job").unwrap_or("working");
            let mut metadata = json!({JOB: step});
            if step != "quoting" {
                metadata[PAYMENT_STATUS] = json!(if step == "funding" {
                    "payment-submitted"
                } else {
                    "payment-verified"
                });
            }
            Ok(task(&id, status(&id, "TASK_STATE_WORKING", step, metadata)))
        }
        (Kind::Read, 402) => {
            let id = named();
            let required = reply
                .header(REQUIRED_HEADER)
                .and_then(|header| x402_object(header).ok())
                .ok_or_else(|| Fault::new(INTERNAL_ERROR, "INTERNAL", "offer malformed"))?;
            let metadata = json!({PAYMENT_STATUS: "payment-required", PAYMENT_REQUIRED: required});
            Ok(task(
                &id,
                status(
                    &id,
                    "TASK_STATE_INPUT_REQUIRED",
                    "A proof is held. Payment is required to release it.",
                    metadata,
                ),
            ))
        }
        (Kind::Read, 200) => {
            let id = named();
            let receipt = reply
                .header(RESPONSE_HEADER)
                .and_then(|header| x402_object(header).ok())
                .ok_or_else(|| Fault::new(INTERNAL_ERROR, "INTERNAL", "receipt malformed"))?;
            let metadata =
                json!({PAYMENT_STATUS: "payment-completed", PAYMENT_RECEIPTS: [receipt]});
            let mut done = task(
                &id,
                status(&id, "TASK_STATE_COMPLETED", "Settled.", metadata),
            );
            done["artifacts"] = json!([{
                "artifactId": id,
                "name": "proof",
                "parts": [{
                    "raw": B64.encode(&reply.body),
                    "mediaType": ARTIFACT_MEDIA_TYPE,
                    "filename": "artifact.ndjson",
                }],
            }]);
            Ok(done)
        }
        // The handler declined the work, or the job ended without delivery.
        (Kind::Read, 422) => Ok(task(
            &named(),
            status(
                &named(),
                "TASK_STATE_REJECTED",
                &refusal(reply),
                json!({JOB: "declined"}),
            ),
        )),
        (Kind::Read, 410) => Ok(task(
            &named(),
            status(
                &named(),
                "TASK_STATE_FAILED",
                &refusal(reply),
                json!({PAYMENT_STATUS: "payment-failed", PAYMENT_ERROR: "EXPIRED_PAYMENT", JOB: "expired"}),
            ),
        )),
        (Kind::Read, 500) => Ok(task(
            &named(),
            status(
                &named(),
                "TASK_STATE_FAILED",
                &refusal(reply),
                json!({JOB: "failed"}),
            ),
        )),
        // A job that is not this key's is reported exactly as one that does
        // not exist (A2A §13.1).
        (_, 403 | 404) => {
            Err(Fault::new(TASK_NOT_FOUND, "TASK_NOT_FOUND", "Task not found").with(reply.status))
        }
        (_, 401) => {
            Err(Fault::new(SERVER_ERROR, "POSSESSION_PROOF_INVALID", refusal(reply)).with(401))
        }
        (_, 503) => Err(Fault::new(SERVER_ERROR, "AGENT_BUSY", refusal(reply)).with(503)),
        (_, status @ (400 | 409 | 413 | 422)) => Err(invalid(&refusal(reply)).with(status)),
        (_, status) => Err(Fault::new(INTERNAL_ERROR, "INTERNAL", refusal(reply)).with(status)),
    }
}

/// Whether a task in this state will change no further.
pub fn terminal(state: &str) -> bool {
    matches!(
        state,
        "TASK_STATE_COMPLETED"
            | "TASK_STATE_FAILED"
            | "TASK_STATE_CANCELED"
            | "TASK_STATE_REJECTED"
    )
}
/// Whether a task in this state waits on the client.
pub fn interrupted(state: &str) -> bool {
    matches!(
        state,
        "TASK_STATE_INPUT_REQUIRED" | "TASK_STATE_AUTH_REQUIRED"
    )
}

// ---- The client half: the inverse of the above.

/// The A2A method and parameters for a handler request.
pub fn outgoing(request: &Request) -> Res<(&'static str, Value)> {
    let job = request.path.strip_prefix("/work/");
    let message_id = hex(&random32()?);
    match (request.method.as_str(), request.path.as_str(), job) {
        ("POST", "/work", _) => {
            let buyer = request
                .headers
                .get(&BUYER_HEADER.to_ascii_lowercase())
                .ok_or("buyer declaration missing")?;
            Ok((
                "SendMessage",
                json!({"message": {
                    "messageId": message_id,
                    "role": "ROLE_USER",
                    "parts": [{"raw": B64.encode(&request.body), "mediaType": WORK_MEDIA_TYPE}],
                    "metadata": {BUYER: buyer},
                    "extensions": [X402_EXTENSION],
                }}),
            ))
        }
        ("GET", _, Some(id)) => Ok(("GetTask", json!({"id": id}))),
        ("POST", _, Some(id)) => {
            let payment = request
                .headers
                .get(&SIGNATURE_HEADER.to_ascii_lowercase())
                .ok_or("payment missing")?;
            Ok((
                "SendMessage",
                json!({"message": {
                    "messageId": message_id,
                    "taskId": id,
                    "contextId": id,
                    "role": "ROLE_USER",
                    "parts": [{"text": "Payment authorization."}],
                    "metadata": {PAYMENT_STATUS: "payment-submitted", PAYMENT_PAYLOAD: x402_object(payment)?},
                    "extensions": [X402_EXTENSION],
                }}),
            ))
        }
        _ => Err("no A2A operation for this request".into()),
    }
}

/// The handler reply a `Task` stands for.
pub fn reply_of(task: &Value) -> Res<Reply> {
    let id = task["id"].as_str().ok_or("task id missing")?;
    let status = &task["status"];
    let metadata = &status["message"]["metadata"];
    let text = status["message"]["parts"][0]["text"]
        .as_str()
        .unwrap_or_default();
    let location = format!("/work/{id}");
    Ok(
        match status["state"].as_str().ok_or("task state missing")? {
            "TASK_STATE_SUBMITTED" => Reply::new(202).with("Location", location),
            "TASK_STATE_WORKING" => Reply::new(202).with("Location", location).with(
                "Nucleus-Job",
                metadata[JOB].as_str().unwrap_or("working").into(),
            ),
            "TASK_STATE_INPUT_REQUIRED" => Reply::text(402, "{}")
                .with(REQUIRED_HEADER, x402_header(&metadata[PAYMENT_REQUIRED])?),
            "TASK_STATE_COMPLETED" => {
                let receipt = metadata[PAYMENT_RECEIPTS]
                    .as_array()
                    .and_then(|receipts| receipts.last())
                    .ok_or("receipt missing")?;
                let artifact = task["artifacts"][0]["parts"][0]["raw"]
                    .as_str()
                    .ok_or("artifact missing")?;
                Reply {
                    status: 200,
                    headers: vec![(RESPONSE_HEADER.to_owned(), x402_header(receipt)?)],
                    body: B64.decode(artifact)?,
                }
            }
            "TASK_STATE_REJECTED" => Reply::text(422, text),
            "TASK_STATE_FAILED" if metadata[JOB] == "expired" => Reply::text(410, text),
            "TASK_STATE_FAILED" => Reply::text(500, text),
            other => return Err(format!("unexpected task state {other}").into()),
        },
    )
}

/// The handler reply a JSON-RPC error stands for.
pub fn reply_of_error(error: &Value) -> Reply {
    let status = error["data"][0]["metadata"]["status"]
        .as_str()
        .and_then(|status| status.parse().ok())
        .unwrap_or(match error["code"].as_i64() {
            Some(TASK_NOT_FOUND) => 404,
            Some(INVALID_PARAMS | INVALID_REQUEST | PARSE_ERROR) => 400,
            Some(SERVER_ERROR) => 401,
            _ => 500,
        });
    Reply::text(status, error["message"].as_str().unwrap_or_default())
}

/// The Agent Card of a seller reachable under this binding at `node`.
pub fn card(node: &str, name: &str, description: &str, version: &str) -> Value {
    nucleus_a2a_iroh_card::card(node, name, description, version)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opened() -> Request {
        Request {
            method: "POST".into(),
            path: "/work".into(),
            headers: [(BUYER_HEADER.to_ascii_lowercase(), "ZGVjbGFyZWQ=".to_owned())].into(),
            body: br#"{"policy":{},"statement":""}"#.to_vec(),
        }
    }

    /// What the client sends for a handler request is, on the server, that
    /// request again: same method, path, headers and body bytes.
    #[test]
    fn a_request_survives_the_trip_through_a2a() {
        let id = format!("0x{}", "ab".repeat(32));
        let paid = Request {
            method: "POST".into(),
            path: format!("/work/{id}"),
            headers: [(
                SIGNATURE_HEADER.to_ascii_lowercase(),
                B64.encode(br#"{"x402Version":2}"#),
            )]
            .into(),
            body: vec![],
        };
        let read = Request {
            method: "GET".into(),
            path: format!("/work/{id}"),
            headers: [].into(),
            body: vec![],
        };
        for request in [opened(), paid, read] {
            let (method, params) = outgoing(&request).unwrap();
            assert_eq!(call(method, &params).unwrap().request, request);
        }
    }

    /// A reply survives too, for every state the handler reports.
    #[test]
    fn a_reply_survives_the_trip_through_a2a() {
        let id = format!("0x{}", "cd".repeat(32));
        let object = B64.encode(br#"{"a":1}"#);
        let cases = [
            (
                Kind::Open,
                Reply::new(202).with("Location", format!("/work/{id}")),
            ),
            (
                Kind::Pay,
                Reply::new(202).with("Location", format!("/work/{id}")),
            ),
            (
                Kind::Read,
                Reply::new(202).with("Nucleus-Job", "quoting".into()),
            ),
            (
                Kind::Read,
                Reply::new(202).with("Nucleus-Job", "proving".into()),
            ),
            (
                Kind::Read,
                Reply::text(402, "{}").with(REQUIRED_HEADER, object.clone()),
            ),
            (
                Kind::Read,
                Reply {
                    status: 200,
                    headers: vec![(RESPONSE_HEADER.to_owned(), object)],
                    body: vec![0, 1, 2, 255],
                },
            ),
            (Kind::Read, Reply::text(422, "no proof found")),
            (Kind::Read, Reply::text(410, "the quote expired unfunded")),
            (Kind::Read, Reply::text(500, "settlement failed")),
        ];
        for (kind, reply) in cases {
            let task = task_of(kind, Some(&id), &reply).unwrap();
            let back = reply_of(&task).unwrap();
            assert_eq!(back.status, reply.status, "{task}");
            assert_eq!(back.body, reply.body, "{task}");
            for name in [REQUIRED_HEADER, RESPONSE_HEADER] {
                assert_eq!(back.header(name), reply.header(name), "{name} {task}");
            }
            // The step name survives a read. The reply to a payment gains
            // one ("funding") that the handler's own reply does not carry.
            if kind == Kind::Read {
                assert_eq!(back.header("nucleus-job"), reply.header("nucleus-job"));
            }
        }
    }

    #[test]
    fn a_refusal_becomes_an_error_and_another_keys_task_looks_absent() {
        let id = format!("0x{}", "ef".repeat(32));
        for status in [403, 404] {
            let fault = task_of(Kind::Read, Some(&id), &Reply::text(status, "x")).unwrap_err();
            assert_eq!(fault.code, TASK_NOT_FOUND);
            assert_eq!(fault.message, "Task not found");
        }
        let fault = task_of(Kind::Open, None, &Reply::text(413, "too large")).unwrap_err();
        assert_eq!(fault.code, INVALID_PARAMS);
        assert_eq!(reply_of_error(&fault.json()).status, 413);
        assert_eq!(call("Nope", &json!({})).unwrap_err().code, METHOD_NOT_FOUND);
        assert_eq!(
            call("GetTask", &json!({"id": "../etc"})).unwrap_err().code,
            TASK_NOT_FOUND
        );
    }
}
