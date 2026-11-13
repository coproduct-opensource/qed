//! A2A 1.0 over iroh (docs/specs/a2a-iroh-transport-binding.md, 0.1), through
//! real iroh endpoints on the loopback interface. The seller is the same
//! handler the other adapters serve; the settler is a recorder, so nothing
//! here touches a chain.
//!
//! Test names carry the conformance requirement they cover (C-n in the
//! specification's §10). Each refusal was driven red once by deleting the
//! check; docs/rfcs/a2a-over-iroh-binding-2026-11-13.md has the table.
use base64::Engine;
use nucleus_commerce_agents::{
    a2a,
    a2a_iroh::{self, A2aTransport},
    buyer::ask,
    dpop::{self, proof_make},
    iroh_net::{self, IrohTransport, Relay},
    job::Accepted,
    message::{Reply, Transport},
    seller::{Jobs, Prover, Seller, Settler, Terms},
    support::{B64, Keys, policy_json},
    world::wall_clock,
};
use nucleus_proof_acceptance::Policy;
use nucleus_proof_commerce::{
    vault::{self, wire as vault_wire},
    x402::{
        TokenDomain,
        wire::{BUYER_HEADER, REQUIRED_HEADER, SIGNATURE_HEADER, declaration_header, request_hash},
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

const STATEMENT: &[u8] = include_bytes!("../../proof-acceptance/core/tests/fixtures/task.ndjson");
const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../proof-acceptance/core/tests/fixtures"
);
const PROTO: &str = include_str!("a2a-spec/a2a.proto");

#[derive(Default, Clone)]
struct Recorder(Arc<Mutex<Vec<String>>>);
impl Settler for Recorder {
    fn start(&self, id: String, _accepted: Accepted, _jobs: Jobs) {
        self.0.lock().unwrap().push(id);
    }
}

fn scratch(name: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "a2a-{}-{}-{name}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
fn keys(name: &str) -> Keys {
    Keys::load_or_create(scratch(name).join("keys").to_str().unwrap()).unwrap()
}

struct World {
    _runtime: tokio::runtime::Runtime,
    _router: iroh::protocol::Router,
    /// `iroh:<node id>@<ip:port>`
    address: String,
    node: String,
    terms: Terms,
    accepted: Recorder,
}
impl World {
    fn with_artifact(artifact: &str) -> Self {
        let seller_keys = keys("seller");
        let terms = Terms {
            deployment: vault::Deployment {
                chain_id: 421614,
                vault: [0x11; 20],
                treasury: [0x22; 20],
                fee_bps: 25,
                maximum_fee_bps: 100,
                rules: nucleus_proof_commerce::vault::Rules::Second,
            },
            domain: TokenDomain {
                name: "USD Coin".into(),
                version: "2".into(),
            },
            token: [0x33; 20],
            verifier: [0x44; 20],
            program: [0x55; 32],
            seller: seller_keys.address(),
            price: 250_000,
            fund_seconds: 900,
            deliver_seconds: 3 * 3600,
            base: None,
        };
        let prover = Prover {
            command: vec![
                env!("CARGO_BIN_EXE_nucleus-fixture-prover").into(),
                format!("{FIXTURES}/task.ndjson"),
                artifact.into(),
            ],
            timeout: Duration::from_secs(30),
            work: scratch("jobs"),
        };
        let accepted = Recorder::default();
        let seller = Arc::new(Mutex::new(Seller::new(
            terms.clone(),
            prover,
            Box::new(accepted.clone()),
        )));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let endpoint = runtime
            .block_on(async {
                iroh_net::endpoint(seller_keys.node, "127.0.0.1:0".parse().unwrap())
                    .await
                    .map_err(|e| e.to_string())
            })
            .unwrap();
        let address = iroh_net::address_text(&endpoint).unwrap();
        let node = endpoint.id().to_string();
        let card = a2a::card(&node, "Test seller", "Sells the fixture proof.", "0.0.0");
        let router = {
            let _guard = runtime.enter();
            a2a_iroh::serve_seller(endpoint, seller, &card)
        };
        Self {
            _runtime: runtime,
            _router: router,
            address,
            node,
            terms,
            accepted,
        }
    }
    fn new() -> Self {
        Self::with_artifact(&format!("{FIXTURES}/suffix.ndjson"))
    }
    fn a2a(&self, keys: &Keys) -> A2aTransport {
        A2aTransport::new_in(
            keys.node,
            keys.possession.clone(),
            &self.address,
            &Relay::None,
        )
        .unwrap()
    }
    fn plain(&self, keys: &Keys) -> IrohTransport {
        IrohTransport::new(keys.node, &self.address).unwrap()
    }
}

fn policy() -> Policy {
    Policy {
        statement_sha256: Sha256::digest(STATEMENT).into(),
        claim: "Nucleus.Claim".into(),
        permitted_axioms: vec![],
        maximum_artifact_bytes: 65_536,
    }
}
fn work_body() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "policy": policy_json(&policy()), "statement": B64.encode(STATEMENT),
    }))
    .unwrap()
}
fn declaration(keys: &Keys) -> BTreeMap<String, String> {
    [(
        BUYER_HEADER.to_ascii_lowercase(),
        declaration_header(keys.address(), keys.binding()).unwrap(),
    )]
    .into()
}
/// The `SendMessage` parameters that open the fixture task for this key.
fn opening(keys: &Keys) -> Value {
    json!({"message": {
        "messageId": "m-1",
        "role": "ROLE_USER",
        "parts": [{"raw": B64.encode(work_body()), "mediaType": a2a::WORK_MEDIA_TYPE}],
        "metadata": {"nucleus.buyer": declaration_header(keys.address(), keys.binding()).unwrap()},
    }})
}
/// One call with a good proof; the first answer frame.
fn rpc(client: &A2aTransport, keys: &Keys, method: &str, params: &Value) -> Value {
    rpc_all(client, keys, method, params, 1).remove(0)
}
fn rpc_all(
    client: &A2aTransport,
    keys: &Keys,
    method: &str,
    params: &Value,
    limit: usize,
) -> Vec<Value> {
    client
        .runtime()
        .block_on(a2a_iroh::rpc(
            client.endpoint(),
            client.seller(),
            &keys.possession,
            method,
            params,
            limit,
        ))
        .unwrap()
}
/// One call with exactly this header frame and request; the first answer, or
/// the transport error.
fn raw(client: &A2aTransport, header: &Value, request: &[u8]) -> Result<Value, String> {
    let frames = [serde_json::to_vec(header).unwrap(), request.to_vec()];
    let answers = client
        .runtime()
        .block_on(a2a_iroh::exchange(
            client.endpoint(),
            client.seller(),
            &frames,
            1,
        ))
        .map_err(|e| e.to_string())?;
    Ok(serde_json::from_slice(answers.first().ok_or("no answer")?).unwrap())
}
fn request_bytes(method: &str, params: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params}))
        .unwrap()
}
struct Claims<'a> {
    typ: &'a str,
    method: &'a str,
    target: String,
    at: u64,
    node: Option<String>,
    request: Option<&'a [u8]>,
}
fn good<'a>(
    world: &World,
    client: &A2aTransport,
    method: &'a str,
    request: &'a [u8],
) -> Claims<'a> {
    Claims {
        typ: dpop::BINDING_TYP,
        method,
        target: a2a_iroh::target(&world.node),
        at: wall_clock().unwrap(),
        node: client.node(),
        request: Some(request),
    }
}
fn proof(keys: &Keys, claims: &Claims) -> String {
    proof_make(
        &keys.possession,
        claims.typ,
        claims.method,
        &claims.target,
        claims.at,
        claims.node.as_deref(),
        claims.request,
    )
    .unwrap()
}
fn reason(answer: &Value) -> (i64, String) {
    (
        answer["error"]["code"].as_i64().unwrap_or_default(),
        answer["error"]["data"][0]["reason"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    )
}
fn state(task: &Value) -> &str {
    task["status"]["state"].as_str().unwrap_or_default()
}
/// `GetTask` until the task leaves the two states that mean "still quoting".
fn await_offer(client: &A2aTransport, keys: &Keys, id: &str) -> Value {
    for _ in 0..200 {
        let answer = rpc(client, keys, "GetTask", &json!({"id": id}));
        let task = &answer["result"];
        if task["status"]["message"]["metadata"]["nucleus.job"] != "quoting" {
            return task.clone();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("no offer for {id}");
}
fn open(client: &A2aTransport, keys: &Keys) -> String {
    let answer = rpc(client, keys, "SendMessage", &opening(keys));
    answer["result"]["task"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{answer}"))
        .to_owned()
}

// ---- The proto as the list of fields: nothing is restated here.

/// message name -> (JSON field name, required, type, repeated)
type Messages = BTreeMap<String, Vec<(String, bool, String, bool)>>;
fn camel(name: &str) -> String {
    let mut out = String::new();
    let mut upper = false;
    for c in name.chars() {
        if c == '_' {
            upper = true;
        } else if upper {
            out.push(c.to_ascii_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}
fn messages() -> Messages {
    let mut all = Messages::new();
    let mut current: Option<String> = None;
    for line in PROTO.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("message ") {
            let name = rest.trim_end_matches('{').trim().to_owned();
            all.insert(name.clone(), vec![]);
            current = Some(name);
            continue;
        }
        let Some(message) = &current else { continue };
        if line.starts_with("//") || line.starts_with("oneof ") || line.starts_with("option ") {
            continue;
        }
        let Some((declaration, _)) = line.split_once('=') else {
            continue;
        };
        let mut words: Vec<&str> = declaration.split_whitespace().collect();
        let repeated = words.first() == Some(&"repeated");
        if matches!(words.first(), Some(&"repeated") | Some(&"optional")) {
            words.remove(0);
        }
        // `map<string, T> name`: a field whose values are not checked further.
        if words.first().is_some_and(|word| word.starts_with("map<")) {
            let name = words.last().copied().unwrap_or_default();
            words = vec!["map", name];
        }
        let [kind, name] = words[..] else { continue };
        all.get_mut(message).unwrap().push((
            camel(name),
            line.contains("= REQUIRED"),
            kind.to_owned(),
            repeated,
        ));
    }
    all
}
/// Every field of `value` is a field of proto message `kind`, every REQUIRED
/// field is present, and message-typed fields hold recursively.
fn conforms(all: &Messages, kind: &str, value: &Value, at: &str) {
    let fields = all.get(kind).unwrap_or_else(|| panic!("no message {kind}"));
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("{at}: {kind} is not an object: {value}"));
    for name in object.keys() {
        assert!(
            fields.iter().any(|(field, ..)| field == name),
            "{at}: {kind} has no field {name}"
        );
    }
    for (name, required, field_kind, repeated) in fields {
        let Some(inner) = object.get(name) else {
            assert!(!required, "{at}: {kind}.{name} is REQUIRED and absent");
            continue;
        };
        if !all.contains_key(field_kind) {
            continue;
        }
        if *repeated {
            for item in inner.as_array().unwrap_or_else(|| panic!("{at}.{name}")) {
                conforms(all, field_kind, item, &format!("{at}.{name}[]"));
            }
        } else {
            conforms(all, field_kind, inner, &format!("{at}.{name}"));
        }
    }
}

#[test]
fn c1_the_agent_card_is_served_over_iroh_and_names_this_node_and_binding() {
    let world = World::new();
    let buyer = keys("buyer");
    let client = world.a2a(&buyer);
    let card = client
        .runtime()
        .block_on(a2a_iroh::fetch_card(client.endpoint(), client.seller()))
        .unwrap();
    conforms(&messages(), "AgentCard", &card, "card");
    let interface = &card["supportedInterfaces"][0];
    assert_eq!(interface["url"], json!(format!("iroh://{}", world.node)));
    assert_eq!(interface["protocolBinding"], a2a::BINDING);
    assert_eq!(interface["protocolVersion"], a2a::VERSION);
    assert_eq!(card["capabilities"]["pushNotifications"], false);
    let required: Vec<&str> = card["capabilities"]["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["required"] == true)
        .filter_map(|e| e["uri"].as_str())
        .collect();
    assert_eq!(required, [a2a::POSSESSION_EXTENSION, a2a::X402_EXTENSION]);
    // Any other well-known name gets nothing.
    let frames = [serde_json::to_vec(&json!({a2a_iroh::WELL_KNOWN: "other.json"})).unwrap()];
    let none = client
        .runtime()
        .block_on(a2a_iroh::exchange(
            client.endpoint(),
            client.seller(),
            &frames,
            1,
        ))
        .unwrap();
    assert!(none.is_empty());
}

#[test]
fn c2_c16_a_task_is_opened_quoted_with_an_x402_object_and_paid_for_once() {
    let world = World::new();
    let buyer = keys("buyer");
    let client = world.a2a(&buyer);
    let all = messages();

    let answer = rpc(&client, &buyer, "SendMessage", &opening(&buyer));
    assert_eq!(answer["jsonrpc"], "2.0");
    assert_eq!(answer["id"], 1);
    let task = &answer["result"]["task"];
    conforms(&all, "Task", task, "opened");
    assert_eq!(state(task), "TASK_STATE_SUBMITTED");
    let id = task["id"].as_str().unwrap().to_owned();

    let offered = await_offer(&client, &buyer, &id);
    conforms(&all, "Task", &offered, "offered");
    assert_eq!(state(&offered), "TASK_STATE_INPUT_REQUIRED");
    let metadata = &offered["status"]["message"]["metadata"];
    assert_eq!(metadata["x402.payment.status"], "payment-required");
    let required = &metadata["x402.payment.required"];
    assert_eq!(required["x402Version"], 2);

    // The offer passes the buyer's own review, exactly as over the other adapter.
    let now = wall_clock().unwrap();
    let uri = format!("{}/work", client.base());
    let intent = vault_wire::Intent {
        wallet: buyer.address(),
        asset: world.terms.token,
        policy_hash: policy().hash(),
        context: vault_wire::context(request_hash("POST", &uri, &work_body()), buyer.binding()),
        maximum_amount: [&[0u8; 24][..], &250_000u64.to_be_bytes()]
            .concat()
            .try_into()
            .unwrap(),
        verifiers: vec![world.terms.verifier],
        programs: vec![world.terms.program],
        fund_no_earlier_than: now + 60,
        deliver_no_later_than: now + 8 * 3600,
        bases: vec![],
    };
    let header = B64.encode(serde_json::to_vec(required).unwrap());
    let reviewed = vault_wire::review_offer(
        &world.terms.deployment,
        &world.terms.domain,
        &header,
        &intent,
        now,
    )
    .unwrap();
    let signature = nucleus_commerce_agents::sign(&buyer.wallet, reviewed.signing_digest());
    let payment =
        vault_wire::signature_header(&world.terms.deployment, reviewed, &signature).unwrap();
    let payload: Value = serde_json::from_slice(&B64.decode(&payment).unwrap()).unwrap();
    let paying = json!({"message": {
        "messageId": "m-2", "taskId": id, "contextId": id, "role": "ROLE_USER",
        "parts": [{"text": "Payment authorization."}],
        "metadata": {"x402.payment.status": "payment-submitted", "x402.payment.payload": payload},
    }});
    let paid = rpc(&client, &buyer, "SendMessage", &paying);
    let task = &paid["result"]["task"];
    conforms(&all, "Task", task, "paid");
    assert_eq!(state(task), "TASK_STATE_WORKING");
    assert_eq!(
        task["status"]["message"]["metadata"]["x402.payment.status"],
        "payment-submitted"
    );
    assert_eq!(*world.accepted.0.lock().unwrap(), std::slice::from_ref(&id));

    // A quote is taken once.
    let again = rpc(&client, &buyer, "SendMessage", &paying);
    assert_eq!(again["error"]["code"], a2a::INVALID_PARAMS, "{again}");
    assert_eq!(world.accepted.0.lock().unwrap().len(), 1);

    let listed = rpc(&client, &buyer, "ListTasks", &json!({}));
    conforms(&all, "ListTasksResponse", &listed["result"], "listed");
    assert_eq!(listed["result"]["tasks"][0]["id"], json!(id));
    assert_eq!(listed["result"]["totalSize"], 1);
}

#[test]
fn c3_a_request_without_the_supported_version_is_refused() {
    let world = World::new();
    let buyer = keys("buyer");
    let client = world.a2a(&buyer);
    let request = request_bytes("ListTasks", &json!({}));
    for version in [json!("0.3"), json!("2.0"), Value::Null] {
        let good = proof(&buyer, &good(&world, &client, "ListTasks", &request));
        let mut header = a2a_iroh::header(&good);
        header["a2a-version"] = version.clone();
        let answer = raw(&client, &header, &request).unwrap();
        assert_eq!(
            reason(&answer),
            (a2a::VERSION_NOT_SUPPORTED, "VERSION_NOT_SUPPORTED".into()),
            "{version}"
        );
    }
}

#[test]
fn c4_to_c11_a_request_without_a_valid_fresh_proof_for_exactly_it_is_refused() {
    let world = World::new();
    let buyer = keys("buyer");
    let other = keys("other");
    let client = world.a2a(&buyer);
    let request = request_bytes("SendMessage", &opening(&buyer));
    let invalid = (a2a::SERVER_ERROR, "POSSESSION_PROOF_INVALID".to_owned());
    let refused = |name: &str, header: Value, request: &[u8], expected: &(i64, String)| {
        let answer = raw(&client, &header, request).unwrap();
        assert_eq!(&reason(&answer), expected, "{name}: {answer}");
    };

    // C4: no proof.
    let mut none = a2a_iroh::header("");
    none.as_object_mut().unwrap().remove(a2a_iroh::PROOF);
    refused(
        "missing",
        none,
        &request,
        &(a2a::SERVER_ERROR, "POSSESSION_PROOF_REQUIRED".into()),
    );

    let ok = || good(&world, &client, "SendMessage", &request);
    let with = |claims: Claims| a2a_iroh::header(&proof(&buyer, &claims));

    // C5: another proof type; a signature that does not verify.
    refused(
        "DPoP typ",
        with(Claims {
            typ: dpop::DPOP_TYP,
            ..ok()
        }),
        &request,
        &invalid,
    );
    let mut forged = proof(&buyer, &ok());
    let dot = forged.rfind('.').unwrap() + 1;
    let first = forged.as_bytes()[dot];
    forged.replace_range(dot..=dot, if first == b'A' { "B" } else { "A" });
    refused("forged", a2a_iroh::header(&forged), &request, &invalid);

    // C6: a proof for another operation.
    refused(
        "other method",
        with(Claims {
            method: "GetTask",
            ..ok()
        }),
        &request,
        &invalid,
    );
    // C7: a proof for another node, and for another protocol on this node.
    refused(
        "other node",
        with(Claims {
            target: a2a_iroh::target(&client.node().unwrap()),
            ..ok()
        }),
        &request,
        &invalid,
    );
    refused(
        "other protocol",
        with(Claims {
            target: format!("iroh://{}/nucleus-commerce/1", world.node),
            ..ok()
        }),
        &request,
        &invalid,
    );
    // C8: outside the time window, either way.
    for at in [wall_clock().unwrap() - 600, wall_clock().unwrap() + 600] {
        refused("stale", with(Claims { at, ..ok() }), &request, &invalid);
    }
    // C10: not bound to the caller's node: absent, another node's, and a
    // proof lifted off another connection (the other key's own node).
    refused(
        "no nid",
        with(Claims { node: None, ..ok() }),
        &request,
        &invalid,
    );
    refused(
        "wrong nid",
        with(Claims {
            node: Some(world.node.clone()),
            ..ok()
        }),
        &request,
        &invalid,
    );
    let elsewhere = world.a2a(&other);
    let lifted = proof(&buyer, &good(&world, &elsewhere, "SendMessage", &request));
    refused("lifted", a2a_iroh::header(&lifted), &request, &invalid);
    // C11: a proof for other request bytes.
    // The altered request is one the agent would otherwise take: the same
    // task from the same key, with another message ID.
    let mut different = opening(&buyer);
    different["message"]["messageId"] = json!("m-9");
    let altered = request_bytes("SendMessage", &different);
    refused("other body", with(ok()), &altered, &invalid);
    refused(
        "no body hash",
        with(Claims {
            request: None,
            ..ok()
        }),
        &request,
        &invalid,
    );

    // Nothing above opened a task. The proof that is right does, and (C9) the
    // same proof a second time does not.
    assert!(world.accepted.0.lock().unwrap().is_empty());
    let once = with(ok());
    let answer = raw(&client, &once, &request).unwrap();
    assert_eq!(
        state(&answer["result"]["task"]),
        "TASK_STATE_SUBMITTED",
        "{answer}"
    );
    refused("replayed", once, &request, &invalid);
}

#[test]
fn c12_a_task_answers_only_to_the_key_that_opened_it() {
    let world = World::new();
    let buyer = keys("buyer");
    let other = keys("other");
    let (mine, theirs) = (world.a2a(&buyer), world.a2a(&other));
    let id = open(&mine, &buyer);
    await_offer(&mine, &buyer, &id);
    let absent = (a2a::TASK_NOT_FOUND, "TASK_NOT_FOUND".to_owned());
    for (method, params) in [
        ("GetTask", json!({"id": id})),
        ("CancelTask", json!({"id": id})),
        ("SubscribeToTask", json!({"id": id})),
        (
            "SendMessage",
            json!({"message": {"messageId": "x", "taskId": id, "role": "ROLE_USER",
                "parts": [{"text": "p"}],
                "metadata": {"x402.payment.status": "payment-submitted", "x402.payment.payload": {}}}}),
        ),
    ] {
        let answer = rpc(&theirs, &other, method, &params);
        // A payment that is malformed is refused as such before the handler
        // is asked; every other call must look exactly like an absent task.
        if method != "SendMessage" {
            assert_eq!(reason(&answer), absent, "{method}: {answer}");
            assert_eq!(answer["error"]["message"], "Task not found");
        } else {
            assert!(!answer["error"].is_null(), "{answer}");
        }
    }
    let listed = rpc(&theirs, &other, "ListTasks", &json!({}));
    assert_eq!(listed["result"]["totalSize"], 0, "{listed}");
    // And the same for a task that never existed.
    let never = rpc(
        &mine,
        &buyer,
        "GetTask",
        &json!({"id": format!("0x{}", "00".repeat(32))}),
    );
    assert_eq!(reason(&never), absent);
    assert!(world.accepted.0.lock().unwrap().is_empty());
}

#[test]
fn c13_malformed_and_oversize_requests_are_refused_as_the_specification_says() {
    let world = World::new();
    let buyer = keys("buyer");
    let client = world.a2a(&buyer);

    let bad = b"{not json".to_vec();
    let header = a2a_iroh::header(&proof(&buyer, &good(&world, &client, "GetTask", &bad)));
    let answer = raw(&client, &header, &bad).unwrap();
    assert_eq!(answer["error"]["code"], a2a::PARSE_ERROR);
    assert_eq!(answer["id"], Value::Null);

    for request in [
        json!({"jsonrpc": "1.0", "id": 1, "method": "GetTask"}),
        json!({"jsonrpc": "2.0", "method": "GetTask"}),
        json!({"jsonrpc": "2.0", "id": 1}),
    ] {
        let bytes = serde_json::to_vec(&request).unwrap();
        let header = a2a_iroh::header(&proof(&buyer, &good(&world, &client, "GetTask", &bytes)));
        let answer = raw(&client, &header, &bytes).unwrap();
        assert_eq!(answer["error"]["code"], a2a::INVALID_REQUEST, "{request}");
    }

    let unknown = rpc(&client, &buyer, "tasks/get", &json!({}));
    assert_eq!(unknown["error"]["code"], a2a::METHOD_NOT_FOUND);
    let empty = rpc(
        &client,
        &buyer,
        "SendMessage",
        &json!({"message": {
        "messageId": "m", "role": "ROLE_USER", "parts": []}}),
    );
    assert_eq!(empty["error"]["code"], a2a::INVALID_PARAMS);

    // A header frame over the limit, and a request frame over the limit: the
    // stream is reset before the bytes are read, and nothing is answered.
    let huge_header = json!({"padding": "x".repeat(a2a_iroh::MAXIMUM_HEADER)});
    assert!(raw(&client, &huge_header, b"{}").is_err());
    let length = u32::try_from(a2a_iroh::MAXIMUM_FRAME + 1)
        .unwrap()
        .to_be_bytes();
    let header = serde_json::to_vec(&a2a_iroh::header("x")).unwrap();
    let mut wire = u32::try_from(header.len()).unwrap().to_be_bytes().to_vec();
    wire.extend_from_slice(&header);
    wire.extend_from_slice(&length);
    let outcome = client.runtime().block_on(async {
        let connection = client
            .endpoint()
            .connect(client.seller().clone(), a2a_iroh::ALPN)
            .await
            .map_err(|e| e.to_string())?;
        let (mut send, mut recv) = connection.open_bi().await.map_err(|e| e.to_string())?;
        send.write_all(&wire).await.map_err(|e| e.to_string())?;
        let mut byte = [0u8; 1];
        recv.read_exact(&mut byte).await.map_err(|e| e.to_string())
    });
    assert!(outcome.is_err(), "an oversize frame was answered");
}

#[test]
fn c14_a_stream_delivers_the_task_then_each_change_in_order_and_ends_when_it_waits() {
    let world = World::new();
    let buyer = keys("buyer");
    let client = world.a2a(&buyer);
    let all = messages();
    let frames = rpc_all(
        &client,
        &buyer,
        "SendStreamingMessage",
        &opening(&buyer),
        50,
    );
    assert!(frames.len() >= 2, "{frames:?}");
    for frame in &frames {
        assert_eq!(frame["jsonrpc"], "2.0");
        assert_eq!(frame["id"], 1);
        conforms(&all, "StreamResponse", &frame["result"], "event");
    }
    let first = &frames[0]["result"]["task"];
    assert_eq!(state(first), "TASK_STATE_SUBMITTED");
    let id = first["id"].as_str().unwrap();
    let states: Vec<&str> = frames[1..]
        .iter()
        .map(|frame| {
            let update = &frame["result"]["statusUpdate"];
            assert_eq!(update["taskId"], json!(id), "{frame}");
            update["status"]["state"].as_str().unwrap()
        })
        .collect();
    // In the order they happened, and the stream ended where the task waits
    // on the caller: nothing follows the payment request.
    assert_eq!(
        states.last(),
        Some(&"TASK_STATE_INPUT_REQUIRED"),
        "{states:?}"
    );
    assert!(
        states[..states.len() - 1]
            .iter()
            .all(|state| *state == "TASK_STATE_WORKING"),
        "{states:?}"
    );

    // Subscribing to a task that waits on the caller gives its state and ends.
    let resumed = rpc_all(&client, &buyer, "SubscribeToTask", &json!({"id": id}), 50);
    assert_eq!(resumed.len(), 1, "{resumed:?}");
    assert_eq!(
        state(&resumed[0]["result"]["task"]),
        "TASK_STATE_INPUT_REQUIRED"
    );
}

#[test]
fn c14_a_caller_that_stops_reading_ends_the_stream_and_not_the_task() {
    let world = World::new();
    let buyer = keys("buyer");
    let client = world.a2a(&buyer);
    // Read one frame, then stop the stream.
    let frames = rpc_all(&client, &buyer, "SendStreamingMessage", &opening(&buyer), 1);
    let id = frames[0]["result"]["task"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // The task went on to its offer without anyone watching.
    assert_eq!(
        state(&await_offer(&client, &buyer, &id)),
        "TASK_STATE_INPUT_REQUIRED"
    );
}

#[test]
fn c14_a_finished_task_cannot_be_subscribed_to() {
    // The prover's artifact proves nothing, so the task is rejected.
    let world = World::with_artifact(&format!("{FIXTURES}/task.ndjson"));
    let buyer = keys("buyer");
    let client = world.a2a(&buyer);
    let id = open(&client, &buyer);
    let ended = await_offer(&client, &buyer, &id);
    assert_eq!(state(&ended), "TASK_STATE_REJECTED", "{ended}");
    conforms(&messages(), "Task", &ended, "rejected");
    let answer = rpc(&client, &buyer, "SubscribeToTask", &json!({"id": id}));
    assert_eq!(
        reason(&answer),
        (a2a::UNSUPPORTED_OPERATION, "UNSUPPORTED_OPERATION".into())
    );
}

#[test]
fn c15_operations_this_agent_does_not_offer_answer_with_the_a2a_error_for_them() {
    let world = World::new();
    let buyer = keys("buyer");
    let client = world.a2a(&buyer);
    let id = open(&client, &buyer);
    for method in [
        "CreateTaskPushNotificationConfig",
        "GetTaskPushNotificationConfig",
        "ListTaskPushNotificationConfigs",
        "DeleteTaskPushNotificationConfig",
    ] {
        let answer = rpc(&client, &buyer, method, &json!({"taskId": id}));
        assert_eq!(answer["error"]["code"], a2a::PUSH_NOT_SUPPORTED, "{method}");
    }
    let card = rpc(&client, &buyer, "GetExtendedAgentCard", &json!({}));
    assert_eq!(card["error"]["code"], a2a::EXTENDED_CARD_NOT_CONFIGURED);
    let cancel = rpc(&client, &buyer, "CancelTask", &json!({"id": id}));
    assert_eq!(cancel["error"]["code"], a2a::TASK_NOT_CANCELABLE);
    let cancel = rpc(
        &client,
        &buyer,
        "CancelTask",
        &json!({"id": format!("0x{}", "11".repeat(32))}),
    );
    assert_eq!(cancel["error"]["code"], a2a::TASK_NOT_FOUND);
}

/// The reply sequence of the buyer's own flow, as far as the offer.
fn flow(transport: &dyn Transport, keys: &Keys) -> (String, Vec<u16>, Value) {
    let first = ask(
        transport,
        keys,
        "POST",
        "/work",
        declaration(keys),
        work_body(),
    )
    .unwrap();
    let mut statuses = vec![first.status];
    let job = first.header("location").unwrap().to_owned();
    let mut offer = Reply::new(0);
    for _ in 0..200 {
        offer = ask(transport, keys, "GET", &job, BTreeMap::new(), vec![]).unwrap();
        if offer.status != 202 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    statuses.push(offer.status);
    let required: Value =
        serde_json::from_slice(&B64.decode(offer.header(REQUIRED_HEADER).unwrap()).unwrap())
            .unwrap();
    (job, statuses, required)
}

#[test]
fn c17_the_same_intent_through_either_adapter_reaches_the_same_handler_state() {
    let world = World::new();
    let buyer = keys("buyer");
    let (plain, a2a) = (world.plain(&buyer), world.a2a(&buyer));
    // The buyer's flow, unchanged, over each adapter: same job, same statuses,
    // same offer. (The job ID is the request's hash under this key, so the
    // second run names the job the first one opened.)
    let (job, statuses, offer) = flow(&plain, &buyer);
    let (job_a2a, statuses_a2a, offer_a2a) = flow(&a2a, &buyer);
    assert_eq!(job, job_a2a);
    assert_eq!(statuses, statuses_a2a);
    assert_eq!(offer, offer_a2a);

    // Pay over A2A what was quoted over the other adapter: one job, one
    // acceptance, and the other adapter then sees it paid for.
    let now = wall_clock().unwrap();
    let uri = format!("{}/work", plain.base());
    let intent = vault_wire::Intent {
        wallet: buyer.address(),
        asset: world.terms.token,
        policy_hash: policy().hash(),
        context: vault_wire::context(request_hash("POST", &uri, &work_body()), buyer.binding()),
        maximum_amount: [&[0u8; 24][..], &250_000u64.to_be_bytes()]
            .concat()
            .try_into()
            .unwrap(),
        verifiers: vec![world.terms.verifier],
        programs: vec![world.terms.program],
        fund_no_earlier_than: now + 60,
        deliver_no_later_than: now + 8 * 3600,
        bases: vec![],
    };
    let header = B64.encode(serde_json::to_vec(&offer).unwrap());
    let reviewed = vault_wire::review_offer(
        &world.terms.deployment,
        &world.terms.domain,
        &header,
        &intent,
        now,
    )
    .unwrap();
    let signature = nucleus_commerce_agents::sign(&buyer.wallet, reviewed.signing_digest());
    let payment =
        vault_wire::signature_header(&world.terms.deployment, reviewed, &signature).unwrap();
    let paid = ask(
        &a2a,
        &buyer,
        "POST",
        &job,
        [(SIGNATURE_HEADER.to_ascii_lowercase(), payment.clone())].into(),
        vec![],
    )
    .unwrap();
    assert_eq!(paid.status, 202, "{}", String::from_utf8_lossy(&paid.body));
    assert_eq!(world.accepted.0.lock().unwrap().len(), 1);
    let seen = ask(&plain, &buyer, "GET", &job, BTreeMap::new(), vec![]).unwrap();
    assert_eq!(
        (seen.status, seen.header("nucleus-job")),
        (202, Some("funding"))
    );
    // And the quote is spent for both.
    let again = ask(
        &plain,
        &buyer,
        "POST",
        &job,
        [(SIGNATURE_HEADER.to_ascii_lowercase(), payment)].into(),
        vec![],
    )
    .unwrap();
    assert_eq!(again.status, 409);
    assert_eq!(world.accepted.0.lock().unwrap().len(), 1);
}

#[test]
fn c18_the_proto_reader_refuses_what_the_proto_does_not_have() {
    let all = messages();
    let good = json!({"id": "t", "status": {"state": "TASK_STATE_WORKING"}});
    conforms(&all, "Task", &good, "task");
    for bad in [
        json!({"status": {"state": "TASK_STATE_WORKING"}}),
        json!({"id": "t", "status": {}}),
        json!({"id": "t", "status": {"state": "x"}, "kind": "task"}),
    ] {
        let all = all.clone();
        assert!(std::panic::catch_unwind(move || conforms(&all, "Task", &bad, "task")).is_err());
    }
}
