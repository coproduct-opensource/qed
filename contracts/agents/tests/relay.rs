//! Reaching a node by its ID alone, through a relay this test starts
//! (docs/rfcs/proof-commerce-cross-machine-2026-11-13.md, pass/fail 3). No
//! socket address is exchanged and the public internet is not used. The
//! handler runs the same proof-of-possession check the seller and the
//! buyer's desk run, so the test also shows that check holds through a relay.
use iroh::{endpoint::Builder, tls::CaTlsConfig};
use nucleus_commerce_agents::{
    buyer::ask,
    dpop,
    iroh_net::{self, IrohTransport, Relay},
    message::{Handler, Reply, Request, Transport, Via},
    support::Keys,
    world::wall_clock,
};
use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
};

/// Answers 200 with the caller's node ID when the request carries a valid
/// fresh proof bound to that node, and refuses otherwise.
#[derive(Default)]
struct Guarded(HashSet<String>);
impl Handler for Guarded {
    fn handle(&mut self, via: &Via, request: &Request) -> Reply {
        match dpop::authenticate(via, request, wall_clock().unwrap(), &mut self.0) {
            Ok(_) => Reply::text(200, via.peer.as_deref().unwrap_or("")),
            Err((status, why)) => Reply::text(status, &why),
        }
    }
}

fn keys(name: &str) -> Keys {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("relay-{}-{name}.keys", std::process::id()));
    let _ = std::fs::remove_file(&path);
    Keys::load_or_create(path.to_str().unwrap()).unwrap()
}
/// Trust the self-signed certificate of the relay started below.
fn trusting(builder: Builder) -> Builder {
    builder.ca_tls_config(CaTlsConfig::insecure_skip_verify())
}

#[test]
fn a_node_is_reached_by_id_alone_through_a_relay_and_the_proof_is_still_checked() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (_map, url, _relay) = runtime
        .block_on(iroh::test_utils::run_relay_server())
        .unwrap();
    let relay = Relay::Url(url);
    let (server_keys, client_keys) = (keys("server"), keys("client"));

    let server = runtime
        .block_on(async {
            iroh_net::endpoint_with(
                server_keys.node,
                "127.0.0.1:0".parse().unwrap(),
                &relay,
                trusting,
            )
            .await
            .map_err(|e| e.to_string())
        })
        .unwrap();
    // What the server hands out: its node ID and nothing else.
    let address = iroh_net::address_text_in(&server, &relay).unwrap();
    assert_eq!(address, format!("iroh:{}", server.id()));
    assert!(!address.contains('@'));
    let _router = {
        let _guard = runtime.enter();
        iroh_net::serve(server, Arc::new(Mutex::new(Guarded::default())))
    };

    let client_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let client = client_runtime
        .block_on(async {
            iroh_net::endpoint_with(
                client_keys.node,
                "127.0.0.1:0".parse().unwrap(),
                &relay,
                trusting,
            )
            .await
            .map_err(|e| e.to_string())
        })
        .unwrap();
    let target = iroh_net::parse_address_in(&address, &relay).unwrap();
    assert_eq!(target.ip_addrs().count(), 0, "no socket address was given");
    let client_node = client.id().to_string();
    let transport = IrohTransport::over(client_runtime, client, target);

    // A request with a fresh proof bound to this caller's node is answered.
    let reply = ask(
        &transport,
        &client_keys,
        "GET",
        "/hello",
        BTreeMap::new(),
        vec![],
    )
    .unwrap();
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    assert_eq!(String::from_utf8_lossy(&reply.body), client_node);

    // Through the relay the checks are the same: no proof, no answer.
    let bare = transport
        .send(&Request {
            method: "GET".into(),
            path: "/hello".into(),
            headers: BTreeMap::new(),
            body: vec![],
        })
        .unwrap();
    assert_eq!(bare.status, 401);
    // A proof that names another node than the one iroh authenticated.
    let uri = format!("{}/hello", transport.base());
    let lifted = dpop::dpop_make(
        &client_keys.possession,
        "GET",
        &uri,
        wall_clock().unwrap(),
        Some(&server_keys_node_text(&server_keys)),
    )
    .unwrap();
    let wrong_node = transport
        .send(&Request {
            method: "GET".into(),
            path: "/hello".into(),
            headers: [("dpop".to_owned(), lifted)].into(),
            body: vec![],
        })
        .unwrap();
    assert_eq!(wrong_node.status, 401);
}

fn server_keys_node_text(keys: &Keys) -> String {
    iroh::SecretKey::from_bytes(&keys.node).public().to_string()
}

#[test]
fn without_a_relay_a_node_id_alone_reaches_nobody() {
    let keys = keys("alone");
    let node = server_keys_node_text(&keys);
    let refused = IrohTransport::new(keys.node, &format!("iroh:{node}"));
    assert!(refused.is_err());
}
