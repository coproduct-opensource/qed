//! The iroh adapter: the seller's handler behind an iroh endpoint, and a
//! buyer's client for it.
//!
//! ALPN `nucleus-commerce/1`. One request and one reply per bidirectional
//! stream, framed as `message.rs` says. iroh authenticates the node at each
//! end of the connection; that is the transport identity, as mTLS would be.
//! It is not what authorizes a request: every request still carries a fresh
//! DPoP proof, and the proof names the caller's node ID, which the seller
//! compares with the node iroh authenticated.
//!
//! Endpoints here use iroh's `Minimal` preset: no relay and no address
//! lookup service. A buyer therefore needs the seller's socket address as
//! well as its node ID, written `iroh:<node id>@<ip:port>`.
use crate::chain::Res;
use crate::message::{Handler, MAXIMUM_BODY, MAXIMUM_HEAD, Reply, Request, Transport, Via};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey,
    endpoint::{Builder, Connection, RecvStream, SendStream, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

pub const ALPN: &[u8] = b"nucleus-commerce/1";
/// A handler shared between an adapter's connections.
pub type Shared = Arc<Mutex<dyn Handler>>;
/// How long one request may take to arrive, and one reply to be read.
const EXCHANGE: Duration = Duration::from_secs(60);
/// How long a relay-mode endpoint may take to find its home relay.
const ONLINE: Duration = Duration::from_secs(30);

/// A length-prefixed part, refused above `limit` before any of it is read.
async fn read_part(recv: &mut RecvStream, limit: usize) -> Result<Vec<u8>, Reply> {
    let bad = |_| Reply::text(400, "truncated message");
    let mut length = [0u8; 4];
    recv.read_exact(&mut length).await.map_err(bad)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > limit {
        return Err(Reply::text(413, "message too large"));
    }
    let mut bytes = vec![0; length];
    recv.read_exact(&mut bytes).await.map_err(bad)?;
    Ok(bytes)
}
async fn read_request(recv: &mut RecvStream) -> Result<Request, Reply> {
    let head = read_part(recv, MAXIMUM_HEAD).await?;
    let body = read_part(recv, MAXIMUM_BODY).await?;
    Request::from_parts(&head, body).map_err(|e| Reply::text(400, &e.to_string()))
}
async fn write_reply(send: &mut SendStream, reply: &Reply) {
    // The error type is not `Send`; drop it before awaiting.
    let encoded = reply.encode().ok();
    if let Some(bytes) = encoded {
        let _ = send.write_all(&bytes).await;
    }
    let _ = send.finish();
}

/// A handler (the seller, or a buyer's desk) as an iroh protocol.
#[derive(Clone)]
pub struct Commerce {
    seller: Shared,
    /// This endpoint's node ID, as callers must name it in `htu`.
    node: String,
}
impl Commerce {
    /// `node` is this endpoint's node ID, as callers must name it in `htu`.
    pub fn new(seller: Shared, node: String) -> Self {
        Self { seller, node }
    }
}
impl std::fmt::Debug for Commerce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Commerce({})", self.node)
    }
}

impl ProtocolHandler for Commerce {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let via = Via {
            base: format!("iroh://{}", self.node),
            // The node iroh authenticated at the other end of this connection.
            peer: Some(connection.remote_id().to_string()),
            owner: None,
        };
        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
            let request = match tokio::time::timeout(EXCHANGE, read_request(&mut recv)).await {
                Ok(Ok(request)) => request,
                Ok(Err(reply)) => {
                    write_reply(&mut send, &reply).await;
                    continue;
                }
                Err(_) => {
                    write_reply(&mut send, &Reply::text(408, "request timed out")).await;
                    continue;
                }
            };
            let (seller, via) = (self.seller.clone(), via.clone());
            let reply = tokio::task::spawn_blocking(move || match seller.lock() {
                Ok(mut seller) => seller.handle(&via, &request),
                Err(_) => Reply::text(500, "seller state poisoned"),
            })
            .await
            .unwrap_or_else(|_| Reply::text(500, "handler failed"));
            write_reply(&mut send, &reply).await;
        }
        Ok(())
    }
}

/// How a node is reachable beyond a socket address someone was told
/// (docs/rfcs/proof-commerce-cross-machine-2026-11-13.md).
///
/// A relay forwards ciphertext between two node keys. It learns who talks to
/// whom and can drop traffic; it cannot read or alter it, and no check in
/// this crate is delegated to it.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Relay {
    /// No relay and no address lookup: a peer needs this node's socket address.
    #[default]
    None,
    /// number 0's public relays and address lookup: a node ID is enough.
    Default,
    /// One relay the operator names, and no address lookup: a peer needs the
    /// node ID and the same relay in its own configuration.
    Url(RelayUrl),
}

/// The environment variable the buyer and the operations tool read; the
/// seller reads `"relay"` from its configuration file.
pub const RELAY_VARIABLE: &str = "NUCLEUS_RELAY";

impl Relay {
    /// `none`, `default`, or an `https://` URL. Anything else is refused:
    /// there is no fallback from one mode to another.
    pub fn parse(text: &str) -> Res<Self> {
        match text {
            "none" => Ok(Self::None),
            "default" => Ok(Self::Default),
            url if url.starts_with("https://") => Ok(Self::Url(
                url.parse().map_err(|e| format!("relay URL: {e}"))?,
            )),
            other => Err(format!(
                "relay must be `none`, `default` or an https:// URL, not {other:?}"
            )
            .into()),
        }
    }
    /// What `NUCLEUS_RELAY` says; unset is `none`.
    pub fn from_environment() -> Res<Self> {
        match std::env::var(RELAY_VARIABLE) {
            Ok(text) => Self::parse(&text),
            Err(std::env::VarError::NotPresent) => Ok(Self::None),
            Err(error) => Err(error.into()),
        }
    }
}

/// An iroh endpoint with this node key, bound to `bind`, with no relay and no
/// address lookup.
pub async fn endpoint(node_key: [u8; 32], bind: SocketAddr) -> Res<Endpoint> {
    endpoint_in(node_key, bind, &Relay::None).await
}

/// An iroh endpoint with this node key, bound to `bind`, in a relay mode. In
/// a relay mode it returns once the endpoint has a home relay, so the node
/// can be dialled by ID as soon as its ID is published.
pub async fn endpoint_in(node_key: [u8; 32], bind: SocketAddr, relay: &Relay) -> Res<Endpoint> {
    endpoint_with(node_key, bind, relay, |builder| builder).await
}

/// As `endpoint_in`, with a last adjustment to iroh's builder. The agents
/// pass none; a test uses it to trust the certificate of a relay it started
/// itself.
pub async fn endpoint_with(
    node_key: [u8; 32],
    bind: SocketAddr,
    relay: &Relay,
    adjust: impl FnOnce(Builder) -> Builder,
) -> Res<Endpoint> {
    let key = SecretKey::from_bytes(&node_key);
    let builder = match relay {
        Relay::None => Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .clear_relay_transports(),
        Relay::Default => Endpoint::builder(presets::N0).secret_key(key),
        Relay::Url(url) => Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(RelayMode::Custom(RelayMap::from(url.clone()))),
    };
    let endpoint = adjust(builder).bind_addr(bind)?.bind().await?;
    if *relay != Relay::None {
        tokio::time::timeout(ONLINE, endpoint.online())
            .await
            .map_err(|_| "no relay answered; the node is not reachable by ID")?;
    }
    Ok(endpoint)
}

/// Serve a handler on this endpoint. The returned router keeps serving until
/// it is shut down or dropped.
pub fn serve(endpoint: Endpoint, handler: Shared) -> Router {
    serve_with(endpoint, handler, None)
}

/// As `serve`, and also serve the blobs in `store` (crate::blobs) to whoever
/// asks for one by its BLAKE3 hash.
pub fn serve_with(
    endpoint: Endpoint,
    handler: Shared,
    store: Option<&crate::blobs::Store>,
) -> Router {
    let node = endpoint.id().to_string();
    let router = Router::builder(endpoint).accept(
        ALPN,
        Commerce {
            seller: handler,
            node,
        },
    );
    match store {
        Some(store) => router
            .accept(crate::blobs::ALPN, crate::blobs::protocol(store))
            .spawn(),
        None => router.spawn(),
    }
}

/// `iroh:<node id>@<ip:port>` for an endpoint and one of its bound sockets.
pub fn address_text(endpoint: &Endpoint) -> Res<String> {
    let socket = endpoint
        .bound_sockets()
        .into_iter()
        .find(SocketAddr::is_ipv4)
        .ok_or("endpoint has no IPv4 socket")?;
    Ok(format!("iroh:{}@{socket}", endpoint.id()))
}
pub fn parse_address(text: &str) -> Res<EndpointAddr> {
    parse_address_in(text, &Relay::None)
}
/// `iroh:<node id>@<ip:port>`, or in a relay mode `iroh:<node id>` alone. A
/// socket address, when given, is an extra hint in a relay mode and the only
/// route in `none` mode, where an address without one is refused: nothing
/// could resolve it.
pub fn parse_address_in(text: &str, relay: &Relay) -> Res<EndpointAddr> {
    let rest = text
        .strip_prefix("iroh:")
        .ok_or("expected iroh:<node id> or iroh:<node id>@<ip:port>")?;
    let (node, socket) = match rest.split_once('@') {
        Some((node, socket)) if !socket.is_empty() => (node, Some(socket)),
        Some((node, _)) => (node, None),
        None => (rest, None),
    };
    let node: EndpointId = node.parse().map_err(|_| "node id")?;
    let mut address = EndpointAddr::new(node);
    if let Some(socket) = socket {
        address = address.with_ip_addr(socket.parse()?);
    }
    match (relay, socket) {
        (Relay::None, None) => {
            Err("with relay `none` a node needs a socket address: iroh:<node id>@<ip:port>".into())
        }
        (Relay::Url(url), _) => Ok(address.with_relay_url(url.clone())),
        (Relay::None | Relay::Default, _) => Ok(address),
    }
}
/// What to hand a peer so it can reach this endpoint: with a relay, the node
/// ID alone; without, the node ID and a bound socket.
pub fn address_text_in(endpoint: &Endpoint, relay: &Relay) -> Res<String> {
    match relay {
        Relay::None => address_text(endpoint),
        Relay::Default | Relay::Url(_) => Ok(format!("iroh:{}", endpoint.id())),
    }
}

/// Which kind of path a connection is using right now, for the record:
/// `direct <address>` after a successful hole punch or on a routable address,
/// `relay <url>` while packets go through a relay.
pub fn path_text(connection: &Connection) -> String {
    let mut seen = vec![];
    for path in connection.paths().iter() {
        let kind = if path.is_relay() { "relay" } else { "direct" };
        let chosen = if path.is_selected() { "selected " } else { "" };
        seen.push(format!("{chosen}{kind} {:?}", path.remote_addr()));
    }
    if seen.is_empty() {
        "no path yet".into()
    } else {
        seen.join("; ")
    }
}

/// Send one request on a fresh connection and read the reply.
pub async fn exchange(endpoint: &Endpoint, seller: &EndpointAddr, frame: Vec<u8>) -> Res<Reply> {
    let work = async {
        let connection = endpoint.connect(seller.clone(), ALPN).await?;
        let (mut send, mut recv) = connection.open_bi().await?;
        send.write_all(&frame).await?;
        send.finish()?;
        let head = read_part(&mut recv, MAXIMUM_HEAD)
            .await
            .map_err(|reply| String::from_utf8_lossy(&reply.body).into_owned())?;
        let body = read_part(&mut recv, MAXIMUM_BODY)
            .await
            .map_err(|reply| String::from_utf8_lossy(&reply.body).into_owned())?;
        // For the record of a run: whether this exchange went direct or
        // through a relay. Nothing depends on it.
        eprintln!(
            "iroh: reply from {} over {}",
            connection.remote_id(),
            path_text(&connection)
        );
        connection.close(0u32.into(), b"done");
        Reply::from_parts(&head, body)
    };
    tokio::time::timeout(EXCHANGE, work)
        .await
        .map_err(|_| "exchange timed out")?
}

/// A buyer's iroh client for one seller. Blocking, for the buyer's
/// straight-line code.
pub struct IrohTransport {
    pub(crate) runtime: tokio::runtime::Runtime,
    pub(crate) endpoint: Endpoint,
    pub(crate) seller: EndpointAddr,
}
impl IrohTransport {
    pub fn new(node_key: [u8; 32], seller: &str) -> Res<Self> {
        Self::new_in(node_key, seller, &Relay::None)
    }
    /// A client over an endpoint the caller built.
    pub fn over(
        runtime: tokio::runtime::Runtime,
        endpoint: Endpoint,
        seller: EndpointAddr,
    ) -> Self {
        Self {
            runtime,
            endpoint,
            seller,
        }
    }
    /// As `new`, in a relay mode: `seller` may then be `iroh:<node id>` alone.
    pub fn new_in(node_key: [u8; 32], seller: &str, relay: &Relay) -> Res<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let seller = parse_address_in(seller, relay)?;
        let endpoint = runtime
            .block_on(async { endpoint_in(node_key, "0.0.0.0:0".parse()?, relay).await })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            runtime,
            endpoint,
            seller,
        })
    }
}
impl Transport for IrohTransport {
    fn base(&self) -> String {
        format!("iroh://{}", self.seller.id)
    }
    fn node(&self) -> Option<String> {
        Some(self.endpoint.id().to_string())
    }
    fn send(&self, request: &Request) -> Res<Reply> {
        let frame = request.encode()?;
        self.runtime
            .block_on(async {
                exchange(&self.endpoint, &self.seller, frame)
                    .await
                    .map_err(|e| e.to_string())
            })
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> String {
        SecretKey::from_bytes(&[7; 32]).public().to_string()
    }

    #[test]
    fn relay_is_none_default_or_an_https_url_and_nothing_else() {
        assert_eq!(Relay::parse("none").unwrap(), Relay::None);
        assert_eq!(Relay::parse("default").unwrap(), Relay::Default);
        assert!(matches!(
            Relay::parse("https://relay.example.org").unwrap(),
            Relay::Url(_)
        ));
        for refused in [
            "",
            "None",
            "DEFAULT",
            "staging",
            "http://relay.example.org",
            "relay.example.org",
            "https://",
        ] {
            assert!(
                Relay::parse(refused).is_err(),
                "{refused:?} must be refused"
            );
        }
    }

    #[test]
    fn a_node_id_alone_is_an_address_only_where_something_can_resolve_it() {
        let node = node();
        let socket = "127.0.0.1:4450";
        let url: RelayUrl = "https://relay.example.org".parse().unwrap();
        let alone = format!("iroh:{node}");
        let hinted = format!("iroh:{node}@{socket}");
        // The form a board post with an empty hint produces.
        let empty_hint = format!("iroh:{node}@");

        // No relay: a socket address is the only route.
        assert!(parse_address_in(&alone, &Relay::None).is_err());
        assert!(parse_address_in(&empty_hint, &Relay::None).is_err());
        let direct = parse_address_in(&hinted, &Relay::None).unwrap();
        assert_eq!(direct.ip_addrs().count(), 1);
        assert_eq!(direct.relay_urls().count(), 0);
        assert_eq!(parse_address(&hinted).unwrap(), direct);

        // number 0's lookup resolves the ID; nothing is added to the address.
        for text in [&alone, &empty_hint] {
            let by_id = parse_address_in(text, &Relay::Default).unwrap();
            assert_eq!(by_id.id.to_string(), node);
            assert_eq!(by_id.ip_addrs().count(), 0);
            assert_eq!(by_id.relay_urls().count(), 0);
        }
        assert_eq!(
            parse_address_in(&hinted, &Relay::Default)
                .unwrap()
                .ip_addrs()
                .count(),
            1
        );

        // A named relay: the dialler's own relay is the route.
        let relayed = parse_address_in(&alone, &Relay::Url(url.clone())).unwrap();
        assert_eq!(relayed.relay_urls().collect::<Vec<_>>(), vec![&url]);
        assert_eq!(relayed.ip_addrs().count(), 0);

        for bad in ["", "iroh:", "iroh:not-a-node", &node, "iroh:@127.0.0.1:1"] {
            assert!(parse_address_in(bad, &Relay::Default).is_err(), "{bad:?}");
        }
        assert!(parse_address_in(&format!("iroh:{node}@nowhere"), &Relay::Default).is_err());
    }
}
