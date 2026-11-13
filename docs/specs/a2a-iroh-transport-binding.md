# A2A over iroh: a custom protocol binding

**Status:** draft. **Binding version:** 0.2. **A2A protocol version:** 1.0.

This document specifies a custom protocol binding, in the sense of section 12
of the Agent2Agent (A2A) Protocol Specification, version 1.0, that carries
A2A's JSON-RPC payloads over [iroh](https://iroh.computer) connections. An
agent is addressed by a public key and not by a host name, and needs no HTTP
server, DNS name or certificate authority.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, MAY and
OPTIONAL are to be interpreted as described in RFC 2119 and RFC 8174.

This is not an official A2A binding. Its identifiers are outside the
`https://a2a-protocol.org/` namespace, which that project reserves.

## 1. Scope

**In scope.** How an Agent Card declares an iroh interface; how the card is
fetched over iroh; how each A2A operation is carried on an iroh stream,
including the two streaming operations; how service parameters and errors are
carried; and a per-request proof of possession that this binding requires.

**Not in scope.** The A2A data model and operation semantics, which are
those of the A2A specification unchanged. How an agent's node identifier
becomes known to a client in the first place (a registry, a ledger, a card
published elsewhere). Push notifications (section 8).

### 1.1. Relation to the A2A specification

A2A 1.0 section 12 says implementers "MAY create custom protocol bindings to
support additional transport mechanisms" and that such bindings "MUST comply
with all requirements defined in Section 5". Section 12.1 requires a custom
binding to implement all core operations, preserve the data model, maintain
semantics and be documented completely. This document is that documentation.
Sections 3 to 9 below answer, in order, sections 12.7, 12.2, 12.3, 12.5, 12.6
and 12.4 of the A2A specification.

An agent MAY offer this binding as its only interface. An agent that offers
several bindings MUST satisfy A2A 1.0 section 5.1 across them.

## 2. Terms

- **Node.** An iroh endpoint. Its **node ID** is its Ed25519 public key,
  written as 64 lowercase hexadecimal characters.
- **Agent.** The A2A server. **Client.** The A2A client. Both are nodes.
- **Frame.** A length-prefixed byte string on a stream (section 5.1).
- **Possession key.** A signing key held by the client, distinct from its
  node key, that identifies the client to the agent across connections and
  nodes (section 7).

## 3. Identification and the Agent Card

### 3.1. Binding identifier

The `protocolBinding` value of this binding version is:

    https://coproduct.one/a2a/ext/iroh-binding/v1

It is a URI, as A2A 1.0 section 5.8 recommends. A document describing the
binding is published at that URI, as the A2A extension guidance recommends
for extension identifiers; the identifier is the string, not the document. A
breaking change to this binding MUST use a new identifier. Identifiers used
by earlier versions are listed in Appendix A and MUST NOT be treated as
equivalent to this one.

### 3.2. Interface URL

An interface of this binding is declared in `supportedInterfaces` with:

- `protocolBinding`: the identifier of section 3.1;
- `protocolVersion`: `"1.0"`;
- `url`: an **iroh URL**, `iroh://<node-id>`, optionally followed by a query
  with address hints.

```json
{
  "supportedInterfaces": [{
    "url": "iroh://81aa72ef0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899a552d",
    "protocolBinding": "https://coproduct.one/a2a/ext/iroh-binding/v1",
    "protocolVersion": "1.0"
  }]
}
```

The `iroh` URL scheme is defined by this document for this purpose; it is not
registered. The authority is the agent's node ID and nothing else. The query,
when present, carries hints as `relay=<https URL>` and zero or more
`addr=<ip:port>`:

    iroh://<node-id>?relay=https%3A%2F%2Frelay.example%2F&addr=203.0.113.7%3A4433

Hints help a client reach the node. They are not part of the agent's
identity: two URLs with the same node ID name the same interface. A client
MUST treat hints as untrusted input (section 10.4). A client configured with
an address-lookup service MAY ignore them.

### 3.3. Required card entries

An agent offering this binding MUST declare, in `capabilities.extensions`,
the possession-proof profile of section 7 with `required: true`:

```json
{
  "uri": "https://coproduct.one/a2a/ext/iroh-possession/v1",
  "required": true,
  "params": {"alg": ["ES256"], "typ": "a2a-iroh-pop+jwt", "maximumSkewSeconds": 120}
}
```

A2A 1.0 offers five kinds of security scheme, none of which describes a
proof of possession that is not HTTP. An agent SHOULD declare a
`mtlsSecurityScheme` to state that the transport authenticates both nodes,
which is true of every iroh connection, and MUST NOT declare a bearer or API
key scheme for this interface.

`capabilities.pushNotifications` MUST be `false` or absent for an agent whose
only interface is this binding (section 8). `capabilities.streaming` MUST be
`true` if the agent serves the streaming operations and `false` or absent
otherwise.

### 3.4. Fetching the card over iroh

An agent MUST serve its Agent Card on this binding's ALPN (section 4) in
answer to a **well-known request**: a stream on which the client writes one
frame, the JSON object

```json
{"a2a-iroh-well-known": "agent-card.json"}
```

and finishes its side. The agent answers with one frame holding the Agent
Card as JSON and finishes. No proof of possession is required. For any other
well-known name the agent MUST finish the stream without a frame.

The card fetched this way comes from the node the client dialled: iroh
authenticated that node's key. So the client knows that the holder of the
node key published this card. It does not know that any claim in the card is
true, nor that the same organisation publishes a card elsewhere. A client
MUST check that the card lists an interface whose `url` names the node it
dialled, and SHOULD refuse a card that does not. Agent Card signatures (A2A
1.0 section 8.4) apply unchanged and are independent of this.

## 4. Connection

- **ALPN.** `x-a2a-jsonrpc/draft-0.1`. A node serving this binding MUST
  accept connections for this ALPN. The name is a draft name under no
  registered prefix. It names the wire format, which version 0.2 of this
  binding did not change; a version that changes the wire format will use
  another.
- **Authentication.** iroh connections are QUIC with TLS 1.3 in which both
  sides present raw public keys. The agent learns the client's node ID and
  the client the agent's. Implementations MUST use the node ID iroh reports
  for the connection and MUST NOT accept one from message content.
- **Early data.** A client MUST NOT send requests in 0-RTT data.
- **Reuse.** A client MAY open any number of streams on one connection, at
  once or in sequence, and MAY open a new connection per request. An agent
  MUST handle streams independently: one stream's failure or slowness MUST
  NOT end another.
- **Relays and address lookup** are deployment choices outside this binding.

## 5. Carrying an operation

### 5.1. Frames

A frame is a 4-byte unsigned big-endian length `n` followed by `n` bytes.
Every frame defined here holds one UTF-8 JSON value.

| frame | limit |
|---|---|
| header frame | 16,384 bytes |
| request frame, response frame | 25,165,824 bytes (24 MiB) |

A receiver MUST check a frame's length against its limit before reading the
frame's bytes, and on excess MUST reset the stream with application error
code 1 and read no further. An agent MAY advertise lower limits out of band;
it MUST NOT require higher ones.

### 5.2. One operation per stream

Each A2A operation uses one bidirectional stream opened by the client.

The client writes exactly two frames and then finishes its sending side:

1. the **header frame**: a JSON object of service parameters (section 6),
   including the possession proof;
2. the **request frame**: a JSON-RPC 2.0 request object exactly as A2A 1.0
   section 9 defines it, with a string or number `id`.

The agent writes one **response frame**, a JSON-RPC 2.0 response object, and
finishes its sending side. For the streaming operations it writes one or
more response frames (section 5.4) and then finishes.

JSON-RPC batch requests MUST NOT be sent; an agent MUST answer an array with
error `-32600`. JSON-RPC notifications (requests without `id`) MUST NOT be
sent and are answered with `-32600` and a null `id`.

A client that has not received the first response frame 60 seconds after
finishing its side MAY reset the stream. An agent MAY reset a stream whose
two frames have not arrived 60 seconds after it was opened.

### 5.3. Methods and data types

Method names, parameters and results are those of A2A 1.0 section 9.4:
`SendMessage`, `SendStreamingMessage`, `GetTask`, `ListTasks`, `CancelTask`,
`SubscribeToTask`, `CreateTaskPushNotificationConfig`,
`GetTaskPushNotificationConfig`, `ListTaskPushNotificationConfigs`,
`DeleteTaskPushNotificationConfig` and `GetExtendedAgentCard`.

Data types are A2A's JSON representation unchanged: field names in
camelCase, enumerations as their string names (`TASK_STATE_WORKING`,
`ROLE_USER`), timestamps as ISO 8601 strings in UTC, and binary content as
standard base64 in the `raw` member of a `Part`.

### 5.4. Streaming

`SendStreamingMessage` and `SubscribeToTask` are answered with a sequence of
response frames on the same stream. Each frame is a complete JSON-RPC
response whose `id` is the request's and whose `result` is one A2A
`StreamResponse`. This replaces the Server-Sent Events of the HTTP binding;
there is no other event framing.

- **Order.** The agent MUST write events in the order they were generated. A
  QUIC stream delivers bytes in order, so the client receives them in that
  order.
- **Termination.** The agent MUST finish the stream after the event that
  reports a terminal state or an interrupted state (`TASK_STATE_INPUT_REQUIRED`,
  `TASK_STATE_AUTH_REQUIRED`), and MUST NOT write events after it. A finished
  stream with no further frame is the end of the stream.
- **Errors.** An error before the first event is a single response frame
  with `error`. An error after events have been written is a final response
  frame with `error`, after which the agent finishes the stream.
- **Cancellation.** A client that no longer wants events stops reading the
  stream (QUIC `STOP_SENDING`). The agent MUST then stop writing to it. This
  cancels the stream and MUST NOT cancel or otherwise affect the task.
- **Back-pressure** is QUIC's stream flow control. An agent MUST NOT buffer
  events for a stream without bound; it MAY reset a stream whose client does
  not read.
- **Reconnection.** A client that loses a stream opens a new one with
  `SubscribeToTask`. The first event of a subscription is the task's current
  state, so nothing needs to be replayed.
- Several streams MAY be open for one task; A2A 1.0 section 3.5.2 applies.

## 6. Service parameters

A2A service parameters (A2A 1.0 section 3.2.6) are the members of the header
frame. Keys are compared without regard to case and SHOULD be written in
lowercase. Values are JSON strings. A parameter with several values
(`a2a-extensions`) is one string with the values separated by commas.

- `a2a-version` MUST be present. An agent MUST answer a request whose value
  is absent or names a version it does not serve on this interface with
  `VersionNotSupportedError` (`-32009`). An absent value is not treated as
  an earlier version: this binding did not exist for one.
- `a2a-extensions` lists the extension URIs the client activates.

The binding reserves every key that begins with `a2a-iroh-`. Two are defined:
`a2a-iroh-proof` (section 7) and `a2a-iroh-well-known` (section 3.4).

## 7. Proof of possession

Node authentication says which node is on the other end of a connection. It
does not say which client a request belongs to when a client uses several
nodes, moves between them, or is reached through a relay it shares. This
binding therefore identifies a client by a possession key, and every request
MUST carry a fresh proof that the sender holds that key, made for that one
request. The proof has the shape of a DPoP proof (RFC 9449) with the HTTP
method and URI replaced by this binding's equivalents. It is not a DPoP
proof and has its own type so that neither can be taken for the other.

### 7.1. The proof

`a2a-iroh-proof` is a JWS in compact serialization (RFC 7515).

Protected header:

| member | value |
|---|---|
| `typ` | `a2a-iroh-pop+jwt` |
| `alg` | `ES256`. Agents MUST support it. Other asymmetric algorithms MAY be added by a later version; `none` and symmetric algorithms MUST be refused. |
| `jwk` | the possession public key (RFC 7517), without private members |

Claims:

| claim | value |
|---|---|
| `htm` | the JSON-RPC method name of the request, for example `SendMessage` |
| `htu` | the target: `iroh://<agent node ID>/<ALPN>`, for example `iroh://81aa…552d/x-a2a-jsonrpc/draft-0.1`, with no query |
| `iat` | creation time, seconds since the Unix epoch |
| `jti` | a unique identifier with at least 96 bits of entropy |
| `nid` | the client's own node ID |
| `rqh` | base64url, without padding, of the SHA-256 of the request frame's bytes |

### 7.2. Verification

For every request other than a well-known request the agent MUST, before
acting on it, verify all of the following and refuse the request if any
fails:

1. the proof is present and is a well-formed JWS with the header above;
2. the signature verifies under `jwk`;
3. `htm` equals the request's `method`;
4. `htu` equals the agent's own node ID and this ALPN, exactly;
5. `iat` is within the agent's window of its own clock (120 seconds either
   way unless the card says otherwise);
6. `jti` has not been seen within that window by this agent, for any
   connection;
7. `nid` equals the node ID iroh authenticated for this connection;
8. `rqh` equals the hash of the request frame as received.

The client is identified by the JWK thumbprint (RFC 7638) of `jwk`. The
agent MUST scope tasks to it: a task is visible to, and may be acted on by,
only the possession key that created it, and a request about another key's
task MUST be answered exactly as a request about a task that does not exist
(`TaskNotFoundError`), as A2A 1.0 section 13.1 requires.

The replay store of step 6 MUST cover every connection to the agent and MUST
retain an identifier for at least the window. A store that does not survive
a restart leaves a window after a restart in which a captured proof could be
replayed from the node it was made on; an agent with such a store SHOULD
refuse requests for one window after it starts.

A proof is not a credential that confers access by being held. Copied to
another node it fails step 7; reused it fails step 6; attached to another
request it fails step 3 or 8; sent to another agent or protocol it fails
step 4.

### 7.3. Failure

A missing proof is answered with JSON-RPC error `-32000` and reason
`POSSESSION_PROOF_REQUIRED`; a proof that fails verification with `-32000`
and reason `POSSESSION_PROOF_INVALID` (section 9). A2A defines no error code
for failed authentication on JSON-RPC; `-32000` is JSON-RPC's
implementation-defined server error and outside the A2A-specific range.

### 7.4. Composition with other schemes

Security schemes declared in the Agent Card apply in addition. A credential
a scheme calls for is carried as the service parameter the scheme names
(`authorization` for HTTP authentication schemes). The possession proof is
required whatever else is presented, and an agent MUST NOT accept a bearer
credential in its place.

## 8. Push notifications

Not supported in this version. A2A push notifications are HTTP POST requests
to a URL the client registers, and a client of this binding may have no HTTP
endpoint. An agent whose only interface is this binding MUST answer the four
push-notification configuration operations with
`PushNotificationNotSupportedError` (`-32003`). A client that wants updates
without holding a stream open polls `GetTask` or re-subscribes.

A later version may define delivery by having the agent open a connection to
a node ID the client registered. That needs its own authorization rule (the
agent would be proving possession to the client) and is left open
(section 12).

## 9. Errors

Errors are JSON-RPC error objects as A2A 1.0 section 9.5 defines them, with
the A2A codes of A2A 1.0 section 5.4 unchanged:

| A2A error type | code |
|---|---|
| `TaskNotFoundError` | `-32001` |
| `TaskNotCancelableError` | `-32002` |
| `PushNotificationNotSupportedError` | `-32003` |
| `UnsupportedOperationError` | `-32004` |
| `ContentTypeNotSupportedError` | `-32005` |
| `InvalidAgentResponseError` | `-32006` |
| `ExtendedAgentCardNotConfiguredError` | `-32007` |
| `ExtensionSupportRequiredError` | `-32008` |
| `VersionNotSupportedError` | `-32009` |

and JSON-RPC's own `-32700`, `-32600`, `-32601`, `-32602` and `-32603`.

Each error's `data` SHOULD hold a `google.rpc.ErrorInfo` object whose
`reason` is an upper-case constant and whose `domain` is the binding
identifier for errors this binding defines.

An agent MUST apply its checks in this order and report the first that
fails: the request frame is JSON (`-32700`, null `id`); it is a JSON-RPC 2.0
request with a method and an `id` (`-32600`); the version (`-32009`); the
proof (`-32000`); then the operation.

Transport-level conditions have no JSON-RPC form:

| condition | behaviour |
|---|---|
| a frame exceeds its limit | the stream is reset with application error code 1 |
| a frame is truncated, or frames do not arrive in time | the stream is reset or abandoned; no response |
| the client stops reading | the agent stops writing; the task is unaffected |
| the connection is lost | all its streams end; tasks are unaffected |

## 10. Security considerations

### 10.1. What the transport gives

An iroh connection is encrypted and authenticated end to end between two
node keys. Whoever relays its packets, including an iroh relay server, sees
which nodes communicate, when, and how much, and can delay or drop traffic.
It cannot read or alter it. No check in this binding is delegated to a
relay.

### 10.2. What it does not give

A node ID is a key, not a name. Nothing here says who operates a node. A
client learns that from whatever told it the node ID, and from signed Agent
Cards if it trusts their signers.

### 10.3. Privacy

Node IDs and possession keys are stable identifiers. An agent can link all
requests made with one possession key, and any observer of an address-lookup
service or relay can link a node ID to network addresses. A client that
wants unlinkable requests uses a fresh node key and possession key for each.

### 10.4. Address hints

A hint in an interface URL, or anywhere else an agent's address is
advertised, is input from whoever wrote it. Dialling it sends packets to an
address of their choosing. A client SHOULD refuse hints that name loopback,
link-local, private, multicast or unspecified addresses unless configured to
allow them, and MUST NOT treat reaching an address as evidence about the
node there: only the authenticated node ID is.

### 10.5. Resource limits

An agent MUST bound frame sizes (section 5.1), the time a stream may take to
deliver its frames, the number of concurrent streams per connection, and the
number of events buffered per stream. Work started by an unauthenticated
well-known request is limited to returning a stored card.

### 10.6. Early data and replay

QUIC 0-RTT data can be replayed by an attacker. Section 4 forbids it. The
`jti` store is the defence against replay of a proof within one agent; the
`htu` claim against replay at another.

## 11. Payments

Extensions ride in A2A's own fields and are unaffected by this binding. In
particular the A2A x402 payments extension, version 0.2, is used unchanged:
a payment request is a task in `TASK_STATE_INPUT_REQUIRED` whose
`status.message.metadata` carries `x402.payment.status` of
`payment-required` and the x402 payment-required object under
`x402.payment.required`; the client answers with a message for that task
whose metadata carries `payment-submitted` and the payload under
`x402.payment.payload`; receipts arrive under `x402.payment.receipts`. The
extension's activation header is this binding's `a2a-extensions` service
parameter.

## 12. Conformance

An implementation conforms to this binding version if it meets every
requirement below. Each has a matching test in the reference test suite.

| | requirement |
|---|---|
| C-1 | The agent serves its Agent Card to a well-known request without a proof; the card lists this interface with the agent's own node ID, this binding identifier and A2A version; any other well-known name gets no frame. |
| C-2 | A unary operation is two client frames and one response frame; the response is a JSON-RPC 2.0 response with the request's `id` and an A2A result. |
| C-3 | A request whose `a2a-version` is absent or unsupported is answered `-32009`. |
| C-4 | A request with no proof is refused. |
| C-5 | A proof of another type, or whose signature does not verify, is refused. |
| C-6 | A proof for another method is refused. |
| C-7 | A proof for another node, or for another protocol on this node, is refused. |
| C-8 | A proof outside the time window, earlier or later, is refused. |
| C-9 | A proof presented a second time is refused. |
| C-10 | A proof whose `nid` is absent, or is not the connection's authenticated node, is refused. |
| C-11 | A proof whose `rqh` is absent, or is not the hash of the request frame, is refused. |
| C-12 | A task answers only to the possession key that created it; to any other key it is reported as not found, by every operation that names a task, and is absent from `ListTasks`. |
| C-13 | Malformed JSON is `-32700`; a malformed request `-32600`; an unknown method `-32601`; invalid parameters `-32602`; a frame over its limit resets the stream and is not answered. |
| C-14 | A stream delivers the task, then each change in order; it ends at a terminal or interrupted state; a terminal task cannot be subscribed to (`-32004`); a client that stops reading ends the stream and not the task. |
| C-15 | The push-notification operations are answered `-32003`; operations an agent does not offer are answered with the A2A error for them. |
| C-16 | With the x402 extension, a payment request, submission and receipt are carried in the metadata keys of section 11. |
| C-17 | An agent that offers another binding behaves the same through both: the same request creates the same task, and a task created through one is the same task through the other. |
| C-18 | Every object the agent emits has the fields A2A requires and no field A2A lacks. |

## 13. Open issues

1. **Identifiers.** The binding and extension identifiers are HTTPS URIs
   whose documents are meant to be published at those URIs; until they are,
   the identifiers still identify, and a client MUST NOT require them to
   resolve. The `iroh` URL scheme is unregistered.
2. **No independent implementation.** One implementation exists. Nothing
   here has been tested against another.
3. **Push notifications** over iroh (section 8).
4. **The proof is this document's own design.** It follows RFC 9449 closely
   and has not been reviewed by anyone else.
5. **Algorithm agility.** Only ES256 is specified. Signing the proof with
   the node key itself (Ed25519) would remove the second key and with it the
   property that a client is the same client from any node; whether that is
   wanted is undecided.
6. **Discovery.** How a client first learns a node ID is out of scope, and
   there is no well-known place to look.
7. **Multi-tenancy.** The `tenant` field of A2A requests is carried
   unchanged in parameters; nothing here says how one node serves several
   agents.
8. **Server-initiated nonces** (RFC 9449 section 8) are not used; replay
   protection rests on `iat` and the `jti` store.
9. **gRPC payloads.** Only the JSON-RPC payload format is bound. Carrying
   A2A's protobuf messages on the same streams would be a separate binding.

## Appendix A. Change history

| version | change |
|---|---|
| 0.2 | Identifiers moved to HTTPS URIs, each meant to dereference to a describing document: binding `https://coproduct.one/a2a/ext/iroh-binding/v1`, proof-of-possession profile `https://coproduct.one/a2a/ext/iroh-possession/v1`. Wire format, ALPN, frames, proof object and errors unchanged. |
| 0.1 | First draft. Identifiers, now superseded: binding `urn:uuid:8637676d-c305-4eb3-b2b2-25dbec1c0cda`, proof-of-possession profile `urn:uuid:80bced81-d7b8-49a5-9031-a0793c1e5f8d`. |

A card that names a superseded identifier declares the version that
identifier belonged to. Because the wire format did not change, a 0.1 client
and a 0.2 agent can exchange frames; whether a client accepts a card naming
an identifier it does not know is that client's decision, and this document
does not make the two identifiers equivalent.
