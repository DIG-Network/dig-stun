# dig-stun — Normative Specification

This document is the authoritative contract an independent reimplementation can be built against. It
is not a README and carries no history.

Every clause below is implemented in `0.1.0`. Clauses tagged **[EXTRACTED]** describe behaviour moved
byte-for-byte and test-for-test from `dig-nat 0.21.1` `src/stun.rs` (origin/main `6d44a43`); the cited
`dig-nat` line is where the behaviour was true before the move. Clauses tagged **[NEW]** did not exist
anywhere before this crate. Clauses tagged **[RECONCILED]** replace two shipped implementations that
disagreed (§5.4) — a deliberate behaviour change, and the only one in this crate's first release.

---

## 1. Scope and role

`dig-stun` is the DIG ecosystem's single home for **reflexive-address discovery**: how a node learns
the public address the outside world sees its traffic arrive from, and how it decides whether to
believe what it was told.

It owns exactly four things:

1. **The RFC 5389 Binding codec** (§2, §3) — request and success-response, both directions.
2. **The UDP STUN client** (§4) — one Binding transaction against one server over one socket.
3. **The address-scope classifier** (§5) — the single predicate every consumer uses to ask "could this
   address be a legitimate reflexive candidate, and could a stranger route to it?".
4. **The peer-observation role** (§6) and **the agreement rule** (§7) — the parts that let every
   directly-reachable DIG node act as a reflexive-address source for its peers, and let a requesting
   node combine what several sources said without trusting any one of them.

It deliberately does NOT own:

- **The IPv6-first happy-eyeballs walk over several STUN servers.** That is
  `dig_nat::stun::discover_reflexive_address`, which composes this crate with `dig-ip`. It cannot live
  here: `dig-ip` is a level-00 crate and so is `dig-stun`, and same-level dependencies are forbidden
  (Appendix B, reference-DOWN-only). See §9.
- **A UDP STUN listener for DIG nodes.** Nodes do not open a STUN port (§6.1). The relay's UDP
  listener (`dig-relay/src/stun.rs`) is a separate GPL-2.0 application and MAY adopt this crate's codec
  (§11.4); nothing here runs a UDP serve loop.
- **Tier policy** — which servers to ask, in what order, with what budget. That is the consumer's
  (`dig-node` `seams/dig_peer/net.rs` `StunPlan`). This crate supplies the primitives and the
  agreement rule the consumer MUST apply.
- **Any proof of inbound reachability.** Nothing in this crate proves a stranger can connect to the
  requester. §10 states exactly what each result does and does not establish.

Units: every port is a 16-bit TCP or UDP port number; every duration is milliseconds unless a Rust
`Duration` is named. No $DIG or XCH quantity appears in this crate.

---

## 2. Wire codec — RFC 5389 Binding **[EXTRACTED unless marked NEW]**

### 2.1 Constants (normative)

| Item | Value | Meaning | Today |
|---|---|---|---|
| `MAGIC_COOKIE: u32` | `0x2112_A442` | bytes 4..8 of every STUN message; its top 16 bits key the XOR of the port | `dig-nat/src/stun.rs:22` |
| `BINDING_REQUEST: u16` | `0x0001` | method Binding, class Request | `:25` |
| `BINDING_SUCCESS: u16` | `0x0101` | method Binding, class Success Response | `:27` |
| `ATTR_XOR_MAPPED_ADDRESS: u16` | `0x0020` | RFC 5389 §15.2 | `:30` |
| `ATTR_MAPPED_ADDRESS: u16` | `0x0001` | RFC 5389 §15.1, legacy; some servers still emit it | `:32` |
| `TransactionId` | `[u8; 12]` (type alias, NOT a newtype) | the 96-bit transaction id | signatures at `:66`, `:180`, `:428` |

`TransactionId` MUST remain a plain `[u8; 12]` alias so that `dig-nat`'s re-exported signatures
(§8.2) are unchanged for existing consumers.

### 2.2 Message header (byte layout, normative)

```
offset  len  field
0       2    message type, big-endian (top two bits MUST be 0 — RFC 5389 §6)
2       2    message length, big-endian: byte count of the attributes that follow the 20-byte header
4       4    MAGIC_COOKIE, big-endian
8       12   transaction id
20      n    attributes, each [type:2][length:2][value:length][pad to 4-byte boundary]
```

### 2.3 `encode_binding_request(&TransactionId) -> Vec<u8>` **[EXTRACTED `:66-73`]**

Exactly 20 bytes: `BINDING_REQUEST`, length `0x0000`, `MAGIC_COOKIE`, the 12 id bytes. No attributes.

Golden vector (normative): for id `00 01 02 03 04 05 06 07 08 09 0a 0b` the encoding is
`00 01 00 00 21 12 a4 42 00 01 02 03 04 05 06 07 08 09 0a 0b`.

### 2.4 `parse_binding_response(msg: &[u8], expected_txid: Option<&TransactionId>) -> Result<SocketAddr, StunError>` **[EXTRACTED `:180-232`]**

A PURE parser. It MUST, in this order:

1. Reject `msg.len() < 20` as `Truncated`.
2. Reject a cookie ≠ `MAGIC_COOKIE` as `BadMagicCookie` — before the type check, so a non-STUN
   datagram is never reported as an "unexpected STUN type".
3. Reject a message type ≠ `BINDING_SUCCESS` as `UnexpectedType(type)`.
4. When `expected_txid` is `Some`, reject a non-matching id as `TransactionIdMismatch`.
5. Reject `msg.len() < 20 + message_length` as `Truncated`.
6. Walk the TLV attributes within `[20, 20 + message_length)`. An attribute whose value overruns that
   window is `Truncated`. Padding is `(4 - len % 4) % 4`.
7. Return the FIRST `XOR_MAPPED_ADDRESS` decoded (§2.6) as soon as it is seen; otherwise the first
   `MAPPED_ADDRESS` decoded without XOR; otherwise `NoMappedAddress`.

It MUST NOT apply the scope guard of §5 — that is the client's job (§4). It MUST NOT verify a
`FINGERPRINT` or `MESSAGE-INTEGRITY` attribute (this crate speaks unauthenticated Binding only).

### 2.5 `parse_binding_request(datagram: &[u8]) -> Result<TransactionId, StunError>` **[NEW]**

The server-side parser. It MUST:

1. Reject `datagram.len() < 20` as `Truncated`.
2. Reject a cookie ≠ `MAGIC_COOKIE` as `BadMagicCookie`.
3. Reject a message type whose top two bits are non-zero, or that is ≠ `BINDING_REQUEST`, as
   `UnexpectedType(type)`. Every other STUN method or class is refused here; a caller that wants RFC
   5389's "silently ignore" latitude does so by not replying.
4. Reject `datagram.len() < 20 + message_length` as `Truncated`.
5. Return the 12 id bytes. Attributes present on a request (e.g. `SOFTWARE`) are accepted and ignored.

### 2.6 `(XOR-)MAPPED-ADDRESS` value layout (normative) **[EXTRACTED `:240-291`]**

```
[reserved:1 = 0x00][family:1][port:2][address:4 (family 0x01) | 16 (family 0x02)]
```

- `family` `0x01` = IPv4, `0x02` = IPv6; any other value is `UnexpectedType(family as u16)`.
- A value shorter than 4 bytes, or shorter than 8 (IPv4) / 20 (IPv6), is `Truncated`.
- With XOR: `port ^= (MAGIC_COOKIE >> 16) as u16`; an IPv4 address is XORed with the 4 cookie bytes;
  an IPv6 address is XORed with `MAGIC_COOKIE ‖ transaction_id` (16 bytes, network order).

### 2.7 `encode_binding_success(&TransactionId, reflexive: SocketAddr) -> Vec<u8>` **[NEW]**

The server-side encoder. The output MUST be exactly: the §2.2 header with type `BINDING_SUCCESS`,
followed by ONE `XOR_MAPPED_ADDRESS` attribute carrying `reflexive` per §2.6 with XOR applied, and
nothing else — no `MAPPED_ADDRESS`, no `SOFTWARE`, no `FINGERPRINT`. An IPv4-mapped IPv6 `reflexive`
(`::ffff:a.b.c.d`) MUST be encoded as family `0x01` with the embedded IPv4 address, never as family
`0x02`; a responder that answers an IPv4 caller with a 16-byte address is exactly the family-crossing
defect measured on `relay.dig.net` (relay.dig.net#11).

Golden vectors (normative), id `00 01 02 03 04 05 06 07 08 09 0a 0b`:

- `1.1.1.1:9444` →
  `01 01 00 0c 21 12 a4 42 00 01 02 03 04 05 06 07 08 09 0a 0b 00 20 00 08 00 01 05 f6 20 13 a5 43`
  (32 bytes; `9444 = 0x24e4`, `0x24e4 ^ 0x2112 = 0x05f6`).
- `[2606:4700:4700::1111]:9444` →
  `01 01 00 18 21 12 a4 42 00 01 02 03 04 05 06 07 08 09 0a 0b 00 20 00 14 00 02 05 f6 07 14 e3 42 47 01 02 03 04 05 06 07 08 09 1b 1a`
  (44 bytes).

`parse_binding_response(encode_binding_success(id, a), Some(id)) == Ok(a)` MUST hold for every
`SocketAddr` `a` whose IP is native IPv4 or native IPv6 (round-trip law).

### 2.8 `StunError` **[EXTRACTED `:38-63`]** — exhaustive, seven variants

| Variant | Raised by |
|---|---|
| `Truncated` | §2.4 steps 1, 5, 6; §2.5 steps 1, 4; §2.6 |
| `BadMagicCookie` | §2.4 step 2; §2.5 step 2 |
| `TransactionIdMismatch` | §2.4 step 4 |
| `NoMappedAddress` | §2.4 step 7; §4 guard rejection |
| `UnexpectedType(u16)` | §2.4 step 3; §2.5 step 3; §2.6 family |
| `Io(String)` | §4 socket errors, stringified so the enum stays `Clone + Eq` |
| `Timeout` | §4 deadline |

The enum MUST derive `Debug, Clone, PartialEq, Eq` and implement `std::error::Error` (via
`thiserror`) with the display strings at `dig-nat/src/stun.rs:40-62`. It is `#[non_exhaustive]`-FREE
today; adding a variant is therefore a breaking change for consumers that match exhaustively
(`dig-nat` re-exports it, §8.2). No variant is added in `0.1.0`.

---

## 3. Transaction id — `new_transaction_id() -> TransactionId` **[EXTRACTED `:428-440`]**

Every byte MUST come from a CSPRNG (`ring::rand::SystemRandom`). It MUST NOT be derived from
wall-clock time, a counter, or any attacker-predictable input (RFC 5389 §10.1). CSPRNG failure MUST
panic rather than fall back to a predictable id — a predictable id reopens the forged-response
poisoning this exists to close. Conformance: the two statistical tests at `dig-nat/tests/stun.rs:195`
and `:230` move to this crate unchanged.

---

## 4. UDP client — `query_reflexive_address(socket: &UdpSocket, server: SocketAddr, timeout: Duration) -> Result<SocketAddr, StunError>` **[EXTRACTED `:314-347`]**

One Binding transaction over `socket` against `server`. It MUST:

1. Send `encode_binding_request(&new_transaction_id())` to `server`.
2. Receive until `timeout` elapses (`Timeout`), discarding — and CONTINUING to wait after — any
   datagram whose source address is not exactly `server`. One spoofed or stray datagram MUST NOT fail
   the transaction; the genuine reply may still be in flight (dig-nat SPEC §6, "response source
   validation").
3. Parse the first datagram from `server` with `parse_binding_response(.., Some(&txid))`; a parse error
   is returned as-is.
4. Apply the §5 guard: a parsed address with `scope_of(addr) == Scope::NeverDialable` MUST be
   returned as `NoMappedAddress`. This is where a malicious or misconfigured server's bogus address is
   stopped (dig-nat #1387).

**What the result means, and only this:** the address:port at which `socket`'s datagrams arrived at
`server`. The port is the NAT mapping of THAT socket. It is a usable dial target only when `socket` is
the very socket whose external mapping the caller wants (dig-nat SPEC §3.4 "dialable candidate vs
public-IP-only"). A caller MUST NOT infer inbound reachability from a successful transaction.

Source validation and the transaction id are INDEPENDENT defences; neither replaces the other.

---

## 5. Address scope — the single classifier **[RECONCILED]**

### 5.1 Why one classifier

Two shipped predicates answer overlapping questions with different range tables:
`dig-nat/src/stun.rs:98-159` `is_usable_reflexive_addr` ("could this ever be a dial target") and
`dig-node/crates/dig-node-service/src/mirror/advertise.rs:588-647` `is_globally_routable` ("could a
stranger route to it"). They are two TIERS of one classification, and their tables have drifted (§5.4).
This crate owns the one table; both predicates are derived from it.

### 5.2 `Scope` — exhaustive, three variants

```rust
pub enum Scope {
    /// Never a destination: reserved, documentation, loopback, link-local, multicast, unspecified,
    /// benchmarking, discard-only, IETF-assignments, or port 0.
    NeverDialable,
    /// Dialable only from inside the same site or carrier region: RFC 1918, RFC 6598 CGNAT, IPv6 ULA.
    PrivateScope,
    /// Everything else: an address a stranger on the open internet could route to.
    GlobalUnicast,
}
pub fn scope_of_ip(ip: IpAddr) -> Scope;
pub fn scope_of(addr: SocketAddr) -> Scope;          // NeverDialable when addr.port() == 0, else scope_of_ip
pub fn is_usable_reflexive_addr(addr: &SocketAddr) -> bool;  // scope_of(*addr) != Scope::NeverDialable
pub fn is_globally_routable(addr: &SocketAddr) -> bool;      // scope_of(*addr) == Scope::GlobalUnicast
```

### 5.3 The table (normative, exhaustive)

**Fold first (canonical, dig_ecosystem `canonical` skill, "IPv4-in-IPv6 canonicalization").** An IPv6
address is classified by `Ipv6Addr::to_ipv4()` — which folds BOTH the mapped form `::ffff:a.b.c.d` AND
the deprecated compatible form `::a.b.c.d` — and, when that yields an IPv4 address, the IPv4 table
applies. `to_canonical()` MUST NOT be used (it misses the compatible form). Consequences that MUST be
preserved: `::1` folds to `0.0.0.1` and is caught by the `0.0.0.0/8` row; `::` folds to `0.0.0.0`
likewise. The `0.0.0.0/8` row is therefore load-bearing for IPv6 and MUST NOT be removed as redundant.

IPv4 (11 `NeverDialable` ranges, 4 `PrivateScope` ranges; anything else `GlobalUnicast`):

| Range | Scope | Reason |
|---|---|---|
| `0.0.0.0/8` | NeverDialable | "this network" (RFC 1122); also where `::`/`::1` land after folding |
| `127.0.0.0/8` | NeverDialable | loopback |
| `169.254.0.0/16` | NeverDialable | link-local |
| `192.0.0.0/24` | NeverDialable | IETF protocol assignments (RFC 6890) |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | NeverDialable | documentation (RFC 5737) |
| `192.88.99.0/24` | NeverDialable | 6to4 relay anycast, deprecated (RFC 7526) |
| `198.18.0.0/15` | NeverDialable | benchmarking (RFC 2544) |
| `224.0.0.0/4` | NeverDialable | multicast |
| `240.0.0.0/4` | NeverDialable | reserved / class E, includes `255.255.255.255` |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | PrivateScope | RFC 1918 |
| `100.64.0.0/10` | PrivateScope | carrier-grade NAT shared space (RFC 6598) |

Native IPv6 (7 `NeverDialable` ranges, 1 `PrivateScope` range; anything else `GlobalUnicast`):

| Range | Scope | Reason |
|---|---|---|
| `::/128` | NeverDialable | unspecified (also folds; see above) |
| `::1/128` | NeverDialable | loopback (also folds) |
| `fe80::/10` | NeverDialable | link-local |
| `ff00::/8` | NeverDialable | multicast |
| `2001:db8::/32` | NeverDialable | documentation (RFC 3849) |
| `2001:2::/48` | NeverDialable | benchmarking (RFC 5180) |
| `100::/64` | NeverDialable | discard-only (RFC 6666) |
| `fc00::/7` | PrivateScope | unique local (RFC 4193) |

`port == 0` is `NeverDialable` for `scope_of(SocketAddr)` regardless of IP.

### 5.4 The disagreements this table settles (finding, normative outcome)

- `192.88.99.0/24`: rejected by dig-nat's dial guard, **accepted as globally routable by dig-node's
  on-chain gate**. The on-chain gate is the one that shipped wrong: it admitted an address the looser
  tier refuses. Outcome: `NeverDialable`.
- `192.0.0.0/24`, `2001:2::/48`, `100::/64`: rejected by dig-node, **accepted by dig-nat's dial
  guard**. Outcome: `NeverDialable`. This tightens `query_reflexive_address` (§4) for three ranges no
  legitimate reflexive answer can carry. Failure direction of the old behaviour: open (a bogus address
  could be advertised as a LAN candidate); of the new: closed.
- `port == 0`: checked by dig-nat, not by dig-node. Outcome: checked by `scope_of`; `scope_of_ip`
  cannot see a port and callers with a bare `IpAddr` MUST use it knowingly.

No provider range is special-cased and none ever may be: many legitimate nodes run on EC2, and a
wrong-but-routable answer is caught by AGREEMENT (§7), not by a range table.

### 5.5 Failure direction

A classification error toward `NeverDialable` costs a LAN or test-network candidate (visible: the
candidate is absent). A classification error toward `GlobalUnicast` puts an address a stranger cannot
reach into an on-chain advertisement. When a range is genuinely ambiguous, classify DOWN.

### 5.6 Vacuity note

`PrivateScope` is accepted by `is_usable_reflexive_addr` and rejected by `is_globally_routable`. Both
are exercised by real inputs (LAN/EC2-VPC discovery in dig-nat's tests; the derived-URL gate in
dig-node). Neither predicate is vacuous.

---

## 6. Peer observation — the responder role **[NEW]**

### 6.1 Transport: the authenticated peer wire, never a UDP listener

A DIG node acting as a reflexive-address source answers over the **existing mTLS peer surface** — the
JSON-RPC method `dig.getObservedAddress` on the `dig-rpc-protocol` `peer` tier (its wire form is
specified in `dig-rpc-protocol` `SPEC.md` §4.2; this section specifies the decision behind the answer).
A node MUST NOT open a UDP STUN listener to serve peers. Reasons, each sufficient alone:

1. **No reflection.** A UDP responder replies to whatever source address a datagram claims; a spoofed
   source turns every node into a reflector aimed at a victim. An answer returned on the requester's
   own established TCP/mTLS session cannot be redirected anywhere.
2. **No new inbound port on a user's machine.** A directly-reachable node already exposes its mTLS
   listener; a NAT'd node exposes nothing and a UDP listener on it would be unreachable anyway.
3. **The responder knows who asked.** The session is authenticated (`peer_id = SHA-256(TLS SPKI
   DER)`), so limits (§6.4) key on transport facts, never on payload.

Interoperability with generic RFC 5389 clients is NOT a goal of the peer tier; the central UDP tiers
(operator / relay / public) keep the RFC 5389 codec of §2–§4 for that.

### 6.2 What the responder observes — and what the requester needs

Over TCP the responder observes the **source address of the connection the requester dialled out
on**: the requester's public IP as its traffic leaves its NAT, and an EPHEMERAL source port. What a
node must advertise is `<public ip>:<its own listen port>`. So:

- The reported **IP** is the useful datum. `dig-node` already pairs a discovered IP with its own listen
  port and discards the reported port (`dig-node-core/src/seams/dig_peer/net.rs:801-803`
  `reflexive_candidate`); the peer tier changes nothing about that.
- The reported **port is informational only**. A requester MUST NOT treat it as the mapping of any
  listen socket and MUST NOT include it in an advertisement. It MAY be compared with the requester's own
  local source port for that connection: equality is evidence of "no NAT or a port-preserving NAT on
  this path"; inequality is the ordinary NAT case and is not evidence of anything wrong.

Which NAT behaviours the peer tier serves (normative statement of coverage):

| Requester's situation | Reported IP | Useful for advertisement? |
|---|---|---|
| Public address on the interface (incl. IPv6 GUA), no NAT | the interface address | yes — pair with the listen port |
| NAT with endpoint-independent mapping ("cone"), one public IP | the NAT's public IP | yes — pair with the listen port; inbound still needs a port mapping or an endpoint-independent filter |
| NAT with endpoint-dependent mapping ("symmetric"), one public IP | the NAT's public IP | yes for the IP; the port is per-destination and is discarded anyway; hole-punch is not served by this tier |
| Multi-egress NAT (CGNAT pools, load-balanced NAT, multi-homed host) | differs by responder | **no** — different responders report different IPs, agreement (§7) fails closed |
| Relayed session | not observable | the responder refuses (§6.3) |

### 6.3 `observe(meta: &SessionMeta) -> Result<SocketAddr, Refusal>` — the pure decision

```rust
pub enum Direction { Inbound, Outbound }     // who ACCEPTED the TCP connection: Inbound = this node did
pub enum Path { Direct, Relayed }            // dig_nat::TraversalKind::Relayed => Relayed; every other kind => Direct
pub struct SessionMeta { pub direction: Direction, pub path: Path, pub remote: SocketAddr }
pub enum Refusal { Outbound, Relayed, Unusable, RateLimited }   // exhaustive, four variants
```

The responder MUST answer only when ALL of:

1. `direction == Inbound` — the address is an OBSERVATION only on a connection this node accepted on
   its own listener. On a connection this node dialled, `remote` is the address it chose to dial, not
   something it observed; refuse with `Refusal::Outbound`.
2. `path == Direct` — on a relayed circuit `remote` is the relay's endpoint or the unspecified
   wildcard (`dig-nat/src/accept.rs:30,110`); refuse with `Refusal::Relayed`.
3. `scope_of(remote) != Scope::NeverDialable` — refuse with `Refusal::Unusable`. (A `PrivateScope`
   remote IS answered: the requester may be a LAN peer, and what it does with a private reading is the
   requester's decision under §7.)

The answer is `remote` with an IPv4-mapped IPv6 address FOLDED to IPv4 (`Ipv6Addr::to_ipv4()`), so a
requester that connected over IPv4 is never handed a 16-byte address. `Refusal::RateLimited` is
produced by §6.4, not by `observe`.

A node that has no inbound-direct session with the requester therefore never serves it. This is the
whole of the "is this node reachable enough to serve" question: the connection's existence IS the
evidence, per requester, and no node-level reachability flag is needed or defined.

### 6.4 `ObserveLimiter` — abuse bounds

```rust
pub const OBSERVE_PER_SESSION_PER_MINUTE: u32 = 6;
pub const OBSERVE_GLOBAL_PER_SECOND: u32 = 64;
pub const MAX_TRACKED_SOURCES: usize = 4096;
pub struct ObserveLimiter { /* per-session buckets, per-source-IP buckets, one global bucket */ }
impl ObserveLimiter {
    pub fn new(per_session_per_minute: u32, global_per_second: u32) -> Self;
    /// `session` = the authenticated peer_id of the asking session; `source` = the transport-observed
    /// remote IP (folded per §5.3). `now_ms` is caller-supplied so the decision is pure and testable.
    pub fn allow(&mut self, session: &str, source: IpAddr, now_ms: u64) -> bool;
}
```

- Keys are TRANSPORT facts — the mTLS `peer_id` of the session and the accepted connection's source
  IP. Neither comes from the request payload. `dig.getObservedAddress` takes no params, so there is no
  payload to key on.
- `allow` MUST charge a token in every enabled dimension only when ALL permit, and MUST check the
  per-session and per-source budgets before the global one, so one abuser cannot drain the global
  budget for everyone (the shape of `dig-relay/src/stun.rs:284-300`).
- The per-session and per-source maps MUST be LRU-bounded at `MAX_TRACKED_SOURCES`, so the limiter's
  own state cannot be grown without bound.
- A refused request is answered with the `OBSERVATION_UNAVAILABLE` error carrying
  `data.reason = "rate_limited"` — never silently dropped, because the requester must be able to tell
  "this peer will not tell me" from "this peer is dead".

These bounds are about CPU, not amplification: the answer is ~100 bytes on an already-open session.

### 6.5 What the responder learns, and what it MUST NOT do with it

The responder learns that the requester is discovering its own address. It already knew the
requester's source address from the connection itself, so the method discloses nothing new to the
responder and nothing at all to a third party. This is strictly less disclosure than the public tier,
which tells `stun.l.google.com` or `stun.cloudflare.com` the address of every DIG node that asks.

The responder MUST NOT log the observed address above `debug` on the answer path (the connection's
`remote` is already logged at `info` on establishment by the pool), MUST NOT include any other fact
about the requester or about itself in the answer, and MUST NOT persist a record of who asked.

---

## 7. Provenance and agreement — `establish` **[NEW]**

### 7.1 A reading carries its class

```rust
pub struct Reading {
    /// The independence class of whoever reported it — see §7.2. Two readings corroborate each other
    /// exactly when their `source` strings DIFFER and their addresses agree.
    pub source: String,
    /// Optional identity of the individual reporter (a peer_id, a resolved server address). For
    /// diagnostics only; never consulted by `establish`.
    pub witness: Option<String>,
    /// The address the source said the node appears at. The PORT is carried but never compared.
    pub addr: SocketAddr,
}
```

### 7.2 `SourceClass` — the grammar of `source` (normative)

`source` is a UTF-8 string produced by `SourceClass::to_string()`; `SourceClass::parse(&str)` MUST
round-trip every form below and return `None` for anything else.

| Form | Produced for | Independence semantics |
|---|---|---|
| `operator:<host>:<port>` | a server the operator configured (`DIG_STUN_SERVER` entry, normalised to `host:port`) | each configured endpoint is its own class — the operator vouched for it |
| `relay:<host>` | the DIG relay's co-located STUN server | one class per relay host |
| `public:<host>` | a third-party public STUN host (`stun.l.google.com`, `stun.cloudflare.com`) | one class per host — they are different operators |
| `peer:v4:<a>.<b>` | a DIG peer answering §6 over IPv4, where `a.b` are the first two octets of the PEER's transport address | **one class per IPv4 /16** |
| `peer:v6:<h0>:<h1>` | a DIG peer answering §6 over IPv6, `h0`/`h1` the first two 16-bit groups of the PEER's transport address as 4 lowercase hex digits each, zero-padded | **one class per IPv6 /32** |

The peer partition (IPv4 `/16`, IPv6 `/32`) is the SAME partition as
`dig_gossip::util::ip_address::subnet_group` (dig-gossip `src/util/ip_address.rs:56-67`), which the
pool already uses for its INT-006 eclipse cap. This crate MUST NOT re-implement that function
(it would be a rival at a different level); it defines the rendering of a group the CALLER computes
— `SourceClass::peer(group_ip: IpAddr)` takes the peer's transport IP and renders the class from its
leading bytes after §5.3 folding. A consumer that already holds `subnet_group(ip)` renders the same
class from the same IP. Two peers sharing a `/16` (or `/32`) are ONE source: an attacker's cheap
peers on one provider block cannot manufacture agreement with each other.

**Independence == string inequality.** No other comparison is defined, so the shipped consumer rule
"two readings corroborate when `other.source != reading.source`"
(`dig-node-service/src/mirror/advertise.rs:261-273`) is already the correct comparison once labels
follow this grammar.

### 7.3 `establish(readings: &[Reading]) -> Established`

```rust
pub const MIN_INDEPENDENT_CLASSES: usize = 2;
pub const PEER_ONLY_MIN_CLASSES: usize = 3;
pub enum FamilyVerdict {                       // exhaustive, five variants
    NoReadings,
    Disagreement { addrs: Vec<IpAddr> },      // ≥ 2 distinct IPs reported in this family
    Insufficient { classes: usize, peer_only: bool },
    NotGlobal { ip: IpAddr, scope: Scope },
    Established { ip: IpAddr, classes: usize },
}
pub struct Established { pub ipv6: FamilyVerdict, pub ipv4: FamilyVerdict }
impl Established {
    pub fn ipv6_addr(&self) -> Option<Ipv6Addr>;   // Some only for Established
    pub fn ipv4_addr(&self) -> Option<Ipv4Addr>;
}
```

For each address family, evaluated independently:

1. **Partition.** A reading belongs to IPv4 when `addr.ip()` is IPv4 OR folds to IPv4 under §5.3;
   otherwise IPv6. Compare IPs after folding.
2. **No readings** → `NoReadings`.
3. **Unanimity (fail closed).** If the readings in the family name more than one distinct IP →
   `Disagreement`. Nothing is established for that family, however many readings agree with each
   other. A single dissenting source blocks — by design: a node behind a multi-egress NAT, a
   misconfigured relay, and a lying peer all look the same from here, and in every one of those cases
   advertising is wrong.
4. **Enough independent classes.** Let `classes` = the number of distinct `source` strings. If
   `classes < MIN_INDEPENDENT_CLASSES` → `Insufficient`. If EVERY class is a `peer:*` class and
   `classes < PEER_ONLY_MIN_CLASSES` → `Insufficient { peer_only: true }`.
5. **Global unicast.** If `scope_of_ip(ip) != Scope::GlobalUnicast` → `NotGlobal`. (A LAN or CGNAT
   reading is a true reading of the node's position; it is still never something to advertise to
   strangers.)
6. Otherwise `Established { ip, classes }`.

Non-answers — a timeout, a refusal (§6.3), an `-32601`, a parse error — are NOT readings. They neither
agree nor dissent and MUST NOT be passed to `establish`.

**Only the IP is compared.** Readings from the UDP tiers carry the listen socket's mapped port;
readings from peers carry an ephemeral port (§6.2). Comparing `SocketAddr`s would make the tiers
incapable of agreeing by construction. The consumer pairs the established IP with its own listen port.

### 7.4 Why these thresholds, and what they do NOT prove

- Two classes is the floor everywhere else in this ecosystem calls corroboration (dig-node SPEC
  §18.16 `CORROBORATION_FLOOR = 2`; §25.10 "two DIFFERENT sources"). It is an assumption, not a
  derived constant.
- Three classes when only peers answered, because two peer classes is exactly two cheap VMs in two
  provider blocks. Three raises the price and — with unanimity — requires the attacker to be EVERY
  peer the requester asked, in three distinct `/16`s, while no honest peer answered. That is a full
  eclipse of the requester's direct outbound pool. **This rule does not defeat a full eclipse; it
  makes the peer tier no weaker than the pool it rides on**, whose eclipse defences (INT-006 `/16`,
  INT-007 AS, cycling — NC-12) are dig-gossip's, not this crate's.
- AS-level independence (INT-007) would be stronger. It is **vacuous today**: dig-gossip's
  `AsLookupTable` is reference data with no production loader (`src/util/as_lookup.rs:20-23`), and
  unknown IPs fail open. The `/16`//`/32` class is the live discriminator. When an AS table ships, the
  peer class MAY be upgraded to `peer:as:<asn>` — an additive grammar change.
- An established address proves that several independent observers saw the requester's traffic
  leave from that IP. It does NOT prove a stranger can connect to any port at it, that the mapping is
  stable for an epoch, or that it is the requester's ONLY public address. Liveness and reachability
  are the consumer's gates (dig-node SPEC §25.10).

### 7.5 Failure direction

Every branch of §7.3 other than `Established` yields NO address. A wrong `Established` puts an address
into a coin, permanently, with $DIG collateral behind it (dig-node#566, #562). A wrong non-establishment
costs one epoch's rewards and is visible in `dign network-info`. The rule therefore resolves every
ambiguity toward not establishing.

---

## 8. Public API surface

### 8.1 Items (normative; `0.1.0`)

| Module | Items |
|---|---|
| `dig_stun` (root) | `MAGIC_COOKIE`, `BINDING_REQUEST`, `BINDING_SUCCESS`, `ATTR_XOR_MAPPED_ADDRESS`, `ATTR_MAPPED_ADDRESS`, `TransactionId`, `StunError`, `encode_binding_request`, `parse_binding_response`, `parse_binding_request`, `encode_binding_success`, `new_transaction_id`, `query_reflexive_address` |
| `dig_stun::scope` | `Scope`, `scope_of`, `scope_of_ip`, `is_usable_reflexive_addr`, `is_globally_routable` |
| `dig_stun::observe` | `Direction`, `Path`, `SessionMeta`, `Refusal`, `observe`, `ObserveLimiter`, `OBSERVE_PER_SESSION_PER_MINUTE`, `OBSERVE_GLOBAL_PER_SECOND`, `MAX_TRACKED_SOURCES` |
| `dig_stun::establish` | `Reading`, `SourceClass`, `FamilyVerdict`, `Established`, `establish`, `MIN_INDEPENDENT_CLASSES`, `PEER_ONLY_MIN_CLASSES` |

`query_reflexive_address` is the crate's only `async fn` and its only I/O; everything else is pure.

### 8.2 Re-export contract for `dig-nat` (normative for the extraction)

`dig_nat::stun` MUST continue to export, under the same names and signatures as `0.21.1`, these ten
items as re-exports of this crate: `MAGIC_COOKIE`, `BINDING_REQUEST`, `BINDING_SUCCESS`,
`ATTR_XOR_MAPPED_ADDRESS`, `ATTR_MAPPED_ADDRESS`, `StunError`, `encode_binding_request`,
`parse_binding_response`, `query_reflexive_address`, `new_transaction_id`. `discover_reflexive_address`
stays defined in `dig-nat` (§1, §9). The private `is_usable_reflexive_addr` at
`dig-nat/src/stun.rs:98` is DELETED there and its five tests (`reflexive_guard_tests`) move here;
`tests/stun.rs` (codec) moves here; `tests/reflexive.rs` (the happy-eyeballs walk) stays in `dig-nat`
and its private `build_xor_response` helper is replaced by `dig_stun::encode_binding_success`.

The type identity of `StunError` changes from a dig-nat type to a dig-stun type re-exported by
dig-nat. No consumer in the ecosystem implements a trait for it or names it by path other than
`dig_nat::stun::StunError` (measured 2026-09-05: dig-node calls
`dig_nat::stun::query_reflexive_address` at `net.rs:773` and matches on `Ok`/`Err` only).

---

## 9. Dependencies and level

- Level **`00-foundation`** (`modules/crates/00-foundation/dig-stun`). The crate MUST NOT depend on any
  `dig-*` or `chia-*` crate. Permitted external dependencies: `tokio` (`net`, `time`), `ring` (§3),
  `thiserror`, `tracing`. `dig-nat` (`10-primitives`) depends on it: a legal reference-DOWN edge.
- `discover_reflexive_address` needs `dig_ip::{connect, PeerCandidates, CandidateSource, DialConfig,
  LocalStack}` (`dig-nat/src/stun.rs:369-420`). `dig-ip` is level 00, so it cannot be a dependency of
  this crate and that function cannot move here. It stays in `dig-nat`, composing `dig-ip` with §4.
- `license = "Apache-2.0 OR MIT"`, `rust-version = "1.75.0"`, matching `dig-nat`.
- Published to crates.io as `dig-stun` (name verified free 2026-09-05: `index.crates.io/di/g-/dig-stun`
  → 404 with `User-Agent: dig-loop`). Consumers depend by version, never `git =` (NC-7).

---

## 10. Security properties, and what a reader may NOT conclude

1. A parsed Binding response is trusted only after cookie, type, transaction id, and source-address
   checks (§2.4, §4). A forged response needs the 96-bit CSPRNG id AND the server's source address.
2. A decoded address is never advertised without the §5 scope guard; mapped/compat IPv6 cannot smuggle
   a reserved IPv4 range past it (§5.3 fold rule).
3. The peer tier has no reflection surface (§6.1) and its limiter keys on transport facts (§6.4).
4. No single source — server, relay, or peer — can establish an address (§7.3 step 4); one dissenting
   source can prevent establishment (§7.3 step 3). The second property is deliberate and is a
   denial-of-advertisement lever for a peer that lies; the cost it imposes is an epoch's rewards, not
   money, and the dissenter is identifiable by its `witness`.

A reader MAY NOT conclude from any result in this crate that: the requester is reachable at any port;
the reported port is a listen mapping; the address is stable for an epoch; the address is the
requester's only egress; a `PrivateScope` reading is wrong (it is a true reading and an unadvertisable
one); or that agreement among `PEER_ONLY_MIN_CLASSES` classes is proof against an adversary who has
eclipsed the requester's whole direct pool.

---

## 11. Conformance

The crate MUST ship these tests; each is a requirement, not a suggestion.

1. **Codec golden vectors** — the three vectors of §2.3 and §2.7 byte-exact, plus the §2.7 round-trip
   law over native IPv4 and IPv6 and the mapped-IPv6-encodes-as-family-1 rule.
2. **`parse_binding_response`** — the nine tests at `dig-nat/tests/stun.rs:13-105` moved intact
   (RFC header, XOR v4, XOR v6, legacy MAPPED fallback, bad cookie, txid mismatch, truncated, no
   mapped address, non-success type).
3. **`parse_binding_request`** — accepts a bare request and one carrying an ignored attribute;
   rejects short, wrong-cookie, non-request-type, top-bits-set, and length-overrun datagrams.
4. **Transaction id** — the two statistical tests at `dig-nat/tests/stun.rs:195,230` moved intact.
5. **Scope table** — the five `reflexive_guard_tests` at `dig-nat/src/stun.rs:443-533` moved intact,
   PLUS one assertion per row of §5.3 for BOTH predicates (so the table is checked, not the examples),
   PLUS the four §5.4 reconciliation cases named explicitly.
6. **`observe`** — a truth table over `Direction × Path × Scope` (2 × 2 × 3 = 12 cells) and the
   mapped-v6-folds-to-v4 case.
7. **`ObserveLimiter`** — per-session, per-source, and global budgets each refuse independently; the
   LRU bound holds under `MAX_TRACKED_SOURCES + 1` distinct sources.
8. **`establish`** — one test per `FamilyVerdict` variant per family, plus: two peers in one `/16` are
   one class; three peer classes establish and two do not; one relay + one peer establish; a single
   dissenting public reading blocks two agreeing peers; UDP-tier and peer readings with different
   PORTS but the same IP agree; a mapped-v6 reading lands in the IPv4 family; a `PrivateScope`
   unanimous reading is `NotGlobal`.
9. **Cross-crate byte identity** (in the consumers, with `dig-stun` as a dev-dependency):
   `dig-nat`'s `tests/reflexive.rs` responder uses `encode_binding_success`; `dig-relay` asserts
   `build_binding_response(id, a) == dig_stun::encode_binding_success(&id, a)` for one v4 and one v6
   `a` (§11.4).

### 11.4 Relay adoption (optional, deferred)

`dig-relay` MAY replace its `parse_binding_request` / `build_binding_response` with §2.5 / §2.7 and
keep its own UDP serve loop and limiter. Until it does, the §11 item 9 byte-identity test is the
contract between the two codecs. Adoption is deferred because the relay is a separate GPL-2.0
application with its own e2e and deploy pipeline and gains no behaviour from the swap.

---

## 12. Versioning and compatibility

- `0.1.0` is the first release. Everything in §8.1 is public; `StunError`, `Scope`, `Refusal`,
  `FamilyVerdict` are exhaustive enums and adding a variant to any of them is a breaking change.
  `Reading` and `SessionMeta` MUST be `#[non_exhaustive]` with constructors, so an additive field is a
  patch for consumers.
- **NC-6 posture for the peer tier.** A node that does not implement `dig.getObservedAddress` answers
  `-32601 METHOD_NOT_FOUND` (dig-rpc-protocol SPEC §3.1). A requester MUST treat that exactly as a
  refusal (§7.3: not a reading) and move on. Old and new nodes therefore interoperate with no
  negotiation: the method is a soft-fork addition.
- The `source` grammar (§7.2) is additive: new prefixes may be added; existing renderings never change.

---

## 13. Cross-references

- dig_ecosystem `SYSTEM.md` — the crate row for `dig-stun` (added with this crate; superproject-owned).
- `dig-nat` `SPEC.md` §3.4, §6, §7 — the walk, the anti-spoof requirements, the config; amended to
  cite this crate.
- `dig-rpc-protocol` `SPEC.md` §2.2 (`-32018 OBSERVATION_UNAVAILABLE`), §3.1 (allowlist), §4.2
  (`dig.getObservedAddress`; `dig.getNetworkInfo` `reflexive_addr` / `reflexive_readings`).
- `dig-node` `SPEC.md` §25.10 — the derived advertisement and its agreement gate.
- docs.dig.net `protocol/peer-network.md` §3 (STUN) and §7 (peer RPC).
- `canonical` skill — "IPv4-in-IPv6 canonicalization for address-usability guards" (this crate is the
  reference implementation from `0.1.0`).
