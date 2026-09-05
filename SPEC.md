# dig-stun — Normative Specification

This document is the authoritative contract an independent reimplementation can be built against. It
is not a README and carries no history.

Every clause below is implemented in `0.1.1` unless marked **[`0.2.0`]**, in which case it is
implemented from that release. Clauses tagged **[EXTRACTED]** describe behaviour moved byte-for-byte
and test-for-test from `dig-nat 0.21.1` `src/stun.rs` (origin/main `6d44a43`); the cited `dig-nat` line
is where the behaviour was true before the move. Clauses tagged **[NEW]** did not exist anywhere before
this crate. Clauses tagged **[RECONCILED]** replace two shipped implementations that disagreed (§5.4) —
a deliberate behaviour change, and the only one in this crate's first release.

---

## 1. Scope and role

`dig-stun` is the DIG ecosystem's single home for **reflexive-address discovery**: how a node learns
the public address the outside world sees its traffic arrive from, and how it decides whether to
believe what it was told.

It owns exactly five things:

1. **The RFC 5389 Binding codec** (§2, §3) — request and success-response, both directions.
2. **The UDP STUN client** (§4) — one Binding transaction against one server over one socket.
3. **The address-scope classifier** (§5) — the single predicate every consumer uses to ask "could this
   address be a legitimate reflexive candidate, and could a stranger route to it?".
4. **The peer-observation role** (§6) and **the agreement rule** (§7) — the parts that let every
   directly-reachable DIG node act as a reflexive-address source for its peers, and let a requesting
   node combine what several sources said without trusting any one of them.
5. **The signed-Binding credential** (§14) — the challenge/response that lets a DIG-operated UDP STUN
   server tell a DIG node's ask from anyone else's, and the exact bytes a requester signs. The crate
   owns the wire form, the nonce contract, the signing preimage and the verifier; it does NOT hold
   private keys (§14.6).

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
- **Any membership policy over a verified credential identity.** The credential yields a verified
  SPKI (and so a `peer_id`); whether that identity is *admitted* is a decision of the deployment that
  runs the server. This crate ships no such policy and defines no registry (§14.10).

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
It MUST NOT interpret a Binding Error Response (type `0x0111`); that is `credential::parse_challenge`
(§14.5). A caller that receives `UnexpectedType(0x0111)` from this function has asked a server that
requires the credential (§14.8) with a client that does not speak it. **[`0.2.0`]**

### 2.5 `parse_binding_request(datagram: &[u8]) -> Result<TransactionId, StunError>` **[NEW]**

The server-side parser. It MUST:

1. Reject `datagram.len() < 20` as `Truncated`.
2. Reject a cookie ≠ `MAGIC_COOKIE` as `BadMagicCookie`.
3. Reject a message type whose top two bits are non-zero, or that is ≠ `BINDING_REQUEST`, as
   `UnexpectedType(type)`. Every other STUN method or class is refused here; a caller that wants RFC
   5389's "silently ignore" latitude does so by not replying.
4. Reject `datagram.len() < 20 + message_length` as `Truncated`.
5. Return the 12 id bytes. Attributes present on a request (e.g. `SOFTWARE`) are accepted and ignored.

This function ignores attributes by design and is sufficient for a server that answers bare requests
only. A server implementing §14 MUST use `credential::classify_request` (§14.5), which walks the
attributes; the two agree on every datagram this function accepts. **[`0.2.0`]**

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
(`dig-nat` re-exports it, §8.2). No variant is added in `0.1.1`.

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
    /// `per_session_and_source_per_minute` sizes BOTH the per-session budget and the per-source-IP
    /// budget — one number, two independently-tracked, independently-keyed maps (§6.4's constructor
    /// note). `global_per_second` sizes the third, shared budget.
    pub fn new(per_session_and_source_per_minute: u32, global_per_second: u32) -> Self;
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

### 8.1 Items (normative; `0.1.1` unless marked `0.2.0`)

| Module | Items |
|---|---|
| `dig_stun` (root) | `MAGIC_COOKIE`, `BINDING_REQUEST`, `BINDING_SUCCESS`, `ATTR_XOR_MAPPED_ADDRESS`, `ATTR_MAPPED_ADDRESS`, `TransactionId`, `StunError`, `encode_binding_request`, `parse_binding_response`, `parse_binding_request`, `encode_binding_success`, `new_transaction_id`, `query_reflexive_address` |
| `dig_stun::scope` | `Scope`, `scope_of`, `scope_of_ip`, `is_usable_reflexive_addr`, `is_globally_routable` |
| `dig_stun::observe` | `Direction`, `Path`, `SessionMeta`, `Refusal`, `observe`, `ObserveLimiter`, `OBSERVE_PER_SESSION_PER_MINUTE`, `OBSERVE_GLOBAL_PER_SECOND`, `MAX_TRACKED_SOURCES` |
| `dig_stun::establish` | `Reading`, `SourceClass`, `FamilyVerdict`, `Established`, `establish`, `MIN_INDEPENDENT_CLASSES`, `PEER_ONLY_MIN_CLASSES` |
| `dig_stun::credential` **[`0.2.0`]** | `ATTR_DIG_IDENTITY`, `ATTR_DIG_SIGNATURE`, `ATTR_ERROR_CODE`, `ATTR_REALM`, `ATTR_NONCE`, `BINDING_ERROR`, `REALM`, `SIG_DOMAIN_TAG`, `CREDENTIAL_VERSION`, `P256_SPKI_LEN`, `P256_SPKI_PREFIX`, `NONCE_LEN`, `NONCE_BUCKET_SECS`, `MAX_SIGNATURE_LEN`, `ERR_BAD_REQUEST`, `ERR_UNAUTHENTICATED`, `ERR_STALE_NONCE`, `CredentialError`, `StunSigner`, `RequestKind`, `classify_request`, `signing_message`, `verify_signed_request`, `VerifiedIdentity`, `NonceIssuer`, `NonceCheck`, `CredentialMode`, `ServerDecision`, `decide`, `encode_challenge`, `encode_identity_request`, `encode_signed_request`, `parse_challenge`, `Challenge`, `query_reflexive_address_signed`, `SignedQueryError` |

`query_reflexive_address` and `query_reflexive_address_signed` are the crate's only `async fn`s and its
only I/O; everything else is pure.

`CredentialError` is exported here even though the epic's original delta table for this module omitted
it: `classify_request`, `verify_signed_request` and `decide` all name it in a public signature
(`Result<_, CredentialError>` / `Option<Result<VerifiedIdentity, CredentialError>>`), so a consumer
cannot match on those results — e.g. to distinguish `Malformed` (→ `400`) from a lower-level `Stun`
failure — without a path to name the type. Recorded as a corrected omission, not a design change.

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
- **[`0.2.0`]** `ring` (already required above) additionally supplies `ring::hmac` (§14.4) and
  `ring::signature` (§14.6); `ring::rand` was already in use (§3). No new dependency. The crate still
  MUST NOT depend on any `dig-*` crate — which is why it verifies against raw SPKI bytes and never
  computes a `peer_id` (§14.6, §14.10).

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
5. **[`0.2.0`]** A signed Binding is answered only after the nonce it carries has been recomputed
   under the server's secret for the sender's source address and one of the two current time buckets
   (§14.4). Signature verification — the only expensive step — is therefore reached only by a sender
   that received a datagram at the address it is sending from, within the last ≤ 120 s. A
   spoofed-source flood cannot reach it at all; a same-source flood is bounded by the response limiter
   the server already runs.
6. **[`0.2.0`]** A captured signed Binding can be replayed only from the source address the nonce is
   bound to, only at the server whose secret issued it, only within the nonce's validity, and yields
   only the reply the original sender already received. No replay cache is kept and none is needed.
7. **[`0.2.0`]** The signing preimage begins with `SIG_DOMAIN_TAG` (§14.6), so a signature produced
   for this purpose is not a valid TLS `CertificateVerify`, `dig:holdings:v1` record signature, or any
   other message the same leaf key signs, and vice versa.
8. **[`0.2.0`]** The SPKI, and so the `peer_id`, is disclosed to the DIG-operated server on every
   signed ask. A client MUST NOT send the credential to a third-party public STUN server (§14.9).

A reader MAY NOT conclude from any result in this crate that: the requester is reachable at any port;
the reported port is a listen mapping; the address is stable for an epoch; the address is the
requester's only egress; a `PrivateScope` reading is wrong (it is a true reading and an unadvertisable
one); or that agreement among `PEER_ONLY_MIN_CLASSES` classes is proof against an adversary who has
eclipsed the requester's whole direct pool; **[`0.2.0`]** or that a verified credential proves the
sender is a member of the DIG network, is registered with any relay, holds any coin, or is anything
more than the holder of a P-256 private key (§14.10); or that a verified requester's ANSWER is more
likely to be true — the credential authenticates the asker, never the reply, and §7 applies to every
reading unchanged (NC-12).

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
10. **[`0.2.0`] Credential codec** — golden vectors for: the 26-byte `P256_SPKI_PREFIX`; a
    bare-refusal `401` (44 bytes); a challenge `401` with `REALM` + a 27-character `NONCE` (88 bytes);
    a `438` (84 bytes); a `400` (40 bytes); an identity request (116 bytes); and a signed request
    built from a fixed test key and a fixed nonce (verify by re-running the verifier, not by
    byte-comparing the DER signature, which is randomised).
11. **[`0.2.0`] Nonce** — `issue` then `check` is `Fresh` in the same bucket and the next; `Stale`
    two buckets later; `Invalid` for any other source IP, any other source PORT, any other secret, any
    flipped byte, and a well-formed nonce of a wrong length; an IPv4-mapped and a native IPv4 source
    yield the SAME nonce.
12. **[`0.2.0`] Server decision table** — one test per row of §14.7, including: an identity request
    is challenged in BOTH modes; a bare request is answered in `Advisory` and refused (no `NONCE`) in
    `Required`; a valid signature under a `Stale` nonce is `438`, never `Answer`; a valid nonce with a
    signature by a DIFFERENT key than the carried SPKI is `401`; a `DIG-SIGNATURE` that is not the
    last attribute is `400`; `verify_signed_request` is NOT invoked for any row other than
    Signed+Fresh (asserted via a counting reference-caller helper).
13. **[`0.2.0`] Client state machine** — against a loopback responder: bare success on first request
    is accepted (old server); challenge → signed → success; `438` once → re-signed → success; `438`
    twice → `Refused{438}`; `401` with a `REALM` other than `dig-stun` → `Refused{401}` with no second
    request sent; a challenge whose transaction id does not match is ignored and the wait continues;
    the whole exchange respects ONE `timeout`.

### 11.4 Relay adoption (optional, deferred)

`dig-relay` MAY replace its `parse_binding_request` / `build_binding_response` with §2.5 / §2.7 and
keep its own UDP serve loop and limiter. Until it does, the §11 item 9 byte-identity test is the
contract between the two codecs. Adoption is deferred because the relay is a separate GPL-2.0
application with its own e2e and deploy pipeline and gains no behaviour from the swap.

---

## 12. Versioning and compatibility

- `0.1.1` is the first release. Everything in §8.1 is public; `StunError`, `Scope`, `Refusal`,
  `FamilyVerdict` are exhaustive enums and adding a variant to any of them is a breaking change.
  `Reading` and `SessionMeta` MUST be `#[non_exhaustive]` with constructors, so an additive field is a
  patch for consumers.
- **NC-6 posture for the peer tier.** A node that does not implement `dig.getObservedAddress` answers
  `-32601 METHOD_NOT_FOUND` (dig-rpc-protocol SPEC §3.1). A requester MUST treat that exactly as a
  refusal (§7.3: not a reading) and move on. Old and new nodes therefore interoperate with no
  negotiation: the method is a soft-fork addition.
- The `source` grammar (§7.2) is additive: new prefixes may be added; existing renderings never change.
- **[`0.2.0`]** adds `dig_stun::credential`. `StunError` is unchanged — no variant added; the
  credential client has its own exhaustive `SignedQueryError`, so `dig-nat`'s re-export and every
  exhaustive matcher of `StunError` keep compiling. `RequestKind`, `NonceCheck`, `CredentialMode`,
  `ServerDecision` and `SignedQueryError` are exhaustive enums; adding a variant to any is a breaking
  change.
- The credential is **version 1** in every field that carries a version byte
  (`CREDENTIAL_VERSION`). A receiver MUST answer `400` to any other version. A second version is not
  additive without negotiation, and how it would be negotiated is out of scope for this document.

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
  reference implementation from `0.1.1`).
- **[`0.2.0`]** `dig-relay` `SPEC.md` §5.2 — the UDP server that requires the credential (the only
  implementer of §14.7 today).
- **[`0.2.0`]** `dig-node` `SPEC.md` §25.10 — the requester (tiers 1-2 signed; tier 4 bare) and the
  statement that the peer tier's authentication is the mTLS client certificate, not this credential.
- **[`0.2.0`]** `relay.dig.net` `SPEC.md` "STUN credential" — the deployment mode and the post-deploy
  probe.
- **[`0.2.0`]** `canonical` skill — "The STUN credential proves key possession, not membership" (this
  crate is the reference implementation from `0.2.0`).

---

## 14. The signed-Binding credential **[NEW, `0.2.0`]**

A **signed Binding** is an RFC 5389 Binding request that carries the requester's TLS-leaf
`SubjectPublicKeyInfo` and an ECDSA-P256 signature, by that leaf's private key, over a server-issued
nonce. It proves three things and only three: (1) the sender **holds the private key** of the SPKI it
carries — the same key whose SHA-256 is its `peer_id` on every mTLS peer session; (2) the sender
**received the server's challenge** at the source address it is sending from (return-routability); (3)
the request is **fresh** (≤ 120 s) and **bound to this server**. It proves **nothing about network
membership**: any party can mint a P-256 key in microseconds and complete the exchange. What it buys is
**attributability** (every answer is tied to a `peer_id`), an **accident filter** (generic STUN clients
and scanners cannot use a DIG server once it requires the credential), a **cost floor** (one signature
per ask), and a **pre-crypto gate** (no signature is verified for a source that has not completed a
round trip). A reader MAY NOT describe this credential as access control or as proof that the sender is
a DIG node.

### 14.1 Purpose, and the bound on it

A DIG-operated UDP STUN server (the relay's `:3478`, or one an operator names in `DIG_STUN_SERVER`)
answers anyone who sends a well-formed Binding request. The credential lets such a server **refuse
requests that do not come from a holder of a DIG peer identity key**, so that generic STUN clients,
scanners and misdirected traffic stop consuming its answers, and so that every answer it does give is
**attributable** to a stable `peer_id`.

**What it does not do, stated once so nothing downstream over-reads it.** The identity key is
self-generated (`dig-tls` `node_cert.rs:117`, `KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)`); the
DigNetwork CA that signs it is public by design (`canonical`, "dig-tls" entry: "the CA key is
intentionally NOT a secret"); and no registry of DIG identities exists that a UDP server could consult
without the circularity of §14.10. Therefore a valid credential proves **key possession, freshness and
return-routability** and nothing else. It raises an attacker's cost from "send 20 bytes" to "complete a
round trip and compute one ECDSA signature per ask" — about 200 µs of CPU — and makes the attacker
nameable. That is the whole of the security gain, and §10 item 5 is where most of it comes from.

### 14.2 Universality — one rule, two mechanisms

**Every DIG reflexive-address source MUST answer only a requester that has proven possession of the
private key of a P-256 `SubjectPublicKeyInfo` whose SHA-256 is its `peer_id`.** The proof differs by
transport, and a source MUST use exactly the mechanism its transport gives it:

| Source | Transport | The proof | Where it is already true |
|---|---|---|---|
| a DIG node answering `dig.getObservedAddress` (§6) | mTLS peer session, client certificate mandatory | the TLS handshake itself — the client's `CertificateVerify` is an ECDSA-P256 signature by the leaf key over the handshake transcript, and rustls rejects the session without it | `dig-tls/src/verify.rs:357` `client_auth_mandatory() -> true`; dig-node `peer.rs:3711` `build_server_tls_config` → `dig_tls::server_config` |
| a DIG-operated UDP STUN server (relay `:3478`, `DIG_STUN_SERVER`) | UDP, no transport identity | this section's signed Binding | this crate, `0.2.0` |
| a third-party public STUN server (tier 4) | UDP, not DIG-operated | none — outside DIG's control; consulted bare | `dig-node` `net.rs:527` `PUBLIC_STUN_SERVERS` |

A node MUST NOT add this credential to `dig.getObservedAddress`: the session already carries a stronger
proof of the same key (a signature over the whole handshake, verified before any request is read), a
second proof on the same connection gives the responder no new fact, and the limiter (§6.4) already keys
on the authenticated `peer_id`. Adding ceremony to a channel that has the property is not "universal"; it
is redundant. The requirement is universal in the RULE, not in the byte format.

### 14.3 Wire — attributes and error responses (byte-level, normative)

All DIG attributes are **comprehension-optional** (type ≥ `0x8000`, RFC 5389 §15/§18.2), chosen in the
`0xC072–0xFFFF` block that IANA lists as Unassigned (verified 2026-09-05 against
`iana.org/assignments/stun-parameters`). A server that does not know them ignores them and answers as it
always did — which is exactly the behaviour the migration relies on (§14.8). They are NOT registered
with IANA; a collision with a future assignment would matter only if a DIG client sent the attribute to
a server implementing that assignment, which §14.9 forbids for non-DIG servers.

| Constant | Value | Meaning |
|---|---|---|
| `ATTR_DIG_IDENTITY: u16` | `0xD160` | the requester's TLS-leaf SPKI (§14.3.1) |
| `ATTR_DIG_SIGNATURE: u16` | `0xD161` | the requester's signature (§14.3.2) |
| `ATTR_ERROR_CODE: u16` | `0x0009` | RFC 5389 §15.6 |
| `ATTR_REALM: u16` | `0x0014` | RFC 5389 §15.7; value is always `REALM` |
| `ATTR_NONCE: u16` | `0x0015` | RFC 5389 §15.8; value per §14.4 |
| `BINDING_ERROR: u16` | `0x0111` | method Binding, class Error Response |
| `REALM: &str` | `"dig-stun"` | 8 bytes; the mechanism discriminator a client checks (§14.5) |
| `CREDENTIAL_VERSION: u8` | `0x01` | the only version |
| `ERR_BAD_REQUEST / ERR_UNAUTHENTICATED / ERR_STALE_NONCE: u16` | `400 / 401 / 438` | RFC 5389 §15.6 classes; 401 is spelled "Unauthenticated" per RFC 8489 |

`REALM`, `NONCE`, `ERROR-CODE` are the standard attributes with their standard meanings; the RFC 5389
long-term-credential mechanism (`USERNAME` / `MESSAGE-INTEGRITY`) is NOT implemented and the RFC 8489
nonce cookie (`obMatJos2`) is deliberately NOT emitted, so a standards client reads a DIG `401` as an
ordinary authentication failure it cannot satisfy — an error it understands, never a silent drop.

#### 14.3.1 `DIG-IDENTITY` value — exactly 92 bytes

```
[version:1 = 0x01][spki_der:91]
```

`spki_der` MUST be the `SubjectPublicKeyInfo` DER of the requester's TLS leaf — the bytes
`dig_tls::NodeCert::spki_der()` returns, the same bytes `peer_id_from_tls_spki_der` hashes. A P-256 SPKI
with an uncompressed point is a fixed 91-byte DER whose first 26 bytes are constant:

```
P256_SPKI_LEN = 91
P256_SPKI_PREFIX = 30 59 30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d 03 01 07 03 42 00
byte[26] = 0x04 (uncompressed SEC1 point), bytes[27..91] = X ‖ Y
```

A receiver MUST reject (as `400`) any value whose length is not 92, whose version is not `0x01`, whose
bytes `1..27` are not `P256_SPKI_PREFIX`, or whose byte `27` is not `0x04`. This accepts exactly the
SPKIs `dig-tls` mints (`node_cert.rs:117`, ring-generated P-256, uncompressed) and rejects every other
algorithm, curve and point encoding without an ASN.1 parser. 92 is a multiple of 4: no padding.

#### 14.3.2 `DIG-SIGNATURE` value — 1 + (8..=72) bytes

```
[version:1 = 0x01][sig_der: ECDSA-P256-SHA256 signature, ASN.1 DER (RFC 3279 Ecdsa-Sig-Value)]
```

`MAX_SIGNATURE_LEN = 72`. A receiver MUST reject (`400`) a value shorter than 9 or longer than 73 bytes
or with a version other than `0x01`. The DER form (rather than fixed `r‖s`) is chosen so the requester
signs with the SAME `ring::signature::EcdsaKeyPair` it already holds for `dig:holdings:v1` records
(`dig-node` `holdings.rs:155-163` `signer_from_node_cert`, `ECDSA_P256_SHA256_ASN1_SIGNING`) — one leaf
signer object, no second key construction. `DIG-SIGNATURE` MUST be the LAST attribute of the request; a
receiver MUST reject (`400`) a request with any attribute after it. Padding per RFC 5389 (to 4).

#### 14.3.3 Error responses — three shapes, byte-exact

Header: type `0x0111`, length, `MAGIC_COOKIE`, the REQUEST's transaction id. `ERROR-CODE` value is
`00 00 <class> <number>` + UTF-8 reason phrase (RFC 5389 §15.6), padded to 4. Reason phrases are fixed:
`401` → `"Unauthenticated"` (15), `438` → `"Stale Nonce"` (11), `400` → `"Bad Request"` (11).

| Shape | Attributes | Size | Sent in reply to | Reflection ratio |
|---|---|---|---|---|
| bare refusal | `ERROR-CODE 401` | **44** bytes | a bare request in `Required` mode | 44/20 = 2.2 — equal to today's IPv6 success (44/20) |
| challenge | `ERROR-CODE 401` + `REALM "dig-stun"` + `NONCE` (27 chars, padded 28) | **88** bytes | an identity request, or a signed request with an invalid nonce or bad signature | 88/116 = 0.76 — smaller than the request |
| stale | `ERROR-CODE 438` + `REALM` + fresh `NONCE` | **84** bytes | a signed request whose nonce is from an expired bucket | 84/≥212 < 0.4 |
| malformed | `ERROR-CODE 400` | **40** bytes | any credential attribute violating §14.3.1/§14.3.2 or the ordering rules | 40/≥116 < 0.35 |

A challenge or stale response MUST NOT carry `XOR-MAPPED-ADDRESS`: that would hand the answer to a
requester that has not yet proven anything, which is the one thing the credential exists to withhold. A
bare request is 20 bytes and its source is unproven; answering it with an 88-byte challenge would raise
the server's worst-case reflection ratio from 2.2 to 4.4 toward a spoofed victim, so a bare refusal
carries no `NONCE` and stays at 44 bytes — exactly today's success-response ratio. A nonce is issued only
to a request that already carries a 92-byte identity, so a challenge, stale, or malformed reply — each
sent only to an already-credentialed request — is never larger than what triggered it. The bare refusal
is the one shape with no such request to size against; it is bounded to today's baseline STUN success
ratio (2.2) rather than exceeding it, so it adds no amplification headroom this credential did not
already inherit from ordinary STUN. Golden vectors for all four shapes are §11 item 10.

### 14.4 The nonce — stateless, source-bound, time-bucketed

```rust
pub const NONCE_LEN: usize = 20;            // raw; the NONCE attribute carries base64url(no pad) of it = 27 chars
pub const NONCE_BUCKET_SECS: u64 = 60;
pub struct NonceIssuer { /* secret: [u8; 32] */ }
pub enum NonceCheck { Fresh, Stale, Invalid }   // exhaustive
impl NonceIssuer {
    pub fn new_random() -> Self;                              // ring::rand::SystemRandom; panics on CSPRNG failure (§3 rule)
    pub fn from_secret(secret: [u8; 32]) -> Self;             // for deployments that must share one issuer across replicas
    pub fn issue(&self, source: SocketAddr, now_unix_secs: u64) -> [u8; NONCE_LEN];
    pub fn check(&self, nonce_attr_value: &[u8], source: SocketAddr, now_unix_secs: u64) -> NonceCheck;
}
```

`issue` MUST compute, with `bucket = (now_unix_secs / NONCE_BUCKET_SECS) as u32`:

```
tag   = HMAC-SHA256(secret, b"dig:stun:nonce:v1" ‖ bucket_be(4) ‖ family(1) ‖ ip_bytes ‖ port_be(2))[..16]
nonce = bucket_be(4) ‖ tag(16)
```

where `source` is FIRST folded per §5.3 (`Ipv6Addr::to_ipv4()`, so `::ffff:a.b.c.d` and `a.b.c.d` are one
source, exactly as the limiter keys them) and then `family` is `0x01` with 4 `ip_bytes` for IPv4 or
`0x02` with 16 for IPv6. The attribute value is the base64url encoding without padding (RFC 4648 §5) of
those 20 bytes — 27 characters, all within RFC 5389's `qdtext`.

`check` MUST: decode base64url (any decode failure or length ≠ 20 → `Invalid`); recompute `tag` for the
nonce's OWN bucket and the caller's `source` and compare in constant time (mismatch → `Invalid`); then
return `Fresh` if the nonce's bucket is `now_bucket` or `now_bucket − 1`, else `Stale`. Tag before bucket,
so a forged nonce is never reported as merely stale. A nonce is therefore valid for **60–120 s**, for
**one source ip:port**, at **the issuer that made it**. No state is kept per nonce, per client, or per
transaction.

**Replicas.** A deployment running several server processes behind one address MUST either share a
secret (`from_secret`) or accept that a nonce issued by one replica is `Invalid` at another. Where the
balancer pins a UDP 5-tuple to one target for the flow's lifetime — AWS NLB does, and both datagrams of a
transaction share the client's socket — the per-process default is correct; a re-balanced flow costs the
client one `401` re-challenge (§14.5 retries once), never a failure. The relay's deployment records which
it relies on (relay.dig.net `SPEC.md`).

**Clock.** Only the SERVER's clock is consulted, only to bucket its own nonces. A client needs no
synchronised clock; a server whose clock jumps invalidates at most the nonces of the last two minutes.

### 14.5 Server side — classification, decision, and the order of the cheap checks

```rust
pub enum RequestKind<'a> {                 // exhaustive
    Bare,                                  // no DIG attribute
    Identity { spki: &'a [u8] },           // DIG-IDENTITY, no NONCE, no DIG-SIGNATURE
    Signed { spki: &'a [u8], nonce: &'a [u8], signature: &'a [u8] },
}
pub fn classify_request(datagram: &[u8]) -> Result<(TransactionId, RequestKind<'_>), CredentialError>;
pub enum CredentialMode { Advisory, Required }   // exhaustive
pub enum ServerDecision { Answer { identity: Option<VerifiedIdentity> }, Challenge { code: u16 }, Refuse { code: u16 } }
pub fn decide(mode: CredentialMode, kind: &RequestKind, nonce: Option<NonceCheck>, verified: Option<Result<VerifiedIdentity, CredentialError>>) -> ServerDecision;
pub fn encode_challenge(txid: &TransactionId, code: u16, nonce: Option<&[u8; NONCE_LEN]>) -> Vec<u8>;
```

`CredentialError` is exhaustive (`Stun(StunError)`, `Malformed`, `BadSignature`) — see the §8.1 note on
why it is exported despite the epic's original delta omitting it.

`classify_request` MUST perform §2.5's checks first (a datagram §2.5 rejects is rejected here with the
same `StunError`, wrapped), then walk the attributes: unknown attributes of ANY type are ignored (the
server keeps the RFC's stateless-ignore latitude it has always used; it does not emit `420`); a
`DIG-IDENTITY` violating §14.3.1, a `DIG-SIGNATURE` violating §14.3.2 or not last, a `NONCE` or
`DIG-SIGNATURE` without `DIG-IDENTITY`, a `NONCE` without `DIG-SIGNATURE` or vice versa, or a duplicated
DIG attribute is `CredentialError::Malformed` (→ `400`). It allocates nothing and verifies nothing.

**The order a server MUST evaluate a datagram in — cheapest first, crypto last:**

1. `classify_request` (byte checks; ~ns).
2. **The response limiter**, keyed on the source IP exactly as today (`dig-relay` `stun.rs:307`
   `StunRateLimiter::allow`, or §6.4's `ObserveLimiter`). A datagram the limiter refuses produces NO
   response and NO further work — including no nonce check and no verification. Every response shape in
   §14.3.3 and every success spends one token; the credential adds no exemption and no new dimension.
3. For `Signed`: `NonceIssuer::check` (one HMAC; ~1 µs). `Invalid` or `Stale` → the decision is made
   without touching the signature.
4. For `Signed` + `Fresh` only: `verify_signed_request` (§14.6; one P-256 verification; ~100 µs).

**CPU bound this order guarantees.** Step 4 is reached at most `global_responses_per_sec` times per
second (1000 by default in dig-relay), each by a source that received a datagram at its claimed address
within 120 s. At ~100 µs per verification that is ≤ 0.1 CPU-second per second — on the relay's 256-CPU-unit
Fargate task (0.25 vCPU) about 40 % of the task in the worst case, and only when ≥ 100 distinct real
sources each sustain the per-IP cap. A spoofed-source flood costs one HMAC per datagram and never reaches
step 4. Garbage signatures without a valid nonce never reach step 4. The operator's lever is the existing
global cap.

### 14.6 The signature — preimage, algorithm, verifier, signer

```rust
pub const SIG_DOMAIN_TAG: &[u8] = b"dig:stun:v1";
pub fn signing_message(txid: &TransactionId, nonce_attr_value: &[u8], spki_der: &[u8]) -> Vec<u8>;
pub struct VerifiedIdentity { spki: [u8; P256_SPKI_LEN] }   // #[non_exhaustive]; pub fn spki_der(&self) -> &[u8; 91]
pub fn verify_signed_request(txid: &TransactionId, kind: &RequestKind /* must be Signed */) -> Result<VerifiedIdentity, CredentialError>;
pub trait StunSigner {
    fn spki_der(&self) -> &[u8];                 // exactly the 91 bytes of §14.3.1
    fn sign(&self, message: &[u8]) -> Vec<u8>;   // ECDSA-P256-SHA256, ASN.1 DER
}
```

The preimage is the FIELDS, not the datagram bytes (the shape `dig-gossip` uses at
`holdings_announce.rs:363-392`, so the signed request's length field and padding never enter the
signature and a DER signature of variable length is unproblematic):

```
signing_message = SIG_DOMAIN_TAG ‖ 0x01 ‖ transaction_id(12) ‖ nonce_len_be(2) ‖ nonce_attr_value ‖ spki_der(91)
```

`nonce_attr_value` is the `NONCE` attribute value EXACTLY as carried (the 27 base64url bytes), not the
decoded 20. The signature is ECDSA with P-256 and SHA-256 (ring hashes the preimage internally), DER
encoded. `verify_signed_request` MUST: take the 65-byte point at `spki[26..91]`; verify with
`ring::signature::ECDSA_P256_SHA256_ASN1` over `signing_message(txid, nonce, spki)`; on success return
`VerifiedIdentity` carrying the SPKI. A `kind` that is not `Signed` is a caller precondition violation;
this crate returns `CredentialError::Malformed` for it rather than panicking, since the function sits on
a path that ultimately parses untrusted datagrams. It MUST NOT compute a `peer_id` — that is
`dig_tls::peer_id_from_tls_spki_der` (`dig-tls/src/identity.rs:71`), which this level-00 crate cannot
depend on; callers that want the `peer_id` hash the SPKI with that function (dig-relay uses its own
existing derivation at `tls.rs:177-180`, which is the same bytes).

**What the preimage binds, and why each field.** `transaction_id`: the response the requester will
accept. `nonce`: the issuing server, the source ip:port, the time bucket (§14.4) — freshness and
return-routability without a client clock. `spki_der`: the key the signature is checked against, so the
identity cannot be swapped under a valid signature. Nothing else is signed: the message type is fixed by
the server (it answers Binding only), and any other attribute a sender adds is ignored (§14.5).

**Signing oracle.** A requester will sign whatever nonce a `401` hands it, including one an on-path
attacker forged. The resulting signature is valid only as a `dig:stun:v1` preimage — a STUN request at
the server whose secret matches that nonce, from that source, within two minutes — and so is worth
nothing to the attacker. This is why `SIG_DOMAIN_TAG` is first in the preimage and why the tag is
distinct from `dig:holdings:v1` and from every TLS context string.

**No private key in this crate.** `StunSigner` is implemented by the consumer over the key it already
holds. dig-node implements it for the object `signer_from_node_cert` builds (`holdings.rs:155-163`: an
`EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, cert.rustls_private_key().secret_der(), …)`
paired with `cert.spki_der()`); no second `from_pkcs8` site is written. The client (§14.9) MUST check
`signer.spki_der()` against §14.3.1 at construction and refuse to start a transaction otherwise (fail
closed: a malformed identity never reaches the wire).

### 14.7 The decision table (normative, exhaustive)

| # | `RequestKind` | `CredentialMode` | nonce | signature | `ServerDecision` | response | counter |
|---|---|---|---|---|---|---|---|
| 1 | `Bare` | `Advisory` | – | – | `Answer{identity: None}` | success (§2.7) | `stun_requests`, `stun_unsigned` |
| 2 | `Bare` | `Required` | – | – | `Refuse{401}` | bare refusal (44 B) | `stun_rejected` |
| 3 | `Identity` | either | – | – | `Challenge{401}` | challenge (88 B) with a fresh nonce | `stun_challenges` |
| 4 | `Signed` | either | `Invalid` | not checked | `Challenge{401}` | challenge with a fresh nonce | `stun_rejected` |
| 5 | `Signed` | either | `Stale` | not checked | `Challenge{438}` | stale (84 B) with a fresh nonce | `stun_challenges` |
| 6 | `Signed` | either | `Fresh` | `Err(BadSignature)` | `Challenge{401}` | challenge with a fresh nonce | `stun_rejected` |
| 7 | `Signed` | either | `Fresh` | `Ok(identity)` | `Answer{identity: Some}` | success (§2.7) | `stun_requests`, `stun_signed` |
| 8 | any `Malformed` (§14.5) | either | – | – | `Refuse{400}` | malformed (40 B) | `stun_rejected` |

Rows 1-2 are inherently mode-specific (they ARE the two values `Bare` can take); rows 3-8 hold for
BOTH modes, so §11 item 12's test suite exercises each of rows 3-8 once per mode in addition to rows 1
and 2, alongside row 8's `Malformed` case (which never reaches `decide` — there is no `RequestKind` to
classify it as, so the caller maps `classify_request`'s `Err(Malformed)` straight to
`encode_challenge(txid, 400, None)`). **An identity request is challenged in BOTH modes.** That is what
makes the client's path identical before and after a deployment flips to `Required`, lets a server
measure its signed population while still `Advisory`, and lets the deploy probe exercise the signed path
from day one. Every response passes the limiter (§14.5 step 2) before it is sent.

The success response to a signed request is the ordinary §2.7 success — it carries no acknowledgement of
the credential and is byte-identical to the one an unsigned request receives. The server MUST NOT sign
its response (there is no server key distribution, and NC-12 makes agreement, not authentication, the
defence against a lying server — §7 unchanged). It MUST NOT log the SPKI or `peer_id` above `debug`, MUST
NOT persist which identities asked, and MAY count per-identity only in bounded memory (the same posture
as §6.5).

### 14.8 Modes and migration — advisory first, then required

`CredentialMode` is a SERVER deployment setting, never wire-negotiated. Its two values differ in exactly
one row of §14.7 (row 1 vs row 2: what a bare request gets). The sequence a deployment MUST follow:

1. **Ship `Advisory`.** Bare requests are answered exactly as before; identity requests are challenged
   and signed requests answered and counted. Nothing any existing client does changes outcome. The
   server exposes `stun_signed`, `stun_unsigned`, `stun_challenges`, `stun_rejected` beside the existing
   `stun_requests` so the operator can watch adoption. `stun_signed` is **vacuously zero** until a client
   that speaks §14.9 exists; the deploy probe (relay.dig.net delta) is the only non-vacuous exerciser
   until dig-node adopts.
2. **Flip to `Required`** when `stun_unsigned` has fallen to the level the operator is willing to refuse.
   The flip is a configuration change and nothing else. From then on a bare request gets row 2.

**What an OLD node sees after the flip.** A dig-node that predates §14.9 sends a bare request and
receives the 44-byte `401`; its `parse_binding_response` (§2.4) returns `UnexpectedType(0x0111)`; its
tier walk moves to the next endpoint and, per its existing rule, warns that the relay tier did not answer
while something below it did. So: an error, logged, with a reason the operator can act on ("the relay is
not answering my node — upgrade"), and the node keeps working from the public tier. Not a silent drop;
not a crash; one tier lost until the node updates.

**Failure directions.** A wrong server secret, a replica mismatch or a clock jump produces `401`/`438` →
the client re-challenges once, then treats the server as refusing → one fewer reading → at worst
`Insufficient` (§7.3) → nothing advertised. A verifier bug that ACCEPTS invalid signatures mis-attributes
asks but changes no address answer, and every answer is still subject to §7. A verifier bug that REJECTS
valid signatures loses the relay tier for every node — visible in `dign network-info` as a missing
`relay:` class. Every direction is closed or visible; none reaches a coin.

### 14.9 Client side — `query_reflexive_address_signed`

```rust
pub struct Challenge { pub code: u16, pub realm: Option<String>, pub nonce: Option<Vec<u8>> }
pub fn parse_challenge(msg: &[u8], expected_txid: &TransactionId) -> Result<Challenge, StunError>;   // Binding Error Response only
pub fn encode_identity_request(txid: &TransactionId, spki_der: &[u8]) -> Vec<u8>;                    // header + DIG-IDENTITY (116 B)
pub fn encode_signed_request(txid: &TransactionId, nonce_attr_value: &[u8], signer: &dyn StunSigner) -> Vec<u8>;  // header + DIG-IDENTITY + NONCE + DIG-SIGNATURE (≤ 228 B)
pub enum SignedQueryError { Stun(StunError), Refused { code: u16 }, BadChallenge }                   // exhaustive
pub async fn query_reflexive_address_signed(socket: &UdpSocket, server: SocketAddr, timeout: Duration, signer: &dyn StunSigner) -> Result<SocketAddr, SignedQueryError>;
```

One signed transaction. It MUST:

1. Check `signer.spki_der()` per §14.3.1 BEFORE sending anything; on failure return
   `SignedQueryError::BadChallenge` (its documented meaning is "the credential exchange cannot proceed":
   a malformed signer SPKI, or a challenge that cannot be satisfied). Nothing is added to `StunError`.
2. Send `encode_identity_request(new_transaction_id(), spki)` to `server`.
3. Receive with §4's source validation and the ONE `timeout` for the whole exchange, ignoring datagrams
   not from `server` and any response whose transaction id does not match the outstanding request:
   - a **success** (`0x0101`) → parse per §2.4, apply the §5 guard exactly as §4 step 4, return. (This is
     an old relay, a non-DIG server that ignored the attribute, or an `Advisory` server given a bare ask
     — the client does not require a challenge.)
   - an **error** (`0x0111`) → `parse_challenge`:
     - `401` with `realm == Some("dig-stun")` and a nonce → go to 4 (first time only).
     - `438` with a nonce → go to 4 (at most ONCE after a signed request has been sent; a second `438` is
       `Refused{438}`).
     - `401` without `realm == "dig-stun"`, or without a nonce, or any other code → `Refused{code}`. No
       further datagram is sent. (A `401` with a foreign realm is a long-term-credential server the
       client cannot satisfy; a `401` without a nonce is a `Required` server answering a BARE ask, which
       this function never sends — treat as refusal.)
   - anything else → §2.4's error, wrapped in `Stun`.
4. Send `encode_signed_request(new_transaction_id(), nonce, signer)` — a NEW transaction id — and return
   to 3.

At most three datagrams are sent (identity, signed, re-signed after one `438`). The result has exactly
§4's meaning. **The credential MUST be sent only to DIG-operated servers**: in dig-node terms, the
`operator:` and `relay:` tiers. The `public:` tier MUST keep using `query_reflexive_address` (bare) —
those servers would ignore the attribute (comprehension-optional) and the SPKI would tell a third party
which DIG node is asking, which the public tier otherwise does not learn.

IPv6-first (§5.2) is unchanged: the credential rides on each transaction; the walk order and the family
choice are the caller's (§1: tier policy is the consumer's).

### 14.10 What the key is checked against — nothing, and why that is the honest answer

The verifier checks the signature against **the SPKI the request carries**, and nothing else. The
alternatives were evaluated and are recorded so no one re-derives them:

| Check the key against | Membership proven? | Cost | Why not (today) |
|---|---|---|---|
| **nothing** (any valid P-256 key) | **no** | none | — this is the specified behaviour; it buys §14.1's list and is labelled as such |
| the relay's registration table | only where the table is authenticated | a lookup | on `relay.dig.net` TLS terminates at the NLB, so `Register`'s `peer_id` is self-declared (`dig-relay` `server.rs:640` `verified_peer_id: Option`, `None` on the plain-ws path; the mTLS listener that would verify it is optional, `tls.rs:1-30`) — the set is not authenticated; and dig-node discovers its address BEFORE it registers (`peer.rs:2682` → `:2731`), so gating STUN on registration is circular for the node the relay exists to serve; and an `operator:`-tier STUN server has no registry at all |
| the DHT / gossip pool | no (Sybil: identities are free — `canonical` line 781, "attacker IDENTITIES are free and unlimited") | a lookup | proves the key has been SEEN, not that it is anyone in particular; and a brand-new node has not been seen |
| on-chain evidence (mirror coin, collateral) | yes, for the asking key | a chain read on a UDP hot path | circular: the mirror coin carries the ADDRESS this ask is trying to learn (dig-node SPEC §25.10); a chain read per datagram is a latency and availability coupling the STUN path cannot carry; the retainer economy that would give a node a coin BEFORE it has an address is epic #1202, FUTURE, vacuous today |
| a per-identity rate budget | no | a bounded map | keys are free, so a per-key budget bounds honest nodes and not attackers; return-routability already makes the per-IP key real (§14.4); MAY be added later as an ADDITIVE fairness improvement for CGNAT'd populations (many honest nodes behind one IP share one 5/s budget today — unchanged by this spec) |

The specified design therefore keeps the door open without pretending it is closed: `VerifiedIdentity`
gives the deployment a verified SPKI and `peer_id`, and a deployment MAY refuse identities by any policy
it can compute — this crate ships none, and this document defines none. When an AUTHENTICATED registry
exists (the relay's mTLS listener on a deployment that terminates TLS in-task; or #1202's retainers),
"is this `peer_id` registered/retained" becomes a one-line policy over the value §14.6 already returns,
with no wire change. Until then, a reader MUST describe this credential as **attributable,
return-routable, fresh — not as membership**.
