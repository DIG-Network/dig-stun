//! The UDP STUN client (`SPEC.md` §4) — one Binding transaction against one server, over one
//! socket. Extracted byte-for-byte from `dig-nat 0.21.1` `src/stun.rs:309-347`; the only change is
//! that the address-usability guard is now expressed via [`crate::scope::scope_of`] rather than a
//! private per-crate predicate.
//!
//! This is the crate's only `async fn` and its only I/O (`SPEC.md` §8.1) — every other public item
//! is a pure function.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::codec::{encode_binding_request, parse_binding_response, StunError};
use crate::scope::{scope_of, Scope};
use crate::transaction_id::new_transaction_id;

/// Perform a single STUN Binding transaction against `server` over `socket`, returning the
/// discovered reflexive (public) [`SocketAddr`] of `socket`.
///
/// **What the result means, and only this:** the address:port at which `socket`'s datagrams
/// arrived at `server`. The port is the NAT mapping of THAT socket, so the result is a genuinely
/// dialable candidate only when `socket` is the very socket whose external mapping the caller
/// wants — `socket` should be the caller's real listen socket, not a throwaway one, if the caller
/// needs a dialable port rather than merely its public IP. A caller MUST NOT infer inbound
/// reachability from a successful transaction (`SPEC.md` §4, §10).
///
/// # Anti-spoof: two independent defenses
///
/// A UDP reply's source address is easy to check and hard for an off-path attacker to spoof
/// (spoofing the source AND getting the reply routed back requires being on-path or the same
/// network). This function therefore accepts a datagram only when it actually originates from
/// `server`; anything else (a stray reply, a scan, an attacker racing a forged response) is
/// discarded and the receive loop keeps waiting within the overall `timeout` deadline — one
/// mismatched-source datagram must not fail the whole transaction, since the genuine reply may
/// still be in flight. This is independent, defense-in-depth hygiene alongside the transaction-id
/// check ([`new_transaction_id`]); neither replaces the other.
///
/// # The scope guard
///
/// The parsed address is rejected as [`StunError::NoMappedAddress`] when
/// `scope_of(addr) == Scope::NeverDialable` — a malicious or misconfigured STUN server fully
/// controls the bytes it returns, and this stops it from handing back a bogus reflexive address
/// (loopback, multicast, a documentation range, port `0`, …) that the caller would otherwise
/// advertise (`SPEC.md` §5, §10).
pub async fn query_reflexive_address(
    socket: &UdpSocket,
    server: SocketAddr,
    timeout: Duration,
) -> Result<SocketAddr, StunError> {
    let txid = new_transaction_id();
    let req = encode_binding_request(&txid);
    socket
        .send_to(&req, server)
        .await
        .map_err(|e| StunError::Io(e.to_string()))?;

    let mut buf = [0u8; 512];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(StunError::Timeout);
        }
        let (n, from) = match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok(x)) => x,
            Ok(Err(e)) => return Err(StunError::Io(e.to_string())),
            Err(_) => return Err(StunError::Timeout),
        };
        if from != server {
            // Not from the queried server — ignore and keep waiting for the genuine reply.
            continue;
        }
        let addr = parse_binding_response(&buf[..n], Some(&txid))?;
        if scope_of(addr) == Scope::NeverDialable {
            return Err(StunError::NoMappedAddress);
        }
        return Ok(addr);
    }
}
