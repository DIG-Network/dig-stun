//! The RFC 5389 Binding message wire format, both directions (`SPEC.md` §2).
//!
//! A Binding transaction is a fixed 20-byte header followed by TLV attributes. This module encodes
//! and parses that layout with no network I/O — every branch is unit-testable against the RFC byte
//! layout alone. [`encode_binding_request`] / [`parse_binding_response`] are the CLIENT-side halves,
//! extracted byte-for-byte from `dig-nat 0.21.1` `src/stun.rs` (`SPEC.md` §2 cites the exact lines).
//! [`parse_binding_request`] / [`encode_binding_success`] are the SERVER-side halves this crate adds.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::scope::fold_ip;

/// STUN magic cookie (RFC 5389 §6). Always the first 4 bytes after the message type + length.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Binding request message type (RFC 5389 §6 — method Binding = 0x001, class Request = 0b00).
pub const BINDING_REQUEST: u16 = 0x0001;
/// Binding success response message type (method Binding, class Success = 0b10).
pub const BINDING_SUCCESS: u16 = 0x0101;

/// `XOR-MAPPED-ADDRESS` attribute type (RFC 5389 §15.2).
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// Legacy `MAPPED-ADDRESS` attribute type (RFC 5389 §15.1) — some servers still emit it.
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

/// Address family markers inside a (XOR-)MAPPED-ADDRESS attribute.
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

/// The 96-bit STUN transaction id. A plain array alias (not a newtype) so `dig-nat`'s re-exported
/// signatures stay unchanged for its existing consumers (`SPEC.md` §2.1, §8.2).
pub type TransactionId = [u8; 12];

/// Errors decoding a STUN message or performing a Binding transaction (`SPEC.md` §2.8).
///
/// Exhaustive and NOT `#[non_exhaustive]`: `dig-nat` re-exports this type and some of its consumers
/// match on it exhaustively, so adding a variant is a breaking change tracked by SemVer rather than
/// absorbed silently.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StunError {
    /// The datagram was shorter than a valid STUN message / attribute.
    #[error("STUN message truncated")]
    Truncated,
    /// The magic cookie did not match — not a STUN (RFC 5389) message.
    #[error("bad STUN magic cookie")]
    BadMagicCookie,
    /// The transaction id in the response did not match the request (possible spoof / stale reply).
    #[error("STUN transaction id mismatch")]
    TransactionIdMismatch,
    /// The message parsed but carried no usable mapped address: either no (XOR-)MAPPED-ADDRESS
    /// attribute at all, OR (for [`crate::query_reflexive_address`] only) a parsed address that
    /// failed the reflexive-usability guard (`SPEC.md` §5 — e.g. loopback, link-local, multicast, a
    /// documentation range, or `port == 0`).
    #[error("no usable mapped address in STUN response")]
    NoMappedAddress,
    /// The message type was not the one the caller expected (a Binding success response when
    /// parsing a response; a Binding request when parsing a request), or an attribute's address
    /// family byte was neither IPv4 nor IPv6.
    #[error("unexpected STUN message type: {0:#06x}")]
    UnexpectedType(u16),
    /// Underlying socket I/O error (stringified so [`StunError`] stays `Clone`/`Eq`).
    #[error("STUN io: {0}")]
    Io(String),
    /// The transaction did not complete within the deadline.
    #[error("STUN request timed out")]
    Timeout,
}

/// Encode a STUN **Binding request**: a 20-byte header (type, length = 0, cookie, the 96-bit
/// transaction id) and no attributes. `transaction_id` is caller-supplied so the response can later
/// be matched to this request (`SPEC.md` §2.3).
///
/// Golden vector: for id `00 01 02 03 04 05 06 07 08 09 0a 0b` this returns
/// `00 01 00 00 21 12 a4 42 00 01 02 03 04 05 06 07 08 09 0a 0b` (20 bytes) — proven byte-exact in
/// `tests/codec.rs`.
pub fn encode_binding_request(transaction_id: &TransactionId) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);
    msg.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes()); // message length: no attributes
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(transaction_id);
    msg
}

/// Parse a STUN **Binding success response**, returning the reflexive [`SocketAddr`] from its
/// `XOR-MAPPED-ADDRESS` (preferred) or legacy `MAPPED-ADDRESS` attribute (`SPEC.md` §2.4).
///
/// A PURE parser: it does NOT apply the address-usability guard (`SPEC.md` §5) — that is
/// [`crate::query_reflexive_address`]'s job, layered on top of this parse.
///
/// Validates, in order: length ≥ 20 ([`StunError::Truncated`]); the magic cookie (checked BEFORE
/// the message type, so a non-STUN datagram is never misreported as an unexpected STUN type); the
/// message type is [`BINDING_SUCCESS`]; when `expected_txid` is `Some`, the transaction id matches;
/// the declared message length fits the datagram; then walks the TLV attributes, returning the
/// FIRST `XOR-MAPPED-ADDRESS` as soon as one is seen, else the first `MAPPED-ADDRESS`, else
/// [`StunError::NoMappedAddress`].
pub fn parse_binding_response(
    msg: &[u8],
    expected_txid: Option<&TransactionId>,
) -> Result<SocketAddr, StunError> {
    if msg.len() < 20 {
        return Err(StunError::Truncated);
    }
    let msg_type = u16::from_be_bytes([msg[0], msg[1]]);
    let msg_len = u16::from_be_bytes([msg[2], msg[3]]) as usize;
    let cookie = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunError::BadMagicCookie);
    }
    if msg_type != BINDING_SUCCESS {
        return Err(StunError::UnexpectedType(msg_type));
    }
    let txid: TransactionId = msg[8..20].try_into().map_err(|_| StunError::Truncated)?;
    if let Some(expected) = expected_txid {
        if &txid != expected {
            return Err(StunError::TransactionIdMismatch);
        }
    }
    if msg.len() < 20 + msg_len {
        return Err(StunError::Truncated);
    }

    // Walk the TLV attributes. Prefer XOR-MAPPED-ADDRESS; fall back to MAPPED-ADDRESS.
    let mut fallback: Option<SocketAddr> = None;
    let mut off = 20usize;
    let end = 20 + msg_len;
    while off + 4 <= end {
        let attr_type = u16::from_be_bytes([msg[off], msg[off + 1]]);
        let attr_len = u16::from_be_bytes([msg[off + 2], msg[off + 3]]) as usize;
        let val_start = off + 4;
        let val_end = val_start + attr_len;
        if val_end > end {
            return Err(StunError::Truncated);
        }
        let value = &msg[val_start..val_end];
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                return decode_mapped_address(value, &txid, true);
            }
            ATTR_MAPPED_ADDRESS if fallback.is_none() => {
                fallback = decode_mapped_address(value, &txid, false).ok();
            }
            _ => {}
        }
        // Attributes are padded to a 4-byte boundary (RFC 5389 §15).
        off = val_end + ((4 - (attr_len % 4)) % 4);
    }
    fallback.ok_or(StunError::NoMappedAddress)
}

/// Parse a STUN **Binding request** datagram, returning its transaction id (`SPEC.md` §2.5). The
/// server-side counterpart of [`parse_binding_response`], used to answer a peer or the operator/
/// relay/public UDP tiers with [`encode_binding_success`].
///
/// Validates, in order: length ≥ 20 ([`StunError::Truncated`]); the magic cookie
/// ([`StunError::BadMagicCookie`]); the message type is EXACTLY [`BINDING_REQUEST`]
/// ([`StunError::UnexpectedType`] otherwise — this single equality check also rejects a message
/// whose top two type bits are non-zero, since [`BINDING_REQUEST`]'s own encoding has them clear,
/// so no STUN method or class other than Binding+Request is accepted here; a caller wanting RFC
/// 5389's "silently ignore anything else" latitude does so by not replying to that error); the
/// declared message length fits the datagram. Attributes present on the request (e.g. `SOFTWARE`)
/// are accepted and ignored — nothing here needs them.
pub fn parse_binding_request(datagram: &[u8]) -> Result<TransactionId, StunError> {
    if datagram.len() < 20 {
        return Err(StunError::Truncated);
    }
    let msg_type = u16::from_be_bytes([datagram[0], datagram[1]]);
    let msg_len = u16::from_be_bytes([datagram[2], datagram[3]]) as usize;
    let cookie = u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunError::BadMagicCookie);
    }
    if msg_type != BINDING_REQUEST {
        return Err(StunError::UnexpectedType(msg_type));
    }
    if datagram.len() < 20 + msg_len {
        return Err(StunError::Truncated);
    }
    Ok(datagram[8..20]
        .try_into()
        .expect("slice of exactly 12 bytes"))
}

/// Encode a STUN **Binding success response** carrying `reflexive` in one `XOR-MAPPED-ADDRESS`
/// attribute and nothing else — no `MAPPED-ADDRESS`, no `SOFTWARE`, no `FINGERPRINT` (`SPEC.md`
/// §2.7). The server-side counterpart of [`parse_binding_response`].
///
/// `reflexive`'s IP is folded per `SPEC.md` §5.3 (`fold_ip`) BEFORE encoding, so an IPv4-mapped
/// IPv6 address (`::ffff:a.b.c.d`) is encoded as family `0x01` carrying the embedded IPv4 address,
/// never as a 16-byte family `0x02` value — answering an IPv4 caller with a 16-byte address is
/// exactly the family-crossing defect measured on `relay.dig.net` (relay.dig.net#11). The port is
/// carried unchanged; only the IP is folded.
///
/// `parse_binding_response(&encode_binding_success(id, a), Some(id)) == Ok(a)` for every
/// `SocketAddr` `a` whose IP is native IPv4 or native IPv6 — proven in `tests/codec.rs` as the
/// round-trip law `SPEC.md` §2.7 requires.
pub fn encode_binding_success(transaction_id: &TransactionId, reflexive: SocketAddr) -> Vec<u8> {
    let folded = SocketAddr::new(fold_ip(reflexive.ip()), reflexive.port());
    let cookie_be = MAGIC_COOKIE.to_be_bytes();
    let xor_port = folded.port() ^ ((MAGIC_COOKIE >> 16) as u16);

    let mut value = Vec::new();
    value.push(0); // reserved
    match folded.ip() {
        IpAddr::V4(v4) => {
            value.push(FAMILY_IPV4);
            value.extend_from_slice(&xor_port.to_be_bytes());
            let mut octets = v4.octets();
            for (i, o) in octets.iter_mut().enumerate() {
                *o ^= cookie_be[i];
            }
            value.extend_from_slice(&octets);
        }
        IpAddr::V6(v6) => {
            value.push(FAMILY_IPV6);
            value.extend_from_slice(&xor_port.to_be_bytes());
            let mut octets = v6.octets();
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&cookie_be);
            key[4..].copy_from_slice(transaction_id);
            for (o, k) in octets.iter_mut().zip(key.iter()) {
                *o ^= *k;
            }
            value.extend_from_slice(&octets);
        }
    }
    // Both possible value lengths (8 for IPv4, 20 for IPv6) are already 4-byte aligned, so the
    // attribute never needs padding — unlike the general TLV walk in `parse_binding_response`.
    debug_assert_eq!(
        value.len() % 4,
        0,
        "XOR-MAPPED-ADDRESS value must be 4-byte aligned"
    );

    let mut attr = Vec::with_capacity(4 + value.len());
    attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    attr.extend_from_slice(&(value.len() as u16).to_be_bytes());
    attr.extend_from_slice(&value);

    let mut msg = Vec::with_capacity(20 + attr.len());
    msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    msg.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    msg.extend_from_slice(&cookie_be);
    msg.extend_from_slice(transaction_id);
    msg.extend_from_slice(&attr);
    msg
}

/// Decode a (XOR-)MAPPED-ADDRESS attribute value into a [`SocketAddr`] (RFC 5389 §15.1/§15.2).
///
/// Layout: `[reserved:1][family:1][port:2][address:4 or 16]`. When `xor` is set, the port is XORed
/// with the top 16 bits of the magic cookie and the address is XORed with the full cookie (IPv4) or
/// cookie‖transaction-id (IPv6).
fn decode_mapped_address(
    value: &[u8],
    txid: &TransactionId,
    xor: bool,
) -> Result<SocketAddr, StunError> {
    if value.len() < 4 {
        return Err(StunError::Truncated);
    }
    let family = value[1];
    let raw_port = u16::from_be_bytes([value[2], value[3]]);
    let cookie_be = MAGIC_COOKIE.to_be_bytes();
    let port = if xor {
        raw_port ^ ((MAGIC_COOKIE >> 16) as u16)
    } else {
        raw_port
    };

    match family {
        FAMILY_IPV4 => {
            if value.len() < 8 {
                return Err(StunError::Truncated);
            }
            let mut octets = [value[4], value[5], value[6], value[7]];
            if xor {
                for (i, o) in octets.iter_mut().enumerate() {
                    *o ^= cookie_be[i];
                }
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        FAMILY_IPV6 => {
            if value.len() < 20 {
                return Err(StunError::Truncated);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            if xor {
                let mut key = [0u8; 16];
                key[..4].copy_from_slice(&cookie_be);
                key[4..].copy_from_slice(txid);
                for (o, k) in octets.iter_mut().zip(key.iter()) {
                    *o ^= *k;
                }
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        other => Err(StunError::UnexpectedType(other as u16)),
    }
}
