//! RFC 5389 Binding codec tests — no network (`SPEC.md` §11 items 1-3).
//!
//! `binding_request_has_rfc_header` through `rejects_non_success_type` are the nine
//! `parse_binding_response` tests moved intact from `dig-nat 0.21.1` `tests/stun.rs:13-105`
//! (`SPEC.md` §11 item 2). Everything else is new: the `encode_binding_success`/
//! `parse_binding_request` golden vectors and suites the extraction adds.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use dig_stun::{
    encode_binding_request, encode_binding_success, parse_binding_request, parse_binding_response,
    StunError, TransactionId, ATTR_MAPPED_ADDRESS, ATTR_XOR_MAPPED_ADDRESS, BINDING_REQUEST,
    BINDING_SUCCESS, MAGIC_COOKIE,
};

const TXID: TransactionId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
/// The transaction id used in every SPEC.md golden vector (§2.3, §2.7).
const SPEC_TXID: TransactionId = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).expect("valid hex byte"))
        .collect()
}

// ---- §2.3 encode_binding_request golden vector ----

#[test]
fn encode_binding_request_matches_spec_golden_vector() {
    let got = encode_binding_request(&SPEC_TXID);
    let want = hex_to_bytes("00 01 00 00 21 12 a4 42 00 01 02 03 04 05 06 07 08 09 0a 0b");
    assert_eq!(got, want);
    assert_eq!(got.len(), 20);
}

// ---- §2.7 encode_binding_success golden vectors ----

#[test]
fn encode_binding_success_matches_spec_golden_vector_ipv4() {
    let reflexive = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 9444);
    let got = encode_binding_success(&SPEC_TXID, reflexive);
    let want = hex_to_bytes(
        "01 01 00 0c 21 12 a4 42 00 01 02 03 04 05 06 07 08 09 0a 0b \
         00 20 00 08 00 01 05 f6 20 13 a5 43",
    );
    assert_eq!(got, want);
    assert_eq!(got.len(), 32);
}

#[test]
fn encode_binding_success_matches_spec_golden_vector_ipv6() {
    let reflexive: SocketAddr = "[2606:4700:4700::1111]:9444".parse().unwrap();
    let got = encode_binding_success(&SPEC_TXID, reflexive);
    let want = hex_to_bytes(
        "01 01 00 18 21 12 a4 42 00 01 02 03 04 05 06 07 08 09 0a 0b \
         00 20 00 14 00 02 05 f6 07 14 e3 42 47 01 02 03 04 05 06 07 08 09 1b 1a",
    );
    assert_eq!(got, want);
    assert_eq!(got.len(), 44);
}

/// A mapped IPv4-in-IPv6 reflexive address MUST encode as family 0x01 with the embedded IPv4
/// address — the same bytes as encoding the plain IPv4 address, never a 16-byte family 0x02 value
/// (`SPEC.md` §2.7; the family-crossing defect measured on relay.dig.net#11).
#[test]
fn encode_binding_success_folds_mapped_ipv6_to_ipv4_family() {
    let mapped = SocketAddr::new(IpAddr::V6(Ipv4Addr::new(1, 1, 1, 1).to_ipv6_mapped()), 9444);
    let plain = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 9444);
    assert_eq!(
        encode_binding_success(&SPEC_TXID, mapped),
        encode_binding_success(&SPEC_TXID, plain)
    );
}

/// Round-trip law (`SPEC.md` §2.7): every native IPv4/IPv6 address encodes and parses back
/// unchanged.
///
/// `::1` is deliberately NOT in this list: per `SPEC.md` §5.3 it folds to `0.0.0.1` under
/// `to_ipv4()` (the fold `encode_binding_success` itself applies before encoding), so it is not
/// "native" from this function's point of view — that fold is asserted on its own terms by
/// [`encoding_a_folding_ipv6_address_produces_the_folded_ipv4_bytes`], not conflated with this law.
#[test]
fn encode_then_parse_round_trips_for_every_native_family() {
    let addrs: &[SocketAddr] = &[
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 51234),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 1),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 65535),
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
            9444,
        ),
        // A genuinely native IPv6 address: segments[0] != 0, so `to_ipv4()` cannot fold it.
        SocketAddr::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into(), 443),
    ];
    for &addr in addrs {
        let msg = encode_binding_success(&SPEC_TXID, addr);
        let got = parse_binding_response(&msg, Some(&SPEC_TXID)).unwrap();
        assert_eq!(got, addr, "round-trip failed for {addr}");
    }
}

/// `::1` (IPv6 loopback) folds to `0.0.0.1` under `SPEC.md` §5.3's fold rule, so encoding it
/// produces the SAME bytes as encoding `0.0.0.1` directly (family `0x01`), never a 16-byte family
/// `0x02` value. This is the fold rule applied at the point `SPEC.md` §5.3 says it must be —
/// `encode_binding_success` folds before it ever looks at the address's own family.
#[test]
fn encoding_a_folding_ipv6_address_produces_the_folded_ipv4_bytes() {
    let loopback_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
    let loopback_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)), 443);
    assert_eq!(
        encode_binding_success(&SPEC_TXID, loopback_v6),
        encode_binding_success(&SPEC_TXID, loopback_v4)
    );
    // And parsing it back therefore yields the FOLDED address, not the original `::1`.
    let msg = encode_binding_success(&SPEC_TXID, loopback_v6);
    assert_eq!(
        parse_binding_response(&msg, Some(&SPEC_TXID)).unwrap(),
        loopback_v4
    );
}

// ---- parse_binding_response: moved from dig-nat tests/stun.rs:13-105 ----

#[test]
fn binding_request_has_rfc_header() {
    let req = encode_binding_request(&TXID);
    assert_eq!(req.len(), 20);
    assert_eq!(u16::from_be_bytes([req[0], req[1]]), BINDING_REQUEST);
    assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0, "no attributes");
    assert_eq!(
        u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
        MAGIC_COOKIE
    );
    assert_eq!(&req[8..20], &TXID);
}

#[test]
fn parses_xor_mapped_ipv4() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 51234);
    let msg = build_response(ATTR_XOR_MAPPED_ADDRESS, addr, &TXID);
    let got = parse_binding_response(&msg, Some(&TXID)).unwrap();
    assert_eq!(got, addr);
}

#[test]
fn parses_xor_mapped_ipv6() {
    let addr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1234)),
        9450,
    );
    let msg = build_response(ATTR_XOR_MAPPED_ADDRESS, addr, &TXID);
    let got = parse_binding_response(&msg, Some(&TXID)).unwrap();
    assert_eq!(got, addr);
}

/// Legacy MAPPED-ADDRESS (non-XOR) is a fallback when no XOR attribute is present.
#[test]
fn parses_legacy_mapped_address_fallback() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)), 1234);
    let msg = build_response(ATTR_MAPPED_ADDRESS, addr, &TXID);
    let got = parse_binding_response(&msg, Some(&TXID)).unwrap();
    assert_eq!(got, addr);
}

#[test]
fn rejects_bad_magic_cookie() {
    let mut msg = build_response(
        ATTR_XOR_MAPPED_ADDRESS,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        &TXID,
    );
    msg[4] ^= 0xff; // corrupt the cookie
    assert_eq!(
        parse_binding_response(&msg, Some(&TXID)),
        Err(StunError::BadMagicCookie)
    );
}

#[test]
fn rejects_transaction_id_mismatch() {
    let msg = build_response(
        ATTR_XOR_MAPPED_ADDRESS,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        &TXID,
    );
    let other = [9u8; 12];
    assert_eq!(
        parse_binding_response(&msg, Some(&other)),
        Err(StunError::TransactionIdMismatch)
    );
}

#[test]
fn rejects_truncated() {
    assert_eq!(
        parse_binding_response(&[0u8; 4], None),
        Err(StunError::Truncated)
    );
}

#[test]
fn rejects_no_mapped_address() {
    // A valid Binding success header with zero attributes -> no mapped address.
    let mut msg = Vec::new();
    msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(&TXID);
    assert_eq!(
        parse_binding_response(&msg, Some(&TXID)),
        Err(StunError::NoMappedAddress)
    );
}

#[test]
fn rejects_non_success_type() {
    // A Binding REQUEST is not a success response.
    let req = encode_binding_request(&TXID);
    assert!(matches!(
        parse_binding_response(&req, Some(&TXID)),
        Err(StunError::UnexpectedType(_))
    ));
}

/// Build a STUN Binding success response carrying `addr` in the given attribute type. For an XOR
/// attribute the value is XOR-obfuscated per RFC 5389 §15.2; for a plain MAPPED-ADDRESS it is not.
fn build_response(attr_type: u16, addr: SocketAddr, txid: &TransactionId) -> Vec<u8> {
    let xor = attr_type == ATTR_XOR_MAPPED_ADDRESS;
    let cookie_be = MAGIC_COOKIE.to_be_bytes();

    let mut value = Vec::new();
    value.push(0); // reserved
    match addr.ip() {
        IpAddr::V4(v4) => {
            value.push(0x01); // family IPv4
            let port = if xor {
                addr.port() ^ ((MAGIC_COOKIE >> 16) as u16)
            } else {
                addr.port()
            };
            value.extend_from_slice(&port.to_be_bytes());
            let mut octets = v4.octets();
            if xor {
                for (i, o) in octets.iter_mut().enumerate() {
                    *o ^= cookie_be[i];
                }
            }
            value.extend_from_slice(&octets);
        }
        IpAddr::V6(v6) => {
            value.push(0x02); // family IPv6
            let port = if xor {
                addr.port() ^ ((MAGIC_COOKIE >> 16) as u16)
            } else {
                addr.port()
            };
            value.extend_from_slice(&port.to_be_bytes());
            let mut octets = v6.octets();
            if xor {
                let mut key = [0u8; 16];
                key[..4].copy_from_slice(&cookie_be);
                key[4..].copy_from_slice(txid);
                for (o, k) in octets.iter_mut().zip(key.iter()) {
                    *o ^= *k;
                }
            }
            value.extend_from_slice(&octets);
        }
    }

    let mut attr = Vec::new();
    attr.extend_from_slice(&attr_type.to_be_bytes());
    attr.extend_from_slice(&(value.len() as u16).to_be_bytes());
    attr.extend_from_slice(&value);
    while attr.len() % 4 != 0 {
        attr.push(0);
    }

    let mut msg = Vec::new();
    msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    msg.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    msg.extend_from_slice(&cookie_be);
    msg.extend_from_slice(txid);
    msg.extend_from_slice(&attr);
    msg
}

// ---- parse_binding_request: new server-side parser (`SPEC.md` §2.5, §11 item 3) ----

#[test]
fn parse_binding_request_accepts_a_bare_request() {
    let req = encode_binding_request(&TXID);
    let got = parse_binding_request(&req).unwrap();
    assert_eq!(got, TXID);
}

/// A request carrying an attribute (e.g. `SOFTWARE`) is accepted; the attribute is ignored.
#[test]
fn parse_binding_request_accepts_a_request_with_an_ignored_attribute() {
    let mut req = Vec::new();
    let software = b"dig-stun-test-client\0\0\0\0"; // pre-padded to a 4-byte boundary (24 bytes)
    req.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    req.extend_from_slice(&((4 + software.len()) as u16).to_be_bytes());
    req.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    req.extend_from_slice(&TXID);
    req.extend_from_slice(&0x8022u16.to_be_bytes()); // SOFTWARE attribute type
    req.extend_from_slice(&(software.len() as u16).to_be_bytes());
    req.extend_from_slice(software);

    let got = parse_binding_request(&req).unwrap();
    assert_eq!(got, TXID);
}

#[test]
fn parse_binding_request_rejects_short_datagram() {
    assert_eq!(parse_binding_request(&[0u8; 4]), Err(StunError::Truncated));
}

#[test]
fn parse_binding_request_rejects_wrong_cookie() {
    let mut req = encode_binding_request(&TXID);
    req[4] ^= 0xff;
    assert_eq!(parse_binding_request(&req), Err(StunError::BadMagicCookie));
}

#[test]
fn parse_binding_request_rejects_non_request_type() {
    // A Binding SUCCESS RESPONSE is not a request.
    let resp = build_response(
        ATTR_XOR_MAPPED_ADDRESS,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        &TXID,
    );
    assert!(matches!(
        parse_binding_request(&resp),
        Err(StunError::UnexpectedType(t)) if t == BINDING_SUCCESS
    ));
}

/// A message type whose top two bits are non-zero is never Binding+Request (whose own encoding
/// has them clear), so the single equality check in `parse_binding_request` rejects it too.
#[test]
fn parse_binding_request_rejects_top_bits_set() {
    let mut req = encode_binding_request(&TXID);
    req[0] |= 0xC0; // set the two reserved top bits of the message-type field
    assert!(matches!(
        parse_binding_request(&req),
        Err(StunError::UnexpectedType(_))
    ));
}

#[test]
fn parse_binding_request_rejects_length_overrun() {
    let mut req = encode_binding_request(&TXID);
    // Claim 4 bytes of attributes that are not actually present.
    req[2..4].copy_from_slice(&4u16.to_be_bytes());
    assert_eq!(parse_binding_request(&req), Err(StunError::Truncated));
}
