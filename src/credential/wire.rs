//! Wire-level plumbing shared by every other `credential` file (`SPEC.md` §14.3): the DIG
//! attribute constants, the RFC 4648 §5 base64url (no padding) codec the `NONCE` attribute uses,
//! the SPKI shape check both the server (`request::classify_request`) and the client
//! (`signed_client::query_reflexive_address_signed`) apply, and the low-level TLV attribute
//! writer every encoder in this module builds on.

use crate::codec::StunError;

/// The requester's TLS-leaf SPKI (`SPEC.md` §14.3.1).
pub const ATTR_DIG_IDENTITY: u16 = 0xD160;
/// The requester's signature over the server's nonce (`SPEC.md` §14.3.2).
pub const ATTR_DIG_SIGNATURE: u16 = 0xD161;
/// RFC 5389 §15.6 `ERROR-CODE`.
pub const ATTR_ERROR_CODE: u16 = 0x0009;
/// RFC 5389 §15.7 `REALM`; this crate's servers always carry [`REALM`] as its value.
pub const ATTR_REALM: u16 = 0x0014;
/// RFC 5389 §15.8 `NONCE`; value per [`crate::credential::NonceIssuer`].
pub const ATTR_NONCE: u16 = 0x0015;
/// Method Binding, class Error Response (RFC 5389 §6).
pub const BINDING_ERROR: u16 = 0x0111;

/// The realm value every DIG credential challenge carries, and the mechanism discriminator a
/// client checks before treating a `401` as one it can satisfy (`SPEC.md` §14.3, §14.9).
pub const REALM: &str = "dig-stun";
/// The only credential version this crate speaks. A receiver MUST answer `400` to any other
/// version (`SPEC.md` §14.8, §12).
pub const CREDENTIAL_VERSION: u8 = 0x01;

/// Byte length of a P-256 `SubjectPublicKeyInfo` DER with an uncompressed point — the `spki_der`
/// carried by `DIG-IDENTITY` and returned by [`crate::credential::StunSigner::spki_der`]
/// (`SPEC.md` §14.3.1).
pub const P256_SPKI_LEN: usize = 91;
/// The constant first 26 bytes of every such SPKI: the ASN.1 `AlgorithmIdentifier` for
/// id-ecPublicKey / prime256v1 (`SPEC.md` §14.3.1). Byte 26 (the 27th byte, checked separately by
/// [`is_valid_spki_der`]) is always `0x04`, the uncompressed SEC1 point marker.
pub const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
/// Upper bound on the DER-encoded ECDSA-P256-SHA256 signature carried by `DIG-SIGNATURE`, after
/// its 1-byte version prefix is stripped (`SPEC.md` §14.3.2).
pub const MAX_SIGNATURE_LEN: usize = 72;
/// Lower bound on that same DER signature (a value shorter than this cannot be a well-formed
/// ASN.1 `Ecdsa-Sig-Value`) — not spec-named, kept private since it is a parser detail rather
/// than a public contract (`SPEC.md` §14.3.2: "shorter than 9 ... bytes").
const MIN_SIGNATURE_ATTR_LEN: usize = 9;

/// RFC 5389 §15.6 class 4, number 00 — "Bad Request" (`SPEC.md` §14.3.3).
pub const ERR_BAD_REQUEST: u16 = 400;
/// RFC 8489's spelling of RFC 5389's `401` — "Unauthenticated" (`SPEC.md` §14.3.3).
pub const ERR_UNAUTHENTICATED: u16 = 401;
/// "Stale Nonce" — a signed request whose nonce has aged out of its 60-120s window
/// (`SPEC.md` §14.3.3, §14.4).
pub const ERR_STALE_NONCE: u16 = 438;

/// Errors classifying or verifying a DIG credential (`SPEC.md` §14.5-§14.6). Exhaustive: this
/// type is new in `0.2.0` and consumed only within this crate and by callers matching on
/// [`crate::credential::decide`]'s inputs, so a variant addition is tracked as an ordinary
/// breaking change rather than absorbed silently.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    /// The datagram failed the crate's ordinary Binding-request checks (`SPEC.md` §2.5) before a
    /// single DIG attribute was inspected — truncated, bad magic cookie, wrong message type, or a
    /// declared length that overruns the datagram.
    #[error("underlying STUN error: {0}")]
    Stun(#[from] StunError),
    /// A DIG credential attribute violated its wire shape (§14.3.1/§14.3.2), appeared out of the
    /// required order, was duplicated, or appeared without its required companion attribute
    /// (`SPEC.md` §14.5). Maps to a `400` response.
    #[error("malformed DIG credential attribute")]
    Malformed,
    /// The signature did not verify against the carried SPKI over the expected preimage
    /// (`SPEC.md` §14.6). Maps to a `401` challenge (`SPEC.md` §14.7 row 6) — a bad signature is
    /// treated exactly like an unauthenticated ask, never surfaced as a distinct wire code.
    #[error("signature did not verify")]
    BadSignature,
}

/// Whether `spki` is exactly the shape `dig-tls` mints (`SPEC.md` §14.3.1): 91 bytes, the constant
/// [`P256_SPKI_PREFIX`], then the `0x04` uncompressed-point marker. `spki` here is the SPKI DER
/// WITHOUT the 1-byte credential-version prefix that precedes it on the wire — callers holding the
/// raw 92-byte `DIG-IDENTITY` value slice off `value[1..]` first.
///
/// Used both by the server ([`crate::credential::classify_request`], validating an incoming
/// `DIG-IDENTITY`) and by the client ([`crate::credential::query_reflexive_address_signed`],
/// validating its own signer's claimed SPKI before sending anything).
pub(super) fn is_valid_spki_der(spki: &[u8]) -> bool {
    spki.len() == P256_SPKI_LEN && spki[..26] == P256_SPKI_PREFIX && spki[26] == 0x04
}

/// Whether a raw (post-version-byte) `DIG-SIGNATURE` value is in bounds (`SPEC.md` §14.3.2):
/// between 8 and [`MAX_SIGNATURE_LEN`] bytes.
pub(super) fn is_valid_signature_der_len(sig_der: &[u8]) -> bool {
    let attr_len = sig_der.len() + 1; // + the version byte this length excludes
    (MIN_SIGNATURE_ATTR_LEN..=1 + MAX_SIGNATURE_LEN).contains(&attr_len)
}

/// Append one TLV attribute — `[type:2][length:2][value][pad to 4 bytes]` — to `msg` (RFC 5389
/// §15). Shared by every encoder in this module so the padding arithmetic exists in one place.
pub(super) fn write_attr(msg: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    msg.extend_from_slice(&attr_type.to_be_bytes());
    msg.extend_from_slice(&(value.len() as u16).to_be_bytes());
    msg.extend_from_slice(value);
    let pad = (4 - (value.len() % 4)) % 4;
    msg.resize(msg.len() + pad, 0);
}

/// Write the 20-byte STUN header — message type, the attribute-section length that follows, the
/// magic cookie, and the transaction id (`SPEC.md` §2.2) — shared by every message this module
/// encodes (requests and error responses alike).
pub(super) fn write_header(
    msg: &mut Vec<u8>,
    msg_type: u16,
    attrs_len: u16,
    txid: &crate::codec::TransactionId,
) {
    msg.extend_from_slice(&msg_type.to_be_bytes());
    msg.extend_from_slice(&attrs_len.to_be_bytes());
    msg.extend_from_slice(&crate::codec::MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(txid);
}

/// RFC 4648 §5 base64url alphabet, no padding.
const B64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode `input` as base64url with no padding (RFC 4648 §5) — the `NONCE` attribute's wire form
/// of the raw bytes [`crate::credential::NonceIssuer::issue`] returns (`SPEC.md` §14.4). Hand-rolled
/// rather than a dependency: the crate's `SPEC.md` §9 permits no new dependency for this, and the
/// alphabet + no-padding rule are both fixed and small.
pub(super) fn base64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(B64URL_ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64URL_ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64URL_ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL_ALPHABET[(n & 0x3f) as usize] as char);
        }
    }
    out
}

/// Decode base64url with no padding, rejecting any byte outside the alphabet or a final group of
/// exactly 1 leftover character (which cannot decode to a whole byte). The inverse of
/// [`base64url_encode`]; returns `None` on any malformed input rather than panicking, since the
/// caller ([`crate::credential::NonceIssuer::check`]) feeds it attacker-controlled bytes.
pub(super) fn base64url_decode(input: &[u8]) -> Option<Vec<u8>> {
    fn char_value(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for group in input.chunks(4) {
        let vals: Vec<u8> = group
            .iter()
            .map(|&c| char_value(c))
            .collect::<Option<Vec<u8>>>()?;
        match vals.len() {
            4 => {
                let n = ((vals[0] as u32) << 18)
                    | ((vals[1] as u32) << 12)
                    | ((vals[2] as u32) << 6)
                    | (vals[3] as u32);
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
            3 => {
                let n =
                    ((vals[0] as u32) << 18) | ((vals[1] as u32) << 12) | ((vals[2] as u32) << 6);
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
            }
            2 => {
                let n = ((vals[0] as u32) << 18) | ((vals[1] as u32) << 12);
                out.push((n >> 16) as u8);
            }
            _ => return None, // a lone trailing char cannot decode to a whole byte
        }
    }
    Some(out)
}
