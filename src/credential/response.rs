//! The error-response shape, both directions (`SPEC.md` §14.3.3, §14.9): how a server encodes the
//! four DIG error shapes (bare refusal, challenge, stale, malformed), and how a client parses one
//! back into a [`Challenge`] it can act on.

use crate::codec::{StunError, TransactionId, MAGIC_COOKIE};
use crate::credential::nonce::NONCE_LEN;
use crate::credential::wire::{
    base64url_encode, write_attr, write_header, ATTR_ERROR_CODE, ATTR_NONCE, ATTR_REALM,
    BINDING_ERROR, ERR_BAD_REQUEST, ERR_STALE_NONCE, ERR_UNAUTHENTICATED, REALM,
};

/// A parsed Binding Error Response (`SPEC.md` §14.9). `realm`/`nonce` are `None` when the
/// response simply did not carry that attribute — [`parse_challenge`] never errors for a missing
/// optional attribute; only a message-level failure (wrong type, wrong txid, truncated) is an
/// `Err`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The `ERROR-CODE` class+number (400/401/438, or 0 if the response carried none at all).
    pub code: u16,
    /// The `REALM` attribute's UTF-8 value, if present and valid UTF-8.
    pub realm: Option<String>,
    /// The `NONCE` attribute value EXACTLY as carried (base64url text), if present.
    pub nonce: Option<Vec<u8>>,
}

/// The reason phrase RFC 5389 §15.6 pairs with each code this crate emits (`SPEC.md` §14.3.3).
fn reason_phrase(code: u16) -> &'static str {
    match code {
        ERR_UNAUTHENTICATED => "Unauthenticated",
        ERR_STALE_NONCE => "Stale Nonce",
        ERR_BAD_REQUEST => "Bad Request",
        other => panic!(
            "encode_challenge: unsupported error code {other} (caller error, not wire input)"
        ),
    }
}

/// Encode one of the four DIG error-response shapes (`SPEC.md` §14.3.3): pass `nonce = None` for a
/// bare refusal (`code = 401`, 44 bytes) or a malformed refusal (`code = 400`, 40 bytes); pass
/// `nonce = Some(..)` for a challenge (`code = 401`, 88 bytes) or a stale-nonce response
/// (`code = 438`, 84 bytes) — both carry [`REALM`] and a fresh `NONCE`.
///
/// A response built with `nonce = Some(..)` never carries `XOR-MAPPED-ADDRESS`: handing the answer
/// to a requester that has not yet proven anything is exactly what the credential exists to
/// withhold (`SPEC.md` §14.3.3).
pub fn encode_challenge(
    txid: &TransactionId,
    code: u16,
    nonce: Option<&[u8; NONCE_LEN]>,
) -> Vec<u8> {
    let reason = reason_phrase(code);
    let mut error_code_value = Vec::with_capacity(4 + reason.len());
    error_code_value.extend_from_slice(&[0, 0, (code / 100) as u8, (code % 100) as u8]);
    error_code_value.extend_from_slice(reason.as_bytes());

    let mut attrs = Vec::new();
    write_attr(&mut attrs, ATTR_ERROR_CODE, &error_code_value);
    if let Some(raw_nonce) = nonce {
        write_attr(&mut attrs, ATTR_REALM, REALM.as_bytes());
        let encoded = base64url_encode(raw_nonce);
        write_attr(&mut attrs, ATTR_NONCE, encoded.as_bytes());
    }

    let mut msg = Vec::with_capacity(20 + attrs.len());
    write_header(&mut msg, BINDING_ERROR, attrs.len() as u16, txid);
    msg.extend_from_slice(&attrs);
    msg
}

/// Parse a Binding Error Response (`SPEC.md` §14.9) — the ONLY function in this crate that
/// interprets message type `0x0111` ([`crate::parse_binding_response`] explicitly does not,
/// `SPEC.md` §2.4).
///
/// Validates, in order: length, magic cookie, message type `== BINDING_ERROR`, and (when
/// `expected_txid` matches the RFC 5389 contract every other parser here follows) the transaction
/// id. A message that passes those checks always returns `Ok` — a missing or unparsable `REALM`/
/// `NONCE` simply leaves that field `None` in the returned [`Challenge`]; the caller
/// ([`crate::credential::query_reflexive_address_signed`]) is what turns an incomplete challenge
/// into a refusal.
pub fn parse_challenge(msg: &[u8], expected_txid: &TransactionId) -> Result<Challenge, StunError> {
    if msg.len() < 20 {
        return Err(StunError::Truncated);
    }
    let msg_type = u16::from_be_bytes([msg[0], msg[1]]);
    let msg_len = u16::from_be_bytes([msg[2], msg[3]]) as usize;
    let cookie = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunError::BadMagicCookie);
    }
    if msg_type != BINDING_ERROR {
        return Err(StunError::UnexpectedType(msg_type));
    }
    let txid: TransactionId = msg[8..20].try_into().map_err(|_| StunError::Truncated)?;
    if &txid != expected_txid {
        return Err(StunError::TransactionIdMismatch);
    }
    if msg.len() < 20 + msg_len {
        return Err(StunError::Truncated);
    }

    let area = &msg[20..20 + msg_len];
    let mut code: u16 = 0;
    let mut realm: Option<String> = None;
    let mut nonce: Option<Vec<u8>> = None;

    let mut off = 0usize;
    while off + 4 <= area.len() {
        let attr_type = u16::from_be_bytes([area[off], area[off + 1]]);
        let attr_len = u16::from_be_bytes([area[off + 2], area[off + 3]]) as usize;
        let val_start = off + 4;
        let val_end = val_start + attr_len;
        if val_end > area.len() {
            break; // a truncated trailing attribute must not discard an ERROR-CODE already read
        }
        let value = &area[val_start..val_end];
        match attr_type {
            ATTR_ERROR_CODE if value.len() >= 4 => {
                code = 100 * value[2] as u16 + value[3] as u16;
            }
            ATTR_REALM => {
                if let Ok(s) = std::str::from_utf8(value) {
                    realm = Some(s.to_string());
                }
            }
            ATTR_NONCE => {
                nonce = Some(value.to_vec());
            }
            _ => {}
        }
        off = val_end + ((4 - (attr_len % 4)) % 4);
    }

    Ok(Challenge { code, realm, nonce })
}
