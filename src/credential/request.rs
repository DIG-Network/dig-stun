//! The request shape, both directions (`SPEC.md` §14.3, §14.5, §14.9): how a server classifies an
//! incoming Binding request's DIG attributes, and how a client encodes its own identity / signed
//! asks.

use crate::codec::{parse_binding_request, TransactionId, BINDING_REQUEST};
use crate::credential::signature::StunSigner;
use crate::credential::wire::{
    is_valid_signature_der_len, is_valid_spki_der, write_attr, write_header, CredentialError,
    ATTR_DIG_IDENTITY, ATTR_DIG_SIGNATURE, ATTR_NONCE, CREDENTIAL_VERSION,
};

/// A classified incoming Binding request (`SPEC.md` §14.5). Exhaustive: a fourth shape would be a
/// wire-format change requiring a version bump (`SPEC.md` §12).
///
/// Every variant borrows directly from the datagram [`classify_request`] was given — nothing here
/// allocates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind<'a> {
    /// No DIG attribute at all — an ordinary, uncredentialed Binding request.
    Bare,
    /// A `DIG-IDENTITY` alone, with no `NONCE` and no `DIG-SIGNATURE` — the first datagram of the
    /// client's challenge/response exchange (`SPEC.md` §14.9 step 2).
    Identity {
        /// The 91-byte SPKI DER (no version-byte prefix), already shape-validated.
        spki: &'a [u8],
    },
    /// `DIG-IDENTITY` + `NONCE` + `DIG-SIGNATURE`, in that order, with the signature last.
    Signed {
        /// The 91-byte SPKI DER (no version-byte prefix), already shape-validated.
        spki: &'a [u8],
        /// The `NONCE` attribute value EXACTLY as carried (base64url text) — the same bytes
        /// [`crate::credential::signing_message`] expects.
        nonce: &'a [u8],
        /// The DER-encoded ECDSA signature (no version-byte prefix), already length-validated.
        signature: &'a [u8],
    },
}

/// Classify an incoming Binding request's DIG attributes (`SPEC.md` §14.5).
///
/// Performs `SPEC.md` §2.5's ordinary checks FIRST ([`parse_binding_request`]) — any failure there
/// is returned wrapped as [`CredentialError::Stun`] before a single DIG attribute is inspected.
/// Then walks the attribute area once: an unknown attribute type is silently ignored (this
/// server's RFC 5389 stateless-ignore latitude, unchanged); a `DIG-IDENTITY`/`DIG-SIGNATURE`
/// violating its wire shape, a duplicated DIG attribute, any attribute after `DIG-SIGNATURE`, or a
/// combination other than the three named in [`RequestKind`] is [`CredentialError::Malformed`].
///
/// Allocates nothing; verifies nothing (that is [`crate::credential::verify_signed_request`],
/// called by the caller only for [`RequestKind::Signed`] with a fresh nonce).
pub fn classify_request(
    datagram: &[u8],
) -> Result<(TransactionId, RequestKind<'_>), CredentialError> {
    let txid = parse_binding_request(datagram)?;
    // parse_binding_request already proved datagram.len() >= 20 + msg_len, so this slice is safe.
    let msg_len = u16::from_be_bytes([datagram[2], datagram[3]]) as usize;
    let area = &datagram[20..20 + msg_len];
    let kind = classify_attrs(area)?;
    Ok((txid, kind))
}

fn classify_attrs(area: &[u8]) -> Result<RequestKind<'_>, CredentialError> {
    let mut identity: Option<&[u8]> = None;
    let mut nonce: Option<&[u8]> = None;
    let mut signature: Option<&[u8]> = None;
    let mut signature_seen = false;

    let mut off = 0usize;
    while off + 4 <= area.len() {
        // DIG-SIGNATURE MUST be the last attribute (`SPEC.md` §14.3.2) — once we have recorded
        // one, ANY further attribute of ANY type (including a repeated DIG-SIGNATURE) is a
        // violation, checked before we even look at this attribute's type.
        if signature_seen {
            return Err(CredentialError::Malformed);
        }

        let attr_type = u16::from_be_bytes([area[off], area[off + 1]]);
        let attr_len = u16::from_be_bytes([area[off + 2], area[off + 3]]) as usize;
        let val_start = off + 4;
        let val_end = val_start + attr_len;
        if val_end > area.len() {
            return Err(CredentialError::Malformed);
        }
        let value = &area[val_start..val_end];

        match attr_type {
            ATTR_DIG_IDENTITY => {
                if identity.is_some() {
                    return Err(CredentialError::Malformed);
                }
                if value.len() != 1 + crate::credential::wire::P256_SPKI_LEN
                    || value[0] != CREDENTIAL_VERSION
                    || !is_valid_spki_der(&value[1..])
                {
                    return Err(CredentialError::Malformed);
                }
                identity = Some(&value[1..]);
            }
            ATTR_NONCE => {
                if nonce.is_some() {
                    return Err(CredentialError::Malformed);
                }
                nonce = Some(value);
            }
            ATTR_DIG_SIGNATURE => {
                if value.is_empty()
                    || value[0] != CREDENTIAL_VERSION
                    || !is_valid_signature_der_len(&value[1..])
                {
                    return Err(CredentialError::Malformed);
                }
                signature = Some(&value[1..]);
                signature_seen = true;
            }
            _ => {} // unknown attribute: ignored, per this server's stateless-ignore latitude
        }

        off = val_end + ((4 - (attr_len % 4)) % 4);
    }

    match (identity, nonce, signature) {
        (None, None, None) => Ok(RequestKind::Bare),
        (Some(spki), None, None) => Ok(RequestKind::Identity { spki }),
        (Some(spki), Some(nonce), Some(signature)) => Ok(RequestKind::Signed {
            spki,
            nonce,
            signature,
        }),
        _ => Err(CredentialError::Malformed), // any other combination (SPEC.md §14.5)
    }
}

/// Encode a `DIG-IDENTITY`-only Binding request — 116 bytes: the 20-byte header plus one 96-byte
/// attribute (`SPEC.md` §14.9 step 2). `spki_der` MUST be exactly the 91 bytes of `SPEC.md`
/// §14.3.1; callers that hold a [`StunSigner`] get this from `signer.spki_der()`.
pub fn encode_identity_request(txid: &TransactionId, spki_der: &[u8]) -> Vec<u8> {
    debug_assert!(
        is_valid_spki_der(spki_der),
        "encode_identity_request requires a valid 91-byte P-256 SPKI DER"
    );

    let mut identity_value = Vec::with_capacity(1 + spki_der.len());
    identity_value.push(CREDENTIAL_VERSION);
    identity_value.extend_from_slice(spki_der);

    let mut attrs = Vec::new();
    write_attr(&mut attrs, ATTR_DIG_IDENTITY, &identity_value);

    let mut msg = Vec::with_capacity(20 + attrs.len());
    write_header(&mut msg, BINDING_REQUEST, attrs.len() as u16, txid);
    msg.extend_from_slice(&attrs);
    msg
}

/// Encode a fully signed Binding request — `DIG-IDENTITY` + `NONCE` + `DIG-SIGNATURE`, in that
/// order, at most 228 bytes (`SPEC.md` §14.9 step 4). `nonce_attr_value` is echoed back EXACTLY as
/// received in a challenge; `signer` supplies both the SPKI and the signature over
/// [`crate::credential::signing_message`].
pub fn encode_signed_request(
    txid: &TransactionId,
    nonce_attr_value: &[u8],
    signer: &dyn StunSigner,
) -> Vec<u8> {
    let spki = signer.spki_der();
    let message = crate::credential::signature::signing_message(txid, nonce_attr_value, spki);
    let sig_der = signer.sign(&message);

    let mut identity_value = Vec::with_capacity(1 + spki.len());
    identity_value.push(CREDENTIAL_VERSION);
    identity_value.extend_from_slice(spki);

    let mut signature_value = Vec::with_capacity(1 + sig_der.len());
    signature_value.push(CREDENTIAL_VERSION);
    signature_value.extend_from_slice(&sig_der);

    let mut attrs = Vec::new();
    write_attr(&mut attrs, ATTR_DIG_IDENTITY, &identity_value);
    write_attr(&mut attrs, ATTR_NONCE, nonce_attr_value);
    write_attr(&mut attrs, ATTR_DIG_SIGNATURE, &signature_value);

    let mut msg = Vec::with_capacity(20 + attrs.len());
    write_header(&mut msg, BINDING_REQUEST, attrs.len() as u16, txid);
    msg.extend_from_slice(&attrs);
    msg
}
