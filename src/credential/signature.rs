//! The signature: preimage, algorithm, verifier, signer trait (`SPEC.md` §14.6). This crate never
//! holds a private key — [`StunSigner`] is implemented by the consumer over whatever key object it
//! already has (dig-node reuses `signer_from_node_cert`'s object, per the SPEC's citation).

use crate::codec::TransactionId;
use crate::credential::request::RequestKind;
use crate::credential::wire::{is_valid_spki_der, CredentialError};

/// Domain-separates a `dig:stun:v1` signature from every other message the same TLS-leaf key
/// signs — a TLS `CertificateVerify`, a `dig:holdings:v1` record, or a future purpose — so a
/// signature produced for one is never valid for another, in either direction (`SPEC.md` §14.6,
/// §10 item 7).
pub const SIG_DOMAIN_TAG: &[u8] = b"dig:stun:v1";

/// Build the exact bytes a signed Binding's signature covers (`SPEC.md` §14.6):
/// `SIG_DOMAIN_TAG ‖ 0x01 ‖ transaction_id(12) ‖ nonce_len_be(2) ‖ nonce_attr_value ‖ spki_der(91)`.
///
/// `nonce_attr_value` MUST be the `NONCE` attribute value EXACTLY as carried on the wire (the
/// base64url text), never the decoded 20 raw bytes — the signer and the verifier must agree on
/// this or every signature fails. `spki_der` is the 91-byte SPKI (no version-byte prefix).
///
/// Binding the transaction id fixes which response the requester will accept; binding the nonce
/// fixes the issuing server, the source address, and the time bucket; binding the SPKI stops the
/// identity from being swapped under an otherwise-valid signature. Nothing else is signed — the
/// message type is fixed by the server (Binding only) and every other attribute is ignored
/// (`SPEC.md` §14.5).
pub fn signing_message(txid: &TransactionId, nonce_attr_value: &[u8], spki_der: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        SIG_DOMAIN_TAG.len() + 1 + txid.len() + 2 + nonce_attr_value.len() + spki_der.len(),
    );
    message.extend_from_slice(SIG_DOMAIN_TAG);
    message.push(crate::credential::wire::CREDENTIAL_VERSION);
    message.extend_from_slice(txid);
    message.extend_from_slice(&(nonce_attr_value.len() as u16).to_be_bytes());
    message.extend_from_slice(nonce_attr_value);
    message.extend_from_slice(spki_der);
    message
}

/// A signature-verified requester identity (`SPEC.md` §14.6, §14.10). Carries only the SPKI: this
/// level-00 crate cannot compute a `peer_id` from it (that is `dig_tls::peer_id_from_tls_spki_der`,
/// a `dig-*` crate this one must never depend on) — callers that want the `peer_id` hash the SPKI
/// with that function themselves.
///
/// **What this does NOT prove**, stated once so nothing downstream over-reads it: network
/// membership, relay registration, on-chain standing, or that any later claim from the same
/// session is true (`SPEC.md` §14.1, §14.10, §7). It proves exactly key possession, freshness, and
/// return-routability.
///
/// `#[non_exhaustive]`: constructed only by [`verify_signed_request`], so an additive field is a
/// patch release for every consumer.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedIdentity {
    spki: [u8; crate::credential::wire::P256_SPKI_LEN],
}

impl VerifiedIdentity {
    /// The verified 91-byte SPKI DER (no version-byte prefix).
    pub fn spki_der(&self) -> &[u8; crate::credential::wire::P256_SPKI_LEN] {
        &self.spki
    }
}

/// Verify a [`RequestKind::Signed`]'s signature against its own carried SPKI over
/// [`signing_message`] (`SPEC.md` §14.6): ECDSA, P-256, SHA-256, ASN.1 DER
/// (`ring::signature::ECDSA_P256_SHA256_ASN1`).
///
/// `kind` MUST be [`RequestKind::Signed`] — the caller has always already matched on `kind` to
/// decide whether verification even applies (`SPEC.md` §14.5 step 4: reached ONLY for `Signed` +
/// `Fresh`), so this is a precondition rather than adversary-reachable input. A `kind` of any
/// other variant returns [`CredentialError::Malformed`] rather than panicking — this function sits
/// on a path parsing untrusted datagrams, and failing closed costs nothing here.
///
/// `RequestKind`'s fields are public, so a `Signed` variant reaching this function is not
/// guaranteed to carry the 91-byte SPKI shape [`crate::credential::classify_request`] would have
/// enforced — only a value built from the wire via that parser gets that guarantee for free. This
/// function re-validates the shape itself (`is_valid_spki_der`) before it slices `spki`, so a
/// directly-constructed `Signed` carrying a too-short or otherwise malformed SPKI returns
/// [`CredentialError::Malformed`] rather than panicking on an out-of-bounds index.
///
/// # Errors
///
/// [`CredentialError::BadSignature`] when the signature does not verify (wrong key, wrong
/// preimage, or corrupt DER); [`CredentialError::Malformed`] when `kind` is not `Signed`, or when
/// its `spki` does not have the shape `is_valid_spki_der` requires.
pub fn verify_signed_request(
    txid: &TransactionId,
    kind: &RequestKind<'_>,
) -> Result<VerifiedIdentity, CredentialError> {
    let RequestKind::Signed {
        spki,
        nonce,
        signature,
    } = kind
    else {
        return Err(CredentialError::Malformed);
    };

    // A directly-built `Signed` (its fields are public) is not guaranteed to carry a well-formed
    // SPKI the way one parsed via `classify_request` is. The slice below, and the `copy_from_slice`
    // near the end of this function, both require exactly 91 bytes and panic on anything shorter —
    // reject rather than slice blind: a public function must not panic on any input its own type
    // permits.
    if !is_valid_spki_der(spki) {
        return Err(CredentialError::Malformed);
    }

    let message = signing_message(txid, nonce, spki);
    // The 65-byte uncompressed SEC1 point lives at spki[26..91]: byte 26 is the 0x04 marker
    // `is_valid_spki_der` just confirmed, and 27..91 is X ‖ Y (`SPEC.md` §14.6).
    let point = &spki[26..crate::credential::wire::P256_SPKI_LEN];
    let public_key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, point);
    public_key
        .verify(&message, signature)
        .map_err(|_| CredentialError::BadSignature)?;

    let mut spki_arr = [0u8; crate::credential::wire::P256_SPKI_LEN];
    spki_arr.copy_from_slice(spki);
    Ok(VerifiedIdentity { spki: spki_arr })
}

/// Implemented by the consumer over the P-256 private key it already holds for its TLS leaf
/// (`SPEC.md` §14.6). This crate never constructs or stores a private key — no `from_pkcs8` site
/// lives here; dig-node's adapter wraps the SAME object `signer_from_node_cert` already builds for
/// `dig:holdings:v1` records, so no second key-loading site is written anywhere in the ecosystem.
pub trait StunSigner {
    /// Exactly the 91 bytes of `SPEC.md` §14.3.1 — the SPKI DER with no version-byte prefix.
    fn spki_der(&self) -> &[u8];
    /// Sign `message` (always the output of [`signing_message`]) with the leaf's private key,
    /// returning an ECDSA-P256-SHA256 signature in ASN.1 DER form.
    fn sign(&self, message: &[u8]) -> Vec<u8>;
}
