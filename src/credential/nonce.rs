//! The stateless, source-bound, time-bucketed nonce (`SPEC.md` §14.4) — how a server proves a
//! signed Binding request answered ITS challenge, from the SAME source it challenged, within the
//! last one-to-two minutes, without keeping any per-client state.

use std::net::{IpAddr, SocketAddr};

use ring::hmac;

use crate::credential::wire::base64url_decode;
use crate::scope::fold_ip;

/// Raw nonce length in bytes: 4 (bucket) + 16 (HMAC tag). The wire `NONCE` attribute carries
/// `base64url(no padding)` of these bytes — 27 characters (`SPEC.md` §14.4).
pub const NONCE_LEN: usize = 20;
/// Width of one nonce time bucket. A nonce is valid for the bucket it was issued in and the one
/// after, so 60-120 seconds depending on where in its bucket it was issued (`SPEC.md` §14.4).
pub const NONCE_BUCKET_SECS: u64 = 60;

/// The domain-separated HMAC input prefix (`SPEC.md` §14.4) — distinct from [`crate::credential::signature::SIG_DOMAIN_TAG`]
/// so a nonce tag can never be mistaken for, or substituted into, the signature preimage.
const NONCE_DOMAIN_TAG: &[u8] = b"dig:stun:nonce:v1";
/// Address-family markers inside the nonce HMAC input. Deliberately a fresh, crate-local pair
/// rather than a reuse of `codec`'s private `FAMILY_IPV4`/`FAMILY_IPV6` (which are not visible
/// outside `codec.rs`): this byte is part of the HMAC preimage `SPEC.md` §14.4 defines, not the
/// RFC 5389 wire attribute those constants describe, even though the numeric values coincide.
const NONCE_FAMILY_IPV4: u8 = 0x01;
const NONCE_FAMILY_IPV6: u8 = 0x02;

/// The result of checking a `NONCE` attribute against the issuer that (claims to have) minted it
/// (`SPEC.md` §14.4). Exhaustive: adding a variant is a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceCheck {
    /// The nonce's HMAC tag matches its own bucket and source, and that bucket is the current one
    /// or the one before it (0-120s old, depending on issue-time-within-bucket).
    Fresh,
    /// The tag matches, but the bucket is older than "current or previous" — this issuer minted
    /// it, for this source, but too long ago.
    Stale,
    /// The tag does not match (wrong secret, wrong source, forged, or corrupt), OR the value does
    /// not even base64url-decode to [`NONCE_LEN`] bytes. A forged nonce is always `Invalid`, never
    /// `Stale` — the tag is checked BEFORE the bucket age (`SPEC.md` §14.4: "so a forged nonce is
    /// never reported as merely stale").
    Invalid,
}

/// Issues and checks nonces for one DIG-operated UDP STUN server process (`SPEC.md` §14.4). Holds
/// nothing per-client: every `issue`/`check` call is a pure function of the secret, the source
/// address, and the wall-clock second.
pub struct NonceIssuer {
    secret: [u8; 32],
}

impl NonceIssuer {
    /// Build an issuer with a fresh, randomly generated secret (`ring::rand::SystemRandom`). The
    /// ordinary choice for a single-process deployment (`SPEC.md` §14.4 "Replicas").
    ///
    /// # Panics
    ///
    /// Only on catastrophic OS CSPRNG unavailability — the same posture as
    /// [`crate::new_transaction_id`], for the same reason: there is no safe degraded fallback for
    /// a secret that must not be predictable.
    pub fn new_random() -> Self {
        use ring::rand::{SecureRandom, SystemRandom};
        let mut secret = [0u8; 32];
        SystemRandom::new()
            .fill(&mut secret)
            .expect("OS CSPRNG must be available to generate a STUN nonce-issuer secret");
        Self { secret }
    }

    /// Build an issuer from an explicitly supplied secret — for a deployment running several
    /// server replicas behind one address that must share one issuer (`SPEC.md` §14.4
    /// "Replicas"). The caller is responsible for generating and distributing `secret` safely;
    /// this constructor does no validation beyond the type system's (any 32 bytes are accepted).
    pub fn from_secret(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    /// Mint a nonce for `source` at `now_unix_secs`, valid at THIS issuer for `source` alone,
    /// during the resulting bucket and the one after it (`SPEC.md` §14.4). Returns the raw 20
    /// bytes; the caller base64url-encodes them into the wire `NONCE` attribute
    /// ([`crate::credential::encode_challenge`] does this).
    pub fn issue(&self, source: SocketAddr, now_unix_secs: u64) -> [u8; NONCE_LEN] {
        let bucket = (now_unix_secs / NONCE_BUCKET_SECS) as u32;
        let tag = self.tag_for(bucket, source);
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..4].copy_from_slice(&bucket.to_be_bytes());
        nonce[4..].copy_from_slice(&tag);
        nonce
    }

    /// Check a wire `NONCE` attribute value (the base64url text, exactly as carried) against
    /// `source` at `now_unix_secs` (`SPEC.md` §14.4). Recomputes the tag for the nonce's OWN
    /// bucket (not `now`'s) before ever looking at freshness, so a forged nonce is `Invalid`
    /// rather than `Stale` regardless of what bucket number it claims.
    pub fn check(&self, nonce_attr_value: &[u8], source: SocketAddr, now_unix_secs: u64) -> NonceCheck {
        let decoded = match base64url_decode(nonce_attr_value) {
            Some(bytes) if bytes.len() == NONCE_LEN => bytes,
            _ => return NonceCheck::Invalid,
        };
        let bucket = u32::from_be_bytes(decoded[..4].try_into().expect("4-byte slice"));
        let carried_tag = &decoded[4..NONCE_LEN];
        let expected_tag = self.tag_for(bucket, source);
        if !constant_time_eq(carried_tag, &expected_tag) {
            return NonceCheck::Invalid;
        }
        let now_bucket = (now_unix_secs / NONCE_BUCKET_SECS) as u32;
        if bucket == now_bucket || bucket == now_bucket.wrapping_sub(1) {
            NonceCheck::Fresh
        } else {
            NonceCheck::Stale
        }
    }

    /// `HMAC-SHA256(secret, "dig:stun:nonce:v1" ‖ bucket_be(4) ‖ family(1) ‖ ip_bytes ‖
    /// port_be(2))[..16]` (`SPEC.md` §14.4). `source` is folded per §5.3 FIRST, so an IPv4-mapped
    /// IPv6 source (`::ffff:a.b.c.d`) and the plain IPv4 form yield the identical tag — the same
    /// source, as the response limiter already sees it.
    fn tag_for(&self, bucket: u32, source: SocketAddr) -> [u8; 16] {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.secret);
        let mut message = Vec::with_capacity(NONCE_DOMAIN_TAG.len() + 4 + 1 + 16 + 2);
        message.extend_from_slice(NONCE_DOMAIN_TAG);
        message.extend_from_slice(&bucket.to_be_bytes());
        match fold_ip(source.ip()) {
            IpAddr::V4(v4) => {
                message.push(NONCE_FAMILY_IPV4);
                message.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                message.push(NONCE_FAMILY_IPV6);
                message.extend_from_slice(&v6.octets());
            }
        }
        message.extend_from_slice(&source.port().to_be_bytes());

        let full = hmac::sign(&key, &message);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&full.as_ref()[..16]);
        tag
    }
}

/// Constant-time byte-slice equality (XOR-accumulate, no early exit) — a truncated tag can't be
/// checked with `ring::hmac::verify` (which compares a FULL, untruncated MAC), so this crate
/// carries its own rather than reaching for `ring`'s own internal `constant_time` helper, which
/// `ring` itself documents as heading for removal. Returns `false` on any length mismatch.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

