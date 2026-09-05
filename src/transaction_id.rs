//! The STUN transaction id (`SPEC.md` §3) — extracted byte-for-byte from `dig-nat 0.21.1`
//! `src/stun.rs:428-440`.

use crate::codec::TransactionId;

/// Generate a 96-bit STUN transaction id from a CSPRNG (RFC 5389 §10.1: "It primarily serves to
/// correlate requests with responses... **and MUST be uniformly and randomly chosen from the
/// interval 0 .. 2**96 - 1, and SHOULD be cryptographically random").
///
/// This id is the ONLY anti-spoof mechanism [`crate::query_reflexive_address`] applies to a Binding
/// response beyond source-address validation (`SPEC.md` §4) — a predictable id (e.g. one derived
/// from wall-clock time) would let an off-path attacker who can approximate the send instant forge a
/// `BINDING_SUCCESS` carrying a poisoned reflexive address before the real server's reply arrives.
/// Sourcing every bit from [`ring::rand::SystemRandom`] closes that.
///
/// # Panics
///
/// `SystemRandom::fill` only fails on catastrophic RNG unavailability (no OS entropy source). There
/// is no sane fallback in that case, so this panics rather than silently degrading to a predictable
/// id — which would reopen exactly the vulnerability this function exists to close.
pub fn new_transaction_id() -> TransactionId {
    use ring::rand::{SecureRandom, SystemRandom};

    let mut id = [0u8; 12];
    SystemRandom::new()
        .fill(&mut id)
        .expect("OS CSPRNG must be available to generate a STUN transaction id");
    id
}
