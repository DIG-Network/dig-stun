//! Transaction id statistical tests — moved intact from `dig-nat 0.21.1` `tests/stun.rs:195,230`
//! (`SPEC.md` §3, §11 item 4).
//!
//! Regression for SECURITY_AUDIT_P2P.md `## dig-nat` finding 1: `new_transaction_id` used to copy
//! `SystemTime::now()` nanoseconds (little-endian) into all 12 bytes. That id is the ONLY anti-spoof
//! check in `parse_binding_response` beyond source-address validation, so a predictable id lets an
//! off-path attacker forge a `BINDING_SUCCESS` carrying a poisoned reflexive address. These tests
//! prove the id is CSPRNG-sourced.

use dig_stun::new_transaction_id;

#[test]
fn transaction_ids_are_not_sequential_wall_clock_samples() {
    let ids: Vec<[u8; 12]> = (0..64).map(|_| new_transaction_id()).collect();

    // No two samples collide.
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            assert_ne!(ids[i], ids[j], "txids must not collide across samples");
        }
    }

    // The old implementation packed `SystemTime::now()` nanoseconds-since-epoch (a ~63-bit value)
    // little-endian into the 12 bytes, so bytes 8..12 (the high-order 32 bits of the 96-bit field)
    // were always zero for centuries to come. A CSPRNG must NOT exhibit that: at least one sample's
    // high 4 bytes must be nonzero.
    assert!(
        ids.iter().any(|id| id[8..12] != [0u8, 0, 0, 0]),
        "high-order bytes must vary — a wall-clock-nanosecond source leaves them zero, which is the \
         forgeable pattern finding 1 flags"
    );

    // A CSPRNG spreads bit values roughly evenly; a monotonic wall-clock counter does not. Check
    // that consecutive samples differ in more than just their low few bytes (the wall-clock bug kept
    // the top bytes constant across calls made microseconds apart).
    let differing_high_bytes = ids
        .windows(2)
        .filter(|w| w[0][6..12] != w[1][6..12])
        .count();
    assert!(
        differing_high_bytes > ids.len() / 2,
        "most consecutive samples should differ in their high-order bytes too (CSPRNG), not just \
         the low bytes (wall-clock nanosecond counter)"
    );
}

#[test]
fn transaction_id_is_not_derived_from_current_time() {
    // Sample the wall clock and a txid together; the old buggy implementation encoded
    // `duration_since(UNIX_EPOCH).as_nanos()` little-endian into the id, so the id's low 8 bytes
    // equalled the current nanosecond timestamp (mod 2^64) at generation time. A CSPRNG id must not
    // match that derivation.
    let now_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let id = new_transaction_id();
    let low8 = u64::from_le_bytes(id[0..8].try_into().unwrap());
    assert_ne!(
        low8, now_nanos as u64,
        "transaction id must not equal the wall-clock nanosecond timestamp"
    );
}
