//! The address-scope table — every row of `SPEC.md` §5.3, both predicates, plus the four §5.4
//! reconciliation cases named explicitly and the §5.3 IPv4-in-IPv6 fold rule (`SPEC.md` §11 item 5).
//!
//! `accepts_genuinely_global_addresses` through `rejects_never_dialable_ipv4_ranges` are the five
//! `reflexive_guard_tests` moved intact from `dig-nat 0.21.1` `src/stun.rs:443-533` (`SPEC.md` §8.2),
//! adapted to call the crate's now-public [`is_usable_reflexive_addr`].

use std::net::SocketAddr;

use dig_stun::scope::{is_globally_routable, is_usable_reflexive_addr, scope_of, Scope};

fn addr(s: &str) -> SocketAddr {
    s.parse().expect("valid SocketAddr literal")
}

/// Assert `scope_of` AND both derived predicates agree with `expected` for `addr_str` — so the
/// table is checked through every public surface that reads it, not just the `Scope` enum itself.
fn assert_scope(addr_str: &str, expected: Scope) {
    let a = addr(addr_str);
    assert_eq!(scope_of(a), expected, "scope_of({addr_str})");
    assert_eq!(
        is_usable_reflexive_addr(&a),
        expected != Scope::NeverDialable,
        "is_usable_reflexive_addr({addr_str})"
    );
    assert_eq!(
        is_globally_routable(&a),
        expected == Scope::GlobalUnicast,
        "is_globally_routable({addr_str})"
    );
}

// ---- moved from dig-nat/src/stun.rs:443-533 (reflexive_guard_tests) ----

#[test]
fn accepts_genuinely_global_addresses() {
    assert!(is_usable_reflexive_addr(&addr("1.1.1.1:443")));
    assert!(is_usable_reflexive_addr(&addr("8.8.8.8:53")));
    assert!(is_usable_reflexive_addr(&addr(
        "[2606:4700:4700::1111]:443"
    )));
}

#[test]
fn accepts_private_cgnat_and_ula() {
    assert!(is_usable_reflexive_addr(&addr("192.168.1.5:9000")));
    assert!(is_usable_reflexive_addr(&addr("10.0.0.7:9000")));
    assert!(is_usable_reflexive_addr(&addr("172.16.5.5:9000")));
    assert!(is_usable_reflexive_addr(&addr("100.64.0.1:9000")));
    assert!(is_usable_reflexive_addr(&addr("[fd00::1]:9000")));
}

#[test]
fn rejects_port_zero() {
    assert!(!is_usable_reflexive_addr(&addr("1.1.1.1:0")));
    assert!(!is_usable_reflexive_addr(&addr("[2606:4700:4700::1111]:0")));
}

#[test]
fn rejects_reserved_ipv4() {
    assert!(!is_usable_reflexive_addr(&addr("0.0.0.0:1234")));
    assert!(!is_usable_reflexive_addr(&addr("127.0.0.1:1234")));
    assert!(!is_usable_reflexive_addr(&addr("169.254.1.1:1234")));
    assert!(!is_usable_reflexive_addr(&addr("224.0.0.1:1234")));
    assert!(!is_usable_reflexive_addr(&addr("255.255.255.255:1234")));
    assert!(!is_usable_reflexive_addr(&addr("192.0.2.1:1234")));
    assert!(!is_usable_reflexive_addr(&addr("198.51.100.1:1234")));
    assert!(!is_usable_reflexive_addr(&addr("203.0.113.1:1234")));
}

#[test]
fn rejects_reserved_ipv6() {
    assert!(!is_usable_reflexive_addr(&addr("[::]:1234")));
    assert!(!is_usable_reflexive_addr(&addr("[::1]:1234")));
    assert!(!is_usable_reflexive_addr(&addr("[fe80::1]:1234")));
    assert!(!is_usable_reflexive_addr(&addr("[febf::1]:1234")));
    assert!(!is_usable_reflexive_addr(&addr("[ff02::1]:1234")));
    assert!(!is_usable_reflexive_addr(&addr("[2001:db8::1]:1234")));
}

#[test]
fn rejects_never_dialable_ipv4_ranges() {
    assert!(!is_usable_reflexive_addr(&addr("198.18.0.1:1234")));
    assert!(!is_usable_reflexive_addr(&addr("198.19.0.1:1234")));
    assert!(!is_usable_reflexive_addr(&addr("240.0.0.1:1234")));
    assert!(!is_usable_reflexive_addr(&addr("0.1.2.3:1234")));
    assert!(!is_usable_reflexive_addr(&addr("192.88.99.1:1234")));
}

// ---- every row of SPEC.md §5.3, both predicates ----

#[test]
fn ipv4_never_dialable_rows() {
    assert_scope("0.0.0.0:1234", Scope::NeverDialable); // unspecified, also 0.0.0.0/8
    assert_scope("0.1.2.3:1234", Scope::NeverDialable); // this-network, non-zero host
    assert_scope("127.0.0.1:1234", Scope::NeverDialable); // loopback
    assert_scope("169.254.1.1:1234", Scope::NeverDialable); // link-local
    assert_scope("192.0.0.1:1234", Scope::NeverDialable); // IETF protocol assignments
    assert_scope("192.0.2.1:1234", Scope::NeverDialable); // TEST-NET-1
    assert_scope("198.51.100.1:1234", Scope::NeverDialable); // TEST-NET-2
    assert_scope("203.0.113.1:1234", Scope::NeverDialable); // TEST-NET-3
    assert_scope("192.88.99.1:1234", Scope::NeverDialable); // 6to4 relay anycast
    assert_scope("198.18.0.1:1234", Scope::NeverDialable); // benchmarking, lower half
    assert_scope("198.19.255.255:1234", Scope::NeverDialable); // benchmarking, upper half
    assert_scope("224.0.0.1:1234", Scope::NeverDialable); // multicast
    assert_scope("240.0.0.1:1234", Scope::NeverDialable); // reserved / class E
    assert_scope("255.255.255.255:1234", Scope::NeverDialable); // broadcast, inside class E
}

#[test]
fn ipv4_private_scope_rows() {
    assert_scope("10.0.0.7:9000", Scope::PrivateScope);
    assert_scope("172.16.5.5:9000", Scope::PrivateScope);
    assert_scope("172.31.255.255:9000", Scope::PrivateScope); // upper edge of /12
    assert_scope("192.168.1.5:9000", Scope::PrivateScope);
    assert_scope("100.64.0.1:9000", Scope::PrivateScope); // CGNAT lower edge
    assert_scope("100.127.255.255:9000", Scope::PrivateScope); // CGNAT upper edge (/10)
}

#[test]
fn ipv4_global_unicast_control_addresses() {
    assert_scope("1.1.1.1:443", Scope::GlobalUnicast);
    assert_scope("8.8.8.8:53", Scope::GlobalUnicast);
    // Just outside the CGNAT range on both sides — a boundary must fail from BOTH directions.
    assert_scope("100.63.255.255:1", Scope::GlobalUnicast);
    assert_scope("100.128.0.0:1", Scope::GlobalUnicast);
    // Just outside the benchmarking range on both sides.
    assert_scope("198.17.255.255:1", Scope::GlobalUnicast);
    assert_scope("198.20.0.0:1", Scope::GlobalUnicast);
}

#[test]
fn ipv6_never_dialable_rows() {
    assert_scope("[::]:1234", Scope::NeverDialable); // unspecified
    assert_scope("[::1]:1234", Scope::NeverDialable); // loopback
    assert_scope("[fe80::1]:1234", Scope::NeverDialable); // link-local, lower edge
    assert_scope("[febf::ffff]:1234", Scope::NeverDialable); // link-local, upper edge of /10
    assert_scope("[ff02::1]:1234", Scope::NeverDialable); // multicast
    assert_scope("[2001:db8::1]:1234", Scope::NeverDialable); // documentation
    assert_scope("[2001:2::1]:1234", Scope::NeverDialable); // benchmarking (RECONCILED)
    assert_scope("[100::1]:1234", Scope::NeverDialable); // discard-only (RECONCILED)
}

#[test]
fn ipv6_private_scope_row() {
    assert_scope("[fc00::1]:9000", Scope::PrivateScope); // unique-local, lower edge of /7
    assert_scope("[fd00::1]:9000", Scope::PrivateScope); // unique-local, common form
    assert_scope("[fdff:ffff:ffff:ffff::1]:9000", Scope::PrivateScope); // upper edge of /7
}

#[test]
fn ipv6_global_unicast_control_addresses() {
    assert_scope("[2606:4700:4700::1111]:443", Scope::GlobalUnicast);
    // Just outside fe80::/10 on the upper side.
    assert_scope("[fec0::1]:1", Scope::GlobalUnicast);
    // Just outside fc00::/7 on the upper side.
    assert_scope("[fe00::1]:1", Scope::GlobalUnicast);
}

// ---- SPEC.md §5.4: the four reconciliation cases, named explicitly ----

/// RECONCILED: dig-node's on-chain gate used to accept this as globally routable; dig-nat's dial
/// guard already rejected it. The gate was the one that shipped wrong. Outcome: `NeverDialable`.
#[test]
fn reconciled_6to4_relay_anycast_is_never_dialable() {
    assert_scope("192.88.99.1:1234", Scope::NeverDialable);
}

/// RECONCILED: dig-nat's dial guard used to accept this; dig-node's on-chain gate already rejected
/// it. Outcome: `NeverDialable` — tightens the dial guard for a range no legitimate reflexive
/// answer can carry.
#[test]
fn reconciled_ietf_protocol_assignment_is_never_dialable() {
    assert_scope("192.0.0.1:1234", Scope::NeverDialable);
}

/// RECONCILED, same direction as the previous case.
#[test]
fn reconciled_ipv6_benchmarking_is_never_dialable() {
    assert_scope("[2001:2::1]:1234", Scope::NeverDialable);
}

/// RECONCILED, same direction as the previous two cases.
#[test]
fn reconciled_ipv6_discard_only_is_never_dialable() {
    assert_scope("[100::1]:1234", Scope::NeverDialable);
}

// ---- SPEC.md §5.3: fold-first — mapped and deprecated-compatible IPv4-in-IPv6 ----

#[test]
fn mapped_ipv4_in_ipv6_folds_before_classifying() {
    assert_scope("[::ffff:127.0.0.1]:1234", Scope::NeverDialable); // mapped loopback
    assert_scope("[::ffff:0.0.0.0]:1234", Scope::NeverDialable); // mapped unspecified
    assert_scope("[::ffff:224.0.0.1]:1234", Scope::NeverDialable); // mapped multicast
    assert_scope("[::ffff:192.0.2.1]:1234", Scope::NeverDialable); // mapped TEST-NET-1
    assert_scope("[::ffff:255.255.255.255]:1234", Scope::NeverDialable); // mapped broadcast
                                                                         // The AWS instance-metadata address (169.254.169.254) — a real-world reason this guard exists:
                                                                         // a lying source that hands this back as "reflexive" is pointing the requester at metadata.
    assert_scope("[::ffff:169.254.169.254]:1234", Scope::NeverDialable);
    // A mapped PRIVATE address survives folding as PrivateScope, not NeverDialable — folding
    // changes the FAMILY judged, never whether private/CGNAT/ULA stays accepted.
    assert_scope("[::ffff:10.0.0.1]:9000", Scope::PrivateScope);
}

/// The deprecated IPv4-*compatible* form (`::a.b.c.d`, distinct from the mapped `::ffff:a.b.c.d`)
/// must fold identically — `to_ipv4()` covers both, unlike `to_canonical()` which covers only the
/// mapped form (`SPEC.md` §5.3).
#[test]
fn deprecated_compatible_ipv4_in_ipv6_folds_before_classifying() {
    assert_scope("[::7f00:1]:1234", Scope::NeverDialable); // compat form of 127.0.0.1
                                                           // compat form of 169.254.169.254 (a9fe:a9fe = 169.254.169.254 in hex).
    assert_scope("[::a9fe:a9fe]:1234", Scope::NeverDialable);
}

/// `::1` (IPv6 loopback) and `::` (unspecified) both fold to an address inside `0.0.0.0/8`
/// (`0.0.0.1` and `0.0.0.0` respectively) — the `0.0.0.0/8` row is therefore load-bearing for IPv6
/// classification, not redundant with a native-v6 loopback/unspecified check (`SPEC.md` §5.3).
#[test]
fn ipv6_loopback_and_unspecified_fold_into_the_v4_this_network_row() {
    assert_scope("[::1]:1234", Scope::NeverDialable);
    assert_scope("[::]:1234", Scope::NeverDialable);
}

// ---- port == 0 ----

#[test]
fn port_zero_is_never_dialable_regardless_of_ip() {
    assert_scope("1.1.1.1:0", Scope::NeverDialable);
    assert_scope("[2606:4700:4700::1111]:0", Scope::NeverDialable);
    // A PrivateScope IP with port 0 is also NeverDialable — port 0 overrides every IP judgment.
    assert_scope("10.0.0.1:0", Scope::NeverDialable);
}
