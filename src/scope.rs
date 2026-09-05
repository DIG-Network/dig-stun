//! The single address-scope classifier (`SPEC.md` §5) — the one range table every consumer asks
//! "could this address be a legitimate reflexive candidate, and could a stranger route to it?"
//! against.
//!
//! Before this crate, two predicates answered overlapping questions with range tables that had
//! drifted apart: `dig-nat`'s dial guard (`is_usable_reflexive_addr`) and `dig-node`'s on-chain gate
//! (`is_globally_routable`). [`Scope`] is the one table both are now DERIVED from; §5.4 names the
//! four places their old tables disagreed, and this table resolves each one toward the SAFER
//! reading (`SPEC.md` §5.5: a classification error toward [`Scope::NeverDialable`] costs a
//! candidate; toward [`Scope::GlobalUnicast`] puts an unreachable address into an on-chain
//! advertisement — so an ambiguous range classifies down).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// How dialable an address is, as three tiers (`SPEC.md` §5.2). Exhaustive: adding a variant is a
/// breaking change, since [`is_usable_reflexive_addr`] and [`is_globally_routable`] are both
/// defined in terms of an exhaustive match over this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Never a destination: reserved, documentation, loopback, link-local, multicast, unspecified,
    /// benchmarking, discard-only, IETF-assignments, or port `0`.
    NeverDialable,
    /// Dialable only from inside the same site or carrier region: RFC 1918, RFC 6598 CGNAT, IPv6
    /// ULA. A true reading of the node's position, and never something to advertise to strangers.
    PrivateScope,
    /// Everything else: an address a stranger on the open internet could route to.
    GlobalUnicast,
}

/// Fold an IPv4-mapped (`::ffff:a.b.c.d`) OR deprecated IPv4-**compatible** (`::a.b.c.d`) IPv6
/// address down to the IPv4 address it embeds. A genuine IPv4 address, or a genuine native IPv6
/// address, is returned unchanged.
///
/// **Fold first, always** (`SPEC.md` §5.3): an on-path STUN server (or a lying peer) fully controls
/// every decoded byte, so classifying a 16-byte value AS IPv6 without folding first would let it
/// smuggle any rejected IPv4 range — e.g. `::ffff:127.0.0.1` or the compat form `::7f00:1` for
/// loopback — past a v6-only classifier. [`Ipv6Addr::to_ipv4`] folds BOTH forms; `to_canonical` is
/// deliberately NOT used here, since it folds only the mapped form and would miss the compat one.
///
/// This is also the reason `0.0.0.0/8` cannot be dropped from the IPv4 table as "redundant" with an
/// IPv6 unspecified/loopback check: `::` and `::1` both fold to an address in `0.0.0.0/8`
/// (`0.0.0.0` and `0.0.0.1` respectively), so that row is what actually rejects them post-fold.
pub(crate) fn fold_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
    }
}

/// Classify a bare IP (`SPEC.md` §5.3). Folds per `fold_ip` first, so a mapped or compat IPv6
/// value is classified as the IPv4 address it represents.
///
/// A caller holding only an [`IpAddr`] (no port) MUST apply the `port == 0` rule of [`scope_of`]
/// itself if it is relevant to that call site — this function has no port to see.
pub fn scope_of_ip(ip: IpAddr) -> Scope {
    match fold_ip(ip) {
        IpAddr::V4(v4) => scope_of_v4(v4),
        IpAddr::V6(v6) => scope_of_v6(v6),
    }
}

/// Classify a `SocketAddr` (`SPEC.md` §5.3): [`Scope::NeverDialable`] when `addr.port() == 0`,
/// regardless of the IP, else [`scope_of_ip`] of `addr.ip()`.
pub fn scope_of(addr: SocketAddr) -> Scope {
    if addr.port() == 0 {
        return Scope::NeverDialable;
    }
    scope_of_ip(addr.ip())
}

/// Whether `addr` could ever be a legitimate reflexive dial target — true for [`Scope::PrivateScope`]
/// AND [`Scope::GlobalUnicast`], false only for [`Scope::NeverDialable`] (`SPEC.md` §5.2). This is
/// deliberately NOT "is this address public": a LAN or CGNAT address is a genuinely valid dial
/// target for a peer on the same site or carrier region.
pub fn is_usable_reflexive_addr(addr: &SocketAddr) -> bool {
    scope_of(*addr) != Scope::NeverDialable
}

/// Whether a stranger on the open internet could route to `addr` — true only for
/// [`Scope::GlobalUnicast`] (`SPEC.md` §5.2). This is the gate for anything written into an
/// on-chain advertisement: a [`Scope::PrivateScope`] reading is a true reading of the node's
/// position and is still never something to advertise to strangers.
pub fn is_globally_routable(addr: &SocketAddr) -> bool {
    scope_of(*addr) == Scope::GlobalUnicast
}

/// The IPv4 half of the table (`SPEC.md` §5.3): 11 [`Scope::NeverDialable`] ranges, 4
/// [`Scope::PrivateScope`] ranges, everything else [`Scope::GlobalUnicast`].
fn scope_of_v4(v4: Ipv4Addr) -> Scope {
    let o = v4.octets();
    let [a, b, ..] = o;

    // 0.0.0.0/8, "this network" (RFC 1122) — also where `::` and `::1` land after folding
    // (`fold_ip`'s doc comment). Subsumes `is_unspecified` for every v4 input; kept alongside it
    // below for the same explicit-over-implicit reason both source predicates wrote it out.
    let is_this_network = a == 0;
    // 192.0.0.0/24, IETF protocol assignments (RFC 6890) — RECONCILED: dig-node's on-chain gate
    // already rejected this; dig-nat's dial guard did not (`SPEC.md` §5.4).
    let is_ietf_protocol_assignment = a == 192 && b == 0 && o[2] == 0;
    // 192.88.99.0/24, 6to4 relay anycast, deprecated (RFC 7526) — RECONCILED: dig-nat's dial guard
    // already rejected this; dig-node's on-chain gate did not, and shipped wrong (`SPEC.md` §5.4).
    let is_6to4_relay_anycast = o[..3] == [192, 88, 99];
    // 198.18.0.0/15, benchmarking (RFC 2544).
    let is_benchmarking = a == 198 && (b & 0xfe) == 18;
    // 240.0.0.0/4, reserved / class E (RFC 1112) — includes 255.255.255.255.
    let is_reserved_class_e = a >= 240;
    // 100.64.0.0/10, carrier-grade NAT shared space (RFC 6598) — PrivateScope, not NeverDialable.
    let is_carrier_grade_nat = a == 100 && (64..128).contains(&b);

    if v4.is_unspecified()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_multicast()
        || v4.is_broadcast()
        || v4.is_documentation() // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737)
        || is_this_network
        || is_ietf_protocol_assignment
        || is_6to4_relay_anycast
        || is_benchmarking
        || is_reserved_class_e
    {
        Scope::NeverDialable
    } else if v4.is_private() || is_carrier_grade_nat {
        // is_private(): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918).
        Scope::PrivateScope
    } else {
        Scope::GlobalUnicast
    }
}

/// The native-IPv6 half of the table (`SPEC.md` §5.3): 7 [`Scope::NeverDialable`] ranges, 1
/// [`Scope::PrivateScope`] range, everything else [`Scope::GlobalUnicast`]. Only ever sees a
/// genuine native IPv6 address — a mapped or compat form is folded to IPv4 by `fold_ip` before
/// [`scope_of_ip`] reaches here.
fn scope_of_v6(v6: Ipv6Addr) -> Scope {
    let seg = v6.segments();

    // fe80::/10, link-local unicast (`Ipv6Addr::is_unicast_link_local` is unstable; masked here).
    let is_link_local = (seg[0] & 0xffc0) == 0xfe80;
    // 2001:db8::/32, documentation (RFC 3849).
    let is_documentation = seg[0] == 0x2001 && seg[1] == 0x0db8;
    // 2001:2::/48, benchmarking (RFC 5180) — RECONCILED: dig-node's on-chain gate already rejected
    // this; dig-nat's dial guard did not (`SPEC.md` §5.4).
    let is_benchmarking = seg[0] == 0x2001 && seg[1] == 0x0002 && seg[2] == 0x0000;
    // 100::/64, discard-only (RFC 6666) — RECONCILED, same direction as benchmarking above.
    let is_discard_only = seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0;
    // fc00::/7, unique local (RFC 4193) — PrivateScope, the IPv6 analogue of RFC 1918.
    let is_unique_local = (seg[0] & 0xfe00) == 0xfc00;

    if v6.is_unspecified()
        || v6.is_loopback()
        || v6.is_multicast()
        || is_link_local
        || is_documentation
        || is_benchmarking
        || is_discard_only
    {
        Scope::NeverDialable
    } else if is_unique_local {
        Scope::PrivateScope
    } else {
        Scope::GlobalUnicast
    }
}
