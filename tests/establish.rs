//! Agreement (`SPEC.md` §11 item 8): one test per [`FamilyVerdict`] variant per family, plus the
//! named scenarios `SPEC.md` calls out explicitly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use dig_stun::establish::{establish, FamilyVerdict, Reading, SourceClass};
use dig_stun::scope::Scope;

fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
}

fn v6(addr: &str, port: u16) -> SocketAddr {
    SocketAddr::new(addr.parse::<Ipv6Addr>().unwrap().into(), port)
}

// This IP's own scope is irrelevant where it is used below: it is the DISSENTING address in a
// Disagreement test, and `establish` returns `Disagreement` at the unanimity check, before scope
// is ever consulted — so a documentation-range address serves just as well as a routable one.
const DISSENTING_V4: (u8, u8, u8, u8) = (203, 0, 113, 7);
const GLOBAL_V4: (u8, u8, u8, u8) = (1, 1, 1, 1);
const GLOBAL_V6: &str = "2606:4700:4700::1111";

// ---- one test per FamilyVerdict variant, IPv4 family ----

#[test]
fn ipv4_no_readings() {
    // Only IPv6 readings present -> the IPv4 family sees none.
    let readings = vec![Reading::new(
        SourceClass::relay("relay.dig.net").to_string(),
        v6(GLOBAL_V6, 9444),
    )];
    assert_eq!(establish(&readings).ipv4, FamilyVerdict::NoReadings);
}

#[test]
fn ipv4_disagreement() {
    let readings = vec![
        Reading::new(
            SourceClass::relay("r1.dig.net").to_string(),
            v4(1, 1, 1, 1, 9444),
        ),
        Reading::new(
            SourceClass::public("stun.l.google.com").to_string(),
            v4(2, 2, 2, 2, 9444),
        ),
    ];
    let got = establish(&readings);
    assert_eq!(
        got.ipv4,
        FamilyVerdict::Disagreement {
            addrs: vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            ]
        }
    );
    assert_eq!(got.ipv4_addr(), None);
}

#[test]
fn ipv4_insufficient_single_class() {
    let readings = vec![Reading::new(
        SourceClass::relay("r1.dig.net").to_string(),
        v4(GLOBAL_V4.0, GLOBAL_V4.1, GLOBAL_V4.2, GLOBAL_V4.3, 9444),
    )];
    assert_eq!(
        establish(&readings).ipv4,
        FamilyVerdict::Insufficient {
            classes: 1,
            peer_only: false,
        }
    );
}

#[test]
fn ipv4_not_global() {
    // Two classes agree unanimously, but the agreed address is PrivateScope, not GlobalUnicast.
    let readings = vec![
        Reading::new(
            SourceClass::relay("r1.dig.net").to_string(),
            v4(10, 0, 0, 5, 9444),
        ),
        Reading::new(
            SourceClass::public("stun.l.google.com").to_string(),
            v4(10, 0, 0, 5, 9444),
        ),
    ];
    assert_eq!(
        establish(&readings).ipv4,
        FamilyVerdict::NotGlobal {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            scope: Scope::PrivateScope,
        }
    );
}

#[test]
fn ipv4_established() {
    let readings = vec![
        Reading::new(
            SourceClass::relay("r1.dig.net").to_string(),
            v4(GLOBAL_V4.0, GLOBAL_V4.1, GLOBAL_V4.2, GLOBAL_V4.3, 9444),
        ),
        Reading::new(
            SourceClass::public("stun.l.google.com").to_string(),
            v4(GLOBAL_V4.0, GLOBAL_V4.1, GLOBAL_V4.2, GLOBAL_V4.3, 55000),
        ),
    ];
    let got = establish(&readings);
    assert_eq!(
        got.ipv4,
        FamilyVerdict::Established {
            ip: IpAddr::V4(Ipv4Addr::new(
                GLOBAL_V4.0,
                GLOBAL_V4.1,
                GLOBAL_V4.2,
                GLOBAL_V4.3
            )),
            classes: 2,
        }
    );
    assert_eq!(
        got.ipv4_addr(),
        Some(Ipv4Addr::new(
            GLOBAL_V4.0,
            GLOBAL_V4.1,
            GLOBAL_V4.2,
            GLOBAL_V4.3
        ))
    );
    assert_eq!(got.ipv6_addr(), None);
}

// ---- one test per FamilyVerdict variant, IPv6 family ----

#[test]
fn ipv6_no_readings() {
    let readings = vec![Reading::new(
        SourceClass::relay("relay.dig.net").to_string(),
        v4(GLOBAL_V4.0, GLOBAL_V4.1, GLOBAL_V4.2, GLOBAL_V4.3, 9444),
    )];
    assert_eq!(establish(&readings).ipv6, FamilyVerdict::NoReadings);
}

#[test]
fn ipv6_disagreement() {
    let readings = vec![
        Reading::new(
            SourceClass::relay("r1.dig.net").to_string(),
            v6(GLOBAL_V6, 9444),
        ),
        Reading::new(
            SourceClass::public("stun.cloudflare.com").to_string(),
            v6("2001:4860:4860::8888", 9444),
        ),
    ];
    assert!(matches!(
        establish(&readings).ipv6,
        FamilyVerdict::Disagreement { .. }
    ));
}

#[test]
fn ipv6_insufficient_single_class() {
    let readings = vec![Reading::new(
        SourceClass::relay("r1.dig.net").to_string(),
        v6(GLOBAL_V6, 9444),
    )];
    assert_eq!(
        establish(&readings).ipv6,
        FamilyVerdict::Insufficient {
            classes: 1,
            peer_only: false,
        }
    );
}

#[test]
fn ipv6_not_global() {
    let readings = vec![
        Reading::new(
            SourceClass::relay("r1.dig.net").to_string(),
            v6("fd00::1", 9444),
        ),
        Reading::new(
            SourceClass::public("stun.cloudflare.com").to_string(),
            v6("fd00::1", 9444),
        ),
    ];
    assert_eq!(
        establish(&readings).ipv6,
        FamilyVerdict::NotGlobal {
            ip: "fd00::1".parse::<Ipv6Addr>().unwrap().into(),
            scope: Scope::PrivateScope,
        }
    );
}

#[test]
fn ipv6_established() {
    let readings = vec![
        Reading::new(
            SourceClass::relay("r1.dig.net").to_string(),
            v6(GLOBAL_V6, 9444),
        ),
        Reading::new(
            SourceClass::public("stun.cloudflare.com").to_string(),
            v6(GLOBAL_V6, 55000),
        ),
    ];
    let got = establish(&readings);
    let want_ip: Ipv6Addr = GLOBAL_V6.parse().unwrap();
    assert_eq!(
        got.ipv6,
        FamilyVerdict::Established {
            ip: IpAddr::V6(want_ip),
            classes: 2,
        }
    );
    assert_eq!(got.ipv6_addr(), Some(want_ip));
}

// ---- named scenarios (SPEC.md §11 item 8) ----

/// Two peers reporting from the SAME `/16` render the identical class — one class, not two.
#[test]
fn two_peers_in_one_slash16_are_one_class() {
    let readings = vec![
        Reading::new(
            SourceClass::peer("203.0.113.9".parse().unwrap()).to_string(),
            v4(GLOBAL_V4.0, GLOBAL_V4.1, GLOBAL_V4.2, GLOBAL_V4.3, 51000),
        ),
        Reading::new(
            SourceClass::peer("203.0.113.200".parse().unwrap()).to_string(),
            v4(GLOBAL_V4.0, GLOBAL_V4.1, GLOBAL_V4.2, GLOBAL_V4.3, 52000),
        ),
    ];
    assert_eq!(
        establish(&readings).ipv4,
        FamilyVerdict::Insufficient {
            classes: 1,
            peer_only: true,
        }
    );
}

/// Three DISTINCT peer `/16` classes establish; two do not (peer-only floor is 3, not 2).
#[test]
fn three_peer_classes_establish_and_two_do_not() {
    let two = vec![
        Reading::new(
            SourceClass::peer("203.0.113.1".parse().unwrap()).to_string(),
            v4(GLOBAL_V4.0, GLOBAL_V4.1, GLOBAL_V4.2, GLOBAL_V4.3, 1),
        ),
        Reading::new(
            SourceClass::peer("198.51.100.1".parse().unwrap()).to_string(),
            v4(GLOBAL_V4.0, GLOBAL_V4.1, GLOBAL_V4.2, GLOBAL_V4.3, 2),
        ),
    ];
    assert_eq!(
        establish(&two).ipv4,
        FamilyVerdict::Insufficient {
            classes: 2,
            peer_only: true,
        }
    );

    let mut three = two;
    three.push(Reading::new(
        SourceClass::peer("192.0.2.1".parse().unwrap()).to_string(),
        v4(GLOBAL_V4.0, GLOBAL_V4.1, GLOBAL_V4.2, GLOBAL_V4.3, 3),
    ));
    assert_eq!(
        establish(&three).ipv4,
        FamilyVerdict::Established {
            ip: IpAddr::V4(Ipv4Addr::new(
                GLOBAL_V4.0,
                GLOBAL_V4.1,
                GLOBAL_V4.2,
                GLOBAL_V4.3
            )),
            classes: 3,
        }
    );
}

/// One relay class + one peer class establish with only two total, because NOT every class is
/// `peer:*` — the `MIN_INDEPENDENT_CLASSES` floor of 2 applies, not the peer-only floor of 3.
#[test]
fn one_relay_and_one_peer_establish_with_two() {
    let readings = vec![
        Reading::new(
            SourceClass::relay("relay.dig.net").to_string(),
            v4(GLOBAL_V4.0, GLOBAL_V4.1, GLOBAL_V4.2, GLOBAL_V4.3, 1),
        ),
        Reading::new(
            SourceClass::peer("203.0.113.1".parse().unwrap()).to_string(),
            v4(GLOBAL_V4.0, GLOBAL_V4.1, GLOBAL_V4.2, GLOBAL_V4.3, 2),
        ),
    ];
    assert_eq!(
        establish(&readings).ipv4,
        FamilyVerdict::Established {
            ip: IpAddr::V4(Ipv4Addr::new(
                GLOBAL_V4.0,
                GLOBAL_V4.1,
                GLOBAL_V4.2,
                GLOBAL_V4.3
            )),
            classes: 2,
        }
    );
}

/// A single dissenting PUBLIC reading blocks two otherwise-agreeing peers — unanimity is checked
/// before class-counting, so disagreement wins regardless of how many classes would have sufficed.
#[test]
fn a_single_dissenting_public_reading_blocks_two_agreeing_peers() {
    let readings = vec![
        Reading::new(
            SourceClass::peer("203.0.113.1".parse().unwrap()).to_string(),
            v4(GLOBAL_V4.0, GLOBAL_V4.1, GLOBAL_V4.2, GLOBAL_V4.3, 1),
        ),
        Reading::new(
            SourceClass::peer("198.51.100.1".parse().unwrap()).to_string(),
            v4(GLOBAL_V4.0, GLOBAL_V4.1, GLOBAL_V4.2, GLOBAL_V4.3, 2),
        ),
        Reading::new(
            SourceClass::public("stun.l.google.com").to_string(),
            v4(
                DISSENTING_V4.0,
                DISSENTING_V4.1,
                DISSENTING_V4.2,
                DISSENTING_V4.3,
                3,
            ),
        ),
    ];
    assert!(matches!(
        establish(&readings).ipv4,
        FamilyVerdict::Disagreement { .. }
    ));
}

/// A UDP-tier reading and a peer reading with DIFFERENT ports but the SAME IP agree — only the IP
/// is compared, never the port.
#[test]
fn udp_tier_and_peer_readings_with_different_ports_but_the_same_ip_agree() {
    let readings = vec![
        Reading::new(
            SourceClass::operator("stun.example.org", 3478).to_string(),
            v4(GLOBAL_V4.0, GLOBAL_V4.1, GLOBAL_V4.2, GLOBAL_V4.3, 3478), // mapped listen-socket port
        ),
        Reading::new(
            SourceClass::peer("203.0.113.1".parse().unwrap()).to_string(),
            v4(GLOBAL_V4.0, GLOBAL_V4.1, GLOBAL_V4.2, GLOBAL_V4.3, 61234), // ephemeral port
        ),
    ];
    assert_eq!(
        establish(&readings).ipv4,
        FamilyVerdict::Established {
            ip: IpAddr::V4(Ipv4Addr::new(
                GLOBAL_V4.0,
                GLOBAL_V4.1,
                GLOBAL_V4.2,
                GLOBAL_V4.3
            )),
            classes: 2,
        }
    );
}

/// A mapped-IPv6 reading lands in the IPv4 family, not IPv6.
#[test]
fn a_mapped_ipv6_reading_lands_in_the_ipv4_family() {
    let mapped = SocketAddr::new(
        IpAddr::V6(
            Ipv4Addr::new(GLOBAL_V4.0, GLOBAL_V4.1, GLOBAL_V4.2, GLOBAL_V4.3).to_ipv6_mapped(),
        ),
        9444,
    );
    let readings = vec![
        Reading::new(SourceClass::relay("r1.dig.net").to_string(), mapped),
        Reading::new(
            SourceClass::public("stun.l.google.com").to_string(),
            v4(GLOBAL_V4.0, GLOBAL_V4.1, GLOBAL_V4.2, GLOBAL_V4.3, 1),
        ),
    ];
    let got = establish(&readings);
    assert!(matches!(got.ipv4, FamilyVerdict::Established { .. }));
    assert_eq!(got.ipv6, FamilyVerdict::NoReadings);
}

/// A unanimous PrivateScope reading is `NotGlobal`, not `Established` — a true reading of the
/// node's position, and still never something to advertise to strangers.
#[test]
fn a_privatescope_unanimous_reading_is_not_global() {
    let readings = vec![
        Reading::new(
            SourceClass::relay("r1.dig.net").to_string(),
            v4(172, 16, 5, 5, 1),
        ),
        Reading::new(
            SourceClass::public("stun.l.google.com").to_string(),
            v4(172, 16, 5, 5, 2),
        ),
        Reading::new(
            SourceClass::peer("203.0.113.1".parse().unwrap()).to_string(),
            v4(172, 16, 5, 5, 3),
        ),
    ];
    assert_eq!(
        establish(&readings).ipv4,
        FamilyVerdict::NotGlobal {
            ip: IpAddr::V4(Ipv4Addr::new(172, 16, 5, 5)),
            scope: Scope::PrivateScope,
        }
    );
}

// ---- non-answers are never passed as readings (a caller-discipline note, tested at the boundary) ----

#[test]
fn empty_readings_yield_no_readings_for_both_families() {
    let got = establish(&[]);
    assert_eq!(got.ipv4, FamilyVerdict::NoReadings);
    assert_eq!(got.ipv6, FamilyVerdict::NoReadings);
    assert_eq!(got.ipv4_addr(), None);
    assert_eq!(got.ipv6_addr(), None);
}

// ---- SourceClass grammar: render + parse round-trip (SPEC.md §7.2) ----

#[test]
fn source_class_round_trips_every_form() {
    let classes = vec![
        SourceClass::operator("stun.example.org", 3478),
        SourceClass::relay("relay.dig.net"),
        SourceClass::public("stun.l.google.com"),
        SourceClass::peer("203.0.113.9".parse().unwrap()),
        SourceClass::peer(GLOBAL_V6.parse().unwrap()),
    ];
    for class in classes {
        let rendered = class.to_string();
        assert_eq!(
            SourceClass::parse(&rendered),
            Some(class.clone()),
            "round-trip failed for {rendered}"
        );
    }
}

#[test]
fn source_class_parse_rejects_unknown_forms() {
    assert_eq!(SourceClass::parse("bogus:thing"), None);
    assert_eq!(SourceClass::parse(""), None);
    assert_eq!(SourceClass::parse("peer:v4:not-a-number.5"), None);
}

/// A peer's IPv6 `/32` partition is rendered from the leading two 16-bit groups, zero-padded hex.
#[test]
fn source_class_peer_v6_uses_the_slash32_partition() {
    let a = SourceClass::peer("2606:4700:4700::1111".parse().unwrap());
    let b = SourceClass::peer("2606:4700:ffff::2222".parse().unwrap()); // same /32, different tail
    assert_eq!(a, b, "same IPv6 /32 must render the identical class");
    assert_eq!(a.to_string(), "peer:v6:2606:4700");
}
