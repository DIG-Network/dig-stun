//! The peer-observation decision and its limiter (`SPEC.md` §11 items 6-7).
//!
//! `truth_table_*` covers every cell of the `Direction × Path × Scope` matrix (2×2×3 = 12 cells;
//! `SPEC.md` §11 item 6). The `ObserveLimiter`'s LRU-bound test lives in `src/observe.rs` itself,
//! since it needs the limiter's private map lengths (`SPEC.md` §11 item 7).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use dig_stun::observe::{observe, Direction, ObserveLimiter, Path, Refusal, SessionMeta};

fn addr(s: &str) -> SocketAddr {
    s.parse().expect("valid SocketAddr literal")
}

fn ip(s: &str) -> IpAddr {
    s.parse().expect("valid IpAddr literal")
}

// ---- observe(): the full Direction x Path x Scope truth table (12 cells) ----

/// `Direction::Outbound` refuses before `Path` or `Scope` are even consulted — 6 of the 12 cells.
#[test]
fn truth_table_outbound_always_refuses_regardless_of_path_or_scope() {
    for path in [Path::Direct, Path::Relayed] {
        for remote in ["127.0.0.1:1234", "10.0.0.5:1234", "1.1.1.1:1234"] {
            let meta = SessionMeta::new(Direction::Outbound, path, addr(remote));
            assert_eq!(
                observe(&meta),
                Err(Refusal::Outbound),
                "remote={remote} path={path:?}"
            );
        }
    }
}

/// `Direction::Inbound` + `Path::Relayed` refuses before `Scope` is consulted — 3 more cells.
#[test]
fn truth_table_inbound_relayed_always_refuses_regardless_of_scope() {
    for remote in ["127.0.0.1:1234", "10.0.0.5:1234", "1.1.1.1:1234"] {
        let meta = SessionMeta::new(Direction::Inbound, Path::Relayed, addr(remote));
        assert_eq!(observe(&meta), Err(Refusal::Relayed), "remote={remote}");
    }
}

/// The remaining 3 cells: `Inbound` + `Direct`, one per `Scope` variant.
#[test]
fn truth_table_inbound_direct_never_dialable_refuses_unusable() {
    let meta = SessionMeta::new(Direction::Inbound, Path::Direct, addr("127.0.0.1:1234"));
    assert_eq!(observe(&meta), Err(Refusal::Unusable));
}

#[test]
fn truth_table_inbound_direct_private_scope_is_answered() {
    // A PrivateScope remote IS answered: the requester may be a LAN peer, and what it does with a
    // private reading is the requester's own decision under `establish` (`SPEC.md` §6.3).
    let meta = SessionMeta::new(Direction::Inbound, Path::Direct, addr("10.0.0.5:1234"));
    assert_eq!(observe(&meta), Ok(addr("10.0.0.5:1234")));
}

#[test]
fn truth_table_inbound_direct_global_unicast_is_answered() {
    let meta = SessionMeta::new(Direction::Inbound, Path::Direct, addr("1.1.1.1:1234"));
    assert_eq!(observe(&meta), Ok(addr("1.1.1.1:1234")));
}

/// The mapped-v6-folds-to-v4 case: an inbound, direct, globally-routable MAPPED remote is answered
/// with its IPv4 form, never the 16-byte mapped form (`SPEC.md` §6.3).
#[test]
fn inbound_direct_mapped_ipv6_remote_folds_to_ipv4_in_the_answer() {
    let mapped = SocketAddr::new(IpAddr::V6(Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped()), 5555);
    let meta = SessionMeta::new(Direction::Inbound, Path::Direct, mapped);
    let got = observe(&meta).expect("global unicast, direct, inbound => answered");
    assert_eq!(
        got,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 5555)
    );
}

// ---- ObserveLimiter: each budget dimension refuses independently ----

#[test]
fn per_session_budget_refuses_independently_of_source_and_global() {
    // Session budget = 2/min; global budget generous so it can never be the cause of a refusal
    // here. Each call uses a FRESH source IP, so the source dimension never fills either — only
    // the shared SESSION key can be what exhausts.
    let mut limiter = ObserveLimiter::new(2, 1000);
    let now = 0u64;
    assert!(limiter.allow("peer-a", ip("1.1.1.1"), now));
    assert!(limiter.allow("peer-a", ip("2.2.2.2"), now));
    assert!(
        !limiter.allow("peer-a", ip("3.3.3.3"), now),
        "peer-a's session budget of 2/min is exhausted, despite a brand-new source IP"
    );
}

#[test]
fn per_source_budget_refuses_independently_of_session_and_global() {
    // Source budget = 2/min (shares the per-session-per-minute parameter); global budget
    // generous. Each call uses a FRESH session id, so the session dimension never fills — only
    // the shared SOURCE IP can be what exhausts.
    let mut limiter = ObserveLimiter::new(2, 1000);
    let now = 0u64;
    let source = ip("9.9.9.9");
    assert!(limiter.allow("peer-a", source, now));
    assert!(limiter.allow("peer-b", source, now));
    assert!(
        !limiter.allow("peer-c", source, now),
        "the source IP's budget of 2/min is exhausted, despite a brand-new session id"
    );
}

#[test]
fn global_budget_refuses_even_when_session_and_source_have_room() {
    // Session/source budget generous; global budget = 2/sec. Every call uses a distinct
    // session AND source, so only the GLOBAL bucket can be what exhausts.
    let mut limiter = ObserveLimiter::new(1000, 2);
    let now = 0u64;
    assert!(limiter.allow("peer-a", ip("1.1.1.1"), now));
    assert!(limiter.allow("peer-b", ip("2.2.2.2"), now));
    assert!(
        !limiter.allow("peer-c", ip("3.3.3.3"), now),
        "the global budget of 2/sec is exhausted, despite fresh session and source"
    );
}

/// A request refused by a narrower budget spends NOTHING in any dimension — otherwise one abuser
/// hammering an already-exhausted session could still drain tokens meant for everyone else
/// (`SPEC.md` §6.4).
#[test]
fn a_request_refused_by_the_narrower_budgets_does_not_spend_a_global_token() {
    let mut limiter = ObserveLimiter::new(1, 2); // session/source = 1/min, global = 2/sec
    let now = 0u64;

    assert!(limiter.allow("peer-a", ip("1.1.1.1"), now)); // succeeds: session=0 left, global=1 left
    assert!(
        !limiter.allow("peer-a", ip("1.1.1.1"), now),
        "peer-a's own session budget is already exhausted"
    );
    // If that refusal had ALSO spent the remaining global token, this would now fail. It must
    // succeed: a refusal spends nothing beyond the dimension that refused it.
    assert!(
        limiter.allow("peer-b", ip("2.2.2.2"), now),
        "the global budget still has its second token — the refused retry above spent nothing"
    );
}

/// A new one-second window refills the global budget; a new one-minute window refills the
/// session/source budgets. Budgets are per-WINDOW, not lifetime totals.
#[test]
fn budgets_refill_in_a_new_window() {
    let mut limiter = ObserveLimiter::new(1, 1);
    assert!(limiter.allow("peer-a", ip("1.1.1.1"), 0));
    assert!(!limiter.allow("peer-a", ip("1.1.1.1"), 0));
    // 61 seconds later: a new one-minute window for session/source, and a new one-second window
    // for global.
    assert!(limiter.allow("peer-a", ip("1.1.1.1"), 61_000));
}
