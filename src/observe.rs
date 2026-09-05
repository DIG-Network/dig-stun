//! The peer-observation responder role (`SPEC.md` §6) — how a directly-reachable DIG node answers
//! `dig.getObservedAddress` for a peer, and the abuse bounds on doing so.
//!
//! [`observe`] is a PURE decision: no socket, no listener, no spawned task, no clock. A DIG node
//! MUST NOT open a UDP STUN listener to serve peers (`SPEC.md` §6.1) — this module never creates
//! one; the caller owns the authenticated mTLS peer session this rides on and calls [`observe`] once
//! per request.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use crate::scope::{fold_ip, scope_of, Scope};

/// Which side accepted the TCP connection this observation rides on (`SPEC.md` §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// This node accepted the connection — `remote` is a genuine observation of the peer's
    /// traffic. Maps from `dig_nat::TraversalKind` at the call site: every kind other than a relayed
    /// circuit is [`Path::Direct`] (`SPEC.md` §6.3).
    Inbound,
    /// This node dialled out — `remote` is the address it CHOSE to dial, never something it
    /// observed.
    Outbound,
}

/// Whether the session rides directly on the wire or through a relay circuit (`SPEC.md` §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// A direct transport connection between the two peers.
    Direct,
    /// A relayed circuit. `remote` would be the relay's own endpoint (or an unspecified wildcard),
    /// never the requester's address.
    Relayed,
}

/// The facts about a session [`observe`] needs in order to decide whether to answer it.
///
/// `#[non_exhaustive]`: an additive field is a patch release for consumers, who construct this via
/// [`SessionMeta::new`] rather than a struct literal (`SPEC.md` §12).
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct SessionMeta {
    /// Which side accepted the connection.
    pub direction: Direction,
    /// Whether the connection is direct or relayed.
    pub path: Path,
    /// The remote address this node observed the connection arrive from.
    pub remote: SocketAddr,
}

impl SessionMeta {
    /// Construct a [`SessionMeta`] from its three facts.
    pub fn new(direction: Direction, path: Path, remote: SocketAddr) -> Self {
        SessionMeta {
            direction,
            path,
            remote,
        }
    }
}

/// Why [`observe`] declined to answer (`SPEC.md` §6.3). Exhaustive: a new refusal reason is a
/// breaking change for a consumer matching on this exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// This node dialled out on this connection; `remote` is not an observation of anything.
    Outbound,
    /// The session rides a relayed circuit; `remote` is the relay's endpoint, not the requester's.
    Relayed,
    /// The observed address can never be a legitimate dial target
    /// ([`Scope::NeverDialable`] — `SPEC.md` §5).
    Unusable,
    /// The caller's [`ObserveLimiter`] budget for this session, source, or globally is exhausted.
    /// Never produced by [`observe`] itself — the caller applies the limiter separately and reports
    /// this reason instead of silently dropping the request (`SPEC.md` §6.4).
    RateLimited,
}

/// The peer-observation decision (`SPEC.md` §6.3): whether, and at what address, to tell a peer
/// what its own traffic looks like from here.
///
/// Answers only when ALL of: the connection is [`Direction::Inbound`] (else [`Refusal::Outbound`]);
/// the path is [`Path::Direct`] (else [`Refusal::Relayed`]); and `remote`'s [`Scope`] is not
/// [`Scope::NeverDialable`] (else [`Refusal::Unusable`] — a [`Scope::PrivateScope`] remote IS
/// answered, since the requester may be a LAN peer, and what it does with a private reading is the
/// requester's decision under [`crate::establish`]).
///
/// The answer is `meta.remote` with an IPv4-mapped IPv6 address folded to IPv4
/// (`fold_ip`), so a requester that connected over IPv4 is never handed a 16-byte
/// address. The port is preserved unchanged — it is informational only for the CALLER to interpret
/// (`SPEC.md` §6.2), never something this function judges.
pub fn observe(meta: &SessionMeta) -> Result<SocketAddr, Refusal> {
    if meta.direction != Direction::Inbound {
        return Err(Refusal::Outbound);
    }
    if meta.path != Path::Direct {
        return Err(Refusal::Relayed);
    }
    if scope_of(meta.remote) == Scope::NeverDialable {
        return Err(Refusal::Unusable);
    }
    Ok(SocketAddr::new(
        fold_ip(meta.remote.ip()),
        meta.remote.port(),
    ))
}

/// Default: how many `dig.getObservedAddress` answers one authenticated session may receive per
/// rolling minute — and, independently, how many a single source IP may receive per rolling minute
/// (`ObserveLimiter::new`'s single `per_session_per_minute` parameter governs both dimensions;
/// `SPEC.md` §6.4).
pub const OBSERVE_PER_SESSION_PER_MINUTE: u32 = 6;
/// Default: how many answers this node may send in total per second, across every session.
pub const OBSERVE_GLOBAL_PER_SECOND: u32 = 64;
/// Upper bound on distinct sessions, and separately on distinct source IPs, tracked at once. Past
/// this bound the least-recently-seen entry is evicted to make room for a new one, so neither map
/// can be grown without bound by a flood of distinct callers.
pub const MAX_TRACKED_SOURCES: usize = 4096;

const SESSION_SOURCE_WINDOW_MS: u64 = 60_000;
const GLOBAL_WINDOW_MS: u64 = 1_000;

/// A whole-token bucket refilled to `capacity` once per fixed window. The same shape as
/// `dig-relay`'s STUN reflector limiter (`dig-relay/src/stun.rs`) — small enough that copying the
/// algorithm here is cheaper and safer than a cross-license dependency on a GPL-2.0 application.
#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    tokens: u32,
    window: u64,
    last_seen_ms: u64,
}

impl TokenBucket {
    fn new(capacity: u32, now_ms: u64, window_ms: u64) -> Self {
        TokenBucket {
            tokens: capacity,
            window: now_ms / window_ms,
            last_seen_ms: now_ms,
        }
    }

    /// Whether a token is available in the window containing `now_ms`, WITHOUT spending it.
    fn peek(&self, now_ms: u64, window_ms: u64) -> bool {
        now_ms / window_ms != self.window || self.tokens > 0
    }

    /// Spend one token, refilling to `capacity` first if `now_ms` has entered a new window. The
    /// caller must already have confirmed availability via [`Self::peek`] for this same `now_ms`.
    fn spend(&mut self, capacity: u32, now_ms: u64, window_ms: u64) {
        let window = now_ms / window_ms;
        if window != self.window {
            self.window = window;
            self.tokens = capacity;
        }
        self.tokens = self.tokens.saturating_sub(1);
        self.last_seen_ms = now_ms;
    }
}

/// Get or create the bucket for `key`, evicting the least-recently-seen entry first when `map` is
/// at [`MAX_TRACKED_SOURCES`] and `key` is not already tracked.
fn bucket_for<'m, K: std::hash::Hash + Eq + Clone>(
    map: &'m mut HashMap<K, TokenBucket>,
    key: &K,
    capacity: u32,
    now_ms: u64,
    window_ms: u64,
) -> &'m mut TokenBucket {
    if !map.contains_key(key) && map.len() >= MAX_TRACKED_SOURCES {
        if let Some(victim) = map
            .iter()
            .min_by_key(|(_, b)| b.last_seen_ms)
            .map(|(k, _)| k.clone())
        {
            map.remove(&victim);
        }
    }
    map.entry(key.clone())
        .or_insert_with(|| TokenBucket::new(capacity, now_ms, window_ms))
}

/// Abuse bounds for the peer observation responder (`SPEC.md` §6.4): an independent per-session
/// budget, an independent per-source-IP budget, and a global budget checked only once both narrower
/// budgets already permit — so one abuser can never drain the budget meant for everyone else.
///
/// Keys are TRANSPORT facts: the authenticated session's peer_id, and the accepted connection's
/// source IP (folded per `SPEC.md` §5.3). `dig.getObservedAddress` takes no request parameters, so
/// there is no payload for either key to come from.
pub struct ObserveLimiter {
    per_minute_capacity: u32,
    global_capacity: u32,
    per_session: HashMap<String, TokenBucket>,
    per_source: HashMap<IpAddr, TokenBucket>,
    global: TokenBucket,
}

impl ObserveLimiter {
    /// `per_session_per_minute` bounds BOTH the per-session and the per-source-IP dimension (a
    /// session is usually pinned to one source IP, but CGNAT can put many sessions behind one, so
    /// the two dimensions are tracked independently even though they share a rate).
    /// `global_per_second` bounds the shared dimension. A `0` capacity denies every request in that
    /// dimension (a bucket that starts and refills to zero tokens can never be spent from).
    pub fn new(per_session_per_minute: u32, global_per_second: u32) -> Self {
        ObserveLimiter {
            per_minute_capacity: per_session_per_minute,
            global_capacity: global_per_second,
            per_session: HashMap::new(),
            per_source: HashMap::new(),
            global: TokenBucket::new(global_per_second, 0, GLOBAL_WINDOW_MS),
        }
    }

    /// Whether `session` (the requester's authenticated peer_id) may receive another observation
    /// answer right now, given the connection's transport-observed `source` IP.
    ///
    /// Checks the per-session and per-source budgets BEFORE the global one, and — only when all
    /// three permit — spends one token in each. A request refused by the narrower budgets never
    /// touches the global one, so a single abusive session or source cannot drain the budget shared
    /// by every other caller (`SPEC.md` §6.4).
    pub fn allow(&mut self, session: &str, source: IpAddr, now_ms: u64) -> bool {
        let source = fold_ip(source);
        let session_key = session.to_string();
        let capacity = self.per_minute_capacity;

        let session_bucket = bucket_for(
            &mut self.per_session,
            &session_key,
            capacity,
            now_ms,
            SESSION_SOURCE_WINDOW_MS,
        );
        if !session_bucket.peek(now_ms, SESSION_SOURCE_WINDOW_MS) {
            // Touch last_seen so an actively-asking (even if throttled) session isn't the one
            // evicted first the next time this map is full.
            session_bucket.last_seen_ms = now_ms;
            return false;
        }

        let source_bucket = bucket_for(
            &mut self.per_source,
            &source,
            capacity,
            now_ms,
            SESSION_SOURCE_WINDOW_MS,
        );
        if !source_bucket.peek(now_ms, SESSION_SOURCE_WINDOW_MS) {
            source_bucket.last_seen_ms = now_ms;
            return false;
        }

        if !self.global.peek(now_ms, GLOBAL_WINDOW_MS) {
            return false;
        }

        // All three permit: commit a token in each.
        bucket_for(
            &mut self.per_session,
            &session_key,
            capacity,
            now_ms,
            SESSION_SOURCE_WINDOW_MS,
        )
        .spend(capacity, now_ms, SESSION_SOURCE_WINDOW_MS);
        bucket_for(
            &mut self.per_source,
            &source,
            capacity,
            now_ms,
            SESSION_SOURCE_WINDOW_MS,
        )
        .spend(capacity, now_ms, SESSION_SOURCE_WINDOW_MS);
        self.global
            .spend(self.global_capacity, now_ms, GLOBAL_WINDOW_MS);
        true
    }
}

#[cfg(test)]
mod bounded_map_tests {
    //! The LRU bound (`SPEC.md` §11 item 7) needs `per_session`/`per_source`'s private lengths, so
    //! this lives beside the struct rather than in `tests/observe.rs`.
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn per_session_and_per_source_maps_stay_bounded_past_max_tracked_sources() {
        let mut limiter =
            ObserveLimiter::new(OBSERVE_PER_SESSION_PER_MINUTE, OBSERVE_GLOBAL_PER_SECOND);

        // Feed many more distinct (session, source) pairs than MAX_TRACKED_SOURCES; neither map
        // may exceed that bound no matter how many distinct callers are seen.
        for i in 0..(MAX_TRACKED_SOURCES as u64 + 5000) {
            let src = IpAddr::V4(Ipv4Addr::new(
                ((i >> 24) & 0xff) as u8,
                ((i >> 16) & 0xff) as u8,
                ((i >> 8) & 0xff) as u8,
                (i & 0xff) as u8,
            ));
            limiter.allow(&format!("peer-{i}"), src, i);
        }

        assert!(
            limiter.per_session.len() <= MAX_TRACKED_SOURCES,
            "per-session map must stay bounded"
        );
        assert!(
            limiter.per_source.len() <= MAX_TRACKED_SOURCES,
            "per-source map must stay bounded"
        );
    }
}
