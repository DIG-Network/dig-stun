//! Provenance and agreement (`SPEC.md` §7): how several untrusted readings of this node's own
//! reflexive address combine into something worth writing into an on-chain advertisement — or,
//! failing that, into nothing at all.
//!
//! [`establish`] fails closed at every branch except [`FamilyVerdict::Established`] (`SPEC.md` §7.5):
//! a wrong establishment puts an address into a coin, permanently, with collateral behind it; a
//! wrong non-establishment costs one epoch's rewards and is visible to the operator.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::scope::{fold_ip, scope_of_ip, Scope};

/// Floor: an address needs at least this many independent source classes agreeing before it is
/// established (`SPEC.md` §7.4) — the same floor this ecosystem calls corroboration elsewhere
/// (`dig-node` `SPEC.md` §18.16 `CORROBORATION_FLOOR`). An assumption, not a derived constant.
pub const MIN_INDEPENDENT_CLASSES: usize = 2;
/// Floor when EVERY agreeing class is a `peer:*` class (`SPEC.md` §7.4): raised because two peer
/// classes is exactly two cheap VMs in two provider blocks, and three makes a full eclipse of the
/// requester's direct pool the only way to forge agreement.
pub const PEER_ONLY_MIN_CLASSES: usize = 3;

/// One source's report of this node's reflexive address (`SPEC.md` §7.1).
///
/// `#[non_exhaustive]`: an additive field is a patch release for consumers, who construct this via
/// [`Reading::new`] rather than a struct literal.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Reading {
    /// The independence class of whoever reported this, rendered by `SourceClass`'s
    /// [`Display`](std::fmt::Display) impl (i.e. `SourceClass::operator(..).to_string()`).
    /// Two readings corroborate each other exactly when their `source` strings DIFFER and their
    /// addresses agree — string inequality is the ONLY independence comparison this crate defines.
    pub source: String,
    /// Optional identity of the individual reporter (a peer_id, a resolved server address). For
    /// diagnostics only; never consulted by [`establish`].
    pub witness: Option<String>,
    /// The address the source said this node appears at. The PORT is carried but never compared —
    /// only the IP participates in agreement (`SPEC.md` §7.3).
    pub addr: SocketAddr,
}

impl Reading {
    /// Construct a reading with no witness.
    pub fn new(source: impl Into<String>, addr: SocketAddr) -> Self {
        Reading {
            source: source.into(),
            witness: None,
            addr,
        }
    }

    /// Attach a witness identity for diagnostics (never consulted by [`establish`]).
    pub fn with_witness(mut self, witness: impl Into<String>) -> Self {
        self.witness = Some(witness.into());
        self
    }
}

/// The grammar [`Reading::source`] follows (`SPEC.md` §7.2). Each variant is one independence
/// class; two readings whose classes render the SAME string are the same class and cannot
/// corroborate each other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceClass {
    /// A server the operator configured (a `DIG_STUN_SERVER` entry). Each configured endpoint is
    /// its own class — the operator vouched for it specifically.
    Operator {
        /// The endpoint host, normalised the same way the operator's config entry was.
        host: String,
        /// The endpoint port.
        port: u16,
    },
    /// The DIG relay's co-located STUN server. One class per relay host.
    Relay {
        /// The relay's host.
        host: String,
    },
    /// A third-party public STUN host (`stun.l.google.com`, `stun.cloudflare.com`, …). One class
    /// per host — they are different operators.
    Public {
        /// The public STUN host.
        host: String,
    },
    /// A DIG peer answering over IPv4 (`SPEC.md` §6). One class per IPv4 `/16` — the SAME partition
    /// `dig_gossip::util::ip_address::subnet_group` uses, so a consumer already holding that group
    /// key renders the identical class from the same IP.
    PeerV4 {
        /// The first octet of the peer's transport address.
        a: u8,
        /// The second octet of the peer's transport address.
        b: u8,
    },
    /// A DIG peer answering over IPv6. One class per IPv6 `/32`.
    PeerV6 {
        /// The first 16-bit group of the peer's transport address.
        h0: u16,
        /// The second 16-bit group of the peer's transport address.
        h1: u16,
    },
}

impl SourceClass {
    /// The class for a server the operator configured.
    pub fn operator(host: impl Into<String>, port: u16) -> Self {
        SourceClass::Operator {
            host: host.into(),
            port,
        }
    }

    /// The class for the DIG relay's co-located STUN server.
    pub fn relay(host: impl Into<String>) -> Self {
        SourceClass::Relay { host: host.into() }
    }

    /// The class for a third-party public STUN host.
    pub fn public(host: impl Into<String>) -> Self {
        SourceClass::Public { host: host.into() }
    }

    /// The class for a DIG peer, from the peer's TRANSPORT address `ip`. `ip` is folded per
    /// `SPEC.md` §5.3 (`fold_ip`) before its leading bytes are taken, so a mapped or compat IPv6
    /// peer renders the same class as its plain-IPv4 twin. A consumer that already computed
    /// `dig_gossip::util::ip_address::subnet_group(ip)` for the same `ip` lands in the same
    /// partition (`SPEC.md` §7.2) — this crate does not, and must not, re-implement that function.
    pub fn peer(ip: IpAddr) -> Self {
        match fold_ip(ip) {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                SourceClass::PeerV4 { a: o[0], b: o[1] }
            }
            IpAddr::V6(v6) => {
                let s = v6.segments();
                SourceClass::PeerV6 { h0: s[0], h1: s[1] }
            }
        }
    }

    /// Whether this class is one of the two `peer:*` forms (`SPEC.md` §7.3 step 4).
    fn is_peer(&self) -> bool {
        matches!(
            self,
            SourceClass::PeerV4 { .. } | SourceClass::PeerV6 { .. }
        )
    }

    /// Parse a rendered class back out of the grammar. Round-trips every form the
    /// [`Display`](std::fmt::Display) impl above produces; `None` for anything else.
    pub fn parse(s: &str) -> Option<Self> {
        if let Some(rest) = s.strip_prefix("operator:") {
            let (host, port) = rest.rsplit_once(':')?;
            return Some(SourceClass::Operator {
                host: host.to_string(),
                port: port.parse().ok()?,
            });
        }
        if let Some(host) = s.strip_prefix("relay:") {
            return Some(SourceClass::Relay {
                host: host.to_string(),
            });
        }
        if let Some(host) = s.strip_prefix("public:") {
            return Some(SourceClass::Public {
                host: host.to_string(),
            });
        }
        if let Some(rest) = s.strip_prefix("peer:v4:") {
            let (a, b) = rest.split_once('.')?;
            return Some(SourceClass::PeerV4 {
                a: a.parse().ok()?,
                b: b.parse().ok()?,
            });
        }
        if let Some(rest) = s.strip_prefix("peer:v6:") {
            let (h0, h1) = rest.split_once(':')?;
            return Some(SourceClass::PeerV6 {
                h0: u16::from_str_radix(h0, 16).ok()?,
                h1: u16::from_str_radix(h1, 16).ok()?,
            });
        }
        None
    }
}

impl std::fmt::Display for SourceClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceClass::Operator { host, port } => write!(f, "operator:{host}:{port}"),
            SourceClass::Relay { host } => write!(f, "relay:{host}"),
            SourceClass::Public { host } => write!(f, "public:{host}"),
            SourceClass::PeerV4 { a, b } => write!(f, "peer:v4:{a}.{b}"),
            SourceClass::PeerV6 { h0, h1 } => write!(f, "peer:v6:{h0:04x}:{h1:04x}"),
        }
    }
}

/// The outcome for ONE address family (`SPEC.md` §7.3). Exhaustive: a new variant is a breaking
/// change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FamilyVerdict {
    /// No reading named an address in this family at all.
    NoReadings,
    /// More than one distinct IP was reported in this family — nothing is established, however
    /// many readings agree with each other, because a single dissenting source is treated as proof
    /// that something is wrong (`SPEC.md` §7.3 step 3).
    Disagreement {
        /// The distinct IPs reported, sorted and deduplicated.
        addrs: Vec<IpAddr>,
    },
    /// The readings agree on one IP, but too few independent classes reported it.
    Insufficient {
        /// The number of distinct source classes that reported the agreed IP.
        classes: usize,
        /// Whether every one of those classes was a `peer:*` class (`SPEC.md` §7.3 step 4) — when
        /// true the floor is [`PEER_ONLY_MIN_CLASSES`] rather than [`MIN_INDEPENDENT_CLASSES`].
        peer_only: bool,
    },
    /// Enough independent classes agree, but the agreed IP is not [`Scope::GlobalUnicast`] — a true
    /// reading of the node's position, and still never something to advertise to strangers.
    NotGlobal {
        /// The agreed IP.
        ip: IpAddr,
        /// Its scope.
        scope: Scope,
    },
    /// The agreed IP is established: enough independent classes agree, unanimously, on a globally
    /// routable address.
    Established {
        /// The established IP.
        ip: IpAddr,
        /// How many independent classes agreed on it.
        classes: usize,
    },
}

/// The result of [`establish`]: one [`FamilyVerdict`] per address family, evaluated independently
/// (`SPEC.md` §7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Established {
    /// The IPv6 family's verdict.
    pub ipv6: FamilyVerdict,
    /// The IPv4 family's verdict.
    pub ipv4: FamilyVerdict,
}

impl Established {
    /// The established IPv6 address, or `None` for any verdict other than
    /// [`FamilyVerdict::Established`].
    pub fn ipv6_addr(&self) -> Option<Ipv6Addr> {
        match &self.ipv6 {
            FamilyVerdict::Established {
                ip: IpAddr::V6(v6), ..
            } => Some(*v6),
            _ => None,
        }
    }

    /// The established IPv4 address, or `None` for any verdict other than
    /// [`FamilyVerdict::Established`].
    pub fn ipv4_addr(&self) -> Option<Ipv4Addr> {
        match &self.ipv4 {
            FamilyVerdict::Established {
                ip: IpAddr::V4(v4), ..
            } => Some(*v4),
            _ => None,
        }
    }
}

/// Combine untrusted `readings` of this node's own reflexive address into an [`Established`]
/// verdict per address family (`SPEC.md` §7.3).
///
/// A reading belongs to the IPv4 family when its address is IPv4, or folds to IPv4 under `SPEC.md`
/// §5.3 (`fold_ip`); otherwise IPv6. Non-answers — a timeout, an [`crate::observe::Refusal`], an
/// RPC method-not-found, a parse error — are NOT readings and MUST NOT be passed here: they neither
/// agree nor dissent.
pub fn establish(readings: &[Reading]) -> Established {
    let mut ipv4: Vec<(IpAddr, &str)> = Vec::new();
    let mut ipv6: Vec<(IpAddr, &str)> = Vec::new();
    for reading in readings {
        let folded = fold_ip(reading.addr.ip());
        let bucket = match folded {
            IpAddr::V4(_) => &mut ipv4,
            IpAddr::V6(_) => &mut ipv6,
        };
        bucket.push((folded, reading.source.as_str()));
    }

    Established {
        ipv4: verdict_for_family(&ipv4),
        ipv6: verdict_for_family(&ipv6),
    }
}

/// The five-step decision of `SPEC.md` §7.3, applied to the readings of ONE address family.
fn verdict_for_family(readings: &[(IpAddr, &str)]) -> FamilyVerdict {
    if readings.is_empty() {
        return FamilyVerdict::NoReadings;
    }

    let mut addrs: Vec<IpAddr> = readings.iter().map(|(ip, _)| *ip).collect();
    addrs.sort();
    addrs.dedup();
    if addrs.len() > 1 {
        return FamilyVerdict::Disagreement { addrs };
    }
    let ip = addrs[0];

    let mut classes: Vec<&str> = readings.iter().map(|(_, source)| *source).collect();
    classes.sort_unstable();
    classes.dedup();
    let peer_only = classes
        .iter()
        .all(|s| SourceClass::parse(s).map(|c| c.is_peer()).unwrap_or(false));

    if classes.len() < MIN_INDEPENDENT_CLASSES {
        return FamilyVerdict::Insufficient {
            classes: classes.len(),
            peer_only,
        };
    }
    if peer_only && classes.len() < PEER_ONLY_MIN_CLASSES {
        return FamilyVerdict::Insufficient {
            classes: classes.len(),
            peer_only: true,
        };
    }

    let scope = scope_of_ip(ip);
    if scope != Scope::GlobalUnicast {
        return FamilyVerdict::NotGlobal { ip, scope };
    }

    FamilyVerdict::Established {
        ip,
        classes: classes.len(),
    }
}
