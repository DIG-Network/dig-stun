//! `dig-stun` — the DIG ecosystem's single home for reflexive-address discovery: how a node learns
//! the public address the outside world sees its traffic arrive from, and how it decides whether to
//! believe what it was told. `SPEC.md` at the repository root is the normative contract this crate
//! implements; every public item here is cross-referenced to the section that specifies it.
//!
//! It owns exactly five things (`SPEC.md` §1):
//!
//! 1. **The RFC 5389 Binding codec** ([`encode_binding_request`], [`parse_binding_response`],
//!    [`parse_binding_request`], [`encode_binding_success`]) — request and success-response, both
//!    directions.
//! 2. **The UDP STUN client** ([`query_reflexive_address`]) — one Binding transaction against one
//!    server over one socket. This is the crate's only I/O and its only `async fn`; every other
//!    public item is a pure function.
//! 3. **The address-scope classifier** ([`scope`]) — the single predicate every consumer uses to
//!    ask "could this address be a legitimate reflexive candidate, and could a stranger route to
//!    it?".
//! 4. **The peer-observation role** ([`observe`]) and **the agreement rule** ([`establish`]) — the
//!    parts that let every directly-reachable DIG node act as a reflexive-address source for its
//!    peers, and let a requesting node combine what several sources said without trusting any one
//!    of them.
//! 5. **The signed-Binding credential** ([`credential`], §14) — the challenge/response that lets a
//!    DIG-operated UDP STUN server tell a DIG node's ask from anyone else's, and the exact bytes a
//!    requester signs. The crate owns the wire form, the nonce contract, the signing preimage and
//!    the verifier; it does NOT hold private keys (§14.6).
//!
//! It deliberately does NOT own the happy-eyeballs walk over several STUN servers (that is
//! `dig_nat::stun::discover_reflexive_address`, which composes this crate with `dig-ip`), a UDP STUN
//! listener for DIG nodes (nodes never open one — [`observe`]), tier policy (which servers to ask,
//! in what order — the consumer's job), any proof of inbound reachability (`SPEC.md` §1, §10), or
//! any membership policy over a verified credential identity — that is a decision of the deployment
//! that runs the server (§14.10).

mod client;
mod codec;
mod transaction_id;

pub mod credential;
pub mod establish;
pub mod observe;
pub mod scope;

pub use client::query_reflexive_address;
pub use codec::{
    encode_binding_request, encode_binding_success, parse_binding_request, parse_binding_response,
    StunError, TransactionId, ATTR_MAPPED_ADDRESS, ATTR_XOR_MAPPED_ADDRESS, BINDING_REQUEST,
    BINDING_SUCCESS, MAGIC_COOKIE,
};
pub use transaction_id::new_transaction_id;
