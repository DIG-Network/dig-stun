//! The signed-Binding credential (`SPEC.md` §14) — how a DIG-operated UDP STUN server tells a DIG
//! node's ask from anyone else's.
//!
//! A **signed Binding** is an RFC 5389 Binding request that carries the requester's TLS-leaf
//! `SubjectPublicKeyInfo` and an ECDSA-P256 signature, by that leaf's private key, over a
//! server-issued nonce. It proves three things and only three: (1) the sender **holds the private
//! key** of the SPKI it carries — the same key whose SHA-256 is its `peer_id` on every mTLS peer
//! session; (2) the sender **received the server's challenge** at the source address it is sending
//! from (return-routability); (3) the request is **fresh** (≤ 120 s) and **bound to this server**.
//!
//! **It proves nothing about network membership.** Any party can mint a P-256 key in microseconds
//! and complete the exchange (§14.10). What it buys is attributability (every answer is tied to a
//! `peer_id`), an accident/scanner filter, a cost floor (one signature per ask, ~200 µs of CPU), and
//! a pre-crypto gate (no signature is verified for a source that has not completed a round trip). A
//! caller MUST NOT describe a verified credential as access control or as proof the sender is a
//! member of the DIG network.
//!
//! This module is placeholder scaffolding — filled in clause-by-clause against the SPEC delta.

#![allow(dead_code)] // populated incrementally; every item gains a caller as it lands
