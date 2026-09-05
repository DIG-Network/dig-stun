//! The server decision table (`SPEC.md` §14.7) — a pure function from what a request classified
//! as, plus its already-computed nonce/signature results, to what the server does. `decide` never
//! parses a datagram and never verifies a signature itself; it only combines results its caller
//! already has, which is what makes the "verification is reached only for Signed+Fresh" property
//! (`SPEC.md` §14.5 step 4) a fact about the CALLER'S control flow rather than something this
//! function could violate.

use crate::credential::nonce::NonceCheck;
use crate::credential::request::RequestKind;
use crate::credential::signature::VerifiedIdentity;
use crate::credential::wire::{CredentialError, ERR_STALE_NONCE, ERR_UNAUTHENTICATED};

/// A server deployment's credential requirement (`SPEC.md` §14.8) — never wire-negotiated, set
/// once per deployment. The two modes differ in exactly one decision: what a [`RequestKind::Bare`]
/// request gets (`SPEC.md` §14.7 rows 1-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialMode {
    /// Bare requests are answered exactly as before `0.2.0`; identity and signed requests are
    /// additionally handled. The migration starting point (`SPEC.md` §14.8 step 1).
    Advisory,
    /// Bare requests are refused (`401`, no nonce). The migration endpoint (`SPEC.md` §14.8 step
    /// 2), flipped only once an operator has measured how little traffic it would cost.
    Required,
}

/// What the server does with one classified request (`SPEC.md` §14.7). Exhaustive: a fourth
/// outcome is a decision-table change tracked as a breaking change (`SPEC.md` §12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerDecision {
    /// Send the ordinary §2.7 success response — byte-identical whether or not a credential was
    /// presented. `identity` is `Some` only when a signature verified (row 7); the response itself
    /// carries no acknowledgement of it.
    Answer {
        /// The verified requester, when the request carried and passed a signature.
        identity: Option<VerifiedIdentity>,
    },
    /// Send [`crate::credential::encode_challenge`] with a freshly issued nonce — the requester
    /// has more work to do to be answered.
    Challenge {
        /// `401` (needs to sign, or signed wrong) or `438` (nonce aged out).
        code: u16,
    },
    /// Send [`crate::credential::encode_challenge`] with `nonce: None` — the requester will not be
    /// answered on this datagram at all.
    Refuse {
        /// `401` (bare request under [`CredentialMode::Required`]) or `400` (malformed, decided by
        /// the caller directly from a [`CredentialError::Malformed`] — `decide` is never called
        /// for that case, since there is no [`RequestKind`] to pass it).
        code: u16,
    },
}

/// The decision table (`SPEC.md` §14.7, rows 1-7 — row 8, "any `Malformed`", has no
/// `RequestKind` to classify and so is handled by the caller directly from
/// [`crate::credential::classify_request`]'s `Err` rather than through this function).
///
/// `nonce` and `verified` are `None` whenever they do not apply — a [`RequestKind::Bare`] or
/// [`RequestKind::Identity`] request never has a nonce to check or a signature to verify, and this
/// function never asks the caller to have computed either for those. Every non-`Signed`+`Fresh`
/// row is decided WITHOUT `verified` needing to be `Some` at all — reflecting, at the type level,
/// that a correct caller invokes [`crate::credential::verify_signed_request`] only when it is about
/// to reach this branch.
pub fn decide(
    mode: CredentialMode,
    kind: &RequestKind<'_>,
    nonce: Option<NonceCheck>,
    verified: Option<Result<VerifiedIdentity, CredentialError>>,
) -> ServerDecision {
    match kind {
        RequestKind::Bare => match mode {
            CredentialMode::Advisory => ServerDecision::Answer { identity: None }, // row 1
            CredentialMode::Required => ServerDecision::Refuse {
                code: ERR_UNAUTHENTICATED, // row 2
            },
        },
        RequestKind::Identity { .. } => ServerDecision::Challenge {
            code: ERR_UNAUTHENTICATED, // row 3: challenged in BOTH modes
        },
        RequestKind::Signed { .. } => match nonce {
            Some(NonceCheck::Fresh) => match verified {
                Some(Ok(identity)) => ServerDecision::Answer {
                    identity: Some(identity), // row 7
                },
                _ => ServerDecision::Challenge {
                    code: ERR_UNAUTHENTICATED, // row 6 (Err(BadSignature)); defensive default if
                                               // `verified` was left `None` for a Fresh nonce
                },
            },
            Some(NonceCheck::Stale) => ServerDecision::Challenge {
                code: ERR_STALE_NONCE, // row 5
            },
            Some(NonceCheck::Invalid) | None => ServerDecision::Challenge {
                code: ERR_UNAUTHENTICATED, // row 4
            },
        },
    }
}
