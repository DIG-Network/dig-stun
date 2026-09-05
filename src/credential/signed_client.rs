//! The client state machine (`SPEC.md` §14.9): one signed Binding transaction, sending at most
//! three datagrams (identity, signed, re-signed after one stale nonce) and respecting ONE overall
//! timeout across all of them.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::codec::{parse_binding_response, StunError, BINDING_SUCCESS};
use crate::credential::request::encode_identity_request;
use crate::credential::response::parse_challenge;
use crate::credential::signature::StunSigner;
use crate::credential::wire::{
    is_valid_spki_der, BINDING_ERROR, ERR_STALE_NONCE, ERR_UNAUTHENTICATED, REALM,
};
use crate::scope::{scope_of, Scope};
use crate::transaction_id::new_transaction_id;

use super::request::encode_signed_request;

/// Why a signed query did not produce a reflexive address (`SPEC.md` §14.9). Exhaustive: this
/// crate defines no `StunError` variant for the credential (`SPEC.md` §14, "deliberately
/// deferred"), so every credential-specific failure lives in this type instead.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignedQueryError {
    /// An ordinary STUN-level failure — timeout, I/O, a malformed success, or a response of a
    /// type this function does not expect at all.
    #[error("{0}")]
    Stun(#[from] StunError),
    /// The server explicitly declined to answer with this code — a bare `401` from a `Required`
    /// server, a repeated or foreign-realm `401`, a second `438`, or any other error code this
    /// exchange does not know how to satisfy.
    #[error("server refused with code {code}")]
    Refused {
        /// The RFC 5389 `ERROR-CODE` number the server sent.
        code: u16,
    },
    /// The credential exchange cannot proceed: the signer's own SPKI is not a valid `SPEC.md`
    /// §14.3.1 shape, so no request would ever be accepted.
    #[error("credential exchange cannot proceed")]
    BadChallenge,
}

/// The three datagrams this exchange may send, in order (`SPEC.md` §14.9): identity, then a signed
/// request in response to the first challenge, then at most one re-signed request in response to a
/// single stale-nonce reply. No stage ever sends a fourth datagram.
enum Stage {
    /// Just sent the identity request; awaiting the server's first reply.
    Initial,
    /// Just sent a signed request in response to a `401` challenge.
    AfterFirstChallenge,
    /// Just sent a re-signed request in response to a `438` stale-nonce reply. This is the last
    /// datagram this exchange will ever send — any further challenge here is a refusal.
    AfterReSign,
}

/// Perform one signed Binding transaction against a DIG-operated server (`SPEC.md` §14.9): the
/// `operator:`/`relay:` tiers only — the `public:` tier MUST keep using
/// [`crate::query_reflexive_address`], since a third-party server would ignore this attribute and
/// the SPKI would otherwise disclose which DIG node is asking to a party the public tier does not
/// tell today.
///
/// At most three datagrams are sent, all within the ONE `timeout` given here — the deadline is
/// computed once and never reset by a resend. Any datagram not from `server`, or whose transaction
/// id does not match the one currently outstanding, is discarded and the wait continues (a stale
/// reply to an earlier step in this same exchange must not fail it).
pub async fn query_reflexive_address_signed(
    socket: &UdpSocket,
    server: SocketAddr,
    timeout: Duration,
    signer: &dyn StunSigner,
) -> Result<SocketAddr, SignedQueryError> {
    let spki = signer.spki_der();
    if !is_valid_spki_der(spki) {
        return Err(SignedQueryError::BadChallenge);
    }

    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = [0u8; 512];

    let mut expected_txid = new_transaction_id();
    send(
        socket,
        server,
        &encode_identity_request(&expected_txid, spki),
    )
    .await?;
    let mut stage = Stage::Initial;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(SignedQueryError::Stun(StunError::Timeout));
        }
        let (n, from) = match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok(x)) => x,
            Ok(Err(e)) => return Err(SignedQueryError::Stun(StunError::Io(e.to_string()))),
            Err(_) => return Err(SignedQueryError::Stun(StunError::Timeout)),
        };
        if from != server {
            continue; // not the server we asked — keep waiting for the genuine reply
        }
        let msg = &buf[..n];
        if msg.len() < 2 {
            return Err(SignedQueryError::Stun(StunError::Truncated));
        }
        let msg_type = u16::from_be_bytes([msg[0], msg[1]]);

        if msg_type == BINDING_SUCCESS {
            match parse_binding_response(msg, Some(&expected_txid)) {
                Ok(addr) if scope_of(addr) == Scope::NeverDialable => {
                    return Err(SignedQueryError::Stun(StunError::NoMappedAddress));
                }
                Ok(addr) => return Ok(addr),
                Err(StunError::TransactionIdMismatch) => continue, // stale reply; keep waiting
                Err(e) => return Err(SignedQueryError::Stun(e)),
            }
        } else if msg_type == BINDING_ERROR {
            let challenge = match parse_challenge(msg, &expected_txid) {
                Ok(c) => c,
                Err(StunError::TransactionIdMismatch) => continue, // stale reply; keep waiting
                Err(e) => return Err(SignedQueryError::Stun(e)),
            };

            match stage {
                Stage::Initial => {
                    let has_dig_realm = challenge.realm.as_deref() == Some(REALM);
                    match (challenge.code, has_dig_realm, &challenge.nonce) {
                        (ERR_UNAUTHENTICATED, true, Some(nonce)) => {
                            expected_txid = new_transaction_id();
                            let req = encode_signed_request(&expected_txid, nonce, signer);
                            send(socket, server, &req).await?;
                            stage = Stage::AfterFirstChallenge;
                        }
                        _ => {
                            return Err(SignedQueryError::Refused {
                                code: challenge.code,
                            })
                        }
                    }
                }
                Stage::AfterFirstChallenge => match (challenge.code, &challenge.nonce) {
                    (ERR_STALE_NONCE, Some(nonce)) => {
                        expected_txid = new_transaction_id();
                        let req = encode_signed_request(&expected_txid, nonce, signer);
                        send(socket, server, &req).await?;
                        stage = Stage::AfterReSign;
                    }
                    _ => {
                        return Err(SignedQueryError::Refused {
                            code: challenge.code,
                        })
                    }
                },
                Stage::AfterReSign => {
                    // No fourth datagram is ever sent (`SPEC.md` §14.9): a second stale-nonce
                    // reply, or anything else, ends the exchange as a refusal.
                    return Err(SignedQueryError::Refused {
                        code: challenge.code,
                    });
                }
            }
        } else {
            return Err(SignedQueryError::Stun(StunError::UnexpectedType(msg_type)));
        }
    }
}

async fn send(
    socket: &UdpSocket,
    server: SocketAddr,
    datagram: &[u8],
) -> Result<(), SignedQueryError> {
    socket
        .send_to(datagram, server)
        .await
        .map(|_| ())
        .map_err(|e| SignedQueryError::Stun(StunError::Io(e.to_string())))
}
