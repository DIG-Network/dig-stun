//! The UDP STUN client (`SPEC.md` §4) — exercised over real loopback sockets (no real network,
//! but real send/recv timing) rather than mocked, so the anti-spoof source check and the timeout
//! path are proven against actual socket behaviour, not an idealized stand-in for it.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

use dig_stun::{encode_binding_success, parse_binding_request, query_reflexive_address, StunError};

async fn bind_loopback() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback UDP socket");
    let addr = socket.local_addr().expect("bound socket has a local addr");
    (socket, addr)
}

/// A GlobalUnicast address for the happy-path fixtures below — deliberately NOT a documentation or
/// private range, since the scope guard would reject those and this test is not about the guard.
fn a_globally_routable_reflexive_addr() -> SocketAddr {
    "1.1.1.1:51000".parse().unwrap()
}

#[tokio::test]
async fn returns_the_servers_answer_for_a_usable_reflexive_address() {
    let (client, _client_addr) = bind_loopback().await;
    let (server, server_addr) = bind_loopback().await;
    let reflexive = a_globally_routable_reflexive_addr();

    let server_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (n, from) = server.recv_from(&mut buf).await.unwrap();
        let txid = parse_binding_request(&buf[..n]).unwrap();
        let resp = encode_binding_success(&txid, reflexive);
        server.send_to(&resp, from).await.unwrap();
    });

    let got = query_reflexive_address(&client, server_addr, Duration::from_secs(2))
        .await
        .expect("the server answered with a usable reflexive address");
    assert_eq!(got, reflexive);

    server_task.await.unwrap();
}

/// The scope guard (`SPEC.md` §4 step 4): a server that hands back a `NeverDialable` address (a
/// malicious or misconfigured server fully controls the bytes it returns) is rejected as
/// `NoMappedAddress`, never surfaced as a usable reflexive candidate.
#[tokio::test]
async fn rejects_a_server_returning_a_never_dialable_address() {
    let (client, _client_addr) = bind_loopback().await;
    let (server, server_addr) = bind_loopback().await;
    let bogus: SocketAddr = "127.0.0.1:1234".parse().unwrap(); // loopback: NeverDialable

    let server_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (n, from) = server.recv_from(&mut buf).await.unwrap();
        let txid = parse_binding_request(&buf[..n]).unwrap();
        let resp = encode_binding_success(&txid, bogus);
        server.send_to(&resp, from).await.unwrap();
    });

    let err = query_reflexive_address(&client, server_addr, Duration::from_secs(2))
        .await
        .expect_err("a NeverDialable reflexive address must be rejected");
    assert_eq!(err, StunError::NoMappedAddress);

    server_task.await.unwrap();
}

/// A server that never answers surfaces `Timeout` within the caller's deadline rather than
/// hanging forever.
#[tokio::test]
async fn times_out_when_the_server_never_replies() {
    let (client, _client_addr) = bind_loopback().await;
    let (_silent_server, server_addr) = bind_loopback().await; // bound, but never reads or replies

    let err = query_reflexive_address(&client, server_addr, Duration::from_millis(200))
        .await
        .expect_err("no reply within the deadline must time out");
    assert_eq!(err, StunError::Timeout);
}

/// Anti-spoof (`SPEC.md` §4): a stray datagram from a source OTHER than the queried server must be
/// discarded, and the transaction keeps waiting for the genuine reply rather than failing on the
/// first mismatched-source packet.
#[tokio::test]
async fn ignores_a_stray_datagram_from_the_wrong_source_and_still_succeeds() {
    let (client, client_addr) = bind_loopback().await;
    let (server, server_addr) = bind_loopback().await;
    let (stray, _stray_addr) = bind_loopback().await;
    let reflexive = a_globally_routable_reflexive_addr();

    let server_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (n, from) = server.recv_from(&mut buf).await.unwrap();
        let txid = parse_binding_request(&buf[..n]).unwrap();

        // An unrelated datagram from a DIFFERENT socket arrives first — must be ignored, not
        // treated as (or mistaken for a failure caused by) the real reply.
        stray
            .send_to(b"not a stun message at all, ignore me", client_addr)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = encode_binding_success(&txid, reflexive);
        server.send_to(&resp, from).await.unwrap();
    });

    let got = query_reflexive_address(&client, server_addr, Duration::from_secs(2))
        .await
        .expect("the genuine reply must still be accepted after a stray datagram");
    assert_eq!(got, reflexive);

    server_task.await.unwrap();
}
