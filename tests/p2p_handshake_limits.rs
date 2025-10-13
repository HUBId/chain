use std::io;

use rpp_p2p::{HandshakeCodec, HandshakePayload, TierLevel, HANDSHAKE_PROTOCOL};
use tokio::io::duplex;

#[tokio::test]
async fn handshake_messages_over_limit_are_rejected() {
    let oversized_proof = vec![0u8; 10 * 1024];
    let payload = HandshakePayload::new(
        "peer",
        Some(vec![1u8; 32]),
        Some(oversized_proof),
        TierLevel::Tl3,
    );

    let (mut client, mut server) = duplex(20_000);
    let protocol = HANDSHAKE_PROTOCOL.to_string();
    let writer_protocol = protocol.clone();

    let writer = tokio::spawn(async move {
        let mut codec = HandshakeCodec::default();
        codec
            .write_request(&writer_protocol, &mut client, payload)
            .await
    });

    let mut codec = HandshakeCodec::default();
    let result = codec.read_request(&protocol, &mut server).await;
    let write_result = writer.await.expect("writer task panicked");
    write_result.expect("handshake payload should be written");

    let err = result.expect_err("oversized handshake should be rejected");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("too large"));
}
