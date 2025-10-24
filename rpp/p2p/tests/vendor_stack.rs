#![cfg(all(
    feature = "request-response",
    feature = "noise",
    feature = "tcp",
    feature = "yamux",
))]

use futures::StreamExt;
use rpp_p2p::handshake::{HandshakeCodec, HandshakePayload, HANDSHAKE_PROTOCOL};
use rpp_p2p::tier::TierLevel;
use rpp_p2p::vendor::identity::Keypair;
use rpp_p2p::vendor::multiaddr::multiaddr;
use rpp_p2p::vendor::protocols::request_response::{self, ProtocolSupport};
use rpp_p2p::vendor::swarm::{NetworkBehaviour, SwarmEvent};
use rpp_p2p::vendor::PeerId;
use rpp_p2p::vendor::{noise, tcp, yamux, Multiaddr, Swarm, SwarmBuilder};
use rpp_p2p::{
    GossipTopic, Network, NodeIdentity, Peerstore, PeerstoreConfig, ReputationHeuristics,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::time::{timeout, Duration};

#[derive(NetworkBehaviour)]
struct HandshakeBehaviour {
    request_response: request_response::Behaviour<HandshakeCodec>,
}

impl HandshakeBehaviour {
    fn new() -> Self {
        let protocols = std::iter::once((HANDSHAKE_PROTOCOL.to_string(), ProtocolSupport::Full));
        let config = request_response::Config::default();
        let request_response =
            request_response::Behaviour::with_codec(HandshakeCodec::default(), protocols, config);
        Self { request_response }
    }
}

struct TestSwarm {
    swarm: Swarm<HandshakeBehaviour>,
    handshake: HandshakePayload,
}

impl TestSwarm {
    fn new(name: &str) -> Self {
        Self::with_throttle(name, yamux::allow_all())
    }

    fn with_throttle(name: &str, permit: yamux::InboundStreamPermit) -> Self {
        let keypair = Keypair::generate_ed25519();
        let handshake = HandshakePayload::new(name, None, None, TierLevel::Tl1)
            .signed(&keypair)
            .expect("handshake signed");
        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::for_swarm(permit.clone()),
            )
            .expect("tcp transport")
            .with_behaviour(|_| Ok(HandshakeBehaviour::new()))
            .expect("behaviour")
            .build();
        Self { swarm, handshake }
    }

    fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn vendor_transport_handshake_completes() {
    let mut listener = TestSwarm::new("listener");
    let mut dialer = TestSwarm::new("dialer");

    let listen_addr: Multiaddr = multiaddr!("/ip4/127.0.0.1/tcp/0");
    listener
        .swarm
        .listen_on(listen_addr)
        .expect("listen address");

    let mut dial_addr = None;
    let mut dial_attempted = false;
    let mut listener_handshake = None;
    let mut dialer_handshake = None;

    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = listener.swarm.select_next_some() => {
                    if let SwarmEvent::NewListenAddr { address, .. } = &event {
                        dial_addr.get_or_insert_with(|| address.clone());
                    }
                    match handle_event(&mut listener.swarm, event, &listener.handshake) {
                        Ok(Some(payload)) => {
                            listener_handshake.get_or_insert(payload);
                        }
                        Ok(None) => {}
                        Err(err) => panic!("listener handshake failed: {err:?}"),
                    }
                }
                event = dialer.swarm.select_next_some() => {
                    match handle_event(&mut dialer.swarm, event, &dialer.handshake) {
                        Ok(Some(payload)) => {
                            dialer_handshake.get_or_insert(payload);
                        }
                        Ok(None) => {}
                        Err(err) => panic!("dialer handshake failed: {err:?}"),
                    }
                }
            }

            if let Some(addr) = dial_addr.as_ref() {
                if !dial_attempted {
                    dialer.swarm.dial(addr.clone()).expect("dial peer");
                    dial_attempted = true;
                }
            }

            if listener_handshake.is_some() && dialer_handshake.is_some() {
                break;
            }
        }
    })
    .await
    .expect("handshake within timeout");

    assert_eq!(
        listener_handshake.expect("listener handshake"),
        dialer.handshake,
        "listener should record the dialer's payload",
    );
    assert_eq!(
        dialer_handshake.expect("dialer handshake"),
        listener.handshake,
        "dialer should record the listener's payload",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn vendor_transport_throttles_inbound_streams() {
    let permit_counter = Arc::new(AtomicUsize::new(0));
    let listener_permit = {
        let counter = permit_counter.clone();
        yamux::allow(move |_peer: &PeerId| counter.fetch_add(1, Ordering::SeqCst) == 0)
    };

    let mut listener = TestSwarm::with_throttle("listener", listener_permit);
    let mut dialer = TestSwarm::new("dialer");

    let listen_addr: Multiaddr = multiaddr!("/ip4/127.0.0.1/tcp/0");
    listener
        .swarm
        .listen_on(listen_addr)
        .expect("listen address");

    let mut dial_addr = None;
    let mut dial_attempted = false;
    let mut listener_handshake = None;
    let mut dialer_handshake = None;
    let mut extra_request_sent = false;
    let mut throttle_failure = None;

    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = listener.swarm.select_next_some() => {
                    if let SwarmEvent::NewListenAddr { address, .. } = &event {
                        dial_addr.get_or_insert_with(|| address.clone());
                    }
                    match handle_event(&mut listener.swarm, event, &listener.handshake) {
                        Ok(Some(payload)) => {
                            listener_handshake.get_or_insert(payload);
                        }
                        Ok(None) => {}
                        Err(err) => panic!("listener handshake failed: {err:?}"),
                    }
                }
                event = dialer.swarm.select_next_some() => {
                    match handle_event(&mut dialer.swarm, event, &dialer.handshake) {
                        Ok(Some(payload)) => {
                            dialer_handshake.get_or_insert(payload);
                        }
                        Ok(None) => {}
                        Err(err) => {
                            throttle_failure.get_or_insert(err);
                        }
                    }
                }
            }

            if let Some(addr) = dial_addr.as_ref() {
                if !dial_attempted {
                    dialer.swarm.dial(addr.clone()).expect("dial peer");
                    dial_attempted = true;
                }
            }

            if listener_handshake.is_some() && dialer_handshake.is_some() && !extra_request_sent {
                dialer
                    .swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&listener.local_peer_id(), dialer.handshake.clone());
                extra_request_sent = true;
            }

            if throttle_failure.is_some() {
                break;
            }
        }
    })
    .await
    .expect("throttle within timeout");

    let failure = throttle_failure.expect("expected outbound failure after throttling");
    match failure {
        HandshakeFailure::Outbound { .. } => {}
        other => panic!("unexpected failure variant: {other:?}"),
    }

    assert!(
        extra_request_sent,
        "dialer should attempt additional request"
    );
    assert!(
        permit_counter.load(Ordering::SeqCst) >= 1,
        "permit counter should increment"
    );
}

#[test]
fn network_metrics_snapshot_records_outbound_bytes() {
    let dir = tempdir().expect("tmpdir");
    let key_path = dir.path().join("node.key");
    let identity = Arc::new(NodeIdentity::load_or_generate(&key_path).expect("identity"));
    let peerstore = Arc::new(Peerstore::open(PeerstoreConfig::memory()).expect("peerstore"));
    let mut network = Network::new(
        identity,
        peerstore,
        HandshakePayload::new("node", None, None, TierLevel::Tl3),
        None,
        128,
        1_024,
        ReputationHeuristics::default(),
    )
    .expect("network");

    let payload = b"hello-metrics".to_vec();
    let expected = payload.len() as u64;
    network
        .publish(GossipTopic::Meta, payload)
        .expect("publish meta telemetry");

    let snapshot = network.metrics_snapshot();
    let meta_metrics = snapshot
        .topics
        .into_iter()
        .find(|entry| entry.topic == GossipTopic::Meta)
        .expect("meta topic metrics available");

    assert_eq!(meta_metrics.outbound_bytes, expected);
    assert_eq!(snapshot.bandwidth.outbound_bytes, expected);
}

#[derive(Debug)]
enum HandshakeFailure {
    Outbound {
        peer: PeerId,
        error: request_response::OutboundFailure,
    },
    Inbound {
        peer: PeerId,
        error: request_response::InboundFailure,
    },
}

fn handle_event(
    swarm: &mut Swarm<HandshakeBehaviour>,
    event: SwarmEvent<HandshakeBehaviourEvent>,
    handshake: &HandshakePayload,
) -> Result<Option<HandshakePayload>, HandshakeFailure> {
    match event {
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id, handshake.clone());
            Ok(None)
        }
        SwarmEvent::Behaviour(HandshakeBehaviourEvent::RequestResponse(event)) => match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    swarm
                        .behaviour_mut()
                        .request_response
                        .send_response(channel, handshake.clone())
                        .expect("send response");
                    Ok(Some(request))
                }
                request_response::Message::Response { response, .. } => Ok(Some(response)),
            },
            request_response::Event::ResponseSent { .. } => Ok(None),
            request_response::Event::OutboundFailure { peer, error, .. } => {
                Err(HandshakeFailure::Outbound { peer, error })
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                Err(HandshakeFailure::Inbound { peer, error })
            }
        },
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            panic!("outgoing connection to {peer_id:?} failed: {error:?}");
        }
        SwarmEvent::IncomingConnectionError { error, .. } => {
            panic!("incoming connection error: {error:?}");
        }
        SwarmEvent::Dialing { .. }
        | SwarmEvent::NewListenAddr { .. }
        | SwarmEvent::ConnectionClosed { .. }
        | SwarmEvent::ListenerClosed { .. }
        | SwarmEvent::ListenerError { .. }
        | SwarmEvent::IncomingConnection { .. }
        | SwarmEvent::ExpiredListenAddr { .. }
        | SwarmEvent::ExternalAddrConfirmed { .. }
        | SwarmEvent::ExternalAddrExpired { .. }
        | SwarmEvent::NewExternalAddrCandidate { .. }
        | SwarmEvent::ConnectionAttemptCancelled { .. }
        | SwarmEvent::NewListenAddrCandidate { .. } => Ok(None),
    }
}
