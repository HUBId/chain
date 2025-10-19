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
use rpp_p2p::vendor::request_response::{self, ProtocolSupport};
use rpp_p2p::vendor::swarm::{NetworkBehaviour, SwarmEvent};
use rpp_p2p::vendor::{noise, tcp, yamux, Multiaddr, Swarm, SwarmBuilder};
use rpp_p2p::vendor::PeerId;
use rpp_p2p::vendor::multiaddr::multiaddr;
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
        let keypair = Keypair::generate_ed25519();
        let handshake = HandshakePayload::new(name, None, None, TierLevel::Tl1)
            .signed(&keypair)
            .expect("handshake signed");
        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
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
                    if let Some(payload) = handle_event(&mut listener.swarm, event, &listener.handshake) {
                        listener_handshake.get_or_insert(payload);
                    }
                }
                event = dialer.swarm.select_next_some() => {
                    if let Some(payload) = handle_event(&mut dialer.swarm, event, &dialer.handshake) {
                        dialer_handshake.get_or_insert(payload);
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

fn handle_event(
    swarm: &mut Swarm<HandshakeBehaviour>,
    event: SwarmEvent<HandshakeBehaviourEvent>,
    handshake: &HandshakePayload,
) -> Option<HandshakePayload> {
    match event {
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id, handshake.clone());
            None
        }
        SwarmEvent::Behaviour(HandshakeBehaviourEvent::RequestResponse(event)) => {
            match event {
                request_response::Event::Message { peer, message, .. } => match message {
                    request_response::Message::Request { request, channel, .. } => {
                        swarm
                            .behaviour_mut()
                            .request_response
                            .send_response(channel, handshake.clone())
                            .expect("send response");
                        Some(request)
                    }
                    request_response::Message::Response { response, .. } => Some(response),
                },
                request_response::Event::ResponseSent { .. } => None,
                request_response::Event::OutboundFailure { peer, error, .. }
                | request_response::Event::InboundFailure { peer, error, .. } => {
                    panic!("handshake with {peer:?} failed: {error:?}");
                }
            }
        }
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
        | SwarmEvent::NewListenAddrCandidate { .. } => None,
    }
}
