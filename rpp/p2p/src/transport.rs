use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::admission::TierLevel;

#[derive(Debug, Clone)]
pub enum TransportError {
    AlreadyListening(Multiaddr),
    UnknownMultiaddr(Multiaddr),
    SelfDial,
    Unreachable,
    ChannelClosed,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::AlreadyListening(addr) => {
                write!(f, "address {} already registered", addr)
            }
            TransportError::UnknownMultiaddr(addr) => {
                write!(f, "unknown multiaddr {}", addr)
            }
            TransportError::SelfDial => write!(f, "attempted to dial self"),
            TransportError::Unreachable => write!(f, "remote transport unreachable"),
            TransportError::ChannelClosed => write!(f, "connection channel closed"),
        }
    }
}

impl std::error::Error for TransportError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Quic,
    Tcp,
}

#[derive(Debug, Clone)]
pub struct TransportConfig {
    preferred: TransportProtocol,
    fallback: TransportProtocol,
    tier: TierLevel,
    vrf_tag: [u8; 32],
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            preferred: TransportProtocol::Quic,
            fallback: TransportProtocol::Tcp,
            tier: TierLevel::Tier3,
            vrf_tag: [0u8; 32],
        }
    }
}

impl TransportConfig {
    pub fn with_preferred(mut self, protocol: TransportProtocol) -> Self {
        self.preferred = protocol;
        self
    }

    pub fn with_vrf_tag(mut self, tag: [u8; 32]) -> Self {
        self.vrf_tag = tag;
        self
    }

    pub fn with_tier(mut self, tier: TierLevel) -> Self {
        self.tier = tier;
        self
    }

    pub fn preferred(&self) -> TransportProtocol {
        self.preferred
    }

    pub fn fallback(&self) -> TransportProtocol {
        self.fallback
    }
}

#[derive(Debug, Clone)]
pub struct HandshakeData {
    pub vrf_tag: [u8; 32],
    pub noise_static_key: [u8; 32],
    pub established_at: SystemTime,
}

impl HandshakeData {
    fn new(vrf_tag: [u8; 32]) -> Self {
        let established_at = SystemTime::now();
        let mut noise_static_key = [0u8; 32];
        let nanos = established_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_nanos();
        noise_static_key[..16].copy_from_slice(&nanos.to_le_bytes());
        noise_static_key[16..].copy_from_slice(&vrf_tag[..16]);
        Self {
            vrf_tag,
            noise_static_key,
            established_at,
        }
    }
}

#[derive(Debug)]
pub struct Connection {
    local_peer: String,
    remote_peer: String,
    protocol: TransportProtocol,
    handshake: HandshakeData,
    outbound: Sender<Vec<u8>>,
    inbound: Mutex<Receiver<Vec<u8>>>,
}

impl Connection {
    fn new(
        local_peer: String,
        remote_peer: String,
        protocol: TransportProtocol,
        handshake: HandshakeData,
        outbound: Sender<Vec<u8>>,
        inbound: Receiver<Vec<u8>>,
    ) -> Self {
        Self {
            local_peer,
            remote_peer,
            protocol,
            handshake,
            outbound,
            inbound: Mutex::new(inbound),
        }
    }

    pub fn remote_peer(&self) -> &str {
        &self.remote_peer
    }

    pub fn local_peer(&self) -> &str {
        &self.local_peer
    }

    pub fn protocol(&self) -> TransportProtocol {
        self.protocol
    }

    pub fn handshake(&self) -> &HandshakeData {
        &self.handshake
    }

    pub fn send(&self, payload: &[u8]) -> Result<(), TransportError> {
        self.outbound
            .send(payload.to_vec())
            .map_err(|_| TransportError::ChannelClosed)
    }

    pub fn recv(&self) -> Result<Option<Vec<u8>>, TransportError> {
        let guard = self.inbound.lock().expect("receiver mutex poisoned");
        match guard.try_recv() {
            Ok(data) => Ok(Some(data)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(TransportError::ChannelClosed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Multiaddr(String);

impl Multiaddr {
    pub fn new(addr: impl Into<String>) -> Self {
        Self(addr.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Multiaddr {
    fn from(value: &str) -> Self {
        Multiaddr::new(value)
    }
}

impl From<String> for Multiaddr {
    fn from(value: String) -> Self {
        Multiaddr::new(value)
    }
}

impl fmt::Display for Multiaddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq for Multiaddr {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Multiaddr {}

impl Hash for Multiaddr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

#[derive(Debug)]
struct TransportState {
    peer_id: String,
    config: TransportConfig,
    incoming: Mutex<VecDeque<Connection>>,
}

impl TransportState {
    fn new(peer_id: String, config: TransportConfig) -> Self {
        Self {
            peer_id,
            config,
            incoming: Mutex::new(VecDeque::new()),
        }
    }

    fn enqueue(&self, connection: Connection) {
        self.incoming
            .lock()
            .expect("incoming queue poisoned")
            .push_back(connection);
    }

    fn dequeue(&self) -> Option<Connection> {
        self.incoming
            .lock()
            .expect("incoming queue poisoned")
            .pop_front()
    }
}

struct Router {
    listeners: Mutex<HashMap<Multiaddr, Weak<TransportState>>>,
}

impl Router {
    fn new() -> Self {
        Self {
            listeners: Mutex::new(HashMap::new()),
        }
    }

    fn register(&self, addr: Multiaddr, transport: &Arc<TransportState>) -> Result<(), TransportError> {
        let mut listeners = self.listeners.lock().expect("router mutex poisoned");
        if let Some(existing) = listeners.get(&addr) {
            if existing.upgrade().is_some() {
                return Err(TransportError::AlreadyListening(addr));
            }
        }
        listeners.insert(addr, Arc::downgrade(transport));
        Ok(())
    }

    fn resolve(&self, addr: &Multiaddr) -> Option<Arc<TransportState>> {
        let mut listeners = self.listeners.lock().expect("router mutex poisoned");
        if let Some(state) = listeners.get(addr) {
            if let Some(transport) = state.upgrade() {
                return Some(transport);
            }
        }
        listeners.remove(addr);
        None
    }
}

fn router() -> &'static Arc<Router> {
    static ROUTER: OnceLock<Arc<Router>> = OnceLock::new();
    ROUTER.get_or_init(|| Arc::new(Router::new()))
}

#[derive(Debug, Clone)]
pub struct Transport {
    inner: Arc<TransportState>,
}

impl Transport {
    pub fn new_transport(local_id: impl Into<String>) -> Self {
        Self::with_config(local_id, TransportConfig::default())
    }

    pub fn with_config(local_id: impl Into<String>, config: TransportConfig) -> Self {
        let state = Arc::new(TransportState::new(local_id.into(), config));
        Self { inner: state }
    }

    pub fn listen(&self, addr: Multiaddr) -> Result<(), TransportError> {
        if self.inner.peer_id.is_empty() {
            return Err(TransportError::Unreachable);
        }
        router().register(addr, &self.inner)
    }

    pub fn dial(&self, addr: Multiaddr) -> Result<Connection, TransportError> {
        let remote = router()
            .resolve(&addr)
            .ok_or_else(|| TransportError::UnknownMultiaddr(addr.clone()))?;
        if Arc::ptr_eq(&remote, &self.inner) {
            return Err(TransportError::SelfDial);
        }

        let (to_remote_tx, to_remote_rx) = mpsc::channel();
        let (to_local_tx, to_local_rx) = mpsc::channel();

        let local_handshake = HandshakeData::new(self.inner.config.vrf_tag);
        let remote_handshake = HandshakeData::new(remote.config.vrf_tag);

        let local_protocol = if self.inner.config.preferred() == remote.config.preferred() {
            self.inner.config.preferred()
        } else {
            self.inner.config.fallback()
        };
        let remote_protocol = if remote.config.preferred() == self.inner.config.preferred() {
            remote.config.preferred()
        } else {
            remote.config.fallback()
        };

        let local_connection = Connection::new(
            self.inner.peer_id.clone(),
            remote.peer_id.clone(),
            local_protocol,
            local_handshake,
            to_local_tx,
            to_remote_rx,
        );

        let remote_connection = Connection::new(
            remote.peer_id.clone(),
            self.inner.peer_id.clone(),
            remote_protocol,
            remote_handshake,
            to_remote_tx,
            to_local_rx,
        );

        remote.enqueue(remote_connection);
        Ok(local_connection)
    }

    pub fn accept(&self) -> Option<Connection> {
        self.inner.dequeue()
    }

    pub fn local_peer(&self) -> &str {
        &self.inner.peer_id
    }

    pub fn tier(&self) -> TierLevel {
        self.inner.config.tier
    }

    pub fn vrf_tag(&self) -> [u8; 32] {
        self.inner.config.vrf_tag
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn establishes_loopback_connection() {
        let transport_a = Transport::new_transport("node-a");
        let transport_b = Transport::new_transport("node-b");
        let addr = Multiaddr::from("/ip4/127.0.0.1/quic/7000");
        transport_b.listen(addr.clone()).expect("listen");

        let conn = transport_a.dial(addr.clone()).expect("dial");
        assert_eq!(conn.remote_peer(), "node-b");
        assert_eq!(conn.local_peer(), "node-a");
        assert_eq!(conn.protocol(), TransportProtocol::Quic);

        let inbound = transport_b.accept().expect("incoming");
        assert_eq!(inbound.remote_peer(), "node-a");
        assert_eq!(inbound.local_peer(), "node-b");
        assert_eq!(inbound.protocol(), TransportProtocol::Quic);
    }

    #[test]
    fn prevents_self_dial() {
        let transport = Transport::new_transport("node-self");
        let addr = Multiaddr::from("/ip4/127.0.0.1/tcp/8000");
        transport.listen(addr.clone()).expect("listen");
        assert!(matches!(transport.dial(addr), Err(TransportError::SelfDial)));
    }
}
