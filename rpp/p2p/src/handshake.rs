use std::collections::BTreeMap;
use std::io;

use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncWrite};
use serde::{Deserialize, Serialize};

use crate::identity::{IdentityKeypairExt, IdentityPublicKeyExt};
use crate::tier::TierLevel;
use crate::vendor::identity;
#[cfg(feature = "request-response")]
pub use crate::vendor::protocols::request_response::MAX_HANDSHAKE_BYTES;
#[cfg(feature = "request-response")]
use crate::vendor::protocols::request_response::{self, read_handshake_payload, write_payload};
use crate::vendor::PeerId;
use tracing::{info, warn};

pub const HANDSHAKE_PROTOCOL: &str = "/rpp/handshake/1.0.0";
pub const VRF_HANDSHAKE_CONTEXT: &[u8] = b"rpp.handshake.vrf";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakePayload {
    pub zsi_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf_public_key: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf_proof: Option<Vec<u8>>,
    pub tier: TierLevel,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<TelemetryMetadata>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub features: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeOutcome {
    Accepted {
        tier: TierLevel,
        allowlisted: bool,
    },
    Blocklisted,
    MissingPublicKey,
    MissingSignature,
    InvalidSignature,
    InvalidVrf {
        reason: String,
    },
    AllowlistTierMismatch {
        required: TierLevel,
        actual: TierLevel,
    },
}

impl HandshakeOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            HandshakeOutcome::Accepted { .. } => "accepted",
            HandshakeOutcome::Blocklisted => "blocklisted",
            HandshakeOutcome::MissingPublicKey => "missing_public_key",
            HandshakeOutcome::MissingSignature => "missing_signature",
            HandshakeOutcome::InvalidSignature => "invalid_signature",
            HandshakeOutcome::InvalidVrf { .. } => "invalid_vrf",
            HandshakeOutcome::AllowlistTierMismatch { .. } => "allowlist_tier_mismatch",
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            HandshakeOutcome::InvalidVrf { reason } => Some(reason.as_str()),
            _ => None,
        }
    }
}

pub fn emit_handshake_telemetry(
    peer: &PeerId,
    payload: &HandshakePayload,
    outcome: &HandshakeOutcome,
) {
    let agent = payload
        .telemetry
        .as_ref()
        .and_then(|meta| meta.tags.get("agent"))
        .map(|value| value.as_str())
        .unwrap_or("unknown");
    let zsi_id = payload.zsi_id.as_str();
    match outcome {
        HandshakeOutcome::Accepted { tier, allowlisted } => {
            info!(
                target: "telemetry.handshake",
                peer = %peer,
                tier = ?tier,
                allowlisted = *allowlisted,
                agent,
                zsi_id,
                "handshake_accepted"
            );
        }
        HandshakeOutcome::InvalidVrf { reason } => {
            warn!(
                target: "telemetry.handshake",
                peer = %peer,
                agent,
                zsi_id,
                reason = %reason,
                "handshake_rejected_vrf"
            );
        }
        HandshakeOutcome::AllowlistTierMismatch { required, actual } => {
            warn!(
                target: "telemetry.handshake",
                peer = %peer,
                agent,
                zsi_id,
                required = ?required,
                actual = ?actual,
                "handshake_rejected_allowlist"
            );
        }
        HandshakeOutcome::MissingPublicKey => {
            warn!(
                target: "telemetry.handshake",
                peer = %peer,
                agent,
                zsi_id,
                "handshake_rejected_missing_public_key"
            );
        }
        HandshakeOutcome::MissingSignature => {
            warn!(
                target: "telemetry.handshake",
                peer = %peer,
                agent,
                zsi_id,
                "handshake_rejected_missing_signature"
            );
        }
        HandshakeOutcome::InvalidSignature => {
            warn!(
                target: "telemetry.handshake",
                peer = %peer,
                agent,
                zsi_id,
                "handshake_rejected_signature"
            );
        }
        HandshakeOutcome::Blocklisted => {
            warn!(
                target: "telemetry.handshake",
                peer = %peer,
                agent,
                zsi_id,
                "handshake_rejected_blocklisted"
            );
        }
    }
}

impl HandshakePayload {
    pub fn new(
        zsi_id: impl Into<String>,
        vrf_public_key: Option<Vec<u8>>,
        vrf_proof: Option<Vec<u8>>,
        tier: TierLevel,
    ) -> Self {
        Self {
            zsi_id: zsi_id.into(),
            vrf_public_key,
            vrf_proof,
            tier,
            signature: Vec::new(),
            telemetry: None,
            features: BTreeMap::new(),
        }
    }

    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
        self
    }

    pub fn with_features(mut self, features: BTreeMap<String, bool>) -> Self {
        self.features = features;
        self
    }

    pub fn with_telemetry(mut self, telemetry: TelemetryMetadata) -> Self {
        self.telemetry = Some(telemetry);
        self
    }

    pub fn signed(&self, signer: &identity::Keypair) -> Result<Self, identity::SigningError> {
        let mut payload = self.clone();
        if payload.vrf_public_key.is_none() {
            if let Some(public) = signer.vrf_public_key() {
                payload.vrf_public_key = Some(public);
            }
        }
        if payload.vrf_proof.is_none() {
            if let Some(proof) = signer.vrf_sign(VRF_HANDSHAKE_CONTEXT, &payload.vrf_message()) {
                payload.vrf_proof = Some(proof);
            }
        }
        let digest = payload.digest();
        payload.signature = signer.sign_with_extensions(&digest)?;
        Ok(payload)
    }

    pub fn digest(&self) -> [u8; 32] {
        Self::digest_parts(
            &self.zsi_id,
            self.vrf_public_key.as_deref(),
            self.vrf_proof.as_deref(),
            self.tier,
            &self.features,
            self.telemetry.as_ref(),
        )
    }

    pub fn vrf_message(&self) -> Vec<u8> {
        let digest = Self::digest_parts(
            &self.zsi_id,
            self.vrf_public_key.as_deref(),
            None,
            self.tier,
            &self.features,
            self.telemetry.as_ref(),
        );
        digest.to_vec()
    }

    pub fn verify_signature_with(&self, public_key: &identity::PublicKey) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        public_key.verify_with_extensions(&self.digest(), &self.signature)
    }

    fn digest_parts(
        zsi_id: &str,
        vrf_public_key: Option<&[u8]>,
        vrf_proof: Option<&[u8]>,
        tier: TierLevel,
        features: &BTreeMap<String, bool>,
        telemetry: Option<&TelemetryMetadata>,
    ) -> [u8; 32] {
        use blake2::digest::Digest;

        let mut hasher = blake2::Blake2s256::new();
        let id_bytes = zsi_id.as_bytes();
        hasher.update((id_bytes.len() as u32).to_le_bytes());
        hasher.update(id_bytes);
        match vrf_public_key {
            Some(public_key) => {
                hasher.update([1u8]);
                hasher.update((public_key.len() as u32).to_le_bytes());
                hasher.update(public_key);
            }
            None => hasher.update([0u8]),
        }
        match vrf_proof {
            Some(proof) => {
                hasher.update([1u8]);
                hasher.update((proof.len() as u32).to_le_bytes());
                hasher.update(proof);
            }
            None => hasher.update([0u8]),
        }
        hasher.update([tier as u8]);
        hasher.update((features.len() as u32).to_le_bytes());
        for (name, enabled) in features {
            let bytes = name.as_bytes();
            hasher.update((bytes.len() as u32).to_le_bytes());
            hasher.update(bytes);
            hasher.update([*enabled as u8]);
        }
        match telemetry {
            Some(meta) => {
                hasher.update([1u8]);
                meta.update_digest(&mut hasher);
            }
            None => hasher.update([0u8]),
        }
        let digest = hasher.finalize();
        let mut buffer = [0u8; 32];
        buffer.copy_from_slice(&digest);
        buffer
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TelemetryMetadata {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
}

impl TelemetryMetadata {
    pub fn new() -> Self {
        Self {
            tags: BTreeMap::new(),
        }
    }

    pub fn with_agent(agent: impl Into<String>) -> Self {
        let mut meta = Self::new();
        meta.tags.insert("agent".into(), agent.into());
        meta
    }

    pub fn insert(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.insert(key.into(), value.into());
        self
    }

    fn update_digest(&self, hasher: &mut blake2::Blake2s256) {
        hasher.update((self.tags.len() as u32).to_le_bytes());
        for (key, value) in &self.tags {
            let key_bytes = key.as_bytes();
            hasher.update((key_bytes.len() as u32).to_le_bytes());
            hasher.update(key_bytes);

            let value_bytes = value.as_bytes();
            hasher.update((value_bytes.len() as u32).to_le_bytes());
            hasher.update(value_bytes);
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct HandshakeCodec;

#[async_trait]
#[cfg(feature = "request-response")]
impl request_response::Codec for HandshakeCodec {
    type Protocol = String;
    type Request = HandshakePayload;
    type Response = HandshakePayload;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_handshake_payload(io).await?;
        serde_json::from_slice(&buf).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_handshake_payload(io).await?;
        serde_json::from_slice(&buf).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let payload = serde_json::to_vec(&request)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        write_payload(io, &payload).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let payload = serde_json::to_vec(&response)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        write_payload(io, &payload).await
    }
}

#[cfg(all(test, feature = "request-response"))]
mod tests {
    use super::*;
    use crate::vendor::identity;
    use crate::vendor::protocols::request_response::Codec;
    use futures::executor::block_on;
    use futures::io::Cursor;
    use proptest::prelude::*;
    use rand::rngs::OsRng;
    use schnorrkel::{keys::ExpansionMode, signing_context, MiniSecretKey, Signature};
    use tempfile::tempdir;

    proptest! {
        #[test]
        fn handshake_roundtrips(
            zsi in "[a-zA-Z0-9]{0,16}",
            tier in any::<u8>(),
            public in prop::collection::vec(any::<u8>(), 0..64),
            proof in prop::collection::vec(any::<u8>(), 0..64)
        ) {
            let tier = match tier % 6 {
                0 => TierLevel::Tl0,
                1 => TierLevel::Tl1,
                2 => TierLevel::Tl2,
                3 => TierLevel::Tl3,
                4 => TierLevel::Tl4,
                _ => TierLevel::Tl5,
            };
            let keypair = identity::Keypair::generate_ed25519();
            let vrf_public_key = (!public.is_empty()).then(|| public.clone());
            let vrf_proof = (!proof.is_empty()).then(|| proof.clone());
            let template = HandshakePayload::new(zsi.clone(), vrf_public_key, vrf_proof, tier);
            let signed = template.signed(&keypair).expect("sign");
            prop_assert!(signed.verify_signature_with(&keypair.public()));
            let encoded = serde_json::to_vec(&signed).expect("encode");
            let decoded: HandshakePayload = serde_json::from_slice(&encoded).expect("decode");
            prop_assert_eq!(signed, decoded);
        }
    }

    #[test]
    fn oversized_handshakes_are_rejected() {
        let protocol = HANDSHAKE_PROTOCOL.to_string();

        let mut large_payload = HandshakePayload::new("oversized", None, None, TierLevel::Tl0)
            .with_signature(vec![0u8; MAX_HANDSHAKE_BYTES]);
        // Ensure the serialized payload exceeds the maximum size limit.
        let mut encoded = serde_json::to_vec(&large_payload).expect("encode");
        if encoded.len() <= MAX_HANDSHAKE_BYTES {
            // Pad the signature to exceed the limit if necessary.
            let extra = MAX_HANDSHAKE_BYTES - encoded.len() + 1;
            large_payload
                .signature
                .extend(std::iter::repeat(0u8).take(extra));
            encoded = serde_json::to_vec(&large_payload).expect("encode");
        }
        assert!(encoded.len() > MAX_HANDSHAKE_BYTES);

        let mut request_codec = HandshakeCodec::default();
        let mut request_reader = Cursor::new(encoded.clone());
        let err = block_on(request_codec.read_request(&protocol, &mut request_reader))
            .expect_err("oversized request should fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let mut response_codec = HandshakeCodec::default();
        let mut response_reader = Cursor::new(encoded);
        let err = block_on(response_codec.read_response(&protocol, &mut response_reader))
            .expect_err("oversized response should fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn normal_handshakes_are_accepted() {
        let protocol = HANDSHAKE_PROTOCOL.to_string();

        let payload = HandshakePayload::new("normal", None, None, TierLevel::Tl1)
            .with_signature(vec![1, 2, 3, 4]);
        let encoded = serde_json::to_vec(&payload).expect("encode");
        assert!(encoded.len() <= MAX_HANDSHAKE_BYTES);

        let mut request_codec = HandshakeCodec::default();
        let mut request_reader = Cursor::new(encoded.clone());
        let decoded_request = block_on(request_codec.read_request(&protocol, &mut request_reader))
            .expect("normal request should succeed");
        assert_eq!(decoded_request, payload);

        let mut response_codec = HandshakeCodec::default();
        let mut response_reader = Cursor::new(encoded);
        let decoded_response =
            block_on(response_codec.read_response(&protocol, &mut response_reader))
                .expect("normal response should succeed");
        assert_eq!(decoded_response, payload);
    }

    #[test]
    fn vrf_handshakes_produce_verifiable_proofs() {
        use crate::identity::NodeIdentity;

        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("node.key");
        let mut identity = NodeIdentity::load_or_generate(&path).expect("identity");
        let mut rng = OsRng;
        let vrf_secret = MiniSecretKey::generate_with(&mut rng);
        let derived = vrf_secret.expand_to_keypair(ExpansionMode::Uniform);
        let expected_public = derived.public.to_bytes().to_vec();

        identity.set_vrf_secret(Some(&vrf_secret));
        let keypair = identity.clone_keypair();

        let handshake = HandshakePayload::new("node", None, None, TierLevel::Tl2)
            .signed(&keypair)
            .expect("signed payload");

        assert_eq!(handshake.vrf_public_key, Some(expected_public));

        let proof_bytes: [u8; 64] = handshake
            .vrf_proof
            .clone()
            .expect("proof present")
            .try_into()
            .expect("signature length");
        let proof = Signature::from_bytes(&proof_bytes).expect("signature bytes");

        let context = signing_context(VRF_HANDSHAKE_CONTEXT);
        derived
            .public
            .verify_simple(context, &handshake.vrf_message(), &proof)
            .expect("valid VRF proof");

        assert!(handshake.verify_signature_with(&keypair.public()));
    }
}
