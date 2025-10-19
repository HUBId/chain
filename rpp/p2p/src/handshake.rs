use std::collections::BTreeMap;
use std::io;

use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use serde::{Deserialize, Serialize};

use crate::identity::{IdentityKeypairExt, IdentityPublicKeyExt};
use crate::tier::TierLevel;
use crate::vendor::identity;
#[cfg(feature = "request-response")]
use crate::vendor::request_response;

pub const HANDSHAKE_PROTOCOL: &str = "/rpp/handshake/1.0.0";
pub const VRF_HANDSHAKE_CONTEXT: &[u8] = b"rpp.handshake.vrf";
pub const MAX_HANDSHAKE_BYTES: usize = 8 * 1024;

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
        }
    }

    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
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
            self.telemetry.as_ref(),
        )
    }

    pub fn vrf_message(&self) -> Vec<u8> {
        let digest = Self::digest_parts(
            &self.zsi_id,
            self.vrf_public_key.as_deref(),
            None,
            self.tier,
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
        let mut buf = Vec::new();
        let mut limited = io.take(MAX_HANDSHAKE_BYTES as u64);
        limited.read_to_end(&mut buf).await?;
        let limit_reached = limited.limit() == 0;
        drop(limited);

        if limit_reached {
            let mut extra = [0u8; 1];
            if io.read(&mut extra).await? != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "handshake message too large",
                ));
            }
        }

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
        let mut buf = Vec::new();
        let mut limited = io.take(MAX_HANDSHAKE_BYTES as u64);
        limited.read_to_end(&mut buf).await?;
        let limit_reached = limited.limit() == 0;
        drop(limited);

        if limit_reached {
            let mut extra = [0u8; 1];
            if io.read(&mut extra).await? != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "handshake message too large",
                ));
            }
        }

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
        io.write_all(&payload).await?;
        io.close().await
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
        io.write_all(&payload).await?;
        io.close().await
    }
}

#[cfg(all(test, feature = "request-response"))]
mod tests {
    use super::*;
    use crate::vendor::identity;
    use crate::vendor::request_response::Codec;
    use futures::executor::block_on;
    use futures::io::Cursor;
    use proptest::prelude::*;

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
}
