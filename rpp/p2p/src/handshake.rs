use std::io;

use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use serde::{Deserialize, Serialize};

use crate::tier::TierLevel;

pub const HANDSHAKE_PROTOCOL: &str = "/rpp/handshake/1.0.0";
const VRF_DOMAIN: &[u8] = b"rpp.handshake.vrf";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakePayload {
    pub zsi_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf_proof: Option<Vec<u8>>,
    pub tier: TierLevel,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature: Vec<u8>,
}

impl HandshakePayload {
    pub fn new(
        zsi_id: impl Into<String>,
        vrf_proof: Option<Vec<u8>>,
        tier: TierLevel,
    ) -> Self {
        Self {
            zsi_id: zsi_id.into(),
            vrf_proof,
            tier,
            signature: Vec::new(),
        }
    }

    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
        self
    }

    pub fn signed(&self, signer: &libp2p::identity::Keypair) -> Result<Self, libp2p::identity::SigningError> {
        let mut payload = self.clone();
        let digest = payload.digest();
        payload.signature = signer.sign(&digest)?;
        Ok(payload)
    }

    pub fn digest(&self) -> [u8; 32] {
        Self::digest_parts(&self.zsi_id, self.vrf_proof.as_deref(), self.tier)
    }

    pub fn vrf_message(&self) -> Vec<u8> {
        let mut message = Vec::with_capacity(VRF_DOMAIN.len() + 32);
        message.extend_from_slice(VRF_DOMAIN);
        let digest = Self::digest_parts(&self.zsi_id, None, self.tier);
        message.extend_from_slice(&digest);
        message
    }

    pub fn verify_signature_with(&self, public_key: &libp2p::identity::PublicKey) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        public_key.verify(&self.digest(), &self.signature)
    }

    fn digest_parts(zsi_id: &str, vrf_proof: Option<&[u8]>, tier: TierLevel) -> [u8; 32] {
        use blake2::digest::Digest;

        let mut hasher = blake2::Blake2s256::new();
        let id_bytes = zsi_id.as_bytes();
        hasher.update((id_bytes.len() as u32).to_le_bytes());
        hasher.update(id_bytes);
        match vrf_proof {
            Some(proof) => {
                hasher.update([1u8]);
                hasher.update((proof.len() as u32).to_le_bytes());
                hasher.update(proof);
            }
            None => hasher.update([0u8]),
        }
        hasher.update([tier as u8]);
        let digest = hasher.finalize();
        let mut buffer = [0u8; 32];
        buffer.copy_from_slice(&digest);
        buffer
    }
}

#[derive(Debug, Clone, Default)]
pub struct HandshakeCodec;

#[async_trait]
impl libp2p::request_response::Codec for HandshakeCodec {
    type Protocol = String;
    type Request = HandshakePayload;
    type Response = HandshakePayload;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
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
        io.read_to_end(&mut buf).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn handshake_roundtrips(zsi in "[a-zA-Z0-9]{0,16}", tier in any::<u8>(), proof in prop::collection::vec(any::<u8>(), 0..64)) {
            let tier = match tier % 6 {
                0 => TierLevel::Tl0,
                1 => TierLevel::Tl1,
                2 => TierLevel::Tl2,
                3 => TierLevel::Tl3,
                4 => TierLevel::Tl4,
                _ => TierLevel::Tl5,
            };
            let keypair = libp2p::identity::Keypair::generate_ed25519();
            let template = HandshakePayload::new(zsi.clone(), Some(proof.clone()), tier);
            let signed = template.signed(&keypair).expect("sign");
            prop_assert!(signed.verify_signature_with(&keypair.public()));
            let encoded = serde_json::to_vec(&signed).expect("encode");
            let decoded: HandshakePayload = serde_json::from_slice(&encoded).expect("decode");
            prop_assert_eq!(signed, decoded);
        }
    }
}
