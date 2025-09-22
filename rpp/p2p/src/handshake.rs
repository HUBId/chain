use std::io;

use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use serde::{Deserialize, Serialize};

use crate::tier::TierLevel;

pub const HANDSHAKE_PROTOCOL: &str = "/rpp/handshake/1.0.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakePayload {
    pub zsi_id: String,
    pub vrf_proof: Vec<u8>,
    pub tier: TierLevel,
}

impl HandshakePayload {
    pub fn new(zsi_id: impl Into<String>, vrf_proof: Vec<u8>, tier: TierLevel) -> Self {
        Self {
            zsi_id: zsi_id.into(),
            vrf_proof,
            tier,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct HandshakeCodec;

#[async_trait]
impl libp2p::request_response::Codec for HandshakeCodec {
    type Protocol = String;
    type Request = HandshakePayload;
    type Response = HandshakePayload;

    async fn read_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
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
            let payload = HandshakePayload::new(zsi.clone(), proof.clone(), tier);
            let encoded = serde_json::to_vec(&payload).expect("encode");
            let decoded: HandshakePayload = serde_json::from_slice(&encoded).expect("decode");
            prop_assert_eq!(payload, decoded);
        }
    }
}
