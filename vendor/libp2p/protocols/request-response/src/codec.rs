// Copyright 2020 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::io;

use async_trait::async_trait;
use futures::prelude::*;

/// Maximum payload size (in bytes) accepted by the handshake codec.
///
/// The limit is enforced when reading both inbound requests and outbound
/// responses via [`read_handshake_payload`].
pub const MAX_HANDSHAKE_BYTES: usize = 8 * 1024;

/// Convenience alias for raw payload buffers exchanged by codecs.
pub type Payload = Vec<u8>;

/// A `Codec` defines the request and response types
/// for a request-response [`Behaviour`](crate::Behaviour) protocol or
/// protocol family and how they are encoded / decoded on an I/O stream.
#[async_trait]
pub trait Codec {
    /// The type of protocol(s) or protocol versions being negotiated.
    type Protocol: AsRef<str> + Send + Clone;
    /// The type of inbound and outbound requests.
    type Request: Send;
    /// The type of inbound and outbound responses.
    type Response: Send;

    /// Reads a request from the given I/O stream according to the
    /// negotiated protocol.
    async fn read_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send;

    /// Reads a response from the given I/O stream according to the
    /// negotiated protocol.
    async fn read_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send;

    /// Writes a request to the given I/O stream according to the
    /// negotiated protocol.
    async fn write_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send;

    /// Writes a response to the given I/O stream according to the
    /// negotiated protocol.
    async fn write_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send;
}

/// Reads an entire payload from `io` while ensuring the number of bytes does
/// not exceed `limit`.
pub async fn read_limited<T>(io: &mut T, limit: usize) -> io::Result<Payload>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = Vec::new();
    let mut limited = io.take(limit as u64);
    limited.read_to_end(&mut buf).await?;
    let limit_reached = limited.limit() == 0;
    drop(limited);

    if limit_reached {
        let mut extra = [0u8; 1];
        if io.read(&mut extra).await? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request-response payload exceeds configured limit",
            ));
        }
    }

    Ok(buf)
}

/// Reads a handshake payload subject to [`MAX_HANDSHAKE_BYTES`].
pub async fn read_handshake_payload<T>(io: &mut T) -> io::Result<Payload>
where
    T: AsyncRead + Unpin + Send,
{
    read_limited(io, MAX_HANDSHAKE_BYTES).await
}

/// Writes `payload` into `io` and gracefully closes the stream afterwards.
pub async fn write_payload<T>(io: &mut T, payload: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    io.write_all(payload).await?;
    io.close().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{executor::block_on, io::Cursor};

    #[test]
    fn accepts_payloads_within_limit() {
        block_on(async {
            let data = vec![1u8, 2, 3];
            let mut cursor = Cursor::new(data.clone());
            let result = read_limited(&mut cursor, 8).await.expect("read payload");
            assert_eq!(result, data);
        });
    }

    #[test]
    fn rejects_payloads_over_limit() {
        block_on(async {
            let mut cursor = Cursor::new(vec![0u8; MAX_HANDSHAKE_BYTES + 4]);
            let err = read_handshake_payload(&mut cursor)
                .await
                .expect_err("payload should exceed limit");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        });
    }

    #[test]
    fn write_payload_closes_stream() {
        block_on(async {
            let mut buffer = Cursor::new(Vec::new());
            write_payload(&mut buffer, b"hello world")
                .await
                .expect("write payload");
            assert_eq!(buffer.into_inner(), b"hello world".to_vec());
        });
    }
}
