// Copyright 2022 Parity Technologies (UK) Ltd.
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

use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use libp2p_core::{
    upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade},
    UpgradeInfo,
};
use libp2p_identity as identity;
use libp2p_identity::PeerId;
use libp2p_noise as noise;
pub use noise::Error;

use crate::fingerprint::Fingerprint;

pub async fn inbound<T>(
    id_keys: identity::Keypair,
    stream: T,
    client_fingerprint: Fingerprint,
    server_fingerprint: Fingerprint,
) -> Result<PeerId, Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let noise = noise::Config::new(&id_keys)
        .unwrap()
        .with_prologue(noise_prologue(client_fingerprint, server_fingerprint));
    let info = noise.protocol_info().next().unwrap();
    // Note the roles are reversed because it allows the server (webrtc connection responder) to
    // send application data 0.5 RTT earlier.
    let (peer_id, mut channel) = noise.upgrade_outbound(stream, info).await?;

    channel.close().await?;

    Ok(peer_id)
}

pub async fn outbound<T>(
    id_keys: identity::Keypair,
    stream: T,
    server_fingerprint: Fingerprint,
    client_fingerprint: Fingerprint,
) -> Result<PeerId, Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let noise = noise::Config::new(&id_keys)
        .unwrap()
        .with_prologue(noise_prologue(client_fingerprint, server_fingerprint));
    let info = noise.protocol_info().next().unwrap();
    // Note the roles are reversed because it allows the server (webrtc connection responder) to
    // send application data 0.5 RTT earlier.
    let (peer_id, mut channel) = noise.upgrade_inbound(stream, info).await?;

    channel.close().await?;

    Ok(peer_id)
}

pub(crate) fn noise_prologue(
    client_fingerprint: Fingerprint,
    server_fingerprint: Fingerprint,
) -> Vec<u8> {
    let client = client_fingerprint.to_multihash().to_bytes();
    let server = server_fingerprint.to_multihash().to_bytes();
    const PREFIX: &[u8] = b"libp2p-webrtc-noise:";
    let mut out = Vec::with_capacity(PREFIX.len() + client.len() + server.len());
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(&client);
    out.extend_from_slice(&server);
    out
}

