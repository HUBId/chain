use futures::prelude::*;
use libp2p_core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade, UpgradeInfo};
use std::time::Duration;

pub use libp2p_yamux::{Error, Muxer, Stream};

const MAX_CONNECTION_RECEIVE_WINDOW: usize = 128 * 1024 * 1024;
const MAX_NUM_STREAMS: usize = 512;
const MAX_STREAM_BUFFER_SIZE: usize = 4 * 1024 * 1024;
const MAX_FRAME_PAYLOAD: usize = 256 * 1024;
const SPLIT_SEND_SIZE: usize = 16 * 1024;
const KEEPALIVE_INTERVAL_SECS: u64 = 5;

#[derive(Debug, Clone)]
pub struct Config {
    inner: libp2p_yamux::Config,
}

impl Config {
    fn rpp_defaults() -> libp2p_yamux::Config {
        let mut cfg = libp2p_yamux::Config::default();
        cfg.set_max_num_streams(MAX_NUM_STREAMS);
        cfg.set_max_connection_receive_window(Some(MAX_CONNECTION_RECEIVE_WINDOW));
        cfg.set_max_buffer_size(MAX_STREAM_BUFFER_SIZE);
        cfg.set_max_frame_data_len(MAX_FRAME_PAYLOAD);
        cfg.set_split_send_size(SPLIT_SEND_SIZE);
        cfg.set_keepalive_interval(Duration::from_secs(KEEPALIVE_INTERVAL_SECS));
        cfg.set_read_after_close(false);
        cfg
    }

    pub fn new(inner: libp2p_yamux::Config) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> libp2p_yamux::Config {
        self.inner
    }

    pub fn as_inner(&self) -> &libp2p_yamux::Config {
        &self.inner
    }

    pub fn as_inner_mut(&mut self) -> &mut libp2p_yamux::Config {
        &mut self.inner
    }

    pub fn set_max_connection_receive_window(&mut self, limit: Option<usize>) -> &mut Self {
        self.inner.set_max_connection_receive_window(limit);
        self
    }

    pub fn set_max_num_streams(&mut self, max: usize) -> &mut Self {
        self.inner.set_max_num_streams(max);
        self
    }

    pub fn set_max_buffer_size(&mut self, bytes: usize) -> &mut Self {
        self.inner.set_max_buffer_size(bytes);
        self
    }

    pub fn set_max_frame_data_len(&mut self, bytes: usize) -> &mut Self {
        self.inner.set_max_frame_data_len(bytes);
        self
    }

    pub fn set_split_send_size(&mut self, bytes: usize) -> &mut Self {
        self.inner.set_split_send_size(bytes);
        self
    }

    pub fn set_read_after_close(&mut self, allow: bool) -> &mut Self {
        self.inner.set_read_after_close(allow);
        self
    }

    pub fn set_keepalive_interval(&mut self, interval: Duration) -> &mut Self {
        self.inner.set_keepalive_interval(interval);
        self
    }

    pub fn max_connection_receive_window(&self) -> Option<usize> {
        self.inner.max_connection_receive_window()
    }

    pub fn max_num_streams(&self) -> usize {
        self.inner.max_num_streams()
    }

    pub fn max_buffer_size(&self) -> usize {
        self.inner.max_buffer_size()
    }

    pub fn max_frame_data_len(&self) -> usize {
        self.inner.max_frame_data_len()
    }

    pub fn read_after_close(&self) -> bool {
        self.inner.read_after_close()
    }

    pub fn keepalive_interval(&self) -> Duration {
        self.inner.keepalive_interval()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            inner: Self::rpp_defaults(),
        }
    }
}

impl From<libp2p_yamux::Config> for Config {
    fn from(inner: libp2p_yamux::Config) -> Self {
        Self { inner }
    }
}

impl From<Config> for libp2p_yamux::Config {
    fn from(cfg: Config) -> Self {
        cfg.inner
    }
}

impl UpgradeInfo for Config {
    type Info = <libp2p_yamux::Config as UpgradeInfo>::Info;
    type InfoIter = <libp2p_yamux::Config as UpgradeInfo>::InfoIter;

    fn protocol_info(&self) -> Self::InfoIter {
        self.inner.protocol_info()
    }
}

impl<C> InboundConnectionUpgrade<C> for Config
where
    C: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = <libp2p_yamux::Config as InboundConnectionUpgrade<C>>::Output;
    type Error = <libp2p_yamux::Config as InboundConnectionUpgrade<C>>::Error;
    type Future = <libp2p_yamux::Config as InboundConnectionUpgrade<C>>::Future;

    fn upgrade_inbound(self, io: C, info: Self::Info) -> Self::Future {
        self.inner.upgrade_inbound(io, info)
    }
}

impl<C> OutboundConnectionUpgrade<C> for Config
where
    C: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = <libp2p_yamux::Config as OutboundConnectionUpgrade<C>>::Output;
    type Error = <libp2p_yamux::Config as OutboundConnectionUpgrade<C>>::Error;
    type Future = <libp2p_yamux::Config as OutboundConnectionUpgrade<C>>::Future;

    fn upgrade_outbound(self, io: C, info: Self::Info) -> Self::Future {
        self.inner.upgrade_outbound(io, info)
    }
}
