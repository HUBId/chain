use std::cmp::Ordering;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::wallet::WalletFeeConfig;
use crate::node_client::{BlockFeeSummary, MempoolInfo, NodeClient, NodeClientError};

#[derive(Clone, Debug)]
pub struct FeeEstimator {
    config: WalletFeeConfig,
    cache: Mutex<Option<CachedQuote>>,
}

impl FeeEstimator {
    pub fn new(config: WalletFeeConfig) -> Self {
        Self {
            config,
            cache: Mutex::new(None),
        }
    }

    pub fn resolve(
        &self,
        node: Option<&dyn NodeClient>,
        override_rate: Option<u64>,
    ) -> Result<FeeQuote, FeeError> {
        if let Some(rate) = override_rate {
            let rate = self.validate_override(rate)?;
            return Ok(FeeQuote::new(rate, FeeEstimateSource::Override));
        }

        if let Some(node) = node {
            if let Some(quote) = self.cached_if_fresh() {
                return Ok(quote);
            }

            let info = node.mempool_info().map_err(FeeError::from)?;
            let block_limit = usize::max(1, self.config.target_confirmations as usize);
            let blocks = node.recent_blocks(block_limit).map_err(FeeError::from)?;

            if let Some(mut quote) = self.derive_from_stats(&info, &blocks) {
                let clamped = self.clamp_absolute(quote.rate);
                quote.rate = clamped;
                self.store_cache(quote.clone());
                return Ok(quote);
            }
        }

        let fallback_rate = self.clamp_absolute(self.config.default_sats_per_vbyte);
        let quote = FeeQuote::new(fallback_rate, FeeEstimateSource::ConfigFallback);
        self.store_cache(quote.clone());
        Ok(quote)
    }

    pub fn config(&self) -> &WalletFeeConfig {
        &self.config
    }

    pub fn last_quote(&self) -> Option<FeeQuote> {
        self.cache
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|cached| cached.quote.clone()))
    }

    fn validate_override(&self, rate: u64) -> Result<u64, FeeError> {
        if rate < self.config.min_sats_per_vbyte {
            return Err(FeeError::BelowMinimum {
                requested: rate,
                minimum: self.config.min_sats_per_vbyte,
            });
        }
        if rate > self.config.max_sats_per_vbyte {
            return Err(FeeError::AboveMaximum {
                requested: rate,
                maximum: self.config.max_sats_per_vbyte,
            });
        }
        Ok(rate)
    }

    fn clamp_absolute(&self, rate: u64) -> u64 {
        rate.clamp(
            self.config.min_sats_per_vbyte,
            self.config.max_sats_per_vbyte,
        )
    }

    fn cached_if_fresh(&self) -> Option<FeeQuote> {
        let ttl = Duration::from_secs(self.config.cache_ttl_secs);
        let mut guard = self.cache.lock().ok()?;
        if let Some(cached) = guard.as_ref() {
            if ttl.is_zero() || cached.created.elapsed() <= ttl {
                return Some(cached.quote.clone());
            }
        }
        guard.take();
        None
    }

    fn store_cache(&self, quote: FeeQuote) {
        if self.config.cache_ttl_secs == 0 {
            return;
        }
        if let Ok(mut guard) = self.cache.lock() {
            *guard = Some(CachedQuote {
                quote,
                created: Instant::now(),
            });
        }
    }

    fn derive_from_stats(
        &self,
        info: &MempoolInfo,
        blocks: &[BlockFeeSummary],
    ) -> Option<FeeQuote> {
        let mut samples: Vec<u64> = blocks
            .iter()
            .filter_map(|block| block.median_fee_rate)
            .collect();
        let sample_count = samples.len();
        if samples.is_empty() && info.min_fee_rate.is_none() {
            return None;
        }
        samples.sort_unstable();
        let mut base_rate = samples
            .get(sample_count / 2)
            .copied()
            .or(info.min_fee_rate)
            .unwrap_or(self.config.default_sats_per_vbyte);

        if let Some(min_hint) = info.min_fee_rate {
            base_rate = base_rate.max(min_hint);
        }

        let congestion = classify_congestion(info.utilization());
        let mut candidate = match congestion {
            FeeCongestionLevel::High => base_rate.saturating_mul(2),
            FeeCongestionLevel::Moderate => {
                let bump = (base_rate / 2).max(1);
                base_rate.saturating_add(bump)
            }
            FeeCongestionLevel::Low | FeeCongestionLevel::Unknown => base_rate,
        };

        if let Some(max_hint) = info.max_fee_rate {
            match congestion {
                FeeCongestionLevel::High => {
                    candidate = candidate.max(max_hint);
                }
                FeeCongestionLevel::Moderate => {
                    candidate = candidate.max(base_rate.min(max_hint));
                }
                FeeCongestionLevel::Low | FeeCongestionLevel::Unknown => {
                    candidate = candidate.max(base_rate.min(max_hint));
                }
            }
        }

        candidate = candidate.clamp(
            self.config.heuristic_min_sats_per_vbyte,
            self.config.heuristic_max_sats_per_vbyte,
        );

        Some(FeeQuote::new(
            candidate,
            FeeEstimateSource::Node {
                congestion,
                samples: sample_count,
            },
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeQuote {
    rate: u64,
    source: FeeEstimateSource,
}

impl FeeQuote {
    fn new(rate: u64, source: FeeEstimateSource) -> Self {
        Self { rate, source }
    }

    pub fn rate(&self) -> u64 {
        self.rate
    }

    pub fn source(&self) -> &FeeEstimateSource {
        &self.source
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeeEstimateSource {
    Override,
    Node {
        congestion: FeeCongestionLevel,
        samples: usize,
    },
    ConfigFallback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeCongestionLevel {
    Low,
    Moderate,
    High,
    Unknown,
}

fn classify_congestion(utilization: f64) -> FeeCongestionLevel {
    match utilization.partial_cmp(&0.0).unwrap_or(Ordering::Equal) {
        Ordering::Less | Ordering::Equal => FeeCongestionLevel::Unknown,
        Ordering::Greater => {
            if utilization >= 0.85 {
                FeeCongestionLevel::High
            } else if utilization >= 0.55 {
                FeeCongestionLevel::Moderate
            } else {
                FeeCongestionLevel::Low
            }
        }
    }
}

#[derive(Debug)]
struct CachedQuote {
    quote: FeeQuote,
    created: Instant,
}

#[derive(Debug, thiserror::Error)]
pub enum FeeError {
    #[error("fee rate {requested} sats/vB below minimum {minimum}")]
    BelowMinimum { requested: u64, minimum: u64 },
    #[error("fee rate {requested} sats/vB above maximum {maximum}")]
    AboveMaximum { requested: u64, maximum: u64 },
    #[error("node error: {0}")]
    Node(#[from] NodeClientError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::DraftTransaction;
    use crate::node_client::{ChainHead, NodeClient, NodeClientError, StubNodeClient};
    use anyhow::anyhow;

    fn test_config() -> WalletFeeConfig {
        WalletFeeConfig {
            default_sats_per_vbyte: 5,
            min_sats_per_vbyte: 1,
            max_sats_per_vbyte: 500,
            target_confirmations: 3,
            heuristic_min_sats_per_vbyte: 2,
            heuristic_max_sats_per_vbyte: 200,
            cache_ttl_secs: 60,
        }
    }

    fn low_congestion_info() -> MempoolInfo {
        MempoolInfo {
            tx_count: 1_000,
            vsize_limit: 1_000_000,
            vsize_in_use: 200_000,
            min_fee_rate: Some(3),
            max_fee_rate: Some(20),
        }
    }

    fn high_congestion_info() -> MempoolInfo {
        MempoolInfo {
            tx_count: 10_000,
            vsize_limit: 1_000_000,
            vsize_in_use: 950_000,
            min_fee_rate: Some(10),
            max_fee_rate: Some(60),
        }
    }

    fn block_samples(rates: &[u64]) -> Vec<BlockFeeSummary> {
        rates
            .iter()
            .enumerate()
            .map(|(idx, rate)| BlockFeeSummary {
                height: idx as u64,
                median_fee_rate: Some(*rate),
                max_fee_rate: Some(*rate + 2),
            })
            .collect()
    }

    #[test]
    fn override_fee_rate_is_respected() {
        let estimator = FeeEstimator::new(test_config());
        let quote = estimator.resolve(None, Some(8)).expect("override");
        assert_eq!(quote.rate(), 8);
        assert!(matches!(quote.source(), FeeEstimateSource::Override));
    }

    #[test]
    fn override_below_minimum_rejected() {
        let estimator = FeeEstimator::new(test_config());
        let err = estimator.resolve(None, Some(0)).expect_err("below min");
        assert!(matches!(err, FeeError::BelowMinimum { .. }));
    }

    #[test]
    fn low_congestion_samples_produce_moderate_rate() {
        let estimator = FeeEstimator::new(test_config());
        let client = StubNodeClient::default()
            .with_mempool_info(low_congestion_info())
            .with_recent_blocks(block_samples(&[4, 5]));
        let quote = estimator
            .resolve(Some(&client), None)
            .expect("low congestion quote");
        assert_eq!(quote.rate(), 5);
        assert!(matches!(
            quote.source(),
            FeeEstimateSource::Node {
                congestion: FeeCongestionLevel::Low,
                samples: 2
            }
        ));
    }

    #[test]
    fn high_congestion_bumps_rate() {
        let estimator = FeeEstimator::new(test_config());
        let client = StubNodeClient::default()
            .with_mempool_info(high_congestion_info())
            .with_recent_blocks(block_samples(&[18, 20, 22]));
        let quote = estimator
            .resolve(Some(&client), None)
            .expect("high congestion quote");
        assert_eq!(quote.rate(), 60);
        assert!(matches!(
            quote.source(),
            FeeEstimateSource::Node {
                congestion: FeeCongestionLevel::High,
                samples: 3
            }
        ));
    }

    #[test]
    fn missing_samples_fall_back_to_config() {
        let estimator = FeeEstimator::new(test_config());
        let client = StubNodeClient::default()
            .with_mempool_info(MempoolInfo {
                tx_count: 0,
                vsize_limit: 0,
                vsize_in_use: 0,
                min_fee_rate: None,
                max_fee_rate: None,
            })
            .with_recent_blocks(Vec::new());
        let quote = estimator
            .resolve(Some(&client), None)
            .expect("fallback quote");
        assert_eq!(quote.rate(), estimator.config().default_sats_per_vbyte);
        assert!(matches!(quote.source(), FeeEstimateSource::ConfigFallback));
    }

    #[test]
    fn propagates_node_errors() {
        struct FailingNode;

        impl NodeClient for FailingNode {
            fn submit_tx(&self, _draft: &DraftTransaction) -> Result<(), NodeClientError> {
                Ok(())
            }

            fn submit_raw_tx(&self, _tx: &[u8]) -> Result<(), NodeClientError> {
                Ok(())
            }

            fn estimate_fee(&self, _confirmation_target: u16) -> Result<u64, NodeClientError> {
                Ok(1)
            }

            fn chain_head(&self) -> Result<ChainHead, NodeClientError> {
                Ok(ChainHead::new(0, [0u8; 32]))
            }

            fn mempool_status(
                &self,
            ) -> Result<crate::runtime::node::MempoolStatus, NodeClientError> {
                Err(NodeClientError::network(anyhow!("boom")))
            }

            fn mempool_info(&self) -> Result<MempoolInfo, NodeClientError> {
                Err(NodeClientError::network(anyhow!("boom")))
            }

            fn recent_blocks(
                &self,
                _limit: usize,
            ) -> Result<Vec<BlockFeeSummary>, NodeClientError> {
                Err(NodeClientError::network(anyhow!("boom")))
            }
        }

        let estimator = FeeEstimator::new(test_config());
        let err = estimator
            .resolve(Some(&FailingNode), None)
            .expect_err("node failure");
        assert!(matches!(err, FeeError::Node(_)));
    }
}
