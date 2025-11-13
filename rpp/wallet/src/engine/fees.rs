use crate::config::wallet::WalletFeeConfig;

#[derive(Clone, Debug)]
pub struct FeeEstimator {
    config: WalletFeeConfig,
}

impl FeeEstimator {
    pub fn new(config: WalletFeeConfig) -> Self {
        Self { config }
    }

    pub fn resolve(&self, override_rate: Option<u64>) -> Result<u64, FeeError> {
        let candidate = override_rate.unwrap_or(self.config.default_sats_per_vbyte);
        if candidate < self.config.min_sats_per_vbyte {
            return Err(FeeError::BelowMinimum {
                requested: candidate,
                minimum: self.config.min_sats_per_vbyte,
            });
        }
        if candidate > self.config.max_sats_per_vbyte {
            return Err(FeeError::AboveMaximum {
                requested: candidate,
                maximum: self.config.max_sats_per_vbyte,
            });
        }
        Ok(candidate)
    }

    pub fn config(&self) -> &WalletFeeConfig {
        &self.config
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FeeError {
    #[error("fee rate {requested} sats/vB below minimum {minimum}")]
    BelowMinimum { requested: u64, minimum: u64 },
    #[error("fee rate {requested} sats/vB above maximum {maximum}")]
    AboveMaximum { requested: u64, maximum: u64 },
}

