use crate::errors::ChainError;

pub use rpp_wallet_interface::runtime_config::{
    WalletIdentity, WalletRole, WalletRoleSet, WalletSecurityBinding,
};
pub use rpp_wallet_interface::runtime_wallet::{
    WalletClientCertificates, WalletRbacStore, WalletSecurityContext, WalletSecurityError,
    WalletSecurityPaths, WalletSecurityResult,
};

impl From<WalletSecurityError> for ChainError {
    fn from(err: WalletSecurityError) -> Self {
        ChainError::Config(err.to_string())
    }
}
