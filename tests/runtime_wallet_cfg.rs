#![cfg(test)]

#[cfg(feature = "wallet-integration")]
#[test]
fn wallet_runtime_exposes_service_types() {
    use rpp_chain::runtime::wallet::runtime::{GenericWalletRuntimeHandle, WalletRuntime};
    use rpp_wallet_interface::WalletService;

    fn assert_handle_type<W: WalletService>() {
        let _: Option<GenericWalletRuntimeHandle<W>> = None;
    }

    // Compile-time verification that the runtime exposes the generic handle when the
    // wallet integration feature is enabled.
    assert_handle_type::<rpp_wallet::wallet::Wallet>();

    // Ensure the runtime type itself is reachable.
    let _ = WalletRuntime {};
}

#[cfg(not(feature = "wallet-integration"))]
#[test]
fn wallet_security_types_available_without_wallet_module() {
    use rpp_chain::runtime::wallet_security::{WalletIdentity, WalletRole, WalletRoleSet};

    let identity = WalletIdentity::from_bearer_token("runtime-wallet-cfg");
    let mut roles = WalletRoleSet::new();
    roles.insert(WalletRole::Viewer);
    assert!(matches!(identity, WalletIdentity::Token(_)));
    assert_eq!(roles.len(), 1);
}
