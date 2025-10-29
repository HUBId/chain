use std::sync::Arc;

use http::StatusCode;

use rpp_chain::runtime::telemetry::metrics::{RuntimeMetrics, WalletRpcMethod};
use rpp_chain::runtime::wallet::rpc::{
    AuthToken, AuthenticatedRpcHandler, RpcRequest, StaticAuthenticator,
};

#[test]
fn wallet_rpc_requires_authentication() {
    let metrics = RuntimeMetrics::noop();
    let handler = AuthenticatedRpcHandler::new(
        StaticAuthenticator::new(Some(AuthToken::new("secret-token"))),
        |request: RpcRequest<'_>| {
            assert_eq!(request.bearer_token, Some("secret-token"));
            "ok".to_string()
        },
        Arc::clone(&metrics),
        WalletRpcMethod::Status,
    );

    let err = handler
        .call(RpcRequest { bearer_token: None })
        .expect_err("missing auth should fail");
    assert_eq!(err.status(), StatusCode::UNAUTHORIZED);

    let ok = handler
        .call(RpcRequest {
            bearer_token: Some("secret-token"),
        })
        .expect("authenticated call succeeds");
    assert_eq!(ok, "ok");
}
