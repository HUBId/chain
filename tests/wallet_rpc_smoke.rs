use std::sync::Arc;

use http::StatusCode;

use rpp_chain::runtime::telemetry::metrics::{RuntimeMetrics, WalletRpcMethod};
use rpp_chain::runtime::wallet::rpc::{
    AuthToken, AuthenticatedRpcHandler, RpcInvocation, RpcRequest, StaticAuthenticator,
};

#[test]
fn wallet_rpc_requires_authentication() {
    let metrics = RuntimeMetrics::noop();
    let handler = AuthenticatedRpcHandler::new(
        StaticAuthenticator::new(Some(AuthToken::new("secret-token"))),
        |invocation: RpcInvocation<'_, ()>| {
            assert_eq!(invocation.request.bearer_token, Some("secret-token"));
            "ok".to_string()
        },
        Arc::clone(&metrics),
        WalletRpcMethod::RuntimeStatus,
        None,
    );

    let err = handler
        .call(RpcInvocation {
            request: RpcRequest { bearer_token: None },
            payload: (),
        })
        .expect_err("missing auth should fail");
    assert_eq!(err.status(), StatusCode::UNAUTHORIZED);

    let ok = handler
        .call(RpcInvocation {
            request: RpcRequest {
                bearer_token: Some("secret-token"),
            },
            payload: (),
        })
        .expect("authenticated call succeeds");
    assert_eq!(ok, "ok");
}
