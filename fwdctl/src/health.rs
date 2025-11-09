use std::{
    env::{self, VarError},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    thread,
};

use axum::{http::StatusCode, routing::get, Router};
use tokio::runtime::Runtime;

const DEFAULT_PORT: u16 = 8080;
const PORT_ENV: &str = "FWDCTL_HEALTH_PORT";

pub fn spawn_health_server() {
    let port = match env::var(PORT_ENV) {
        Ok(raw) => match raw.trim() {
            "" => DEFAULT_PORT,
            value => match value.parse::<u16>() {
                Ok(port) => port,
                Err(error) => {
                    log::warn!(
                        "Invalid {PORT_ENV} value '{value}': {error}. Falling back to default port {DEFAULT_PORT}."
                    );
                    DEFAULT_PORT
                }
            },
        },
        Err(VarError::NotPresent) => DEFAULT_PORT,
        Err(error) => {
            log::warn!(
                "Failed to read {PORT_ENV}: {error}. Falling back to default port {DEFAULT_PORT}."
            );
            DEFAULT_PORT
        }
    };

    if port == 0 {
        log::info!("Health server disabled because {PORT_ENV} is set to 0");
        return;
    }

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);

    if let Err(error) = thread::Builder::new()
        .name("fwdctl-health".to_string())
        .spawn(move || {
            let runtime = match Runtime::new() {
                Ok(runtime) => runtime,
                Err(error) => {
                    log::error!("Failed to construct Tokio runtime for health server: {error}");
                    return;
                }
            };

            runtime.block_on(async {
                let app = Router::new()
                    .route("/health/live", get(|| async { StatusCode::OK }))
                    .route("/health/ready", get(|| async { StatusCode::OK }));

                log::info!("Starting fwdctl health server on {addr}");

                if let Err(error) = axum::Server::bind(&addr)
                    .serve(app.into_make_service())
                    .await
                {
                    log::error!("Health server terminated with error: {error}");
                }
            });
        })
    {
        log::error!("Failed to spawn health server thread: {error}");
    }
}
