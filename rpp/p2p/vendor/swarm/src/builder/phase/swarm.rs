#[allow(unused_imports)]
use super::*;

#[allow(unused)] // used below but due to feature flag combinations, clippy gives an unnecessary warning.
const DEFAULT_CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[allow(dead_code)]
pub struct SwarmPhase<T, B> {
    pub(crate) behaviour: B,
    pub(crate) transport: T,
}

macro_rules! impl_with_swarm_config {
    ($providerKebabCase:literal, $providerPascalCase:ty, $config:expr) => {
        #[cfg(feature = $providerKebabCase)]
        impl<T, B> SwarmBuilder<$providerPascalCase, SwarmPhase<T, B>> {
            pub fn with_swarm_config(
                self,
                constructor: impl FnOnce(crate::Config) -> crate::Config,
            ) -> SwarmBuilder<$providerPascalCase, BuildPhase<T, B>> {
                SwarmBuilder {
                    phase: BuildPhase {
                        behaviour: self.phase.behaviour,
                        transport: self.phase.transport,
                        swarm_config: constructor($config),
                        connection_timeout: DEFAULT_CONNECTION_TIMEOUT,
                    },
                    keypair: self.keypair,
                    phantom: std::marker::PhantomData,
                }
            }

            // Shortcuts
            pub fn build(self) -> crate::Swarm<B>
            where
                B: crate::NetworkBehaviour,
                T: AuthenticatedMultiplexedTransport,
            {
                self.with_swarm_config(std::convert::identity).build()
            }
        }
    };
}

#[cfg(not(target_arch = "wasm32"))]
impl_with_swarm_config!(
    "tokio",
    super::provider::Tokio,
    crate::Config::with_tokio_executor()
);

