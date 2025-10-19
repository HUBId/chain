use std::{convert::Infallible, marker::PhantomData};

use crate::NetworkBehaviour;

use super::*;
use crate::builder::SwarmBuilder;

pub struct BehaviourPhase<T> {
    pub(crate) transport: T,
}

impl<T, Provider> SwarmBuilder<Provider, BehaviourPhase<T>> {
    pub fn with_behaviour<B, R: TryIntoBehaviour<B>>(
        self,
        constructor: impl FnOnce(&libp2p_identity::Keypair) -> R,
    ) -> Result<SwarmBuilder<Provider, SwarmPhase<T, B>>, R::Error> {
        Ok(SwarmBuilder {
            phase: SwarmPhase {
                behaviour: constructor(&self.keypair).try_into_behaviour()?,
                transport: self.phase.transport,
            },
            keypair: self.keypair,
            phantom: PhantomData,
        })
    }
}

pub trait TryIntoBehaviour<B>: private::Sealed<Self::Error> {
    type Error;

    fn try_into_behaviour(self) -> Result<B, Self::Error>;
}

impl<B> TryIntoBehaviour<B> for B
where
    B: NetworkBehaviour,
{
    type Error = Infallible;

    fn try_into_behaviour(self) -> Result<B, Self::Error> {
        Ok(self)
    }
}

impl<B> TryIntoBehaviour<B> for Result<B, Box<dyn std::error::Error + Send + Sync>>
where
    B: NetworkBehaviour,
{
    type Error = BehaviourError;

    fn try_into_behaviour(self) -> Result<B, Self::Error> {
        self.map_err(BehaviourError)
    }
}

mod private {
    pub trait Sealed<Error> {}
}

impl<B: NetworkBehaviour> private::Sealed<Infallible> for B {}

impl<B: NetworkBehaviour> private::Sealed<BehaviourError>
    for Result<B, Box<dyn std::error::Error + Send + Sync>>
{
}

#[derive(Debug, thiserror::Error)]
#[error("failed to build behaviour: {0}")]
pub struct BehaviourError(Box<dyn std::error::Error + Send + Sync + 'static>);
