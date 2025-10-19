use std::sync::{Arc, OnceLock, RwLock};

use crate::{Keypair, PublicKey, SigningError};

/// Hook invoked when signing messages through [`Keypair::sign_with_extensions`].
pub type SignHook = Arc<dyn Fn(&Keypair, &[u8]) -> Option<Result<Vec<u8>, SigningError>> + Send + Sync>;

/// Hook invoked when verifying signatures through [`PublicKey::verify_with_extensions`].
pub type VerifyHook = Arc<dyn Fn(&PublicKey, &[u8], &[u8]) -> Option<bool> + Send + Sync>;

/// Hook invoked when requesting a VRF proof for a message.
pub type VrfSignHook = Arc<dyn Fn(&Keypair, &[u8], &[u8]) -> Option<Vec<u8>> + Send + Sync>;

/// Hook invoked when retrieving the VRF public key associated with an identity.
pub type VrfPublicKeyHook = Arc<dyn Fn(&PublicKey) -> Option<Vec<u8>> + Send + Sync>;

#[derive(Default)]
pub struct IdentityHooks {
    pub sign: Option<SignHook>,
    pub verify: Option<VerifyHook>,
    pub vrf_sign: Option<VrfSignHook>,
    pub vrf_public_key: Option<VrfPublicKeyHook>,
}

impl IdentityHooks {
    pub fn is_empty(&self) -> bool {
        self.sign.is_none()
            && self.verify.is_none()
            && self.vrf_sign.is_none()
            && self.vrf_public_key.is_none()
    }
}

static HOOKS: OnceLock<RwLock<IdentityHooks>> = OnceLock::new();

fn hooks() -> &'static RwLock<IdentityHooks> {
    HOOKS.get_or_init(|| RwLock::new(IdentityHooks::default()))
}

pub fn set_hooks(new_hooks: IdentityHooks) {
    *hooks().write().unwrap() = new_hooks;
}

pub fn clear_hooks() {
    *hooks().write().unwrap() = IdentityHooks::default();
}

pub(crate) fn with_hooks<R>(f: impl FnOnce(&IdentityHooks) -> R) -> R {
    let guard = hooks().read().unwrap();
    f(&*guard)
}

pub(crate) fn try_with_hooks<R>(f: impl FnOnce(&IdentityHooks) -> Option<R>) -> Option<R> {
    let guard = hooks().read().unwrap();
    f(&*guard)
}
