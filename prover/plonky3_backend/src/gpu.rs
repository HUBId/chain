#![allow(dead_code)]

use gpu_alloc::{Request, UsageFlags};
use gpu_descriptor::DescriptorAllocator;
use once_cell::sync::OnceLock;
use std::{env, fmt};

/// Environment flag that operators can use to force CPU execution even when
/// the backend was configured for GPU proving.
pub const GPU_DISABLE_ENV: &str = "PLONKY3_GPU_DISABLE";

/// Lightweight helpers for initializing GPU acceleration plumbing when the
/// `plonky3-gpu` feature is enabled.
pub struct GpuResources {
    descriptor_allocator: DescriptorAllocator<(), ()>,
    warmup_request: Request,
}

static GPU_RESOURCES: OnceLock<GpuResources> = OnceLock::new();

impl fmt::Debug for GpuResources {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GpuResources").finish()
    }
}

impl GpuResources {
    fn initialize() -> Result<GpuResources, String> {
        let descriptor_allocator = DescriptorAllocator::<(), ()>::new(0);
        let warmup_request = Request {
            size: 0,
            align_mask: 0,
            usage: UsageFlags::empty(),
            memory_types: 0,
        };
        Ok(GpuResources {
            descriptor_allocator,
            warmup_request,
        })
    }

    /// Returns `true` when GPU execution has been disabled via the
    /// [`GPU_DISABLE_ENV`] environment variable.
    pub fn disabled_via_env() -> bool {
        match env::var(GPU_DISABLE_ENV) {
            Ok(value) => {
                let normalized = value.trim().to_ascii_lowercase();
                matches!(
                    normalized.as_str(),
                    "1" | "true" | "yes" | "on" | "enable" | "enabled"
                )
            }
            Err(env::VarError::NotUnicode(_)) => true,
            Err(env::VarError::NotPresent) => false,
        }
    }

    /// Returns a global reference to the lazily initialised GPU helper bundle.
    ///
    /// The resource initialisation is intentionally lightweight so that CPU-only
    /// builds remain unaffected while feature-enabled builds exercise the GPU
    /// dependencies. Callers are expected to guard initialisation behind
    /// [`Self::disabled_via_env`] checks so operators can force CPU execution
    /// when troubleshooting.
    pub fn acquire() -> Result<&'static GpuResources, String> {
        if Self::disabled_via_env() {
            return Err(format!("GPU disabled via {GPU_DISABLE_ENV}"));
        }
        GPU_RESOURCES
            .get_or_try_init(Self::initialize)
            .map_err(|err| err)
    }

    /// Return a reference to the descriptor allocator used for staging GPU
    /// descriptor sets. Tests can use this to ensure GPU pathways are available.
    pub fn descriptor_allocator(&self) -> &DescriptorAllocator<(), ()> {
        &self.descriptor_allocator
    }

    /// Return the warmup allocation request that callers can feed into backend
    /// builders when testing GPU probing flows.
    pub fn warmup_request(&self) -> &Request {
        &self.warmup_request
    }
}
