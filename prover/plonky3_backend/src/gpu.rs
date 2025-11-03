#![allow(dead_code)]

use gpu_alloc::{Request, UsageFlags};
use gpu_descriptor::DescriptorAllocator;

/// Lightweight helpers for initializing GPU acceleration plumbing when the
/// `plonky3-gpu` feature is enabled.
pub struct GpuResources {
    descriptor_allocator: DescriptorAllocator<(), ()>,
    warmup_request: Request,
}

impl GpuResources {
    /// Construct a GPU helper bundle with empty descriptor caches. The
    /// resources are intentionally minimal so CPU-only builds are unaffected
    /// while feature-enabled builds exercise the GPU dependencies.
    pub fn new() -> Self {
        let descriptor_allocator = DescriptorAllocator::<(), ()>::new(0);
        let warmup_request = Request {
            size: 0,
            align_mask: 0,
            usage: UsageFlags::empty(),
            memory_types: 0,
        };
        Self {
            descriptor_allocator,
            warmup_request,
        }
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
