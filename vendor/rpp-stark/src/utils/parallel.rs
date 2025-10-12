#[cfg(feature = "parallel")]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "parallel")]
static PARALLEL_ENABLED: AtomicBool = AtomicBool::new(true);

const DEFAULT_CHUNK_SIZE: usize = 64;

pub fn preferred_chunk_size(total_items: usize) -> usize {
    if total_items == 0 {
        1
    } else {
        DEFAULT_CHUNK_SIZE.min(total_items.max(1))
    }
}

#[cfg(feature = "parallel")]
pub fn parallelism_enabled() -> bool {
    PARALLEL_ENABLED.load(Ordering::SeqCst)
}

#[cfg(not(feature = "parallel"))]
pub fn parallelism_enabled() -> bool {
    false
}

#[cfg(feature = "parallel")]
pub fn set_parallelism(enabled: bool) -> ParallelismGuard {
    let previous = PARALLEL_ENABLED.swap(enabled, Ordering::SeqCst);
    ParallelismGuard { previous }
}

#[cfg(not(feature = "parallel"))]
pub fn set_parallelism(_enabled: bool) -> ParallelismGuard {
    ParallelismGuard {}
}

pub struct ParallelismGuard {
    #[cfg(feature = "parallel")]
    previous: bool,
}

#[cfg(feature = "parallel")]
impl Drop for ParallelismGuard {
    fn drop(&mut self) {
        PARALLEL_ENABLED.store(self.previous, Ordering::SeqCst);
    }
}

#[cfg(not(feature = "parallel"))]
impl Drop for ParallelismGuard {
    fn drop(&mut self) {}
}
