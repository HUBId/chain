# Release Notes

## Block 12

- Raised the minimum supported Rust version (MSRV) to 1.79 and pinned CI tooling to the same compiler to keep builds reproducible.
- Hardened the FFT generator cache to recover deterministically from poisoned mutex states, preventing panics in production flows.

