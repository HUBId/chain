# Upstream dependency alignment

The authoritative [`ffi/Cargo.toml`](https://github.com/ava-labs/chain/blob/master/ffi/Cargo.toml)
defines the dependency surface for Firewood's FFI crate. As of the latest
sync, the expected versions/features for dependencies we mirror locally are:

- `chrono = "0.4.42"` (regular dependency)
- `oxhttp = "0.3.1"` (regular dependency)
- `tikv-jemallocator = "0.6.0"` (Unix-only optional dependency)
- `cbindgen = "0.29.0"` (build dependency)

This file exists so maintainers can confirm we remain aligned with upstream
when bumping local crates or regenerating `Cargo.lock`.
