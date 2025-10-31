# Troubleshooting MSRV build errors

When a crate fails to compile with an error similar to `requires rustc 1.8x+`,
follow these steps to restore compatibility with the project MSRV (1.83.0).

## 1. Confirm the toolchain

Run `rustc --version` or `cargo +1.83.0 build` to ensure the pinned toolchain is
active. If the error appears while using a different compiler, switch back to
`1.83.0` and re-run the build.

## 2. Check dependency metadata

Inspect the failing crate's `Cargo.toml` (or crates.io page) for a `rust-version`
field. If it now requires a newer compiler, look for an older patch release that
remains compatible. Update `Cargo.toml` to pin that version and add it to
[`docs/msrv_pins.md`](./msrv_pins.md) if the crate is part of the critical path.

## 3. Evaluate feature usage

Some MSRV bumps are triggered by enabling new default features. Try rebuilding
with explicit feature selections:

```sh
cargo +1.83.0 build --no-default-features
cargo +1.83.0 build --features "<subset>"
```

Adjust the crate's feature flags in the workspace if you can disable the
problematic capability without blocking required functionality.

## 4. Coordinate with release engineering

If the dependency cannot be downgraded or configured to build on 1.83.0, open an
issue or pull request describing the blocker. Include:

- The full compiler error
- Links to upstream release notes or issues referencing the MSRV change
- Proposed mitigation (fork, patch, or compiler upgrade request)

The release engineering team will decide whether to carry a patch, pin an older
version, or schedule an MSRV review.
