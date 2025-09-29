# Contributing

- Use the repository's pinned `nightly-2024-06-20` toolchain. `rustup` automatically selects it via `rust-toolchain.toml`, so avoid overriding the channel in local configuration.
- Install required nightly components (rustfmt and clippy) through `rustup component add --toolchain nightly-2024-06-20` to keep formatting and linting aligned with CI.
- Run formatting, linting, and test scripts before submitting changes to ensure parity with automation.
