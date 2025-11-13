# Wallet runtime configuration (phase 1)

This document tracks the initial set of configuration options that the wallet
runtime exposes for early operators. The defaults in `config/wallet.toml` are
safe for local development, but production deployments should review the
following sections:

- `wallet.engine`: controls the engine data directory, keystore bundle path,
  and optional birthday height for partial syncs.
- `wallet.policy`: defines address gap limits and confirmation requirements
  before funds are considered spendable.
- `wallet.fees`: sets minimum/maximum fee rate bounds together with the
  default value used by RPC helpers.
- `wallet.prover`: toggles prover integrations and whether the mock backend is
  allowed when the prover is disabled.

Future phases will expand on these sections with deployment playbooks and
component-specific tuning guidance.
