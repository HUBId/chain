# Wallet operations and troubleshooting

This guide summarizes the wallet workflows exercised by the end-to-end tests and
provides operator hints for common actions.

## Account creation and funding
- Use the wallet CLI or SDK to derive fresh external addresses for incoming
  funds. Addresses are derived deterministically from the root seed; restoring
  from backup recreates the same sequence.
- The wallet sync loop scans from the recorded birthday height. If incoming
  funds are missing, verify the birthday is not ahead of the funding block.
- Gap limits are enforced separately for external and change chains. Advance the
  gap by generating addresses instead of reusing the same one repeatedly.

## Drafting and submitting transactions
- Drafts lock selected inputs until they are signed or explicitly aborted. This
  prevents nonce/lock reuse across concurrent submissions.
- Fees are computed from the confirmed inputs minus outputs; the tests assert
  that the fee recorded in the draft matches this delta before and after
  restarts.
- When broadcasting, the wallet releases locks regardless of success. If the
  node rejects a transaction (for example, because of an invalid signature), the
  lock table is cleared so the inputs can be retried.

## Handling restarts
- Wallet state (UTXOs, locks, policy config, and prover metadata) lives on disk
  alongside the keystore. Restarting the wallet with the same data directory is
  sufficient to continue signing and tracking pending transactions.
- After a restart, allow the sync loop to rescan from the last known tip before
  issuing new drafts. This ensures fee estimates, nonces, and balances are
  aligned with the node and indexer state.

## Common errors
- **Insufficient funds**: The wallet will refuse to create a draft if the
  requested amount plus fees exceeds the available balance. Reduce the amount or
  wait for additional confirmations.
- **Invalid signature or node rejection**: The node may reject submissions with
  signature or policy errors. Re-run the draft with updated fee rates or verify
  the signing configuration (hardware, multisig scope, or RPC permissions).

## Test execution
- End-to-end wallet coverage lives under `tests/wallet_e2e/` and is enabled via
  the `wallet-integration` feature. CI invokes the suite with the
  `wallet_e2e` integration test target to ensure signing, fee accounting, and
  error handling remain stable across restarts and backends.
