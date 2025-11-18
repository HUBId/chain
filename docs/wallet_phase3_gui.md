# Wallet Phase 3 – Graphical User Interface

> **Phase navigation:** Previous phase: [Wallet Phase 2 – Policies & Prover Guide](wallet_phase2_policies_prover.md) · Next
> phase: [Wallet Phase 4 – Advanced Operations](wallet_phase4_advanced.md) · [Wallet documentation index](README.md#wallet-documentation-index)
>
> **Sections:** [Policies](#policies) · [GUI](#gui) · [Backup](#backup) · [Security](#security)

Phase 3 introduces the optional `wallet_gui` feature flag that builds an iced-based
multi-tab desktop experience on top of the existing wallet runtime. This guide
covers the architecture, screen flows, error handling, security affordances, and
telemetry emitted by the GUI layer.

## Policies

The GUI mirrors the policies and prover workflows introduced in [Phase 2](wallet_phase2_policies_prover.md). Keep policy statements, fee estimator defaults, and pending lock lifecycle healthy before launching the GUI so the UI renders the same enforcement diagnostics as the CLI. Operators should continue to update policy statements via `rpp-wallet policy set` or the RPC, then reload the GUI to pick up the changes after the runtime restarts.

## GUI

### Architecture overview

The GUI follows a **Model–View–Update (MVU)** architecture inspired by Elm:

* **Model** – Pure data describing the current wallet state and tab-specific
  projections (balances, transaction drafts, prover queue, etc.). Models are
  serialisable for unit tests and future state-sync integration.
* **View** – Declarative widget trees produced from the model. Each tab renders a
  `fn view(&self, model: &Model) -> Element<Message>` tree.
* **Update** – Message-driven reducer that mutates the model in response to
  internal events (button presses) or external signals (RPC responses, prover
  progress).

```
┌──────────────┐     Message      ┌──────────────┐
│  User Input  │ ───────────────▶ │    Update    │
└──────────────┘                  └──────┬───────┘
         ▲                               │
         │         renders Model         │
         │                               ▼
┌────────┴───────┐ ◀──────────────── ┌────────────┐
│     View       │    Element tree   │   Model    │
└────────────────┘                   └────────────┘
```

The runtime service boundary remains the existing JSON-RPC interface. A thin
async layer bridges the iced command queue with RPC calls, converting them into
MVU messages.

### Command pipeline

```
User action ─▶ Message::Submit ─▶ Update reducer
                                     │
                                     ▼
                             Command::perform
                                     │
                                     ▼
                            Wallet RPC request
                                     │
                                     ▼
                                RPC response
                                     │
                                     ▼
                             Message::RpcResult
                                     │
                                     ▼
                                  Update
```

The reducer ensures all RPC side-effects remain deterministic and testable by
keeping them outside the pure model mutation path.

### Tab flows

The GUI exposes three primary tabs. Each tab uses MVU messages scoped to its
state slice while sharing the wallet summary header.

### Overview tab

Displays balances, sync status, and queued operations.

```
participant User
participant OverviewModel
participant RpcClient

User->OverviewModel: Click "Refresh"
OverviewModel->RpcClient: list_balances()
RpcClient-->OverviewModel: Balances + SyncState
OverviewModel->OverviewModel: Update aggregates
OverviewModel->User: Render summary card
```

### Send tab

Guides the operator through drafting and broadcasting transactions with policy
validation.

```
participant User
participant SendModel
participant RpcClient
participant PolicyEngine

User->SendModel: Enter recipient + amount
SendModel->PolicyEngine: validate_draft()
PolicyEngine-->SendModel: Ok | Err(code)
SendModel->RpcClient: quote_fees()
RpcClient-->SendModel: FeeQuote
User->SendModel: Click "Broadcast"
SendModel->RpcClient: submit_transaction()
RpcClient-->SendModel: Txid | Err(code)
SendModel->User: Confirmation / Error banner
```

### Prover tab

Surfaces STWO job queue state and proofs in flight.

```
participant User
participant ProverModel
participant RpcClient
participant ProverWorker

User->ProverModel: Open tab
ProverModel->RpcClient: list_jobs()
RpcClient-->ProverModel: Pending jobs
ProverModel->ProverWorker: subscribe_progress()
ProverWorker-->ProverModel: Progress(events)
ProverModel->User: Update progress table
```

### Error code mapping

The GUI maps JSON-RPC error codes into contextual banners and inline help:

| RPC code | Surface | Message copy | Operator action |
| --- | --- | --- | --- |
| `wallet::errors::InsufficientFunds` | Send tab banner | "Balance too low for amount + fees." | Reduce amount or wait for confirmations. |
| `wallet::errors::PolicyViolation` | Send tab inline validation | "Draft violates policy: {detail}." | Adjust draft or update policy config. |
| `wallet::errors::LockConflict` | Send tab modal | "Inputs locked by {locker}." | Release via CLI or wait for timeout. |
| `wallet::errors::RpcUnavailable` | All tabs toast | "Wallet RPC offline." | Restart runtime or check network. |
| `wallet::errors::ProverTimeout` | Prover tab row badge | "Proof exceeded {timeout}s." | Increase timeout or inspect prover logs. |

Error handling lives in `Message::RpcError` branches so tests can assert the
copy and severity mapping without rendering widgets.

### Telemetry events

The GUI emits the following events via the existing telemetry sink when the
`telemetry` feature is enabled:

| Event | Payload | Trigger |
| --- | --- | --- |
| `wallet.gui.start` | `{ version, feature_flags }` | GUI boot completes. |
| `wallet.gui.tab_switch` | `{ tab_id }` | Operator changes tabs. |
| `wallet.gui.send_attempt` | `{ amount, policy_checks_passed }` | Send draft submitted. |
| `wallet.gui.prover_retry` | `{ job_id, attempt }` | Prover job manual retry. |
| `wallet.gui.error` | `{ code, surface }` | Error banner displayed. |

Telemetry emission functions live alongside MVU updates so tests can assert both
state transitions and instrumentation hooks.

### Quickstart

1. Build the GUI-enabled binary:

   ```bash
   cargo build -p rpp-wallet --features "runtime wallet_gui telemetry"
   ```

2. Launch the runtime with GUI support (from the repository root):

   ```bash
   cargo run -p rpp-wallet --features "runtime wallet_gui" -- gui
   ```

3. Provide a configuration file with the `[wallet.gui]` section described in
   `config/wallet.toml` and ensure the wallet RPC service is reachable.

4. Run GUI unit tests:

   ```bash
   cargo test -p rpp-wallet --features wallet_gui -- ui
   ```

   The `-- ui` filter scopes to iced MVU suites; omit it to run the full
   crate tests.

These steps assume Phase 2 configuration is already in place. See
[`docs/wallet_phase2_policies_prover.md`](wallet_phase2_policies_prover.md) for
runtime prerequisites.

## Security

### Security UX

* **Passphrase prompts** – Unlocking the keystore triggers a modal that requires
  the operator to confirm the action twice (checkbox + passphrase entry).
  Prompts are always foreground modal dialogs to avoid key capture by background
  windows.
* **Clipboard policy** – Copying sensitive values (addresses, txids) uses a
  guarded command that auto-clears the clipboard after 30 seconds when the OS
  supports it. When auto-clear is unavailable, the UI shows a banner reminding
  operators to clear the clipboard manually.
* **Lock screen** – Inactivity for five minutes collapses the window into a
  locked state requiring passphrase re-entry.

## Backup

Backups continue to rely on manual exports (or filesystem snapshots) until you adopt the encrypted rotation schedule described in [Phase 4](wallet_phase4_advanced.md#backuprecovery-formats-and-rotation). GUI builds should still exercise `rpp-wallet backup export` and `restore` from the CLI during change windows so acceptance evidence covers both UX surfaces.

---

> **Phase navigation:** Previous phase: [Wallet Phase 2 – Policies & Prover Guide](wallet_phase2_policies_prover.md) · Next
> phase: [Wallet Phase 4 – Advanced Operations](wallet_phase4_advanced.md) · [Wallet documentation index](README.md#wallet-documentation-index)
