# Config template catalog

## Network admission

| Template | Setting | Default | Description |
| --- | --- | --- | --- |
| `config/node.toml` | `network.admission.policy_path` | `./data/p2p/admission_policies.json` | Persists the allowlist/blocklist snapshot that the peerstore reloads on startup. |
| `config/node.toml` | `network.admission.audit_retention_days` | `30` | Retention window for admission audit telemetry before operators rotate logs. |
| `config/node.toml` | `network.admission.defaults.<topic>.{subscribe,publish}` | Varies per topic | Seeds tier requirements for gossip topics when no admission metadata exists yet. |
| `config/hybrid.toml` | `network.admission.policy_path` | `./data/p2p/admission_policies.json` | Shares the same admission snapshot path as the standalone node template. |
| `config/validator.toml` | `network.admission.policy_path` | `./data/p2p/admission_policies.json` | Persists validator admission policies alongside the peerstore state. |

The default tier assignments mirror the runtime metadata shipped with the node identity:
blocks and votes publish at tier 3, proofs and snapshots at tier 1, VRF proofs at tier 2,
meta channels at tier 0 or 1, and witness traffic at tier 2. Operators can override any
entry by editing the per-topic `subscribe` or `publish` values.
