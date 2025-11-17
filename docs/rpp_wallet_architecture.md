# RPP Wallet Architekturplan

## 1. Zielarchitektur (BDK/Electrum-inspiriert, auf RPP angepasst)

```
+-------------------------+           +-----------------------+
|        GUI (iced)       |<--------->|  Wallet RPC Facade    |
|  MVU: Model/Update/View |           |  (auth, rate limit)   |
+-----------^-------------+           +-----------^-----------+
            |                                     |
            v                                     |
+-------------------------+           +-----------|-----------+
|      Wallet Engine      |<--------->|   Node Connector     |
|  - Policies/Fee         |  submit   |  (mempool/chain RPC) |
|  - TxBuilder (UTXO/Acct)|  query    +-----------+----------+
|  - Sign/Prove (STWO)    |                     |
|  - Address/Derivation   |                     |
+-----------+-------------+                     |
            |                                    v
            v                         +-----------------------+
+-------------------------+           |  Chain Client/Indexer |
|       Database          |<--------->|  (Electrum-like, RPP) |
| (Wallet store + cache)  |    sync   |  - scan, filters      |
+-------------------------+           |  - checkpoints        |
                                      +-----------+-----------+
                                                  |
                                                  v
                                    +---------------------------+
                                    |     Node / Storage        |
                                    | (Firewood, P2P, Runtime)  |
                                    +---------------------------+
```

## 2. Modul-Mapping

| Komponente           | Pfad(e)                                                               | Beschreibung |
|----------------------|----------------------------------------------------------------------|--------------|
| Wallet Engine        | `rpp/wallet/src/engine/` (neu: `builder.rs`, `policies.rs`, `signing.rs`, `addresses.rs`, `fees.rs`, `utxo_sel.rs`) | Policies, Tx-Bau, Signing/Proving, Adresslogik |
| Datenbank            | `rpp/wallet/src/db/` (neu) + Firewood-Namespace (`storage-firewood`) | Wallet-State, Cache, Schema |
| Chain Client/Indexer | `rpp/wallet/src/vendor/electrs/*`, `firewood_adapter.rs`, neu: `indexer/client.rs`, `indexer/sync/*` | Electrum-artiger Indexer, Scanner, Checkpoints |
| Node Connector       | `rpp/wallet/src/node_client.rs` (neu) | Chain/Mempool RPC |
| Prover Connector     | `rpp/wallet/src/signing/prover.rs` (bestehende Features) | STWO/Mock Prover-Abstraktion |
| RPC-Fassade          | `rpp/runtime/wallet/rpc/*`, `rpp/wallet/src/rpc/*` | Handler & Client |
| GUI (iced)           | `rpp/wallet/ui/*`, `Cargo.toml` | Desktop-Oberfläche |

## 3. Event-Flows

### 3.1 Initial-/Resume-Sync
- WalletRuntime lädt Keys & DB, liest Checkpoint.
- Indexer-Client synchronisiert Header/Snapshots, filtert relevante Adressen/Outpoints.
- Datenbank aktualisiert Accounts, UTXOs, Tx-Cache und Höhen.
- GUI zeigt Fortschritt, RPC liefert `sync_status`.

### 3.2 Empfang (Adress-Lifecycle)
- Wallet Engine erzeugt Empfangsadresse (descriptor-ähnlich, externe Pfade).
- Indexer überwacht Adressen (Gap-Limit) und persistiert `first_seen`.
- UI zeigt QR/URI, RPC stellt `derive_address(account, change=false)` bereit.

### 3.3 Senden (Policy → Draft → Sign/Prove → Broadcast)
- UI ruft `wallet.preview_send(to, amount, fee_policy)` auf.
- Policy Engine bestimmt Fee/Change/Inputs.
- TxBuilder konstruiert Entwurf (UTXO oder Account-Modus).
- Sign/Prove erstellt Signaturen/Proofs (STWO/Mock), speichert Metadaten.
- Broadcast via Node Connector; DB markiert Inputs pending; UI aktualisiert Status.
- Indexer bestätigt, DB finalisiert und Historie wird aktualisiert.

### 3.4 Recovery/Backup
- Export: Keystore, Deskriptoren, DB-Checksum.
- Import: Mnemonic/Keys, Rescan ab "birthday"/Höhe.

### 3.5 ZSI-Lifecycle
- Hooks (`zsi/*`) in RPC/GUI für Identitätsnachweise und Account-Bindung.

## 4. State-Management (DB-Schema, minimal)

Namespaces (Firewood CFs oder logische Buckets):

- `wallet/meta`: Höhe, Birthday, Gap (extern/intern), letzter Scan.
- `wallet/keys`: Verschlüsselter Seed, XPRV/XPUB, Metadaten.
- `wallet/addr_external`, `wallet/addr_internal`: Adress-Indizes, Status, `first_seen_height`.
- `wallet/utxos`: Outpoints mit Amount, Asset, Script, Spend-Status.
- `wallet/tx_cache`: Raw/Parsed Tx, Richtung, Werte, Fee, Status, Timestamps.
- `wallet/policies`: Fee-Preferences, Mindestbestätigungen, Limits.
- `wallet/zsi`: Proofs und Commitments.
- `wallet/checkpoints`: Sync-Anker und Rescan-Markierungen.

### Modell-APIs (Engine)

- `balance(account, confirmed_only)`
- `list_utxos(filter)`
- `list_txs(range)`
- `derive_address(change)`
- `create_draft(to, amount, policy)`
- `sign_and_prove(draft)`
- `broadcast(tx)`
- `rescan(from_height)`

## 5. Sicherheit

### Key-Management
- Verschlüsselter Keystore (Argon2id + AEAD), zeroize für sensitive Daten.
- Standard: FileKeystore mit Passphrase; optional OS Keychain/HSM-Hooks.

### RPC-Absicherung
- Bearer-Token + methodenspezifische Rate-Limits, optional mTLS.
- "Dangerous ops" benötigen Bestätigung & Rollenprüfung.

### Prover-Isolation
- Async-Jobs mit Timeout, Ressourcenlimits, kein Persistieren großer Witness-Blobs.

### Tx-Policies
- Dust-Limits, Mindestgebühren, Pending-UTXO-Locks, Tier/Timetoke-Limits.

### Supply-Chain
- Saubere Feature-Flags, dokumentierte Build-Pfade, reproduzierbare Builds.

## 6. Konkrete To-Dos (Phase 1)

### 6.1 Engine & Policies
- Neues Modul `rpp/wallet/src/engine/` mit Submodulen für Adressen, Coin Selection, Fees, Builder, Signing.
- `rpp/wallet/src/config.rs` um Policies/Limits erweitern.

### 6.2 Chain Client / Sync
- `rpp/wallet/src/indexer/` mit `client.rs`, `scanner.rs`, `checkpoints.rs`.
- `rpp/runtime/wallet/sync/mod.rs` für deterministisches Sync.
- Vendorisierte Electrs-Komponenten vervollständigen.

### 6.3 Datenbank
- `rpp/wallet/src/db/` mit `schema.rs`, `codec.rs`, `store.rs` und Migration `v1_initial`.

### 6.4 Node/Prover Connector
- `rpp/wallet/src/node_client.rs` für Submit/Head/Fee.
- `rpp/wallet/src/signing/prover.rs` als Trait-Abstraktion.

### 6.5 RPC API
- Handler unter `rpp/runtime/wallet/rpc/*`, Client-Fassade `rpp/wallet/src/rpc/*`.
- Methoden: `get_balance`, `list_utxos`, `list_txs`, `derive_address`, `create_tx`, `sign_tx`, `broadcast`, `policy_preview`, `sync_status`, `zsi_*`.

### 6.6 GUI (iced)
- `rpp/wallet/Cargo.toml`: iced + iced_aw (optional).
- `rpp/wallet/ui/*` finalisieren, Runtime-Bridge.

### 6.7 Sicherheit/Härtung
- `rpp/runtime/wallet/keys.rs`: FileWalletKeyProvider mit verschlüsselten Dateien.
- RPC: Auth-Token + mTLS optional.
- Zeroize & Config-Sanitizing.

### 6.8 Tests & Tooling
- E2E-Tests `rpp/wallet-integration-tests/tests/wallet_workflow_snapshot.rs`, `tests/wallet_sync_resume.rs`.
- Fuzz-Targets erweitern.

## 7. Roadmap (Phasen)

1. **Phase 1 – Minimal Wallet (CLI zuerst)**
   - DB v1, KeyStore, Address-Derivation, Basis-Sync, Balance/UTXO, Fixed-Fee Tx, Mock-Sign.
   - RPC: `get_balance`, `derive_address`, `create_tx`, `sign_tx`, `broadcast`, `sync_status`.
   - E2E-Test: Happy Path.

2. **Phase 2 – Policies & Prover**
   - Fee-Estimator, Coin Selection Strategien, Change-Handling, STWO-Integration, Rescan/Checkpointing.

3. **Phase 3 – GUI (iced)**
   - Dashboard, Send/Receive/History/Node-Status, Progress & Alerts.

4. **Phase 4 – Advanced**
   - ZSI-Flows, Watch-Only, Multisig, Exports, mTLS/RBAC, Hardware-Hooks.

## 8. Kurzbewertung

- BDK liefert Muster für Wallet/Blockchain/DB-Trennung.
- Electrum-Inspiration für Indexing-Client sinnvoll, Firewood-Adapter ausbauen.
- Integration in bestehende RPP Runtime (Wallet-Modus) passend.
- iced-GUI bislang unverknüpft, aber gut planbar.

## 9. Nächste Schritte (Sofort umsetzbar)

- Abhängigkeiten in `rpp/wallet/Cargo.toml` pflegen.
- Engine-Skeleton & Connector-Module anlegen.
- RPC-Methodentabelle definieren und Kernmethoden implementieren.
- Minimaler Indexer-Client & Sync-Status.
- E2E-Test für Basis-Workflow mit Mock-Prover.

## 10. Phasen-Backlog (Zusammenfassung)

### Phase 1 (Minimal Wallet, CLI)
- Struktur- und Trait-Anlage.
- DB-Schema v1.
- Node/Prover Connector Stubs.
- RPC/CLI-Grundfunktionen.
- Tests & Dokumentation.

### Phase 2 (Policies, Fee, Prover)
- Policies & Fees ausbauen.
- STWO-Prover (Feature-gated).
- Pending Locks & Replay-Schutz.
- Erweiterte Rescan/Checkpointing.
- Metriken & CLI-Erweiterungen.

### Phase 3 (GUI)
- iced-App mit Tabs (Dashboard, Send, Receive, History, Node, Settings).
- RPC-basierte Commands & Subscriptions.
- Security UX (Passphrase, Clipboard-Opt-in).
- Tests & Dokumentation.

### Phase 4 (Advanced)
- Backup/Recovery, Watch-Only, Multisig-Hooks, ZSI, mTLS/RBAC, HW-Hooks.
- DB-Migration v3.
- RPC/CLI/GUI-Erweiterungen.
- Telemetrie & Auditing.
- Tests & Dokumentation.

