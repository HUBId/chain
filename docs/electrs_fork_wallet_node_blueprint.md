# Electrs-Fork Wallet/Node Blueprint

## 1. Motivation

The Digital Value Network fork extends Electrum/Electrs principles to the RPP blockchain, keeping the stack lightweight while wiring in sovereign identity and recursive proofs. The existing binary already integrates storage, consensus, RPC and proof plumbing so node and wallet functionality can share the same runtime without external services.【F:README.md†L1-L99】【F:src/main.rs†L1-L160】

## 2. Architekturüberblick

* **Wallet Modul (`rpp/wallet`)** – manages keys, transactions, uptime proofs and exposes tab-oriented view models (`History`, `Send`, `Receive`, `Node`) for CLI/GUI layers to consume.【F:src/wallet/wallet.rs†L25-L347】【F:src/wallet/tabs/mod.rs†L1-L9】
* **Node Modul (`rpp/node`)** – orchestrates Malachite-BFT consensus, mempools, proof verification and telemetry while sharing storage and proof registries with the wallet logic.【F:src/node.rs†L1-L199】
* **Frontend Hooks** – the wallet exposes tab data structures that back an Electrum-style interface: transaction history with proof metadata, send previews, derived receive addresses and node metrics.【F:src/wallet/wallet.rs†L161-L326】
* **Unified RPC** – Axum routes expose JSON-RPC style endpoints for both wallet and node clients, including balance queries, proof submission and consensus introspection.【F:src/api.rs†L63-L200】

## 3. Technische Defaults

* **UTXO-Modell** – the RPP blueprint models explicit UTXO records and witnesses that feed the recursive proof system, keeping compatibility with Electrum’s design expectations.【F:src/rpp.rs†L360-L520】
* **ZSI-ID** – identity genesis binds wallet keys, VRF tags and Merkle proofs, guaranteeing every wallet derives a sovereign identifier during setup.【F:src/types/identity.rs†L13-L173】
* **Proofs via STWO** – the wallet-facing prover derives witnesses for identities, transactions, state, pruning, uptime and consensus directly from local RocksDB state before producing STARK proofs.【F:src/stwo/prover/mod.rs†L1-L200】
* **Storage** – the Firewood fork provides append-only KV, pruning logic and Merkle proofs as the default storage backend for local nodes and wallets.【F:storage-firewood/src/lib.rs†L1-L49】
* **P2P** – a libp2p-inspired stack handles admission control, peer discovery and gossip channels dedicated to blocks, votes, proofs and snapshots.【F:rpp/p2p/src/lib.rs†L1-L13】
* **RPC** – the Axum server exposes health, balance, proof submission and consensus telemetry endpoints consumable by light clients.【F:src/api.rs†L63-L200】

## 4. Moduldesign

### `wallet/`

* **Key-Management** – wraps Ed25519 keypairs, derives wallet addresses and signs transactions; hooks for HSM/Yubi integration plug into the `sign_message` abstraction.【F:src/wallet/wallet.rs†L57-L191】
* **ZSI-Setup** – constructs identity declarations with VRF tags and Merkle proofs, verifying commitments before broadcasting.【F:src/wallet/wallet.rs†L75-L116】
* **Tx-Engine** – handles nonce management, balance checks, signature creation and STWO proof bundling for transactions.【F:src/wallet/wallet.rs†L133-L199】
* **Timetoke** – generates hourly uptime proofs tied to recent block heads and epochs for reputation accrual.【F:src/wallet/wallet.rs†L200-L232】
* **Reputation-Score & API** – surfaces audits, consensus receipts and node metrics for UI or RPC consumption.【F:src/wallet/wallet.rs†L233-L347】
* **UI/CLI Tabs** – dedicated data structures power History, Send, Receive and Node tabs for an Electrum-style interface.【F:src/wallet/tabs/mod.rs†L1-L9】

### `node/`

* **Consensus** – embeds Malachite-backed BFT vote aggregation, quorum tracking and validator classification.【F:src/consensus.rs†L1-L193】
* **Storage** – reuses the shared RocksDB/Firewood-backed storage layer to persist blocks, accounts and metadata.【F:src/node.rs†L171-L199】
* **Proof Verification** – leverages the proof registry to check transaction, identity, pruning, uptime and recursive proofs before import.【F:src/node.rs†L171-L199】【F:src/stwo/prover/mod.rs†L1-L200】
* **Block Builder** – aggregates mempools, computes rewards and emits consensus certificates for every sealed block.【F:src/node.rs†L171-L199】
* **Networking** – integrates the gossip stack for block, vote, proof and snapshot propagation.【F:rpp/p2p/src/lib.rs†L1-L13】【F:src/node.rs†L1-L68】
* **RPC Surface** – the same Axum server serves wallet and node requests, providing balance, reputation, timetoke and block data.【F:src/api.rs†L63-L200】

### `rpc/`

* **Unified API** – JSON endpoints abstract wallet and node functionality: balance lookup, transaction building/proving, uptime submissions, reputation queries and block/state inspection.【F:src/api.rs†L63-L200】

## 5. Node/Wallet Toggle

The `rppd` binary exposes subcommands for node lifecycle (start, keygen, migrate) while wallet workflows link directly against the same library, enabling a single binary distribution for both roles. Library consumers can instantiate the `Wallet` with the same storage the node uses, providing a seamless hybrid runtime.【F:src/main.rs†L16-L160】【F:src/wallet/wallet.rs†L25-L347】【F:src/node.rs†L167-L199】

### Wallet Runtime Configuration

* **`data_dir` & `key_path`** – mirror the node defaults so wallets persist RocksDB state and signing material alongside hybrid deployments.【F:rpp/runtime/config.rs†L500-L527】
* **`rpc_listen`** – binds the unified Axum server for wallet and optional node control APIs.【F:rpp/runtime/config.rs†L487-L516】
* **`[node] embedded`** – toggles an embedded node runtime when the wallet should shoulder consensus duties locally; disabled wallets must supply gossip peers instead.【F:rpp/runtime/config.rs†L491-L546】
* **`[node] gossip_endpoints`** – enumerates gossip peers for client-mode wallets and is validated to be non-empty when the embedded node is off, ensuring the wallet can still sync blocks and proofs.【F:rpp/runtime/config.rs†L530-L545】【F:config/wallet.toml†L1-L28】
* **`[electrs] network`** – maps auf `NetworkSelection` und bestimmt Genesis, Header-Hashes und ScriptHash-Prüfpfad des Trackers.【F:rpp/wallet/src/config.rs†L10-L66】【F:rpp/wallet/src/vendor/electrs/init.rs†L66-L101】
* **`[electrs.features] runtime`** – aktiviert Runtime-Adapter, wodurch der Daemon Firewood und Pipeline-Orchestrator des Knotens verwendet.【F:rpp/wallet/src/config.rs†L46-L88】【F:rpp/wallet/src/vendor/electrs/firewood_adapter.rs†L18-L120】
* **`[electrs.features] tracker`** – bringt den High-Level-Tracker hoch; er verlangt aktiviertes Runtime-Flag und stellt History-, Proof- und VRF-APIs bereit. Die Runtime-Konfiguration validiert diese Abhängigkeit bereits beim Laden.【F:rpp/wallet/src/config.rs†L57-L113】【F:vendor/electrs/2024-05-20/src/tracker.rs†L39-L151】【F:rpp/runtime/config.rs†L563-L568】
* **`data/electrs/*`** – sobald Runtime- oder Tracker-Features aktiv sind, legt der Wallet-Loader die Firewood- und Index-Verzeichnisse unterhalb des Wallet-`data_dir` automatisch an (siehe Beispielkonfiguration).【F:rpp/runtime/config.rs†L552-L578】【F:config/wallet.toml†L9-L34】

### Wallet-Electrs-Initialisierung

Die Wallet-Laufzeit persistiert die Electrs-Konfiguration im lokalen Storage und
bringt Daemon, Firewood-Adapter und Tracker anhand dieser Parameter beim
Starten wieder online.【F:rpp/wallet/ui/wallet.rs†L788-L839】 Über
`Wallet::reload_electrs_handles` wird die gespeicherte Konfiguration geladen und
`initialize` erneut aufgerufen. Der Aufruf erzeugt fehlende Firewood- bzw.
Index-Verzeichnisse, verknüpft Runtime-Adapter (falls aktiviert) und achtet
darauf, dass das Tracker-Feature nur gemeinsam mit dem Runtime-Flag aktiv ist.【F:rpp/wallet/ui/wallet.rs†L821-L839】【F:rpp/wallet/src/vendor/electrs/init.rs†L28-L112】
Das Ergebnis – `ElectrsHandles` – wird im Wallet hinterlegt und löst einen neuen
Tracker-Synchronisations-Task aus, der Gossip-Nachrichten des Runtime-Knotens
und Dashboard-Snapshots aus dem Orchestrator konsumiert.【F:rpp/wallet/ui/wallet.rs†L845-L924】

Während der Initialisierung prüft `initialize`, ob der konfigurierte Gossip-Topic
für Tracker-Benachrichtigungen auch im Daemon freigeschaltet ist; fehlt er,
wird er ergänzt, damit Gossip und Tracker konsistent bleiben.【F:rpp/wallet/src/vendor/electrs/init.rs†L96-L122】
Wallet-Deployments können Topics und Netzwerk-IDs über `[electrs.tracker.notifications]`
und `[electrs.p2p]` anpassen; der Parser weist ungültige Topics ab und setzt
automatisch `/rpp/gossip/blocks/1.0.0`, falls keine Liste angegeben ist.【F:rpp/wallet/src/config.rs†L94-L142】【F:rpp/wallet/src/vendor/electrs/init.rs†L112-L152】

### Runtime-Erwartungen

* **Firewood-Pfade** – `WalletConfig::ensure_directories` legt unterhalb von
  `<data_dir>/electrs/firewood` und `<data_dir>/electrs/index` die benötigten
  Verzeichnisse an, sobald Runtime- oder Tracker-Features eingeschaltet
  werden.【F:rpp/runtime/config.rs†L552-L578】
* **Runtime-Adapter** – der Wallet-Tracker setzt Runtime-Adapter voraus, um
  Firewood-Snapshots zu validieren, Gossip-Topics zu abonnieren und Finality-
  Dashboards auszuwerten.【F:rpp/wallet/src/config.rs†L46-L113】【F:rpp/wallet/src/vendor/electrs/init.rs†L84-L138】
* **Gossip-Topics** – Standard ist `/rpp/gossip/blocks/1.0.0`; zusätzliche
  Topics lassen sich über `[electrs.p2p.gossip_topics]` hinterlegen und werden
  automatisch dedupliziert. Der Tracker kann per `[electrs.tracker.notifications.p2p]`
  Broadcast-Kanäle aktivieren, die wiederum das Abonnement beim Runtime-Knoten
  starten.【F:rpp/wallet/src/config.rs†L94-L142】【F:rpp/wallet/src/vendor/electrs/init.rs†L112-L152】

### Tracker-Metadaten in RPC & UI

Wallet-RPC-Antworten enthalten bei aktivem Electrs-Tracker zusätzliche Felder
für Mempool-Deltas, Skript-Metadaten und Tracker-Snapshots. `WalletBalanceResponse`
liefert `mempool_delta`, History-Antworten erweitern die Nutzlast um
`script_metadata` und `tracker`, sodass Downstream-Clients Status-Digests,
Mempool-Fingerprints und optionale VRF-Audits verarbeiten können.【F:rpp/rpc/interfaces.rs†L268-L311】
Die UI spiegelt dieselben Daten wider: `WalletTrackerHandle` signalisiert, ob
der Tracker bereit ist, und `ScriptStatusMetadata` stellt bestätigte Guthaben,
Mempool-Deltas, Status-Digests sowie (optional) Proof-Envelopes und VRF-Audits
pro Skript bereit.【F:rpp/wallet/ui/wallet.rs†L320-L420】【F:rpp/wallet/ui/wallet.rs†L736-L776】

### Vendor-Feature-Flags

`vendor_electrs` spannt die optionalen Abhängigkeiten für Tracker, Runtime-Adapters
und Firewood über das gesamte Wallet-Crate auf. Ohne das Feature bleiben
Konfiguration, `ElectrsConfig` und die Tracker-Implementierung außen vor; mit dem
Flag landen alle Module unter `rpp_wallet::vendor::electrs::*` im Build.【F:rpp/wallet/Cargo.toml†L8-L27】【F:rpp/wallet/src/lib.rs†L13-L27】

### Bootstrap des Trackers

```rust
use rpp_wallet::config::{
    CacheConfig, ElectrsConfig, FeatureGates, NetworkSelection, P2pConfig, TrackerConfig,
};
use rpp_wallet::vendor::electrs::firewood_adapter::RuntimeAdapters;
use rpp_wallet::vendor::electrs::init::initialize;

let runtime = RuntimeAdapters::new(storage, node_handle, orchestrator, payload_provider, proof_verifier);
let config = ElectrsConfig {
    network: NetworkSelection::Signet,
    features: FeatureGates {
        runtime: true,
        tracker: true,
    },
    cache: CacheConfig::default(),
    tracker: TrackerConfig {
        telemetry_endpoint: "127.0.0.1:0".parse().unwrap(),
        ..TrackerConfig::default()
    },
    p2p: P2pConfig::default(),
};
let handles = initialize(&config, "/var/lib/rpp/wallet/firewood", "/var/lib/rpp/wallet/index", Some(runtime))?;

let tracker = handles.tracker.expect("tracker enabled in config");
let daemon = handles.daemon.expect("runtime enabled in config");
tracker.status()?; // Tracker meldet sich bereit
```

Der Tracker liefert anschließend API-Hilfsfunktionen für Skripthash-Status,
Balance, History-Digests und VRF-Audits.【F:vendor/electrs/2024-05-20/src/tracker.rs†L39-L151】

### Szenario „wallet_tracker_rpp“

Unter `scenarios/wallet_tracker_rpp.toml` liegt ein CLI-Simulator, der Regtest,
Runtime-Adapter und Tracker-Feature gemeinsam aktiviert. Die zugehörige
Integration `vendor_electrs_tracker_scenario` erstellt Blöcke, synchronisiert den
Index, fragt History- und Proof-Metadaten ab und prüft VRF-Audits.【F:scenarios/wallet_tracker_rpp.toml†L1-L20】【F:rpp/wallet/tests/vendor_electrs_tracker_scenario.rs†L1-L239】

**Lokale Validierung:**

```bash
cargo check --manifest-path rpp/wallet/Cargo.toml --features vendor_electrs
cargo test  --manifest-path rpp/wallet/Cargo.toml \
  --features "vendor_electrs backend-rpp-stark" \
  --test vendor_electrs_tracker_scenario
```

Die Tests befüllen Firewood, erzeugen deterministische Witness-Digests und
stellen sicher, dass Proof-Envelopes sowie VRF-Audits für Wallet-Clients
verfügbar sind.【F:rpp/wallet/tests/vendor_electrs_tracker_scenario.rs†L96-L206】
> Hinweis: Beide Kommandos erwarten, dass die `rpp`-Runtime und das `rpp_stark`-
> Backend im Workspace verfügbar sind. Im reinen Firewood-Checkout ohne diese
> Crates schlägt der Build mit fehlenden Abhängigkeiten fehl.

## 6. ZSI-Genesis-Validierung

Wallets derive ZSI IDs by hashing their keys, binding VRF tags to the current epoch and verifying vacant Merkle slots before emitting identity declarations and proofs. Verification enforces zero initial reputation and correct commitments, ensuring every identity enters consensus with a validated profile.【F:src/wallet/wallet.rs†L75-L116】【F:src/types/identity.rs†L50-L173】

## 7. Sicherheit

* **Key-Rotation** – address commitments and Merkle proofs allow rotating keys without breaking identity bindings, enforced during identity verification.【F:src/types/identity.rs†L63-L173】
* **Anti-Replay** – transaction witnesses enforce nonce progression and balance conservation inside the STWO circuits.【F:src/stwo/prover/mod.rs†L93-L178】
* **Sandbox-Prover** – wallet proof generation operates entirely on local RocksDB state with deterministic circuits, enabling offline proving workflows.【F:src/stwo/prover/mod.rs†L42-L200】
* **Fail-Safe** – signatures can be produced independently of proof generation; proofs are bundled afterwards via the prover hooks.【F:src/wallet/wallet.rs†L188-L199】

## 8. Integration

* **Consensus Promotion** – validator classification pulls reputation tiers and timetoke hours, advancing wallets into validator roles when thresholds are met.【F:src/consensus.rs†L130-L193】
* **Proof Submission** – uptime, identity and transaction proofs flow through dedicated mempools and RPC endpoints, updating reputation and timetoke records.【F:src/node.rs†L171-L199】【F:src/api.rs†L63-L140】
* **P2P Publication** – gossip channels broadcast blocks, votes, proofs and snapshots so wallet-hybrid nodes participate from TL1 upwards.【F:rpp/p2p/src/lib.rs†L1-L13】
* **History Visibility** – wallets reconstruct transaction and reputation history from local blocks, aligning on-chain state with UI displays.【F:src/wallet/wallet.rs†L233-L347】

## 9. Lizenz & Fork

The project inherits Electrs’ MIT-friendly approach, keeping all integrations self-contained within the repository. Storage, consensus, P2P and proof systems are implemented locally without relying on upstream Electrum or Bitcoin binaries.【F:README.md†L1-L99】【F:src/main.rs†L1-L160】

## 10. UI-RPC-Verträge & Tests

* Neue versionierte Wallet-Endpunkte liefern History-, Send-, Receive- und Node-Tab-Verträge unter `/wallet/ui/*`; jede Antwort trägt einen klaren `wallet-ui.*.v1`-Bezeichner, sodass Frontends Schema-Änderungen erkennen.【F:rpp/rpc/api.rs†L1384-L1400】【F:rpp/rpc/api.rs†L1798-L1864】【F:rpp/rpc/interfaces.rs†L294-L339】
* Contract-Tests sichern die JSON-Formate und Versionen der Wallet-Tabs ab und verhindern Regressionen beim Serialisieren.【F:rpp/rpc/tests/wallet_ui_contract.rs†L1-L124】
* Die Validator-UI erhält eine Wallet-Navigation mit Tabs für History, Send, Receive und Node, inklusive Snapshot- sowie Interaktionstest zum Abdecken der Grundfunktionen.【F:validator-ui/src/components/WalletTabs.tsx†L1-L260】【F:validator-ui/src/components/__tests__/WalletTabs.test.tsx†L1-L116】

## 11. Ergebnis

* ✅ Electrum-inspirierte Wallet- und Full-Node-Funktionalität teilen sich Bibliotheken und Speicher, was hybride Deployments ermöglicht.【F:src/wallet/wallet.rs†L25-L347】【F:src/node.rs†L167-L199】
* ✅ Proofs, Reputation und ZSI sind vollständig integriert und lokal verifizierbar.【F:src/stwo/prover/mod.rs†L1-L200】【F:src/types/identity.rs†L50-L173】【F:src/consensus.rs†L130-L193】
* ✅ Konsensus, Storage, P2P und RPC laufen ohne externe Abhängigkeiten innerhalb der Fork.【F:src/node.rs†L1-L199】【F:rpp/p2p/src/lib.rs†L1-L13】【F:storage-firewood/src/lib.rs†L1-L49】
* ✅ Produktionsreife Grundlage für RPP: Konfiguration, Schlüsselmanagement, Migration und API werden vom selben Binary bedient.【F:src/main.rs†L16-L160】【F:README.md†L32-L99】

## 12. Blueprint-Status

| Blueprint Item    | Status |
| ----------------- | ------ |
| electrs.ui_rpc    | Done   |
