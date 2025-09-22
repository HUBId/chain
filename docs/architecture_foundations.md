# Architekturgrundlagen

## 1. Aktueller Funktionsumfang

### 1.1 Node-Laufzeit und Konsens
- Der Node verwaltet Schlüsselmaterial, Ledger-State und mehrere Mempools (Transaktionen, Identitäten, Uptime-, VRF- und BFT-Votes) innerhalb von `NodeInner` und stellt Laufzeitmetriken für Statusabfragen bereit.【F:src/node.rs†L167-L199】【F:src/node.rs†L56-L156】
- Konsensabhängige Strukturen wie `BftVote`, `SignedBftVote`, `ConsensusCertificate` sowie Stake-/Reputationsgewichtung für Validatoren sind vorhanden und nutzen Malachite für präzise Arithmetik und Tier-Filterung.【F:src/consensus.rs†L20-L200】

### 1.2 Wallet- und Proof-Workflow
- Die Wallet kapselt Key-Management, Transaktionsaufbau, Signaturen und STWO-basierte Beweisführung (`WalletProver`) inklusive Identitäts-, Transaktions-, State- und Pruning-Zeugen aus dem lokalen Storage.【F:src/wallet/wallet.rs†L24-L128】【F:src/stwo/prover/mod.rs†L17-L136】
- Für Identitäten, Transaktionen und Uptime existieren strukturierte Typen mit Commitment-Bildung und Verifikationslogik, wodurch ZSI-Zusicherungen und Anti-Replay-Prüfungen möglich werden.【F:src/types/identity.rs†L13-L173】【F:src/types/transaction.rs†L15-L95】【F:src/types/uptime.rs†L10-L113】

### 1.3 Storage, Proofs und APIs
- Blocks, Accounts und Metadaten werden in RocksDB persistiert; Block-Header tragen State- und Proof-Wurzeln sowie VRF-Metadaten für die Rekonstruktion des Verlaufs.【F:README.md†L7-L18】【F:src/types/block.rs†L32-L118】
- Bündelstrukturen für Transaktions- und Blockbeweise abstrahieren das zugrundeliegende Backend (`ChainProof`), sodass STWO (und optional Plonky3) eingebettet werden können.【F:src/types/proofs.rs†L11-L94】
- Das Axum-basierte HTTP-Interface exponiert Status- und Submit-Endpunkte für Node- und Wallet-Funktionen, einschließlich Mempool-, Konsens- und Uptime-Routen.【F:src/api.rs†L12-L200】

## 2. Zielartefakte für Blueprint-Komponenten

| Blueprint-Bereich | Zielartefakte | Abhängigkeiten |
| --- | --- | --- |
| Firewood ↔ STWO (2.1) | Versionierte APIs `apply_block`, `prove_transition`, `verify_transition`; Protokoll der Root-Historie und Pruning-Belege je Block | Storage-Schicht, STWO-Prover, Ledger-State |
| Wallet + STWO + ZSI (2.2) | UTXO-orientierter Wallet-State, Tier-basierte Policies, ZSI-Attestierungsflow mit Genesis-/BFT-Bestätigung, periodische Uptime-Beweis-Pipeline | Wallet-Service, STWO-Circuits, Reputation |
| Libp2p Backbone (2.3) | Noise-XX Handshake, Peerstore, GossipSub-Kanäle (`blocks`, `votes`, `proofs`, `snapshots`, `meta`), Admission-Control nach Tier-Level | Netzwerk-Stack, Reputation, VRF |
| VRF Validator-Selektion (2.4) | Poseidon-VRF mit verifizierbarem Proof-Format, Epoch-Manager, Gossip-Distribution der VRF-Outputs, Monitoring-Metriken | VRF-Modul, Ledger, Gossip |
| Malachite BFT & Slashing (2.5) | Mehrknoten-BFT-Laufzeit (Proposal/PreVote/PreCommit), Evidence-Pool, Slashing-Logik mit Rewards, Replay-Schutz | Konsensmodul, Networking, Reputation |
| Electrs Binary & UI (2.6) | Differenzierte Node-/Wallet-/Hybrid-Modi, UI-/RPC-Tabs (History, Send, Receive, Node, Reputation), Validator-spezifische Betriebsmodi | CLI/HTTP-Schicht, Wallet, Node |
| End-to-End Lifecycle (Kap. 3) | Orchestrierte Pipeline vom Wallet-Gossip über Blockproduktion bis zu Light-Client-Sync, inklusive Snapshot-/Proof-APIs | Alle obigen Module |
| Test & Validierung (Kap. 4) | Unit- & Integrationstest-Suiten für STWO, Firewood, VRF, BFT; Simulationsframework für 100 Wallets/20 Validatoren | Testing-Infrastruktur, Observability |

## 3. Nachrichten- und Schnittstellenspezifikation

### 3.1 Datenformate
- **Transaction**: Enthält Absender, Empfänger, Betrag, Fee, Nonce, optionales Memo und Timestamp; Hash und kanonische Bytes basieren auf JSON-Encoding.【F:src/types/transaction.rs†L15-L56】
- **SignedTransaction**: Bindet die Transaktion an eine Ed25519-Signatur samt öffentlichem Schlüssel und UUID, inklusive Verifikationsroutine.【F:src/types/transaction.rs†L59-L95】
- **IdentityDeclaration**: Kombination aus `IdentityGenesis` (PK, VRF-Tag, State-/Identity-Root, Commitment-Proof) und `IdentityProof` (Commitment + ChainProof).【F:src/types/identity.rs†L13-L48】
- **BlockHeader**: Trägt Höhenangabe, Hash des Vorgängers, Wurzeln für Transaktionen/State/UTXO/Reputation/Timetoke/ZSI/Proofs sowie VRF-Schlüssel, VRF-Proof und Proposer-Metadaten.【F:src/types/block.rs†L32-L118】
- **BlockProofBundle**: Aggregiert Transaktions-, State-, Pruning- und Recursive-Proofs und kapselt Backend-spezifische Artefakte über `ChainProof`.【F:src/types/proofs.rs†L11-L94】
- **UptimeProof**: Speichert Commitment über Online-Fenster, optionale Meta-Daten (Node-Uhr, Epoch, Head-Hash) und den ZK-Proof.【F:src/types/uptime.rs†L10-L113】

### 3.2 Zustands- & Service-Schnittstellen
- **ProofProver / WalletProver**: Liefert Zeugen für Identität, Transaktion, State, Pruning und Uptime über lokale Storage-Snapshots, inklusive Reputation-Gewichtung und Tier-Schwellen.【F:src/stwo/prover/mod.rs†L17-L136】
- **NodeHandle**: Bietet Status- und Submit-Methoden für Transaktionen, Identitäten, Votes und Uptime-Proofs und dient als API-Backbone für das HTTP-Interface.【F:src/node.rs†L167-L199】【F:src/api.rs†L15-L200】
- **Consensus-Zertifikate & Votes**: Definieren Nachrichtenbytes für PreVote/PreCommit, Hashing- und Verifikationspfade für Ed25519-gestützte Signaturen sowie Aggregationsmetriken.【F:src/consensus.rs†L20-L112】

## 4. Nächste Schritte für Architekturangleichung
1. Ableitung von Sequenzdiagrammen für die bestehenden Pfade (Wallet → Node → Storage/Proof) als Referenz für spätere Netzwerk-Erweiterungen.
2. Definition eines Domain-Modell-Diagramms, das Ledger-, Reputation-, Proof- und Gossip-Komponenten samt Datenflüssen visualisiert.
3. Ergänzung eines Schnittstellenkatalogs, der die noch offenen Services (Libp2p, VRF-Distribution, Light-Client-Sync) mit Verantwortlichkeiten, Inputs/Outputs und geplanten Zustandsabhängigkeiten beschreibt.
