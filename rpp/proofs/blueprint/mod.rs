use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SectionId {
    Architecture,
    FirewoodStwo,
    WalletWorkflows,
    Libp2p,
    Vrf,
    Bft,
    Electrs,
    BlockLifecycle,
    Testing,
}

impl fmt::Display for SectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            SectionId::Architecture => "architecture",
            SectionId::FirewoodStwo => "firewood-stwo",
            SectionId::WalletWorkflows => "wallet-workflows",
            SectionId::Libp2p => "libp2p",
            SectionId::Vrf => "vrf",
            SectionId::Bft => "bft",
            SectionId::Electrs => "electrs",
            SectionId::BlockLifecycle => "block-lifecycle",
            SectionId::Testing => "testing",
        };
        write!(f, "{}", name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Todo,
    InProgress,
    Done,
}

impl TaskStatus {
    pub fn is_done(self) -> bool {
        matches!(self, TaskStatus::Done)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub key: &'static str,
    pub title: &'static str,
    pub detail: &'static str,
    pub status: TaskStatus,
}

impl Task {
    pub fn mark_status(&mut self, status: TaskStatus) {
        self.status = status;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub id: SectionId,
    pub title: &'static str,
    pub description: &'static str,
    pub tasks: Vec<Task>,
}

impl Section {
    pub fn pending_tasks(&self) -> impl Iterator<Item = &Task> {
        self.tasks.iter().filter(|task| !task.status.is_done())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blueprint {
    sections: Vec<Section>,
}

impl Blueprint {
    pub fn new(sections: Vec<Section>) -> Self {
        Self { sections }
    }

    pub fn rpp_end_to_end() -> Self {
        Self::new(vec![
            Section {
                id: SectionId::Architecture,
                title: "Architekturgrundlagen schärfen",
                description: "Dokumente und Zielartefakte für den vollständigen RPP End-to-End Blueprint vorbereiten.",
                tasks: vec![
                    Task {
                        key: "architecture.document_foundations",
                        title: "Ist-Architektur dokumentieren",
                        detail: "Bestehende Node-, Wallet- und Proof-Pipelines beschreiben, um gemeinsame Basis zu schaffen.",
                        status: TaskStatus::Todo,
                    },
                    Task {
                        key: "architecture.spec_interfaces",
                        title: "Schnittstellen spezifizieren",
                        detail: "Nachrichtenformate, Gossip-Topics und Zustandsübergänge definieren und versionieren.",
                        status: TaskStatus::Todo,
                    },
                ],
            },
            Section {
                id: SectionId::FirewoodStwo,
                title: "Firewood ↔ STWO Schnittstellen",
                description: "State-Lifecycle-APIs und rekursive Proof-Verkettung bereitstellen.",
                tasks: vec![
                    Task {
                        key: "state.lifecycle_api",
                        title: "Lifecycle-Services extrahieren",
                        detail: "apply_block, prove_transition und verify_transition als modulare Services veröffentlichen.",
                        status: TaskStatus::InProgress,
                    },
                    Task {
                        key: "state.block_metadata",
                        title: "Block-Metadaten erweitern",
                        detail: "Blockpersistenz um alte/neue Roots, Proof-Hashes und Rekursionsanker ergänzen.",
                        status: TaskStatus::InProgress,
                    },
                    Task {
                        key: "state.pruning_jobs",
                        title: "Pruning-Proof-Automatisierung",
                        detail: "Hintergrundjobs für Generierung und Wiederaufbau historischer Zustände umsetzen.",
                        status: TaskStatus::Todo,
                    },
                ],
            },
            Section {
                id: SectionId::WalletWorkflows,
                title: "Wallet, ZSI und STWO Workflows",
                description: "Wallet- und Identitätsprozesse mit Tier-Governance absichern.",
                tasks: vec![
                    Task {
                        key: "wallet.utxo_policies",
                        title: "UTXO- und Tier-Policies",
                        detail: "UTXO-Snapshots, Reputation-Level und Timetoken-Bücher im Wallet modellieren.",
                        status: TaskStatus::Todo,
                    },
                    Task {
                        key: "wallet.zsi_workflow",
                        title: "ZSI-ID Lifecycle",
                        detail: "Genesis-/BFT-Workflows für die Ausstellung und Verifikation von ZSI-IDs aufbauen.",
                        status: TaskStatus::Todo,
                    },
                    Task {
                        key: "wallet.stwo_circuits",
                        title: "STWO-Circuits erweitern",
                        detail: "Ownership-, Balance-, Double-Spend- und Reputation-Prüfungen implementieren.",
                        status: TaskStatus::Todo,
                    },
                    Task {
                        key: "wallet.uptime_proofs",
                        title: "Uptime-Proofs integrieren",
                        detail: "Stündliche Online-Beweise mit Gossip-Weiterleitung und Validierung bereitstellen.",
                        status: TaskStatus::Todo,
                    },
                ],
            },
            Section {
                id: SectionId::Libp2p,
                title: "Libp2p Netzwerk-Backbone",
                description: "Produktives Gossip-Netz mit Admission-Control und Snapshot-Sync.",
                tasks: vec![
                    Task {
                        key: "p2p.integrate_libp2p",
                        title: "Libp2p integrieren",
                        detail: "Noise-XX-Handshake, Peerstore und GossipSub-Kanäle mit Berechtigungen implementieren.",
                        status: TaskStatus::Todo,
                    },
                    Task {
                        key: "p2p.admission_control",
                        title: "Admission-Control",
                        detail: "Reputationsbasierte Tier-Steuerung inklusive Sperrlisten und Updates entwickeln.",
                        status: TaskStatus::Todo,
                    },
                    Task {
                        key: "p2p.snapshot_sync",
                        title: "Snapshot-Synchronisation",
                        detail: "Firewood-Snapshots und Telemetrie über dedizierte Gossip-Kanäle synchronisieren.",
                        status: TaskStatus::Todo,
                    },
                ],
            },
            Section {
                id: SectionId::Vrf,
                title: "VRF Validator-Selektion",
                description: "Validatoren- und Leader-Auswahl über Poseidon-VRF realisieren (siehe docs/vrf/poseidon_spec.md für Vertrag & Testplan).",
                tasks: vec![
                    Task {
                        key: "vrf.poseidon_impl",
                        title: "Poseidon-VRF umsetzen",
                        detail: "VRF-Beweise generieren und im Netzwerk verifizierbar austauschen – Spezifikationsabgleich gegen docs/vrf/poseidon_spec.md.",
                        status: TaskStatus::Todo,
                    },
                    Task {
                        key: "vrf.epoch_management",
                        title: "Epochenverwaltung",
                        detail: "Validator-Set-Rotation und gewichtete Lotterie nach Reputation+Timetoken implementieren, inklusive Replay-Schutz wie in docs/vrf/poseidon_spec.md beschrieben.",
                        status: TaskStatus::Todo,
                    },
                    Task {
                        key: "vrf.monitoring",
                        title: "VRF-Monitoring",
                        detail: "Leistungskennzahlen überwachen und Replay-Schutz sicherstellen; Telemetrie- und Testplan siehe docs/vrf/poseidon_spec.md.",
                        status: TaskStatus::Todo,
                    },
                ],
            },
            Section {
                id: SectionId::Bft,
                title: "Malachite BFT & Slashing",
                description: "Mehrknoten-Konsens mit Evidence-Pool und Belohnungen verankern.",
                tasks: vec![
                    Task {
                        key: "bft.distributed_loop",
                        title: "Verteilten BFT-Loop bauen",
                        detail: "Proposal, Pre-Vote und Pre-Commit über das Netzwerk orchestrieren.",
                        status: TaskStatus::Todo,
                    },
                    Task {
                        key: "bft.evidence_slashing",
                        title: "Evidence & Slashing",
                        detail: "Double-Sign- und Invalid-Proof-Evidence erfassen und Strafen anwenden.",
                        status: TaskStatus::Todo,
                    },
                    Task {
                        key: "bft.rewards",
                        title: "Belohnungslogik",
                        detail: "Leader-Bonus, Validator-Rewards und Uptime-Penalties verankern.",
                        status: TaskStatus::Todo,
                    },
                ],
            },
            Section {
                id: SectionId::Electrs,
                title: "Electrs Binary & UI",
                description: "CLI-/UI-Modi für Node, Wallet und Hybrid-Betrieb bereitstellen.",
                tasks: vec![
                    Task {
                        key: "electrs.modes",
                        title: "Betriebsmodi trennen",
                        detail: "Node-, Wallet- und Hybrid-Modus im Binary und in Configs abbilden.",
                        status: TaskStatus::Todo,
                    },
                    Task {
                        key: "electrs.ui_rpc",
                        title: "UI & RPC erweitern",
                        detail: "History-, Send-, Receive- und Node-Status-Oberflächen implementieren.",
                        status: TaskStatus::Todo,
                    },
                    Task {
                        key: "electrs.validator_mode",
                        title: "Validator-spezifische Funktionen",
                        detail: "VRF-Key-Management und Konsens-Telemetrie für Validatoren ergänzen.",
                        status: TaskStatus::Todo,
                    },
                ],
            },
            Section {
                id: SectionId::BlockLifecycle,
                title: "End-to-End Block Lifecycle",
                description: "Vom Wallet-Gossip bis zu Rewards orchestrieren.",
                tasks: vec![
                    Task {
                        key: "lifecycle.pipeline",
                        title: "Pipeline orchestrieren",
                        detail: "Wallet → Node → VRF → BFT → Firewood/STWO Ablauf über Prozesse koppeln.",
                        status: TaskStatus::Todo,
                    },
                    Task {
                        key: "lifecycle.state_sync",
                        title: "State-Sync & Light-Clients",
                        detail: "Snapshot-Download, Proof-Verifikation und Head-Abonnements umsetzen.",
                        status: TaskStatus::Todo,
                    },
                    Task {
                        key: "lifecycle.observability",
                        title: "Observability",
                        detail: "Tracing, Metrics und Dashboards für jeden Pipeline-Schritt bereitstellen.",
                        status: TaskStatus::Todo,
                    },
                ],
            },
            Section {
                id: SectionId::Testing,
                title: "Test- und Validierungssuite",
                description: "Unit-, Integrations- und Simulations-Tests gemäß Blueprint etablieren.",
                tasks: vec![
                    Task {
                        key: "testing.unit",
                        title: "Unit-Tests",
                        detail: "STWO-Circuits, Firewood-Roots, VRF-Auswahl und BFT-Voting abdecken.",
                        status: TaskStatus::Todo,
                    },
                    Task {
                        key: "testing.integration",
                        title: "Integrations-Tests",
                        detail: "End-to-End Blockproduktion, Snapshot-Sync und Light-Client-Verifikation prüfen.",
                        status: TaskStatus::Todo,
                    },
                    Task {
                        key: "testing.simulation",
                        title: "Simulationsframework",
                        detail: "100 Wallets, 20 Validatoren mit Zufallstransaktionen und Reputationstracking simulieren.",
                        status: TaskStatus::Todo,
                    },
                ],
            },
        ])
    }

    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    pub fn sections_mut(&mut self) -> &mut [Section] {
        &mut self.sections
    }

    pub fn iter_tasks(&self) -> impl Iterator<Item = &Task> {
        self.sections
            .iter()
            .flat_map(|section| section.tasks.iter())
    }

    pub fn iter_tasks_mut(&mut self) -> impl Iterator<Item = &mut Task> {
        self.sections
            .iter_mut()
            .flat_map(|section| section.tasks.iter_mut())
    }

    pub fn mark_status(
        &mut self,
        task_key: &str,
        status: TaskStatus,
    ) -> Result<(), BlueprintError> {
        for task in self.iter_tasks_mut() {
            if task.key == task_key {
                task.mark_status(status);
                return Ok(());
            }
        }
        Err(BlueprintError::UnknownTask(task_key.to_owned()))
    }

    pub fn pending_tasks(&self) -> Vec<&Task> {
        self.sections
            .iter()
            .flat_map(|section| section.pending_tasks())
            .collect()
    }

    pub fn first_blocking_task(&self) -> Option<&Task> {
        self.pending_tasks().into_iter().next()
    }

    pub fn completion_ratio(&self) -> f32 {
        let mut total = 0f32;
        let mut done = 0f32;
        for task in self.iter_tasks() {
            total += 1.0;
            if task.status.is_done() {
                done += 1.0;
            }
        }
        if total == 0.0 { 1.0 } else { done / total }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BlueprintError {
    #[error("unknown blueprint task `{0}`")]
    UnknownTask(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blueprint_contains_all_sections() {
        let plan = Blueprint::rpp_end_to_end();
        let section_ids: Vec<SectionId> = plan.sections.iter().map(|section| section.id).collect();
        assert_eq!(section_ids.len(), 9);
        assert_eq!(section_ids[0], SectionId::Architecture);
        assert_eq!(section_ids[8], SectionId::Testing);
    }

    #[test]
    fn mark_status_updates_tasks() {
        let mut plan = Blueprint::rpp_end_to_end();
        assert!(
            plan.pending_tasks()
                .iter()
                .any(|task| task.key == "p2p.integrate_libp2p")
        );

        plan.mark_status("p2p.integrate_libp2p", TaskStatus::InProgress)
            .unwrap();

        let task = plan
            .iter_tasks()
            .find(|task| task.key == "p2p.integrate_libp2p")
            .unwrap();
        assert_eq!(task.status, TaskStatus::InProgress);
    }

    #[test]
    fn completion_ratio_is_calculated() {
        let mut plan = Blueprint::rpp_end_to_end();
        assert_eq!(plan.completion_ratio(), 0.0);

        plan.mark_status("architecture.document_foundations", TaskStatus::Done)
            .unwrap();
        plan.mark_status("architecture.spec_interfaces", TaskStatus::Done)
            .unwrap();
        assert!(plan.completion_ratio() > 0.0);
    }

    #[test]
    fn mark_status_unknown_task_errors() {
        let mut plan = Blueprint::rpp_end_to_end();
        let err = plan
            .mark_status("nonexistent.task", TaskStatus::Done)
            .unwrap_err();
        assert_eq!(err.to_string(), "unknown blueprint task `nonexistent.task`");
    }
}
