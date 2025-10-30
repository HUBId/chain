#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskStatus {
    Todo,
    InReview,
    Done,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Task {
    pub key: &'static str,
    pub title: &'static str,
    pub detail: &'static str,
    pub status: TaskStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub tasks: Vec<Task>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blueprint {
    sections: Vec<Section>,
}

impl Blueprint {
    pub fn new(sections: Vec<Section>) -> Self {
        Self { sections }
    }

    pub fn wallet_workflows() -> Self {
        Self::new(vec![Section {
            id: "wallet-workflows",
            title: "Wallet tier governance",
            description: "Track wallet governance and policy tasks across releases.",
            tasks: vec![
                Task {
                    key: "wallet.utxo_policies",
                    title: "UTXO policy enforcement",
                    detail: "Evaluate tiered UTXO limits during transaction construction and document operator guardrails.",
                    status: TaskStatus::Done,
                },
                Task {
                    key: "wallet.zsi_workflow",
                    title: "ZSI identity lifecycle",
                    detail: "Model end-to-end issuance and renewal of ZSI identities.",
                    status: TaskStatus::Todo,
                },
                Task {
                    key: "wallet.stwo_circuits",
                    title: "STWO witness coverage",
                    detail: "Document wallet-side STWO circuits and witness derivation.",
                    status: TaskStatus::Todo,
                },
            ],
        }])
    }

    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    pub fn pending_tasks(&self) -> impl Iterator<Item = &Task> {
        self.sections
            .iter()
            .flat_map(|section| section.tasks.iter())
            .filter(|task| task.status != TaskStatus::Done)
    }
}
