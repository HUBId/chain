#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Todo,
    InProgress,
    Done,
}

impl TaskStatus {
    pub const fn is_done(self) -> bool {
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

pub const STORAGE_TASKS: &[Task] = &[
    Task {
        key: "pruning.metrics",
        title: "Instrument pruning telemetry",
        detail: "Expose counters and histograms that describe pruning cycles and persistence outcomes.",
        status: TaskStatus::Done,
    },
    Task {
        key: "pruning.operations",
        title: "Document pruning operations runbook",
        detail: "Publish monitoring guidance, dashboard examples, and failure-handling procedures for the pruning service.",
        status: TaskStatus::Done,
    },
];

pub fn pending_tasks() -> impl Iterator<Item = &'static Task> {
    STORAGE_TASKS.iter().filter(|task| !task.status.is_done())
}
