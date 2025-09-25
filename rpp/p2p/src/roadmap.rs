//! Static roadmap metadata for the libp2p networking backbone blueprint.
//!
//! The data model is intentionally lightweight so the application, tests or
//! documentation generators can embed the current implementation plan without
//! duplicating the natural language source that lives in the docs.

/// High level plan for the libp2p networking backbone effort.
#[derive(Debug)]
pub struct Plan {
    phases: &'static [Phase],
    cross_cutting_deliverables: &'static [Deliverable],
    milestones: &'static [Milestone],
}

impl Plan {
    /// Returns the ordered phases that describe how the backbone will be
    /// implemented end-to-end.
    pub fn phases(&self) -> &'static [Phase] {
        self.phases
    }

    /// Shared deliverables that cut across all phases.
    pub fn cross_cutting_deliverables(&self) -> &'static [Deliverable] {
        self.cross_cutting_deliverables
    }

    /// Milestones A-C that make progress measurable.
    pub fn milestones(&self) -> &'static [Milestone] {
        self.milestones
    }
}

/// A major implementation stage for the libp2p backbone.
#[derive(Debug)]
pub struct Phase {
    pub name: &'static str,
    pub focus: &'static str,
    pub work_items: &'static [WorkItem],
    pub outcomes: &'static [&'static str],
}

/// Concrete piece of work that belongs to a phase.
#[derive(Debug)]
pub struct WorkItem {
    pub title: &'static str,
    pub summary: &'static str,
}

/// Deliverable that must be satisfied regardless of the phase that produces it.
#[derive(Debug)]
pub struct Deliverable {
    pub name: &'static str,
    pub description: &'static str,
}

/// Major milestone with success criteria.
#[derive(Debug)]
pub struct Milestone {
    pub label: &'static str,
    pub summary: &'static str,
    pub exit_criteria: &'static [&'static str],
}

const PHASE_ONE_WORK: &[WorkItem] = &[
    WorkItem {
        title: "Libp2p integration and secure transport",
        summary: concat!(
            "Wire the node against libp2p with Noise-XX handshake support, ",
            "peerstore bootstrapping and version/feature negotiation."
        ),
    },
    WorkItem {
        title: "Gossip topic specification",
        summary: concat!(
            "Document and register the canonical gossip topics for blocks, votes, ",
            "proofs, snapshots and meta-data including message encoding contracts."
        ),
    },
];

const PHASE_TWO_WORK: &[WorkItem] = &[
    WorkItem {
        title: "Admission control and reputation enforcement",
        summary: concat!(
            "Add tier-aware admission control that gates publish and subscribe ",
            "privileges, updates peer reputation dynamically and enforces blocklists."
        ),
    },
    WorkItem {
        title: "Gossip backbone implementation",
        summary: concat!(
            "Stand up the gossip mesh across the five canonical channels, ",
            "ensuring tier controls are applied consistently across the network."
        ),
    },
];

const PHASE_THREE_WORK: &[WorkItem] = &[
    WorkItem {
        title: "Data path expansion",
        summary: concat!(
            "Extend the backbone to stream proofs, blocks, snapshots and meta ",
            "telemetry so consensus, light clients and monitoring can ride on libp2p."
        ),
    },
    WorkItem {
        title: "Operational hardening",
        summary: concat!(
            "Deliver persistence, security-hardening, large scale simulations and ",
            "failure drills to validate the backbone before production rollout."
        ),
    },
];

const PHASES: &[Phase] = &[
    Phase {
        name: "Phase 1: Transport foundations",
        focus: concat!(
            "Establish core libp2p integration including Noise-XX handshakes, ",
            "peerstore population and canonical gossip topics."
        ),
        work_items: PHASE_ONE_WORK,
        outcomes: &[
            "Nodes can authenticate peers via Noise-XX and persist them in the peerstore.",
            "Gossip topics for blocks, votes, proofs, snapshots and meta are defined with message schemas.",
        ],
    },
    Phase {
        name: "Phase 2: Gossip backbone & enforcement",
        focus: concat!(
            "Implement the gossip mesh with admission control so tier-based access ",
            "policies, reputation updates and blocklists gate channel usage."
        ),
        work_items: PHASE_TWO_WORK,
        outcomes: &[
            "Tier-aware admission control protects publication rights per channel.",
            "Reputation events update peer tiers dynamically and enforce block and allow lists.",
        ],
    },
    Phase {
        name: "Phase 3: Data paths & hardening",
        focus: concat!(
            "Expand libp2p usage to serve proofs, blocks, snapshots and meta telemetry ",
            "while validating robustness through persistence and security work."
        ),
        work_items: PHASE_THREE_WORK,
        outcomes: &[
            "Consensus, light-client sync and telemetry all flow over the libp2p backbone.",
            "Persistence, security review and scale simulations sign off the backbone for launch.",
        ],
    },
];

const CROSS_CUTTING: &[Deliverable] = &[
    Deliverable {
        name: "Peer and channel observability",
        description: concat!(
            "Metrics, tracing and dashboards for gossip mesh health, tier violations ",
            "and Noise-XX handshake outcomes."
        ),
    },
    Deliverable {
        name: "Operational runbooks",
        description: concat!(
            "Playbooks describing deployment, key rotation, failure recovery and ",
            "incident response for the libp2p backbone."
        ),
    },
    Deliverable {
        name: "Security posture",
        description: concat!(
            "Threat model, penetration testing results and mitigations covering ",
            "handshakes, admission control and reputation updates."
        ),
    },
];

const MILESTONES: &[Milestone] = &[
    Milestone {
        label: "Milestone A",
        summary: "Foundational libp2p transport online",
        exit_criteria: &[
            "Noise-XX handshake succeeds between reference nodes.",
            "Peerstore persists authenticated peers across restarts.",
            "Gossip topics and message schemas reviewed with downstream teams.",
        ],
    },
    Milestone {
        label: "Milestone B",
        summary: "Gossip backbone enforcing tier policies",
        exit_criteria: &[
            "Admission control enforces TL0/TL1/TL3+ permissions per channel.",
            "Reputation updates propagate between peers via the meta channel.",
            "Blocklisted peers are prevented from joining the gossip mesh.",
        ],
    },
    Milestone {
        label: "Milestone C",
        summary: "Data paths hardened for production",
        exit_criteria: &[
            "Proofs, blocks and snapshots synchronize reliably across a staged network.",
            "Security review sign-off with mitigations in place.",
            "Scale simulation demonstrates stability under peak load.",
        ],
    },
];

static PLAN: Plan = Plan {
    phases: PHASES,
    cross_cutting_deliverables: CROSS_CUTTING,
    milestones: MILESTONES,
};

/// Returns the globally defined libp2p backbone implementation plan.
pub fn libp2p_backbone_plan() -> &'static Plan {
    &PLAN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_contains_three_phases_and_milestones() {
        let plan = libp2p_backbone_plan();
        assert_eq!(plan.phases().len(), 3);
        assert_eq!(plan.milestones().len(), 3);
        assert!(
            plan.phases()
                .iter()
                .any(|phase| phase.name.contains("Transport foundations"))
        );
        assert!(
            plan.phases()
                .iter()
                .any(|phase| phase.name.contains("Data paths"))
        );
    }

    #[test]
    fn cross_cutting_deliverables_cover_security_and_ops() {
        let plan = libp2p_backbone_plan();
        let names: Vec<&str> = plan
            .cross_cutting_deliverables()
            .iter()
            .map(|deliverable| deliverable.name)
            .collect();
        assert!(names.iter().any(|name| name.contains("Security")));
        assert!(names.iter().any(|name| name.contains("Operational")));
    }
}
