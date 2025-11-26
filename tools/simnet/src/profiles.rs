use std::path::PathBuf;

use clap::ValueEnum;

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum SimnetProfile {
    #[value(alias = "block-pipeline", alias = "ci-block-pipeline")]
    BlockPipeline,
    #[value(alias = "state-sync-guard", alias = "ci-state-sync-guard")]
    StateSyncGuard,
    #[value(alias = "quorum-stress", alias = "consensus-quorum-stress")]
    QuorumStress,
    #[value(alias = "partition", alias = "snapshot-partition")]
    Partition,
    #[value(alias = "partitioned-flood", alias = "partitioned_flood")]
    Flood,
    #[value(alias = "small-world", alias = "small_world")]
    SmallWorld,
    #[value(alias = "reorg-stark", alias = "consensus-reorg-stark")]
    ReorgStark,
    #[value(alias = "canary-rolling", alias = "canary_rolling")]
    CanaryRolling,
    #[value(alias = "leader-rotation", alias = "leader_rotation")]
    LeaderRotationProverLoad,
}

impl SimnetProfile {
    pub fn all() -> &'static [SimnetProfile] {
        &[
            SimnetProfile::BlockPipeline,
            SimnetProfile::StateSyncGuard,
            SimnetProfile::QuorumStress,
            SimnetProfile::Partition,
            SimnetProfile::Flood,
            SimnetProfile::SmallWorld,
            SimnetProfile::ReorgStark,
            SimnetProfile::CanaryRolling,
            SimnetProfile::LeaderRotationProverLoad,
        ]
    }

    pub fn slug(self) -> &'static str {
        match self {
            SimnetProfile::BlockPipeline => "block-pipeline",
            SimnetProfile::StateSyncGuard => "state-sync-guard",
            SimnetProfile::QuorumStress => "quorum-stress",
            SimnetProfile::Partition => "partition",
            SimnetProfile::Flood => "flood",
            SimnetProfile::SmallWorld => "small-world",
            SimnetProfile::ReorgStark => "reorg-stark",
            SimnetProfile::CanaryRolling => "canary-rolling",
            SimnetProfile::LeaderRotationProverLoad => "leader-rotation-prover-load",
        }
    }

    pub fn scenario_path(self) -> PathBuf {
        workspace_root().join(match self {
            SimnetProfile::BlockPipeline => "tools/simnet/scenarios/ci_block_pipeline.ron",
            SimnetProfile::StateSyncGuard => "tools/simnet/scenarios/ci_state_sync_guard.ron",
            SimnetProfile::QuorumStress => "tools/simnet/scenarios/consensus_quorum_stress.ron",
            SimnetProfile::Partition => "tools/simnet/scenarios/snapshot_partition.ron",
            SimnetProfile::Flood => "tools/simnet/scenarios/partitioned_flood.ron",
            SimnetProfile::SmallWorld => "tools/simnet/scenarios/small_world_smoke.ron",
            SimnetProfile::ReorgStark => "tools/simnet/scenarios/consensus_reorg_stark.ron",
            SimnetProfile::CanaryRolling => "tools/simnet/scenarios/canary_rolling_restart.ron",
            SimnetProfile::LeaderRotationProverLoad =>
                "tools/simnet/scenarios/leader_rotation_prover_load.ron",
        })
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("simnet lives under tools/")
        .parent()
        .expect("tools lives under workspace root")
        .to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::SimnetProfile;
    use clap::ValueEnum;

    #[test]
    fn profile_paths_and_slugs_match_scenarios() {
        let expected = vec![
            (
                SimnetProfile::BlockPipeline,
                "tools/simnet/scenarios/ci_block_pipeline.ron",
                "block-pipeline",
            ),
            (
                SimnetProfile::StateSyncGuard,
                "tools/simnet/scenarios/ci_state_sync_guard.ron",
                "state-sync-guard",
            ),
            (
                SimnetProfile::QuorumStress,
                "tools/simnet/scenarios/consensus_quorum_stress.ron",
                "quorum-stress",
            ),
            (
                SimnetProfile::Partition,
                "tools/simnet/scenarios/snapshot_partition.ron",
                "partition",
            ),
            (
                SimnetProfile::Flood,
                "tools/simnet/scenarios/partitioned_flood.ron",
                "flood",
            ),
            (
                SimnetProfile::SmallWorld,
                "tools/simnet/scenarios/small_world_smoke.ron",
                "small-world",
            ),
            (
                SimnetProfile::ReorgStark,
                "tools/simnet/scenarios/consensus_reorg_stark.ron",
                "reorg-stark",
            ),
            (
                SimnetProfile::CanaryRolling,
                "tools/simnet/scenarios/canary_rolling_restart.ron",
                "canary-rolling",
            ),
            (
                SimnetProfile::LeaderRotationProverLoad,
                "tools/simnet/scenarios/leader_rotation_prover_load.ron",
                "leader-rotation-prover-load",
            ),
        ];

        for (profile, path, slug) in expected {
            let scenario_path = profile.scenario_path();
            assert!(scenario_path.ends_with(path), "path for {slug} mismatch");
            assert!(scenario_path.exists(), "scenario path {path} should exist");
            assert_eq!(profile.slug(), slug);
        }
    }

    #[test]
    fn aliases_parse_to_profiles() {
        let aliases = [
            ("partitioned-flood", SimnetProfile::Flood),
            ("partitioned_flood", SimnetProfile::Flood),
            ("snapshot-partition", SimnetProfile::Partition),
            ("ci-state-sync-guard", SimnetProfile::StateSyncGuard),
            ("consensus-quorum-stress", SimnetProfile::QuorumStress),
        ];

        for (alias, profile) in aliases {
            let parsed = SimnetProfile::from_str(alias, true)
                .unwrap_or_else(|_| panic!("failed to parse alias {alias}"));
            assert_eq!(parsed, profile);
        }
    }
}
