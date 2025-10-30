use clap::{ArgAction, Args};

#[derive(Debug, Clone, Default, Args)]
pub struct PruningCliOverrides {
    /// Override the pruning cadence (seconds between scheduled runs)
    #[arg(long = "pruning-cadence-secs", value_name = "SECONDS")]
    pub cadence_secs: Option<u64>,

    /// Override the pruning retention depth (number of finalized blocks to keep hydrated)
    #[arg(long = "pruning-retention-depth", value_name = "BLOCKS")]
    pub retention_depth: Option<u64>,

    /// Pause automatic pruning cycles on startup
    #[arg(long = "pruning-pause", action = ArgAction::SetTrue)]
    pub pause: bool,

    /// Resume automatic pruning cycles on startup
    #[arg(long = "pruning-resume", action = ArgAction::SetTrue)]
    pub resume: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PruningOverrides {
    pub cadence_secs: Option<u64>,
    pub retention_depth: Option<u64>,
    pub emergency_pause: Option<bool>,
}

impl PruningCliOverrides {
    pub fn into_overrides(self) -> PruningOverrides {
        let PruningCliOverrides {
            cadence_secs,
            retention_depth,
            pause,
            resume,
        } = self;

        let mut emergency_pause = None;
        if pause {
            emergency_pause = Some(true);
        }
        if resume {
            emergency_pause = Some(false);
        }

        PruningOverrides {
            cadence_secs,
            retention_depth,
            emergency_pause,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pause_flag_sets_emergency_pause() {
        let overrides = PruningCliOverrides {
            cadence_secs: Some(120),
            retention_depth: Some(256),
            pause: true,
            resume: false,
        }
        .into_overrides();

        assert_eq!(overrides.cadence_secs, Some(120));
        assert_eq!(overrides.retention_depth, Some(256));
        assert_eq!(overrides.emergency_pause, Some(true));
    }

    #[test]
    fn resume_overrides_pause_flag() {
        let overrides = PruningCliOverrides {
            cadence_secs: None,
            retention_depth: None,
            pause: true,
            resume: true,
        }
        .into_overrides();

        assert_eq!(overrides.emergency_pause, Some(false));
    }
}
