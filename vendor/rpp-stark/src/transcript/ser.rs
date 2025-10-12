use super::core::TranscriptStateView;
use super::types::{SerKind, TranscriptError};

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum StageTag {
    ExpectPublic = 0,
    TraceRoot = 1,
    TraceChallenge = 2,
    CompRoot = 3,
    CompChallenge = 4,
    FriRoot = 5,
    FriChallenge = 6,
    QueriesNoCount = 7,
    QueriesCount = 8,
    Finalised = 9,
}

#[allow(dead_code)]
impl StageTag {
    fn from_parts(code: u8, aux: u8) -> Option<(StageTag, u8)> {
        let tag = match code {
            0 => StageTag::ExpectPublic,
            1 => StageTag::TraceRoot,
            2 => StageTag::TraceChallenge,
            3 => StageTag::CompRoot,
            4 => StageTag::CompChallenge,
            5 => StageTag::FriRoot,
            6 => StageTag::FriChallenge,
            7 => StageTag::QueriesNoCount,
            8 => StageTag::QueriesCount,
            9 => StageTag::Finalised,
            _ => return None,
        };
        Some((tag, aux))
    }
}

#[allow(dead_code)]
pub(crate) fn serialize_state(view: &TranscriptStateView) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(&view.state);
    out.extend_from_slice(&view.challenge_counter.to_le_bytes());
    match &view.stage {
        super::core::Stage::ExpectPublic => {
            out.push(StageTag::ExpectPublic as u8);
            out.push(0);
        }
        super::core::Stage::TraceRoot => {
            out.push(StageTag::TraceRoot as u8);
            out.push(0);
        }
        super::core::Stage::TraceChallenge => {
            out.push(StageTag::TraceChallenge as u8);
            out.push(0);
        }
        super::core::Stage::CompRoot => {
            out.push(StageTag::CompRoot as u8);
            out.push(0);
        }
        super::core::Stage::CompChallenge => {
            out.push(StageTag::CompChallenge as u8);
            out.push(0);
        }
        super::core::Stage::Fri { layer, expect } => {
            let tag = match expect {
                super::core::FriExpectation::Root => StageTag::FriRoot,
                super::core::FriExpectation::Challenge => StageTag::FriChallenge,
            };
            out.push(tag as u8);
            out.push(*layer);
        }
        super::core::Stage::Queries { count_absorbed } => {
            if *count_absorbed {
                out.push(StageTag::QueriesCount as u8);
            } else {
                out.push(StageTag::QueriesNoCount as u8);
            }
            out.push(0);
        }
        super::core::Stage::Finalised => {
            out.push(StageTag::Finalised as u8);
            out.push(0);
        }
    }
    let (phase_code, phase_aux) = match view.phase {
        super::types::TranscriptPhase::Init => (0, 0),
        super::types::TranscriptPhase::Public => (1, 0),
        super::types::TranscriptPhase::TraceCommit => (2, 0),
        super::types::TranscriptPhase::CompCommit => (3, 0),
        super::types::TranscriptPhase::FriLayer(layer) => (4, layer),
        super::types::TranscriptPhase::Queries => (5, 0),
        super::types::TranscriptPhase::Final => (6, 0),
    };
    out.push(phase_code);
    out.push(phase_aux);
    out
}

#[allow(dead_code)]
pub(crate) fn deserialize_state(bytes: &[u8]) -> Result<TranscriptStateView, TranscriptError> {
    if bytes.len() < 42 {
        return Err(TranscriptError::Serialization(SerKind::State));
    }
    let mut state = [0u8; 32];
    state.copy_from_slice(&bytes[..32]);
    let mut counter_bytes = [0u8; 8];
    counter_bytes.copy_from_slice(&bytes[32..40]);
    let challenge_counter = u64::from_le_bytes(counter_bytes);
    let stage_code = *bytes
        .get(40)
        .ok_or(TranscriptError::Serialization(SerKind::State))?;
    let stage_aux = *bytes
        .get(41)
        .ok_or(TranscriptError::Serialization(SerKind::State))?;
    let phase_code = *bytes
        .get(42)
        .ok_or(TranscriptError::Serialization(SerKind::State))?;
    let phase_aux = *bytes.get(43).unwrap_or(&0);

    use super::core::{FriExpectation, Stage};
    let stage = match StageTag::from_parts(stage_code, stage_aux) {
        Some((StageTag::ExpectPublic, _)) => Stage::ExpectPublic,
        Some((StageTag::TraceRoot, _)) => Stage::TraceRoot,
        Some((StageTag::TraceChallenge, _)) => Stage::TraceChallenge,
        Some((StageTag::CompRoot, _)) => Stage::CompRoot,
        Some((StageTag::CompChallenge, _)) => Stage::CompChallenge,
        Some((StageTag::FriRoot, layer)) => Stage::Fri {
            layer,
            expect: FriExpectation::Root,
        },
        Some((StageTag::FriChallenge, layer)) => Stage::Fri {
            layer,
            expect: FriExpectation::Challenge,
        },
        Some((StageTag::QueriesNoCount, _)) => Stage::Queries {
            count_absorbed: false,
        },
        Some((StageTag::QueriesCount, _)) => Stage::Queries {
            count_absorbed: true,
        },
        Some((StageTag::Finalised, _)) => Stage::Finalised,
        None => return Err(TranscriptError::Serialization(SerKind::State)),
    };

    use super::types::TranscriptPhase;
    let phase = match (phase_code, phase_aux) {
        (0, _) => TranscriptPhase::Init,
        (1, _) => TranscriptPhase::Public,
        (2, _) => TranscriptPhase::TraceCommit,
        (3, _) => TranscriptPhase::CompCommit,
        (4, layer) => TranscriptPhase::FriLayer(layer),
        (5, _) => TranscriptPhase::Queries,
        (6, _) => TranscriptPhase::Final,
        _ => return Err(TranscriptError::Serialization(SerKind::State)),
    };

    Ok(TranscriptStateView {
        state,
        challenge_counter,
        stage,
        phase,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::core::{FriExpectation, Stage, TranscriptStateView};
    use crate::transcript::types::TranscriptPhase;

    #[test]
    fn roundtrip_state_encoding() {
        let view = TranscriptStateView {
            state: [42u8; 32],
            challenge_counter: 7,
            stage: Stage::Fri {
                layer: 3,
                expect: FriExpectation::Challenge,
            },
            phase: TranscriptPhase::FriLayer(3),
        };
        let bytes = serialize_state(&view);
        let restored = deserialize_state(&bytes).expect("state decode");
        assert_eq!(restored.state, view.state);
        assert_eq!(restored.challenge_counter, view.challenge_counter);
        match restored.stage {
            Stage::Fri { layer, expect } => {
                assert_eq!(layer, 3);
                assert!(matches!(expect, FriExpectation::Challenge));
            }
            _ => panic!("unexpected stage"),
        }
    }
}
