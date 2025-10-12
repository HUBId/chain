use crate::hash::deterministic::{hash, Blake2sXof, Hasher};
use crate::params::{ChallengeBounds, StarkParams};
use crate::utils::serialization::DigestBytes;
use core::convert::TryFrom;

use super::ser;
use super::types::{
    Felt, SerKind, TranscriptContext, TranscriptError, TranscriptLabel, TranscriptPhase,
};

#[derive(Clone)]
struct PhaseTracker {
    stage: Stage,
    fri_layers: u8,
}

#[derive(Clone)]
pub(crate) enum Stage {
    ExpectPublic,
    TraceRoot,
    TraceChallenge,
    CompRoot,
    CompChallenge,
    Fri { layer: u8, expect: FriExpectation },
    Queries { count_absorbed: bool },
    Finalised,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FriExpectation {
    Root,
    Challenge,
}

impl PhaseTracker {
    fn new(fri_layers: u8) -> Self {
        Self {
            stage: Stage::ExpectPublic,
            fri_layers,
        }
    }

    fn phase(&self) -> TranscriptPhase {
        match &self.stage {
            Stage::ExpectPublic => TranscriptPhase::Init,
            Stage::TraceRoot => TranscriptPhase::Public,
            Stage::TraceChallenge => TranscriptPhase::TraceCommit,
            Stage::CompRoot => TranscriptPhase::TraceCommit,
            Stage::CompChallenge => TranscriptPhase::CompCommit,
            Stage::Fri { layer, .. } => TranscriptPhase::FriLayer(*layer),
            Stage::Queries { .. } => TranscriptPhase::Queries,
            Stage::Finalised => TranscriptPhase::Final,
        }
    }

    fn apply_absorb(&mut self, label: TranscriptLabel) -> Result<TranscriptPhase, TranscriptError> {
        match (self.stage.clone(), label) {
            (Stage::ExpectPublic, TranscriptLabel::PublicInputsDigest) => {
                self.stage = Stage::TraceRoot;
                Ok(TranscriptPhase::Public)
            }
            (Stage::TraceRoot, TranscriptLabel::TraceRoot) => {
                self.stage = Stage::TraceChallenge;
                Ok(TranscriptPhase::TraceCommit)
            }
            (Stage::CompRoot, TranscriptLabel::CompRoot) => {
                self.stage = Stage::CompChallenge;
                Ok(TranscriptPhase::CompCommit)
            }
            (
                Stage::Fri {
                    layer,
                    expect: FriExpectation::Root,
                },
                TranscriptLabel::FriRoot(idx),
            ) if layer == idx => {
                self.stage = Stage::Fri {
                    layer,
                    expect: FriExpectation::Challenge,
                };
                Ok(TranscriptPhase::FriLayer(layer))
            }
            (
                Stage::Fri {
                    layer,
                    expect: FriExpectation::Root,
                },
                TranscriptLabel::FriRoot(idx),
            ) if layer != idx => Err(TranscriptError::BoundsViolation),
            (
                Stage::Queries {
                    count_absorbed: false,
                },
                TranscriptLabel::QueryCount,
            ) => {
                self.stage = Stage::Queries {
                    count_absorbed: true,
                };
                Ok(TranscriptPhase::Queries)
            }
            (Stage::Finalised, TranscriptLabel::Fork) => Ok(TranscriptPhase::Final),
            _ => Err(TranscriptError::InvalidLabel),
        }
    }

    fn apply_challenge(
        &mut self,
        label: TranscriptLabel,
    ) -> Result<TranscriptPhase, TranscriptError> {
        match (self.stage.clone(), label) {
            (Stage::TraceChallenge, TranscriptLabel::TraceChallengeA) => {
                self.stage = Stage::CompRoot;
                Ok(TranscriptPhase::TraceCommit)
            }
            (Stage::CompChallenge, TranscriptLabel::CompChallengeA) => {
                if self.fri_layers == 0 {
                    self.stage = Stage::Queries {
                        count_absorbed: false,
                    };
                } else {
                    self.stage = Stage::Fri {
                        layer: 0,
                        expect: FriExpectation::Root,
                    };
                }
                Ok(TranscriptPhase::CompCommit)
            }
            (
                Stage::Fri {
                    layer,
                    expect: FriExpectation::Challenge,
                },
                TranscriptLabel::FriFoldChallenge(idx),
            ) if layer == idx => {
                if idx + 1 < self.fri_layers {
                    self.stage = Stage::Fri {
                        layer: idx + 1,
                        expect: FriExpectation::Root,
                    };
                } else {
                    self.stage = Stage::Queries {
                        count_absorbed: false,
                    };
                }
                Ok(TranscriptPhase::FriLayer(idx))
            }
            (
                Stage::Fri {
                    layer,
                    expect: FriExpectation::Challenge,
                },
                TranscriptLabel::FriFoldChallenge(idx),
            ) if layer != idx => Err(TranscriptError::BoundsViolation),
            (
                Stage::Queries {
                    count_absorbed: true,
                },
                TranscriptLabel::QueryIndexStream,
            ) => Ok(TranscriptPhase::Queries),
            (Stage::Queries { .. }, TranscriptLabel::ProofClose) => {
                self.stage = Stage::Finalised;
                Ok(TranscriptPhase::Final)
            }
            (Stage::Finalised, TranscriptLabel::Fork) => Ok(TranscriptPhase::Final),
            _ => Err(TranscriptError::InvalidLabel),
        }
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct TranscriptStateView {
    pub state: [u8; 32],
    pub challenge_counter: u64,
    pub stage: Stage,
    pub phase: TranscriptPhase,
}

/// Deterministic, domain-separated Fiat–Shamir transcript.
pub struct Transcript {
    params_hash: [u8; 32],
    protocol_tag: u64,
    seed: [u8; 32],
    _context: TranscriptContext,
    state: [u8; 32],
    xof: Blake2sXof,
    phase: TranscriptPhase,
    tracker: PhaseTracker,
    challenge_counter: u64,
    bounds: ChallengeBounds,
}

impl Transcript {
    /// Initialises a new transcript bound to the supplied parameter set.
    pub fn new(params: &StarkParams, context_tag: TranscriptContext) -> Self {
        let params_hash = params.params_hash();
        let protocol_tag = params.transcript().protocol_tag;
        let seed = params.transcript().seed;
        let bounds = params.transcript().challenge_bounds;
        let fri_layers = params.fri().num_layers;

        let mut hasher = Hasher::new();
        hasher.update(b"RPP-TRANSCRIPT-V1");
        hasher.update(&params_hash);
        hasher.update(&protocol_tag.to_le_bytes());
        hasher.update(&seed);
        hasher.update(&context_tag.to_le_bytes());
        let digest = hasher.finalize().into_bytes();

        let mut transcript = Self {
            params_hash,
            protocol_tag,
            seed,
            _context: context_tag,
            state: digest,
            xof: Blake2sXof::from_state(digest),
            phase: TranscriptPhase::Init,
            tracker: PhaseTracker::new(fri_layers),
            challenge_counter: 0,
            bounds,
        };

        transcript.absorb_internal(TranscriptLabel::ParamsHash, &params_hash);
        transcript.absorb_internal(TranscriptLabel::ProtocolTag, &protocol_tag.to_le_bytes());
        transcript.absorb_internal(TranscriptLabel::Seed, &seed);
        transcript.absorb_internal(TranscriptLabel::ContextTag, &context_tag.to_le_bytes());
        transcript
    }

    fn absorb_internal(&mut self, label: TranscriptLabel, bytes: &[u8]) {
        self.state = mix(self.state, label, bytes);
        self.xof = Blake2sXof::from_state(self.state);
        self.phase = match self.tracker.apply_absorb(label) {
            Ok(phase) => phase,
            Err(_) => self.phase,
        };
    }

    fn update_phase_absorb(&mut self, label: TranscriptLabel) -> Result<(), TranscriptError> {
        let phase = self.tracker.apply_absorb(label)?;
        self.phase = phase;
        Ok(())
    }

    fn update_phase_challenge(&mut self, label: TranscriptLabel) -> Result<(), TranscriptError> {
        let phase = self.tracker.apply_challenge(label)?;
        self.phase = phase;
        Ok(())
    }

    /// Creates a deterministic forked transcript using the current state digest.
    pub fn fork(&self, subcontext: TranscriptContext) -> Self {
        let fork_label = TranscriptLabel::Fork;
        let fork_bytes = subcontext.to_le_bytes();
        let fork_state = mix(self.state, fork_label, &fork_bytes);
        let tracker = self.tracker.clone();
        let phase = tracker.phase();
        Self {
            params_hash: self.params_hash,
            protocol_tag: self.protocol_tag,
            seed: self.seed,
            _context: subcontext,
            state: fork_state,
            xof: Blake2sXof::from_state(fork_state),
            phase,
            tracker,
            challenge_counter: 0,
            bounds: self.bounds,
        }
    }

    fn ensure_challenge_bounds(&self) -> Result<(), TranscriptError> {
        if self.challenge_counter > self.bounds.maximum as u64 {
            return Err(TranscriptError::BoundsViolation);
        }
        Ok(())
    }

    fn increment_challenges(&mut self) -> Result<(), TranscriptError> {
        self.challenge_counter = self
            .challenge_counter
            .checked_add(1)
            .ok_or(TranscriptError::Overflow)?;
        self.ensure_challenge_bounds()
    }

    /// Absorbs canonical bytes under the supplied label.
    pub fn absorb_bytes(
        &mut self,
        label: TranscriptLabel,
        data: &[u8],
    ) -> Result<(), TranscriptError> {
        self.update_phase_absorb(label)?;
        self.state = mix(self.state, label, data);
        self.xof = Blake2sXof::from_state(self.state);
        Ok(())
    }

    /// Absorbs canonical field elements.
    pub fn absorb_field_elements(
        &mut self,
        label: TranscriptLabel,
        felts: &[Felt],
    ) -> Result<(), TranscriptError> {
        let mut buffer = Vec::with_capacity(felts.len() * 32);
        for felt in felts {
            let encoded =
                encode_felt(*felt).map_err(|_| TranscriptError::Serialization(SerKind::Felt))?;
            buffer.extend_from_slice(&encoded);
        }
        self.absorb_bytes(label, &buffer)
    }

    /// Absorbs a canonical digest.
    pub fn absorb_digest(
        &mut self,
        label: TranscriptLabel,
        digest: &DigestBytes,
    ) -> Result<(), TranscriptError> {
        self.absorb_bytes(label, &digest.bytes)
    }

    fn derive_challenge(
        &mut self,
        label: TranscriptLabel,
        output: &mut [u8],
    ) -> Result<(), TranscriptError> {
        self.increment_challenges()?;
        self.update_phase_challenge(label)?;
        let mut seed = Vec::with_capacity(32 + 16 + 8);
        seed.extend_from_slice(&self.state);
        seed.extend_from_slice(&label.domain_tag());
        seed.extend_from_slice(&self.challenge_counter.to_le_bytes());
        let mut reader = Blake2sXof::new(&seed);
        reader.squeeze(output).map_err(TranscriptError::from)?;
        self.state = mix(self.state, label, output);
        self.xof = Blake2sXof::from_state(self.state);
        Ok(())
    }

    /// Draws a field element challenge.
    pub fn challenge_field(&mut self, label: TranscriptLabel) -> Result<Felt, TranscriptError> {
        let mut bytes = [0u8; 32];
        self.derive_challenge(label, &mut bytes)?;
        Ok(Felt::from_transcript_bytes(&bytes))
    }

    /// Draws a usize challenge within the specified exclusive range.
    pub fn challenge_usize(
        &mut self,
        label: TranscriptLabel,
        range_exclusive: usize,
    ) -> Result<usize, TranscriptError> {
        if range_exclusive == 0 {
            return Err(TranscriptError::RangeZero);
        }
        let mut bytes = [0u8; 8];
        self.derive_challenge(label, &mut bytes)?;
        let value = u64::from_le_bytes(bytes);
        let result = (value % (range_exclusive as u64)) as usize;
        Ok(result)
    }

    /// Emits `n` random-looking bytes from the transcript.
    pub fn challenge_bytes(
        &mut self,
        label: TranscriptLabel,
        n: usize,
    ) -> Result<Vec<u8>, TranscriptError> {
        let mut output = vec![0u8; n];
        self.derive_challenge(label, &mut output)?;
        Ok(output)
    }

    /// Returns the digest of the current transcript state.
    pub fn state_digest(&self) -> [u8; 32] {
        self.state
    }

    /// Returns the current transcript phase.
    pub fn phase(&self) -> TranscriptPhase {
        self.phase
    }

    /// Exposes the canonical transcript state view for testing.
    #[allow(dead_code)]
    pub(crate) fn snapshot(&self) -> TranscriptStateView {
        TranscriptStateView {
            state: self.state,
            challenge_counter: self.challenge_counter,
            stage: self.tracker.stage.clone(),
            phase: self.phase,
        }
    }

    /// Rewinds the transcript state for deterministic test vectors.
    #[cfg(test)]
    pub fn rewind_for_tests(&mut self, bytes: &[u8]) -> Result<(), TranscriptError> {
        if bytes.len() != 32 {
            return Err(TranscriptError::Serialization(SerKind::State));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(bytes);
        self.state = buf;
        self.xof = Blake2sXof::from_state(self.state);
        Ok(())
    }
}

fn encode_felt(felt: Felt) -> Result<[u8; 32], ()> {
    let value = u64::try_from(felt).map_err(|_| ())?;
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&value.to_le_bytes());
    Ok(out)
}

fn mix(state: [u8; 32], label: TranscriptLabel, data: &[u8]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(32 + 16 + 8 + data.len());
    payload.extend_from_slice(&state);
    payload.extend_from_slice(&label.domain_tag());
    payload.extend_from_slice(&(data.len() as u64).to_le_bytes());
    payload.extend_from_slice(data);
    hash(&payload).into()
}

#[allow(dead_code)]
pub(crate) fn serialize_state(view: &TranscriptStateView) -> Vec<u8> {
    ser::serialize_state(view)
}

#[allow(dead_code)]
pub(crate) fn deserialize_state(bytes: &[u8]) -> Result<TranscriptStateView, TranscriptError> {
    ser::deserialize_state(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{BuiltinProfile, StarkParamsBuilder};

    #[test]
    fn snapshot_serialization_roundtrip() {
        let params = StarkParamsBuilder::from_profile(BuiltinProfile::PROFILE_X8)
            .build()
            .expect("profile");
        let transcript = Transcript::new(&params, TranscriptContext::StarkMain);
        let view = transcript.snapshot();
        let bytes = serialize_state(&view);
        let restored = deserialize_state(&bytes).expect("decode");
        assert_eq!(restored.state, view.state);
        assert_eq!(restored.challenge_counter, view.challenge_counter);
    }
}
