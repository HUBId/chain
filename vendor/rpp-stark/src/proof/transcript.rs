//! Fiat–Shamir transcript implementation backed by BLAKE3.
//!
//! The transcript is split into ordered sections that are absorbed with a
//! four-byte little-endian length prefix. Once the deterministic framing has
//! been completed a challenge stream is derived that yields all randomness used
//! throughout the proof system.  The layout follows the `RPP-FS/V1`
//! specification and is bound to the negotiated [`ParamDigest`].

use crate::config::{
    AirSpecId, ParamDigest, PoseidonParamId, ProofKind, TranscriptVersionId,
    TRANSCRIPT_VERSION_ID_RPP_FS_V1,
};
use crate::hash::{deterministic::DeterministicHashError, Hasher};

/// Domain tag absorbed as the very first section of every transcript.
const TRANSCRIPT_DOMAIN_TAG: &[u8] = b"RPP-FS/V1";

/// Convenience result alias for transcript operations.
pub type TranscriptResult<T> = Result<T, TranscriptError>;

/// Canonical transcript version identifier used by Phase 3.
pub const TRANSCRIPT_VERSION: Blake3TranscriptVersion = Blake3TranscriptVersion::V1;

/// Canonical transcript sections absorbed during proof generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscriptSectionLayout;

impl TranscriptSectionLayout {
    /// Ordered list of transcript sections.
    pub const ORDER: &'static [Blake3TranscriptSection; 5] = Blake3TranscriptSpec::SECTIONS;
    /// Description of the framing rule.
    pub const FRAMING: &'static str = Blake3TranscriptSpec::FRAMING_RULE;
}

/// Transcript phase tags inserted between major protocol stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscriptPhaseRules;

impl TranscriptPhaseRules {
    /// Order of phase tags.
    pub const ORDER: &'static [TranscriptPhaseTag; 2] =
        &[TranscriptPhaseTag::Air, TranscriptPhaseTag::Fri];

    /// Description of reseeding behaviour.
    pub const RESEED_RULE: &'static str =
        "Insert RPP-PHASE-AIR before AIR sections and RPP-PHASE-FRI before FRI sections";
}

/// Specification of the transcript seed derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscriptSeedSpec;

impl TranscriptSeedSpec {
    /// Formula for deriving the initial seed.
    pub const INITIAL_SEED_RULE: &'static str =
        "seed_0 = BLAKE3(domain_prefix || ParamDigest || block_context)";

    /// Formula for deriving seeds per proof kind.
    pub const KIND_SEED_RULE: &'static str = "seed_kind = BLAKE3(seed_0 || ProofKind.code())";
}

/// Challenge derivation specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeDerivationSpec;

impl ChallengeDerivationSpec {
    /// Description of challenge extraction.
    pub const RULE: &'static str = FiatShamirChallengeRules::DESCRIPTION;

    /// Mapping between phases and challenge draws.
    pub const PHASE_CHALLENGES: &'static [&'static str] = &[
        "AIR: α-vector",
        "FRI: query positions",
        "FINAL: integrity salt",
    ];

    /// Poseidon parameter domain separation hint.
    pub const DOMAIN_HINT: &'static str = FiatShamirChallengeRules::SALT_PREFIX;
}

/// Metadata bound into the transcript header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptHeader {
    /// Transcript version identifier.
    pub version: TranscriptVersionId,
    /// Poseidon parameter identifier used for challenges.
    pub poseidon_param_id: PoseidonParamId,
    /// AIR specification identifier.
    pub air_spec_id: AirSpecId,
    /// Proof kind currently being processed.
    pub proof_kind: ProofKind,
    /// Parameter hash binding global configuration.
    pub params_hash: ParamDigest,
}

/// Block context fields absorbed into the transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptBlockContext {
    /// Block height (little-endian u64).
    pub block_height: u64,
    /// Previous state root (32 bytes).
    pub previous_state_root: [u8; 32],
    /// Network identifier (little-endian u32).
    pub network_id: u32,
}

/// Label used to denote challenge draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChallengeLabel(pub &'static str);

/// Builder trait that finalizes a transcript into a challenge stream.
pub trait ChallengeDeriver {
    /// Concrete challenge stream implementation returned by the builder.
    type Stream: ChallengeStream;

    /// Finalizes the transcript and produces the challenge stream.
    fn into_stream(self) -> TranscriptResult<Self::Stream>;
}

/// Streaming interface for deterministic challenge extraction.
pub trait ChallengeStream {
    /// Fills `output` with challenge bytes associated with `label` using the
    /// deterministic chaining rules captured in [`ChallengeDerivationSpec`].
    fn draw_challenge(&mut self, label: ChallengeLabel, output: &mut [u8]) -> TranscriptResult<()>;
}

/// Documentation of transcript validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptValidationError {
    /// Sections were emitted in a non-canonical order.
    SectionOrderMismatch,
    /// Encountered an invalid length prefix.
    LengthPrefixInvalid,
    /// Domain tag did not match the negotiated ASCII prefix.
    UnknownDomainTag,
    /// Parameter digest disagreed with the negotiated digest.
    ParameterDigestMismatch,
    /// Encountered an unknown phase tag while restarting sections.
    UnknownPhaseTag,
}

use crate::hash::blake3::{
    Blake3TranscriptSection, Blake3TranscriptSpec, Blake3TranscriptVersion,
    FiatShamirChallengeRules, TranscriptPhaseTag,
};

/// Internal stage tracker describing the section ordering requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TranscriptStage {
    /// Awaiting the public input section.
    ExpectPublicInputs,
    /// VRF metadata is required before commitment roots.
    ExpectVrfMetadata,
    /// Expecting commitment roots (core and optional auxiliary).
    ExpectCommitmentRoots,
    /// Waiting for the AIR specification identifier.
    ExpectAirSpecId,
    /// Optional block context absorption.
    ExpectBlockContext,
    /// All sections absorbed; challenge derivation may begin.
    ReadyForChallenges,
}

impl TranscriptStage {
    fn as_str(self) -> &'static str {
        match self {
            TranscriptStage::ExpectPublicInputs => "public_inputs",
            TranscriptStage::ExpectVrfMetadata => "vrf_metadata",
            TranscriptStage::ExpectCommitmentRoots => "commitment_roots",
            TranscriptStage::ExpectAirSpecId => "air_spec_id",
            TranscriptStage::ExpectBlockContext => "block_context",
            TranscriptStage::ReadyForChallenges => "challenge_phase",
        }
    }
}

/// Transcript absorption state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcript {
    stage: TranscriptStage,
    state: [u8; 32],
    proof_kind: ProofKind,
    vrf_required: bool,
    vrf_present: bool,
}

/// Error type surfaced by the transcript implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptError {
    /// Sections were emitted out of order.
    ErrTranscriptOrder {
        /// Section that was expected next.
        expected: &'static str,
        /// Section that was attempted instead.
        found: &'static str,
    },
    /// Challenge counters were inconsistent (e.g. missing OOD points).
    ErrChallengeCount {
        /// Label associated with the mismatch.
        label: &'static str,
        /// Expected counter value.
        expected: usize,
        /// Observed counter value.
        actual: usize,
    },
    /// Transcript version did not match `RPP_FS_V1`.
    UnsupportedTranscriptVersion,
    /// VRF proofs require additional metadata.
    MissingVrfMetadata,
    /// Deterministic hashing helper failed while deriving challenges.
    DeterministicHash(DeterministicHashError),
}

impl core::fmt::Display for TranscriptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TranscriptError::ErrTranscriptOrder { expected, found } => {
                write!(
                    f,
                    "transcript section order mismatch: expected {expected}, found {found}"
                )
            }
            TranscriptError::ErrChallengeCount {
                label,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "challenge count mismatch for {label}: expected {expected}, observed {actual}"
                )
            }
            TranscriptError::UnsupportedTranscriptVersion => {
                write!(f, "unsupported transcript version")
            }
            TranscriptError::MissingVrfMetadata => {
                write!(f, "missing VRF metadata before commitment roots")
            }
            TranscriptError::DeterministicHash(err) => {
                write!(f, "deterministic hash error: {err}")
            }
        }
    }
}

impl std::error::Error for TranscriptError {}

impl From<DeterministicHashError> for TranscriptError {
    fn from(err: DeterministicHashError) -> Self {
        TranscriptError::DeterministicHash(err)
    }
}

impl Transcript {
    /// Instantiates a new transcript from the provided header.
    pub fn new(header: TranscriptHeader) -> TranscriptResult<Self> {
        if header.version != TRANSCRIPT_VERSION_ID_RPP_FS_V1 {
            return Err(TranscriptError::UnsupportedTranscriptVersion);
        }

        let mut transcript = Self {
            stage: TranscriptStage::ExpectPublicInputs,
            state: [0u8; 32],
            proof_kind: header.proof_kind,
            vrf_required: matches!(header.proof_kind, ProofKind::VRF),
            vrf_present: false,
        };

        transcript.absorb_section_raw(TRANSCRIPT_DOMAIN_TAG);
        let proof_kind_code = transcript.proof_kind_code();
        transcript.absorb_section_raw(&proof_kind_code);
        transcript.absorb_section_raw(header.params_hash.as_bytes());

        Ok(transcript)
    }

    /// Absorbs the canonical public input encoding.
    pub fn absorb_public_inputs(&mut self, bytes: &[u8]) -> TranscriptResult<()> {
        self.ensure_stage(TranscriptStage::ExpectPublicInputs, "public_inputs")?;
        self.absorb_section_raw(bytes);
        self.stage = if self.vrf_required {
            TranscriptStage::ExpectVrfMetadata
        } else {
            TranscriptStage::ExpectCommitmentRoots
        };
        Ok(())
    }

    /// Absorbs VRF specific metadata (public key, input and PRF parameter digest).
    pub fn absorb_vrf_metadata(
        &mut self,
        vrf_public_key: &[u8],
        vrf_input: &[u8],
        prf_param_digest: [u8; 32],
    ) -> TranscriptResult<()> {
        if !self.vrf_required {
            return Err(TranscriptError::ErrTranscriptOrder {
                expected: "commitment_roots",
                found: self.stage.as_str(),
            });
        }

        self.ensure_stage(TranscriptStage::ExpectVrfMetadata, "vrf_metadata")?;

        let mut payload =
            Vec::with_capacity(8 + vrf_public_key.len() + vrf_input.len() + prf_param_digest.len());
        payload.extend_from_slice(&(vrf_public_key.len() as u32).to_le_bytes());
        payload.extend_from_slice(vrf_public_key);
        payload.extend_from_slice(&(vrf_input.len() as u32).to_le_bytes());
        payload.extend_from_slice(vrf_input);
        payload.extend_from_slice(&prf_param_digest);

        self.absorb_section_raw(&payload);
        self.stage = TranscriptStage::ExpectCommitmentRoots;
        self.vrf_present = true;
        Ok(())
    }

    /// Absorbs commitment roots (core root and optional auxiliary root).
    pub fn absorb_commitment_roots(
        &mut self,
        core_root: [u8; 32],
        aux_root: Option<[u8; 32]>,
    ) -> TranscriptResult<()> {
        match self.stage {
            TranscriptStage::ExpectCommitmentRoots => {}
            TranscriptStage::ExpectVrfMetadata => {
                return Err(TranscriptError::MissingVrfMetadata);
            }
            stage => {
                return Err(TranscriptError::ErrTranscriptOrder {
                    expected: "commitment_roots",
                    found: stage.as_str(),
                });
            }
        }

        self.absorb_section_raw(&core_root);
        if let Some(aux) = aux_root {
            self.absorb_section_raw(&aux);
        } else {
            self.absorb_section_raw(&[]);
        }
        self.stage = TranscriptStage::ExpectAirSpecId;
        Ok(())
    }

    /// Absorbs the AIR specification identifier associated with the proof kind.
    pub fn absorb_air_spec_id(&mut self, air_spec_id: AirSpecId) -> TranscriptResult<()> {
        self.ensure_stage(TranscriptStage::ExpectAirSpecId, "air_spec_id")?;
        let bytes = air_spec_id.bytes().bytes;
        self.absorb_section_raw(&bytes);
        self.stage = TranscriptStage::ExpectBlockContext;
        Ok(())
    }

    /// Absorbs the optional block context (height, previous state root, network id).
    pub fn absorb_block_context(
        &mut self,
        block_context: Option<TranscriptBlockContext>,
    ) -> TranscriptResult<()> {
        self.ensure_stage(TranscriptStage::ExpectBlockContext, "block_context")?;
        if let Some(context) = block_context {
            let mut payload = Vec::with_capacity(8 + 32 + 4);
            payload.extend_from_slice(&context.block_height.to_le_bytes());
            payload.extend_from_slice(&context.previous_state_root);
            payload.extend_from_slice(&context.network_id.to_le_bytes());
            self.absorb_section_raw(&payload);
        } else {
            self.absorb_section_raw(&[]);
        }
        self.stage = TranscriptStage::ReadyForChallenges;
        Ok(())
    }

    /// Finalises the transcript and returns a deterministic challenge stream.
    pub fn finalize(mut self) -> TranscriptResult<TranscriptChallenges> {
        if self.stage == TranscriptStage::ExpectBlockContext {
            self.absorb_block_context(None)?;
        }

        if self.stage == TranscriptStage::ExpectVrfMetadata {
            return Err(TranscriptError::MissingVrfMetadata);
        }

        if self.stage != TranscriptStage::ReadyForChallenges {
            return Err(TranscriptError::ErrTranscriptOrder {
                expected: "challenge_phase",
                found: self.stage.as_str(),
            });
        }

        if self.vrf_required && !self.vrf_present {
            return Err(TranscriptError::MissingVrfMetadata);
        }

        Ok(TranscriptChallenges::new(self.state))
    }

    /// Helper ensuring the transcript is in the expected stage.
    fn ensure_stage(&self, expected: TranscriptStage, label: &'static str) -> TranscriptResult<()> {
        if self.stage != expected {
            if self.vrf_required && expected == TranscriptStage::ExpectVrfMetadata {
                return Err(TranscriptError::MissingVrfMetadata);
            }

            return Err(TranscriptError::ErrTranscriptOrder {
                expected: label,
                found: self.stage.as_str(),
            });
        }
        Ok(())
    }

    /// Absorbs a raw byte slice using the transcript chaining rule.
    fn absorb_section_raw(&mut self, payload: &[u8]) {
        let mut hasher = Hasher::new();
        hasher.update(&self.state);
        hasher.update(&(payload.len() as u32).to_le_bytes());
        hasher.update(payload);
        self.state.copy_from_slice(hasher.finalize().as_bytes());
    }

    /// Returns the canonical proof kind code used in the transcript.
    fn proof_kind_code(&self) -> [u8; 1] {
        [match self.proof_kind {
            ProofKind::Tx => 0,
            ProofKind::State => 1,
            ProofKind::Pruning => 2,
            ProofKind::Uptime => 3,
            ProofKind::Consensus => 4,
            ProofKind::Identity => 5,
            ProofKind::Aggregation => 6,
            ProofKind::VRF => 7,
        }]
    }
}

impl ChallengeDeriver for Transcript {
    type Stream = TranscriptChallenges;

    fn into_stream(self) -> TranscriptResult<Self::Stream> {
        self.finalize()
    }
}

/// Challenge stream derived from the transcript state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptChallenges {
    state: [u8; 32],
    next_alpha: usize,
    alpha_finished: bool,
    next_ood: usize,
    ood_points: usize,
    ood_seed_drawn: bool,
    next_fri_eta: usize,
    fri_seed_drawn: bool,
    query_seed_drawn: bool,
}

impl TranscriptChallenges {
    fn new(state: [u8; 32]) -> Self {
        Self {
            state,
            next_alpha: 0,
            alpha_finished: false,
            next_ood: 1,
            ood_points: 0,
            ood_seed_drawn: false,
            next_fri_eta: 0,
            fri_seed_drawn: false,
            query_seed_drawn: false,
        }
    }

    /// Draws an α-vector consisting of `count` challenges.
    pub fn draw_alpha_vector(&mut self, count: usize) -> TranscriptResult<Vec<[u8; 32]>> {
        if count == 0 {
            return Err(TranscriptError::ErrChallengeCount {
                label: "RPP-FS/C*",
                expected: 1,
                actual: 0,
            });
        }

        let mut challenges = Vec::with_capacity(count);
        for _ in 0..count {
            let label = format!("RPP-FS/C{}", self.next_alpha);
            let mut bytes = [0u8; 32];
            self.draw_label(&label, &mut bytes)?;
            challenges.push(bytes);
            self.next_alpha += 1;
        }

        Ok(challenges)
    }

    /// Draws OOD points, enforcing the canonical numbering starting at ζ₁.
    pub fn draw_ood_points(&mut self, count: usize) -> TranscriptResult<Vec<[u8; 32]>> {
        if count < 2 {
            return Err(TranscriptError::ErrChallengeCount {
                label: "RPP-FS/Cζ*",
                expected: 2,
                actual: count,
            });
        }

        if self.next_alpha == 0 {
            return Err(TranscriptError::ErrTranscriptOrder {
                expected: "alpha_vector",
                found: "ood_points",
            });
        }

        self.alpha_finished = true;
        let mut challenges = Vec::with_capacity(count);
        for _ in 0..count {
            let label = format!("RPP-FS/Cζ{}", self.next_ood);
            let mut bytes = [0u8; 32];
            self.draw_label(&label, &mut bytes)?;
            challenges.push(bytes);
            self.next_ood += 1;
            self.ood_points += 1;
        }
        Ok(challenges)
    }

    /// Draws the OOD seed, ensuring at least two OOD points were sampled.
    pub fn draw_ood_seed(&mut self) -> TranscriptResult<[u8; 32]> {
        if self.ood_points < 2 {
            return Err(TranscriptError::ErrChallengeCount {
                label: "RPP-FS/OOD-SEED",
                expected: 2,
                actual: self.ood_points,
            });
        }

        if self.ood_seed_drawn {
            return Err(TranscriptError::ErrTranscriptOrder {
                expected: "fri_seed",
                found: "ood_seed",
            });
        }

        self.ood_seed_drawn = true;
        let mut seed = [0u8; 32];
        self.draw_label("RPP-FS/OOD-SEED", &mut seed)?;
        Ok(seed)
    }

    /// Draws the FRI seed after the last layer commitment.
    pub fn draw_fri_seed(&mut self) -> TranscriptResult<[u8; 32]> {
        if !self.ood_seed_drawn {
            return Err(TranscriptError::ErrTranscriptOrder {
                expected: "ood_seed",
                found: "fri_seed",
            });
        }

        if self.fri_seed_drawn {
            return Err(TranscriptError::ErrTranscriptOrder {
                expected: "query_seed",
                found: "fri_seed",
            });
        }

        self.fri_seed_drawn = true;
        let mut seed = [0u8; 32];
        self.draw_label("RPP-FS/FRI-SEED", &mut seed)?;
        Ok(seed)
    }

    /// Draws the query seed used for Merkle openings.
    pub fn draw_query_seed(&mut self) -> TranscriptResult<[u8; 32]> {
        if !self.fri_seed_drawn {
            return Err(TranscriptError::ErrTranscriptOrder {
                expected: "fri_seed",
                found: "query_seed",
            });
        }

        if self.query_seed_drawn {
            return Err(TranscriptError::ErrTranscriptOrder {
                expected: "completed",
                found: "query_seed",
            });
        }

        self.query_seed_drawn = true;
        let mut seed = [0u8; 32];
        self.draw_label("RPP-FS/QUERY-SEED", &mut seed)?;
        Ok(seed)
    }

    /// Draws the η challenge for a given FRI layer index.
    pub fn draw_fri_eta(&mut self, layer: usize) -> TranscriptResult<[u8; 32]> {
        if !self.ood_seed_drawn {
            return Err(TranscriptError::ErrTranscriptOrder {
                expected: "ood_seed",
                found: "fri_eta",
            });
        }

        if !self.fri_seed_drawn {
            return Err(TranscriptError::ErrTranscriptOrder {
                expected: "fri_seed",
                found: "fri_eta",
            });
        }

        if layer != self.next_fri_eta {
            return Err(TranscriptError::ErrChallengeCount {
                label: "RPP-FS/FRI/η*",
                expected: self.next_fri_eta,
                actual: layer,
            });
        }

        let label = format!("RPP-FS/FRI/η{}", layer);
        let mut bytes = [0u8; 32];
        self.draw_label(&label, &mut bytes)?;
        self.next_fri_eta += 1;
        Ok(bytes)
    }

    /// Internal helper drawing a challenge labelled by an arbitrary string.
    fn draw_label(&mut self, label: &str, output: &mut [u8]) -> TranscriptResult<()> {
        self.update_state(label, output)
    }

    fn update_state(&mut self, label: &str, output: &mut [u8]) -> TranscriptResult<()> {
        let mut hasher = Hasher::new();
        hasher.update(&self.state);
        hasher.update(label.as_bytes());
        let mut reader = hasher.finalize_xof();
        reader
            .fill(&mut self.state)
            .map_err(TranscriptError::from)?;
        reader.fill(output).map_err(TranscriptError::from)?;
        Ok(())
    }
}

impl ChallengeStream for TranscriptChallenges {
    fn draw_challenge(&mut self, label: ChallengeLabel, output: &mut [u8]) -> TranscriptResult<()> {
        let label_str = label.0;

        if let Some(index_str) = label_str.strip_prefix("RPP-FS/Cζ") {
            let index =
                index_str
                    .parse::<usize>()
                    .map_err(|_| TranscriptError::ErrTranscriptOrder {
                        expected: "ood_index",
                        found: "non_numeric",
                    })?;
            if index != self.next_ood {
                return Err(TranscriptError::ErrChallengeCount {
                    label: "RPP-FS/Cζ*",
                    expected: self.next_ood,
                    actual: index,
                });
            }
            if self.next_alpha == 0 {
                return Err(TranscriptError::ErrTranscriptOrder {
                    expected: "alpha_vector",
                    found: "ood_points",
                });
            }
            self.alpha_finished = true;
            self.next_ood += 1;
            self.ood_points += 1;
        } else if let Some(index_str) = label_str.strip_prefix("RPP-FS/C") {
            if self.alpha_finished {
                return Err(TranscriptError::ErrTranscriptOrder {
                    expected: "ood_points",
                    found: "alpha_vector",
                });
            }
            let index =
                index_str
                    .parse::<usize>()
                    .map_err(|_| TranscriptError::ErrTranscriptOrder {
                        expected: "alpha_index",
                        found: "non_numeric",
                    })?;
            if index != self.next_alpha {
                return Err(TranscriptError::ErrChallengeCount {
                    label: "RPP-FS/C*",
                    expected: self.next_alpha,
                    actual: index,
                });
            }
            self.next_alpha += 1;
        } else if label_str == "RPP-FS/OOD-SEED" {
            if self.ood_points < 2 {
                return Err(TranscriptError::ErrChallengeCount {
                    label: "RPP-FS/OOD-SEED",
                    expected: 2,
                    actual: self.ood_points,
                });
            }
            if self.ood_seed_drawn {
                return Err(TranscriptError::ErrTranscriptOrder {
                    expected: "fri_seed",
                    found: "ood_seed",
                });
            }
            self.ood_seed_drawn = true;
        } else if let Some(index_str) = label_str.strip_prefix("RPP-FS/FRI/η") {
            if !self.ood_seed_drawn {
                return Err(TranscriptError::ErrTranscriptOrder {
                    expected: "ood_seed",
                    found: "fri_eta",
                });
            }
            if !self.fri_seed_drawn {
                return Err(TranscriptError::ErrTranscriptOrder {
                    expected: "fri_seed",
                    found: "fri_eta",
                });
            }
            let index =
                index_str
                    .parse::<usize>()
                    .map_err(|_| TranscriptError::ErrTranscriptOrder {
                        expected: "fri_eta_index",
                        found: "non_numeric",
                    })?;
            if index != self.next_fri_eta {
                return Err(TranscriptError::ErrChallengeCount {
                    label: "RPP-FS/FRI/η*",
                    expected: self.next_fri_eta,
                    actual: index,
                });
            }
            self.next_fri_eta += 1;
        } else if label_str == "RPP-FS/FRI-SEED" {
            if !self.ood_seed_drawn {
                return Err(TranscriptError::ErrTranscriptOrder {
                    expected: "ood_seed",
                    found: "fri_seed",
                });
            }
            if self.fri_seed_drawn {
                return Err(TranscriptError::ErrTranscriptOrder {
                    expected: "query_seed",
                    found: "fri_seed",
                });
            }
            self.fri_seed_drawn = true;
        } else if label_str == "RPP-FS/QUERY-SEED" {
            if !self.fri_seed_drawn {
                return Err(TranscriptError::ErrTranscriptOrder {
                    expected: "fri_seed",
                    found: "query_seed",
                });
            }
            if self.query_seed_drawn {
                return Err(TranscriptError::ErrTranscriptOrder {
                    expected: "completed",
                    found: "query_seed",
                });
            }
            self.query_seed_drawn = true;
        }

        self.update_state(label_str, output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PoseidonParamId, ProofKind, TRANSCRIPT_VERSION_ID_RPP_FS_V1};
    use crate::utils::serialization::DigestBytes;

    fn digest(byte: u8) -> DigestBytes {
        DigestBytes { bytes: [byte; 32] }
    }

    fn make_header(kind: ProofKind, param_byte: u8) -> TranscriptHeader {
        TranscriptHeader {
            version: TRANSCRIPT_VERSION_ID_RPP_FS_V1,
            poseidon_param_id: PoseidonParamId(digest(2)),
            air_spec_id: AirSpecId(digest(3)),
            proof_kind: kind,
            params_hash: ParamDigest(digest(param_byte)),
        }
    }

    #[test]
    fn order_mismatch_is_detected() {
        let header = make_header(ProofKind::Tx, 10);
        let mut transcript = Transcript::new(header).expect("transcript");

        let err = transcript
            .absorb_commitment_roots([1; 32], None)
            .expect_err("order mismatch");
        assert!(matches!(err, TranscriptError::ErrTranscriptOrder { .. }));
    }

    #[test]
    fn determinism_across_runs() {
        let header = make_header(ProofKind::Tx, 42);
        let mut t1 = Transcript::new(header.clone()).unwrap();
        let mut t2 = Transcript::new(header).unwrap();

        let public_inputs = b"public";
        t1.absorb_public_inputs(public_inputs).unwrap();
        t2.absorb_public_inputs(public_inputs).unwrap();

        let core_root = [5u8; 32];
        t1.absorb_commitment_roots(core_root, None).unwrap();
        t2.absorb_commitment_roots(core_root, None).unwrap();

        t1.absorb_air_spec_id(AirSpecId(digest(3))).unwrap();
        t2.absorb_air_spec_id(AirSpecId(digest(3))).unwrap();

        let mut stream1 = t1.finalize().unwrap();
        let mut stream2 = t2.finalize().unwrap();

        let alpha1 = stream1.draw_alpha_vector(3).unwrap();
        let alpha2 = stream2.draw_alpha_vector(3).unwrap();
        assert_eq!(alpha1, alpha2);

        let ood1 = stream1.draw_ood_points(2).unwrap();
        let ood2 = stream2.draw_ood_points(2).unwrap();
        assert_eq!(ood1, ood2);

        let seed1 = stream1.draw_query_seed().expect_err("fri seed required");
        assert!(matches!(seed1, TranscriptError::ErrTranscriptOrder { .. }));
    }

    #[test]
    fn vrf_requires_metadata() {
        let header = make_header(ProofKind::VRF, 11);
        let mut transcript = Transcript::new(header).unwrap();
        transcript.absorb_public_inputs(b"input").unwrap();

        let err = transcript.finalize().expect_err("missing metadata");
        assert!(matches!(err, TranscriptError::MissingVrfMetadata));
    }

    #[test]
    fn param_digest_changes_affect_challenges() {
        let mut t1 = Transcript::new(make_header(ProofKind::Tx, 1)).unwrap();
        t1.absorb_public_inputs(b"").unwrap();
        t1.absorb_commitment_roots([0u8; 32], None).unwrap();
        t1.absorb_air_spec_id(AirSpecId(digest(3))).unwrap();
        let mut s1 = t1.finalize().unwrap();

        let mut t2 = Transcript::new(make_header(ProofKind::Tx, 2)).unwrap();
        t2.absorb_public_inputs(b"").unwrap();
        t2.absorb_commitment_roots([0u8; 32], None).unwrap();
        t2.absorb_air_spec_id(AirSpecId(digest(3))).unwrap();
        let mut s2 = t2.finalize().unwrap();

        let mut c1 = [0u8; 32];
        let mut c2 = [0u8; 32];
        s1.draw_challenge(ChallengeLabel("RPP-FS/C0"), &mut c1)
            .unwrap();
        s2.draw_challenge(ChallengeLabel("RPP-FS/C0"), &mut c2)
            .unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn ood_seed_requires_two_points() {
        let header = make_header(ProofKind::Tx, 5);
        let mut transcript = Transcript::new(header).unwrap();
        transcript.absorb_public_inputs(&[]).unwrap();
        transcript.absorb_commitment_roots([0; 32], None).unwrap();
        transcript.absorb_air_spec_id(AirSpecId(digest(3))).unwrap();
        let mut stream = transcript.finalize().unwrap();
        stream.draw_alpha_vector(1).unwrap();

        let err = stream.draw_ood_seed().expect_err("need two points");
        assert!(matches!(err, TranscriptError::ErrChallengeCount { .. }));
    }

    #[test]
    fn transcript_rejects_query_seed_without_fri_seed() {
        let header = make_header(ProofKind::Tx, 7);
        let mut transcript = Transcript::new(header).unwrap();
        transcript.absorb_public_inputs(&[]).unwrap();
        transcript.absorb_commitment_roots([0; 32], None).unwrap();
        transcript.absorb_air_spec_id(AirSpecId(digest(3))).unwrap();
        let mut stream = transcript.finalize().unwrap();
        stream.draw_alpha_vector(2).unwrap();
        stream.draw_ood_points(2).unwrap();
        stream.draw_ood_seed().unwrap();

        let err = stream
            .draw_query_seed()
            .expect_err("fri seed must precede query seed");
        assert!(matches!(err, TranscriptError::ErrTranscriptOrder { .. }));
    }

    #[test]
    fn transcript_rejects_duplicate_fri_seed_draws() {
        let header = make_header(ProofKind::Tx, 9);
        let mut transcript = Transcript::new(header).unwrap();
        transcript.absorb_public_inputs(&[]).unwrap();
        transcript.absorb_commitment_roots([0; 32], None).unwrap();
        transcript.absorb_air_spec_id(AirSpecId(digest(3))).unwrap();
        let mut stream = transcript.finalize().unwrap();
        stream.draw_alpha_vector(2).unwrap();
        stream.draw_ood_points(2).unwrap();
        stream.draw_ood_seed().unwrap();
        let _ = stream.draw_fri_seed().unwrap();

        let err = stream
            .draw_fri_seed()
            .expect_err("second fri seed draw must fail");
        assert!(matches!(err, TranscriptError::ErrTranscriptOrder { .. }));
    }
}
