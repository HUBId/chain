//! Binary FRI prover and verifier implementation.
//!
//! The prover operates purely in-memory and produces fully deterministic proofs
//! that can be re-verified using the [`FriVerifier`] helper.  Hashing and query
//! sampling rely on the deterministic Blake2s primitives from [`crate::fri`], keeping the
//! implementation self-contained and dependency free.

use crate::field::prime_field::{CanonicalSerialize, FieldDeserializeError};
use crate::field::FieldElement;
use crate::fri::types::{
    FriError, FriParamsView, FriProofVersion, FriSecurityLevel, FriTranscriptSeed, SerKind,
};
use crate::fri::{
    binary_fold, coset_shift_schedule, next_domain_size, parent_index, FriLayer, BINARY_FOLD_ARITY,
};
use crate::fri::{field_from_hash, field_to_bytes, hash, Blake2sXof};
use crate::hash::blake3::FiatShamirChallengeRules;
use crate::hash::merkle::{
    compute_root_from_path, encode_leaf, MerkleError, MerkleIndex, MerklePathElement, DIGEST_SIZE,
};
use crate::params::{BuiltinProfile, StarkParams, StarkParamsBuilder};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::sync::OnceLock;

/// Number of bytes used to encode a field element in canonical little-endian order.
const FIELD_BYTES: usize = core::mem::size_of::<u64>();

/// Little-endian flag signalling that a DEEP/OODS payload follows the proof body.
const OODS_FLAG_PRESENT: u8 = 1;
/// Little-endian flag signalling the absence of DEEP/OODS payload.
const OODS_FLAG_ABSENT: u8 = 0;

/// Deterministic representation of the DEEP out-of-domain sampling payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeepOodsProof {
    /// Point at which the composition polynomial is evaluated.
    pub point: FieldElement,
    /// Evaluations collected at the DEEP sample.
    pub evaluations: Vec<FieldElement>,
}

impl DeepOodsProof {
    fn validate(&self) -> Result<(), FriError> {
        if self.evaluations.len() > u16::MAX as usize {
            return Err(FriError::InvalidStructure(
                "DEEP/OODS evaluation length overflow",
            ));
        }
        Ok(())
    }
}

/// Opening data for a specific FRI layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriQueryLayerProof {
    /// Evaluation revealed at this layer.
    pub value: FieldElement,
    /// Merkle authentication path proving membership.
    pub path: Vec<MerklePathElement>,
}

impl FriQueryLayerProof {
    fn validate(&self) -> Result<(), FriError> {
        if self.path.len() > u8::MAX as usize {
            return Err(FriError::InvalidStructure("layer path length overflow"));
        }
        for element in &self.path {
            if element.index.0 > MerkleIndex::MAX {
                return Err(FriError::InvalidStructure("invalid Merkle index byte"));
            }
            if element.siblings.len() != 1 {
                return Err(FriError::InvalidStructure("unsupported Merkle arity"));
            }
        }
        Ok(())
    }
}

/// Declarative representation of a single query opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriQueryProof {
    /// Position sampled from the LDE domain.
    pub position: usize,
    /// Layer openings ascending from the original codeword to the residual layer.
    pub layers: Vec<FriQueryLayerProof>,
    /// Value revealed at the residual polynomial for this query.
    pub final_value: FieldElement,
}

impl FriQueryProof {
    fn validate(&self, layer_count: usize, domain_size: usize) -> Result<(), FriError> {
        if self.position >= domain_size {
            return Err(FriError::InvalidStructure("query position outside domain"));
        }
        if self.layers.len() != layer_count {
            return Err(FriError::InvalidStructure("query missing layer openings"));
        }
        if self.layers.len() > u16::MAX as usize {
            return Err(FriError::InvalidStructure("query layer count overflow"));
        }
        for layer in &self.layers {
            layer.validate()?;
        }
        Ok(())
    }
}

/// Declarative representation of a FRI proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriProof {
    /// Declared proof version.
    pub version: FriProofVersion,
    /// Declared security profile for the proof.
    pub security_level: FriSecurityLevel,
    /// Size of the initial evaluation domain.
    pub initial_domain_size: usize,
    /// Merkle roots for each folded layer.
    pub layer_roots: Vec<[u8; 32]>,
    /// Transcript fold challenges sampled after each layer commitment.
    pub fold_challenges: Vec<FieldElement>,
    /// Residual polynomial evaluations.
    pub final_polynomial: Vec<FieldElement>,
    /// Digest binding the final polynomial values.
    pub final_polynomial_digest: [u8; 32],
    /// Query openings.
    pub queries: Vec<FriQueryProof>,
    /// Optional DEEP/OODS sampling payload.
    pub deep_oods: Option<DeepOodsProof>,
}

impl FriProof {
    /// Constructs a proof and validates the structural invariants mandated by the spec.
    pub fn new(
        security_level: FriSecurityLevel,
        initial_domain_size: usize,
        layer_roots: Vec<[u8; 32]>,
        fold_challenges: Vec<FieldElement>,
        final_polynomial: Vec<FieldElement>,
        final_polynomial_digest: [u8; 32],
        queries: Vec<FriQueryProof>,
    ) -> Result<Self, FriError> {
        Self::with_deep_oods(
            security_level,
            initial_domain_size,
            layer_roots,
            fold_challenges,
            final_polynomial,
            final_polynomial_digest,
            queries,
            None,
        )
    }

    /// Constructs a proof with an optional DEEP/OODS payload.
    #[allow(clippy::too_many_arguments)]
    pub fn with_deep_oods(
        security_level: FriSecurityLevel,
        initial_domain_size: usize,
        layer_roots: Vec<[u8; 32]>,
        fold_challenges: Vec<FieldElement>,
        final_polynomial: Vec<FieldElement>,
        final_polynomial_digest: [u8; 32],
        queries: Vec<FriQueryProof>,
        deep_oods: Option<DeepOodsProof>,
    ) -> Result<Self, FriError> {
        let proof = Self {
            version: FriProofVersion::CURRENT,
            security_level,
            initial_domain_size,
            layer_roots,
            fold_challenges,
            final_polynomial,
            final_polynomial_digest,
            queries,
            deep_oods,
        };
        proof.validate()?;
        Ok(proof)
    }

    fn validate(&self) -> Result<(), FriError> {
        if self.version != FriProofVersion::CURRENT {
            return Err(FriError::VersionMismatch {
                expected: FriProofVersion::CURRENT,
                actual: self.version,
            });
        }

        if self.initial_domain_size == 0 || !self.initial_domain_size.is_power_of_two() {
            return Err(FriError::InvalidStructure(
                "initial domain size must be a power of two",
            ));
        }

        if self.layer_roots.len() != self.fold_challenges.len() {
            return Err(FriError::InvalidStructure("fold challenges count mismatch"));
        }

        if self.layer_roots.len() > u16::MAX as usize {
            return Err(FriError::InvalidStructure("layer count overflow"));
        }

        if self.final_polynomial.len() > u16::MAX as usize {
            return Err(FriError::InvalidStructure(
                "final polynomial length overflow",
            ));
        }

        if self.queries.len() > u16::MAX as usize {
            return Err(FriError::InvalidStructure("query count overflow"));
        }

        for query in &self.queries {
            query.validate(self.layer_roots.len(), self.initial_domain_size)?;
        }

        if let Some(oods) = &self.deep_oods {
            oods.validate()?;
        }

        Ok(())
    }

    /// Serializes the proof into the canonical little-endian representation.
    pub fn to_bytes(&self) -> Result<Vec<u8>, FriError> {
        self.validate()?;
        let layer_count = self.layer_roots.len();
        let mut buffer = Vec::new();

        buffer.extend_from_slice(&self.version.to_u16().to_le_bytes());
        buffer.push(self.security_level.code());
        buffer.extend_from_slice(&domain_log2(self.initial_domain_size)?.to_le_bytes());
        buffer.extend_from_slice(&(layer_count as u16).to_le_bytes());
        buffer.extend_from_slice(&(self.fold_challenges.len() as u16).to_le_bytes());
        buffer.extend_from_slice(&(self.queries.len() as u16).to_le_bytes());
        buffer.extend_from_slice(&(self.final_polynomial.len() as u16).to_le_bytes());
        buffer.push(match self.deep_oods {
            Some(_) => OODS_FLAG_PRESENT,
            None => OODS_FLAG_ABSENT,
        });

        for root in &self.layer_roots {
            buffer.extend_from_slice(root);
        }

        for challenge in &self.fold_challenges {
            buffer.extend_from_slice(&field_to_bytes(challenge)?);
        }

        buffer.extend_from_slice(&self.final_polynomial_digest);

        for value in &self.final_polynomial {
            buffer.extend_from_slice(&field_to_bytes(value)?);
        }

        for query in &self.queries {
            buffer.extend_from_slice(&(query.position as u32).to_le_bytes());
            buffer.extend_from_slice(&(query.layers.len() as u16).to_le_bytes());
            for layer in &query.layers {
                buffer.extend_from_slice(&field_to_bytes(&layer.value)?);
                buffer.push(layer.path.len() as u8);
                for element in &layer.path {
                    buffer.push(element.index.0);
                    for sibling in &element.siblings {
                        buffer.extend_from_slice(sibling);
                    }
                }
            }
            buffer.extend_from_slice(&field_to_bytes(&query.final_value)?);
        }

        if let Some(oods) = &self.deep_oods {
            buffer.extend_from_slice(&field_to_bytes(&oods.point)?);
            buffer.extend_from_slice(&(oods.evaluations.len() as u16).to_le_bytes());
            for value in &oods.evaluations {
                buffer.extend_from_slice(&field_to_bytes(value)?);
            }
        }

        Ok(buffer)
    }

    /// Deserializes a proof from the canonical little-endian representation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FriError> {
        let mut cursor = Cursor::new(bytes);

        let version = FriProofVersion::from_u16(cursor.read_u16(SerKind::Proof)?)
            .ok_or(FriError::InvalidStructure("unknown proof version"))?;
        let security_level = FriSecurityLevel::from_code(cursor.read_u8(SerKind::Proof)?)
            .ok_or(FriError::InvalidStructure("unknown security level"))?;
        let domain_log2 = cursor.read_u16(SerKind::Proof)?;
        let layer_count = cursor.read_u16(SerKind::Proof)? as usize;
        let challenges_len = cursor.read_u16(SerKind::Proof)? as usize;
        let query_count = cursor.read_u16(SerKind::Proof)? as usize;
        let final_poly_len = cursor.read_u16(SerKind::Proof)? as usize;
        let oods_flag = cursor.read_u8(SerKind::Proof)?;

        let mut layer_roots = Vec::with_capacity(layer_count);
        for _ in 0..layer_count {
            layer_roots.push(cursor.read_digest(SerKind::Proof)?);
        }

        let mut fold_challenges = Vec::with_capacity(challenges_len);
        for _ in 0..challenges_len {
            fold_challenges.push(cursor.read_field(SerKind::Proof)?);
        }

        let final_polynomial_digest = cursor.read_digest(SerKind::Proof)?;

        let mut final_polynomial = Vec::with_capacity(final_poly_len);
        for _ in 0..final_poly_len {
            final_polynomial.push(cursor.read_field(SerKind::FinalPolynomial)?);
        }

        let mut queries = Vec::with_capacity(query_count);
        for _ in 0..query_count {
            let position = cursor.read_u32(SerKind::Query)? as usize;
            let layer_len = cursor.read_u16(SerKind::Query)? as usize;
            let mut layers = Vec::with_capacity(layer_len);
            for _ in 0..layer_len {
                let value = cursor.read_field(SerKind::Layer)?;
                let path_len = cursor.read_u8(SerKind::Layer)? as usize;
                let mut path = Vec::with_capacity(path_len);
                for _ in 0..path_len {
                    let index = cursor.read_u8(SerKind::Layer)?;
                    let mut siblings = [[0u8; DIGEST_SIZE]; 1];
                    for sibling in siblings.iter_mut() {
                        *sibling = cursor.read_digest(SerKind::Layer)?;
                    }
                    path.push(MerklePathElement {
                        index: MerkleIndex(index),
                        siblings,
                    });
                }
                layers.push(FriQueryLayerProof { value, path });
            }
            let final_value = cursor.read_field(SerKind::Query)?;
            queries.push(FriQueryProof {
                position,
                layers,
                final_value,
            });
        }

        let deep_oods = if oods_flag == OODS_FLAG_PRESENT {
            let point = cursor.read_field(SerKind::Proof)?;
            let eval_len = cursor.read_u16(SerKind::Proof)? as usize;
            let mut evaluations = Vec::with_capacity(eval_len);
            for _ in 0..eval_len {
                evaluations.push(cursor.read_field(SerKind::Proof)?);
            }
            Some(DeepOodsProof { point, evaluations })
        } else {
            None
        };

        if cursor.remaining() != 0 {
            return Err(FriError::Serialization(SerKind::Proof));
        }

        let initial_domain_size = 1usize << domain_log2;

        Self::with_deep_oods(
            security_level,
            initial_domain_size,
            layer_roots,
            fold_challenges,
            final_polynomial,
            final_polynomial_digest,
            queries,
            deep_oods,
        )
        .map(|mut proof| {
            proof.version = version;
            proof
        })
    }
}

impl Serialize for FriProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self
            .to_bytes()
            .map_err(|err| serde::ser::Error::custom(err.to_string()))?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for FriProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FriProofVisitor;

        impl<'de> Visitor<'de> for FriProofVisitor {
            type Value = FriProof;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("binary FRI proof bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                FriProof::from_bytes(v).map_err(|err| E::custom(err.to_string()))
            }
        }

        deserializer.deserialize_bytes(FriProofVisitor)
    }
}

/// Cursor helper used while serializing/deserializing the binary proof layout.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

fn domain_log2(size: usize) -> Result<u16, FriError> {
    if size == 0 || !size.is_power_of_two() {
        return Err(FriError::InvalidStructure(
            "initial domain size must be a power of two",
        ));
    }
    Ok(size.trailing_zeros() as u16)
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn read_exact(&mut self, len: usize, kind: SerKind) -> Result<&'a [u8], FriError> {
        if self.remaining() < len {
            return Err(FriError::Serialization(kind));
        }
        let start = self.offset;
        self.offset += len;
        Ok(&self.bytes[start..start + len])
    }

    fn read_u8(&mut self, kind: SerKind) -> Result<u8, FriError> {
        Ok(self.read_exact(1, kind)?[0])
    }

    fn read_u16(&mut self, kind: SerKind) -> Result<u16, FriError> {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(self.read_exact(2, kind)?);
        Ok(u16::from_le_bytes(buf))
    }

    fn read_u32(&mut self, kind: SerKind) -> Result<u32, FriError> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(self.read_exact(4, kind)?);
        Ok(u32::from_le_bytes(buf))
    }

    fn read_digest(&mut self, kind: SerKind) -> Result<[u8; DIGEST_SIZE], FriError> {
        let mut digest = [0u8; DIGEST_SIZE];
        digest.copy_from_slice(self.read_exact(DIGEST_SIZE, kind)?);
        Ok(digest)
    }

    fn read_field(&mut self, kind: SerKind) -> Result<FieldElement, FriError> {
        let mut buf = [0u8; FIELD_BYTES];
        buf.copy_from_slice(self.read_exact(FIELD_BYTES, kind)?);
        FieldElement::from_bytes(&buf).map_err(|err| match err {
            FieldDeserializeError::FieldDeserializeNonCanonical => {
                FriError::InvalidStructure("non-canonical field element")
            }
        })
    }
}

/// Helper struct representing a prover transcript.
#[derive(Debug, Clone)]
struct FriTranscript {
    state: [u8; 32],
}

impl FriTranscript {
    fn new(seed: FriTranscriptSeed) -> Self {
        Self { state: seed }
    }

    fn absorb_layer(&mut self, layer_index: usize, root: &[u8; 32]) {
        let mut payload = Vec::with_capacity(48);
        payload.extend_from_slice(&self.state);
        payload.extend_from_slice(&(layer_index as u64).to_le_bytes());
        payload.extend_from_slice(root);
        self.state = hash(&payload).into();
    }

    fn draw_eta(&mut self, layer_index: usize) -> FieldElement {
        let label = format!("{}ETA-{layer_index}", FiatShamirChallengeRules::SALT_PREFIX);
        let mut payload = Vec::with_capacity(self.state.len() + label.len());
        payload.extend_from_slice(&self.state);
        payload.extend_from_slice(label.as_bytes());
        let challenge: [u8; 32] = hash(&payload).into();
        self.state = hash(&challenge).into();
        field_from_hash(&challenge)
    }

    fn absorb_final(&mut self, digest: &[u8; 32]) {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&self.state);
        payload.extend_from_slice(b"RPP-FS/FINAL");
        payload.extend_from_slice(digest);
        self.state = hash(&payload).into();
    }

    fn derive_query_seed(&mut self) -> [u8; 32] {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&self.state);
        payload.extend_from_slice(b"RPP-FS/QUERY-SEED");
        let seed: [u8; 32] = hash(&payload).into();
        self.state = hash(&seed).into();
        seed
    }
}

/// Residual polynomial commitment hashing all final-layer evaluations.
pub(crate) fn hash_final_layer(values: &[FieldElement]) -> Result<[u8; 32], FriError> {
    let mut payload = Vec::with_capacity(4 + values.len() * 8);
    payload.extend_from_slice(&(values.len() as u32).to_le_bytes());
    for value in values {
        payload.extend_from_slice(&field_to_bytes(value)?);
    }
    Ok(hash(&payload).into())
}

fn default_fri_params() -> &'static StarkParams {
    static PARAMS: OnceLock<StarkParams> = OnceLock::new();
    PARAMS.get_or_init(|| {
        StarkParamsBuilder::from_profile(BuiltinProfile::PROFILE_X8)
            .build()
            .expect("default FRI params")
    })
}

impl FriProof {
    /// Generates a FRI proof from the provided LDE evaluations.
    pub fn prove(
        security_level: FriSecurityLevel,
        seed: FriTranscriptSeed,
        evaluations: &[FieldElement],
    ) -> Result<Self, FriError> {
        let params = default_fri_params();
        Self::prove_with_params(security_level, seed, evaluations, params)
    }

    /// Generates a FRI proof using the provided [`StarkParams`].
    pub fn prove_with_params(
        security_level: FriSecurityLevel,
        seed: FriTranscriptSeed,
        evaluations: &[FieldElement],
        params: &StarkParams,
    ) -> Result<Self, FriError> {
        if evaluations.is_empty() {
            return Err(FriError::EmptyCodeword);
        }

        let expected_queries = params.fri().queries as usize;
        if expected_queries != security_level.query_budget() {
            return Err(FriError::QueryBudgetMismatch {
                expected: expected_queries,
                actual: security_level.query_budget(),
            });
        }

        let query_plan = derive_query_plan_id(security_level, params);
        let view = FriParamsView::from_params(params, security_level, query_plan);
        let coset_shifts = coset_shift_schedule(params, view.num_layers());

        let mut transcript = FriTranscript::new(seed);
        let mut layers: Vec<FriLayer> = Vec::with_capacity(view.num_layers());
        let mut current = evaluations.to_vec();
        let mut layer_roots = Vec::with_capacity(view.num_layers());
        let mut fold_challenges = Vec::with_capacity(view.num_layers());

        for (layer_index, coset_shift) in coset_shifts.into_iter().enumerate() {
            if current.len() <= 1 {
                break;
            }

            let layer = FriLayer::new(layer_index, coset_shift, current)?;
            let root = layer.root();
            transcript.absorb_layer(layer.index(), &root);
            let eta = transcript.draw_eta(layer.index());
            fold_challenges.push(eta);
            layer_roots.push(root);

            let next = binary_fold(layer.evaluations(), eta, layer.coset_shift());
            current = next;
            layers.push(layer);
        }

        // Record the final layer (values only).
        let final_polynomial = current.clone();
        let final_polynomial_digest = hash_final_layer(&final_polynomial)?;
        transcript.absorb_final(&final_polynomial_digest);
        let query_seed = transcript.derive_query_seed();

        let query_positions =
            derive_query_positions(query_seed, view.query_count(), evaluations.len())?;

        let mut queries = Vec::with_capacity(query_positions.len());
        for &position in &query_positions {
            let mut index = position;
            let mut layers_openings: Vec<FriQueryLayerProof> = Vec::with_capacity(layers.len());
            for layer in layers.iter() {
                let opening = layer.open(index)?;
                layers_openings.push(opening);
                index = parent_index(index);
            }

            if index >= final_polynomial.len() {
                return Err(FriError::QueryOutOfRange { position });
            }
            let final_value = final_polynomial[index];
            queries.push(FriQueryProof {
                position,
                layers: layers_openings,
                final_value,
            });
        }

        Self::new(
            security_level,
            evaluations.len(),
            layer_roots,
            fold_challenges,
            final_polynomial,
            final_polynomial_digest,
            queries,
        )
    }
}

/// Derives the canonical query plan identifier.
pub fn derive_query_plan_id(level: FriSecurityLevel, params: &StarkParams) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"FRI-PLAN/BINARY");
    payload.extend_from_slice(&(BINARY_FOLD_ARITY as u32).to_le_bytes());
    payload.extend_from_slice(&(params.fri().domain_log2 as u32).to_le_bytes());
    payload.extend_from_slice(&(params.fri().queries as u32).to_le_bytes());
    payload.extend_from_slice(&(level.query_budget() as u32).to_le_bytes());
    payload.push(params.fri().folding.code());
    payload.extend_from_slice(level.tag().as_bytes());
    payload.extend_from_slice(b"challenge-after-commit");
    payload.extend_from_slice(b"dedup-sort-stable");
    hash(&payload).into()
}

/// Verifier entry point.
pub struct FriVerifier;

impl FriVerifier {
    /// Verifies a FRI proof against the declared security level and transcript seed.
    pub fn verify<F>(
        proof: &FriProof,
        security_level: FriSecurityLevel,
        seed: FriTranscriptSeed,
        final_value_oracle: F,
    ) -> Result<(), FriError>
    where
        F: FnMut(usize) -> FieldElement,
    {
        let params = default_fri_params();
        Self::verify_with_params(proof, security_level, seed, params, final_value_oracle)
    }

    /// Verifies a FRI proof using the provided [`StarkParams`].
    pub fn verify_with_params<F>(
        proof: &FriProof,
        security_level: FriSecurityLevel,
        seed: FriTranscriptSeed,
        params: &StarkParams,
        final_value_oracle: F,
    ) -> Result<(), FriError>
    where
        F: FnMut(usize) -> FieldElement,
    {
        proof.validate()?;
        if proof.security_level != security_level {
            return Err(FriError::SecurityLevelMismatch);
        }
        if proof.initial_domain_size == 0 {
            return Err(FriError::EmptyCodeword);
        }
        let expected_queries = params.fri().queries as usize;
        if expected_queries != security_level.query_budget() {
            return Err(FriError::QueryBudgetMismatch {
                expected: expected_queries,
                actual: security_level.query_budget(),
            });
        }
        if proof.queries.len() != expected_queries {
            return Err(FriError::QueryBudgetMismatch {
                expected: expected_queries,
                actual: proof.queries.len(),
            });
        }

        let mut final_value_oracle = final_value_oracle;

        if proof.fold_challenges.len() != proof.layer_roots.len() {
            return Err(FriError::InvalidStructure("fold challenge length"));
        }

        let query_plan = derive_query_plan_id(security_level, params);
        let view = FriParamsView::from_params(params, security_level, query_plan);
        if proof.layer_roots.len() > view.num_layers() {
            return Err(FriError::InvalidStructure("layer count exceeds profile"));
        }

        let mut transcript = FriTranscript::new(seed);
        for (layer_index, root) in proof.layer_roots.iter().enumerate() {
            transcript.absorb_layer(layer_index, root);
            let eta = transcript.draw_eta(layer_index);
            let expected_eta = proof
                .fold_challenges
                .get(layer_index)
                .copied()
                .ok_or(FriError::InvalidStructure("missing fold challenge"))?;
            if eta != expected_eta {
                return Err(FriError::InvalidStructure("fold challenge mismatch"));
            }
        }

        let recomputed_digest = hash_final_layer(&proof.final_polynomial)?;
        if recomputed_digest != proof.final_polynomial_digest {
            return Err(FriError::LayerRootMismatch {
                layer: proof.layer_roots.len(),
            });
        }

        transcript.absorb_final(&proof.final_polynomial_digest);
        let query_seed = transcript.derive_query_seed();
        let expected_positions =
            derive_query_positions(query_seed, view.query_count(), proof.initial_domain_size)?;

        if expected_positions.len() != proof.queries.len() {
            return Err(FriError::InvalidStructure("query count mismatch"));
        }

        for (expected_position, query) in expected_positions.iter().zip(proof.queries.iter()) {
            if query.position != *expected_position {
                return Err(FriError::InvalidStructure("query position mismatch"));
            }
            if query.layers.len() != proof.layer_roots.len() {
                return Err(FriError::InvalidStructure("layer count mismatch"));
            }
            let mut index = *expected_position;
            let mut layer_domain_size = proof.initial_domain_size;
            for (layer_idx, layer) in query.layers.iter().enumerate() {
                let root = &proof.layer_roots[layer_idx];
                verify_path(
                    layer.value,
                    &layer.path,
                    root,
                    index,
                    layer_idx,
                    layer_domain_size,
                )?;
                index = parent_index(index);
                layer_domain_size = next_domain_size(layer_domain_size);
            }

            if index >= proof.final_polynomial.len() {
                return Err(FriError::QueryOutOfRange {
                    position: *expected_position,
                });
            }

            if proof.final_polynomial[index] != query.final_value {
                return Err(FriError::LayerRootMismatch {
                    layer: proof.layer_roots.len(),
                });
            }

            let expected_final = final_value_oracle(index);
            if expected_final != query.final_value {
                return Err(FriError::LayerRootMismatch {
                    layer: proof.layer_roots.len(),
                });
            }
        }

        Ok(())
    }
}

pub(crate) fn derive_query_positions(
    seed: [u8; 32],
    count: usize,
    domain_size: usize,
) -> Result<Vec<usize>, FriError> {
    assert!(domain_size > 0, "domain size must be positive");
    let mut xof = Blake2sXof::new(&seed);
    let target = count.min(domain_size);
    let mut unique = Vec::with_capacity(target);
    let mut seen = vec![false; domain_size];
    while unique.len() < target {
        let word = xof.next_u64().map_err(FriError::from)?;
        let position = (word % (domain_size as u64)) as usize;
        if !seen[position] {
            seen[position] = true;
            unique.push(position);
        }
    }
    unique.sort();
    Ok(unique)
}

fn verify_path(
    value: FieldElement,
    path: &[MerklePathElement],
    expected_root: &[u8; 32],
    index: usize,
    layer_index: usize,
    leaf_count: usize,
) -> Result<(), FriError> {
    let encoded_leaf = encode_leaf(&field_to_bytes(&value)?);
    let computed =
        compute_root_from_path(&encoded_leaf, index, leaf_count, path).map_err(|err| {
            FriError::PathInvalid {
                layer: layer_index,
                reason: err,
            }
        })?;

    if &computed != expected_root {
        return Err(FriError::PathInvalid {
            layer: layer_index,
            reason: MerkleError::ErrMerkleSiblingOrder,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PROFILE_HIGH_SECURITY_CONFIG, PROFILE_STANDARD_CONFIG};
    use crate::proof::params::canonical_stark_params;

    fn sample_evaluations() -> Vec<FieldElement> {
        (0..1024).map(|i| FieldElement(i as u64 + 1)).collect()
    }

    fn sample_seed() -> FriTranscriptSeed {
        [42u8; 32]
    }

    fn final_value_oracle(values: Vec<FieldElement>) -> impl FnMut(usize) -> FieldElement {
        move |index| values[index]
    }

    #[test]
    fn fri_prover_handles_coset_folding() {
        let evaluations = sample_evaluations();
        let seed = sample_seed();
        let params = canonical_stark_params(&PROFILE_HIGH_SECURITY_CONFIG);

        let proof =
            FriProof::prove_with_params(FriSecurityLevel::HiSec, seed, &evaluations, &params)
                .expect("coset proof");

        let finals = proof.final_polynomial.clone();
        FriVerifier::verify_with_params(
            &proof,
            FriSecurityLevel::HiSec,
            seed,
            &params,
            final_value_oracle(finals),
        )
        .expect("verification");
    }

    #[test]
    fn fri_prover_is_deterministic() {
        let evaluations = sample_evaluations();
        let seed = sample_seed();
        let params = canonical_stark_params(&PROFILE_STANDARD_CONFIG);

        let proof_a =
            FriProof::prove_with_params(FriSecurityLevel::Standard, seed, &evaluations, &params)
                .expect("first proof");
        let proof_b =
            FriProof::prove_with_params(FriSecurityLevel::Standard, seed, &evaluations, &params)
                .expect("second proof");

        assert_eq!(proof_a, proof_b, "proofs must be identical across runs");

        let finals = proof_a.final_polynomial.clone();
        FriVerifier::verify_with_params(
            &proof_a,
            FriSecurityLevel::Standard,
            seed,
            &params,
            final_value_oracle(finals),
        )
        .expect("verification");
    }

    #[test]
    fn fri_verifier_enforces_query_budget() {
        let evaluations = sample_evaluations();
        let seed = sample_seed();
        let params = canonical_stark_params(&PROFILE_STANDARD_CONFIG);

        let proof =
            FriProof::prove_with_params(FriSecurityLevel::Standard, seed, &evaluations, &params)
                .expect("proof");
        let mut tampered = proof.clone();
        tampered.queries.pop();

        let finals = tampered.final_polynomial.clone();
        let err = FriVerifier::verify_with_params(
            &tampered,
            FriSecurityLevel::Standard,
            seed,
            &params,
            final_value_oracle(finals),
        )
        .expect_err("query budget mismatch");

        assert!(
            matches!(err, FriError::QueryBudgetMismatch { expected, actual } if expected == FriSecurityLevel::Standard.query_budget() && actual + 1 == expected)
        );
    }

    #[test]
    fn fri_verifier_reports_path_mismatch() {
        let evaluations = sample_evaluations();
        let seed = sample_seed();
        let params = canonical_stark_params(&PROFILE_STANDARD_CONFIG);
        let proof =
            FriProof::prove_with_params(FriSecurityLevel::Standard, seed, &evaluations, &params)
                .expect("proof");

        let mut tampered = proof.clone();
        if let Some(layer) = tampered
            .queries
            .get_mut(0)
            .and_then(|query| query.layers.get_mut(0))
        {
            if let Some(element) = layer.path.get_mut(0) {
                element.siblings[0][0] ^= 0x01;
            }
        }

        let finals = tampered.final_polynomial.clone();
        let err = FriVerifier::verify_with_params(
            &tampered,
            FriSecurityLevel::Standard,
            seed,
            &params,
            final_value_oracle(finals),
        )
        .expect_err("path corruption");

        assert!(matches!(err, FriError::PathInvalid { layer: 0, .. }));
    }

    #[test]
    fn fri_verifier_reports_query_out_of_range() {
        let seed = sample_seed();
        let security = FriSecurityLevel::Standard;
        let final_polynomial: Vec<FieldElement> = Vec::new();
        let final_digest = hash_final_layer(&final_polynomial).expect("final layer hash");

        let mut transcript = FriTranscript::new(seed);
        transcript.absorb_final(&final_digest);
        let query_seed = transcript.derive_query_seed();
        let positions = derive_query_positions(query_seed, security.query_budget(), 1024)
            .expect("query positions");

        let queries: Vec<FriQueryProof> = positions
            .into_iter()
            .map(|position| FriQueryProof {
                position,
                layers: Vec::new(),
                final_value: FieldElement::ZERO,
            })
            .collect();

        let proof = FriProof::new(
            security,
            1024,
            Vec::new(),
            Vec::new(),
            final_polynomial,
            final_digest,
            queries,
        )
        .expect("synthetic proof");

        let params = canonical_stark_params(&PROFILE_STANDARD_CONFIG);
        let err = FriVerifier::verify_with_params(&proof, security, seed, &params, |_| {
            FieldElement::ZERO
        })
        .expect_err("query out of range");

        assert!(matches!(err, FriError::QueryOutOfRange { .. }));
    }
}
