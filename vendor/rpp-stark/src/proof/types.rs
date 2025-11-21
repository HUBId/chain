use crate::config::{AirSpecId, ParamDigest, ProofKind};
use crate::fri::FriProof;
use crate::hash::deterministic::DeterministicHashError;
use crate::ser::{
    ensure_consumed, ensure_u32, read_digest, read_u16, read_u32, read_u8, write_bytes,
    write_digest, write_u16, write_u32, write_u8, ByteReader, SerError, SerKind,
};
use crate::utils::serialization::DigestBytes;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::time::Duration;

/// Canonical proof version implemented by this crate.
pub const PROOF_VERSION: u16 = 1;

/// Canonical number of α challenges drawn from the Fiat–Shamir transcript.
///
/// The specification fixes the composition vector to four coefficients so the
/// prover and verifier must always request exactly four challenges.
pub const PROOF_ALPHA_VECTOR_LEN: usize = 4;

/// Minimum number of out-of-domain points drawn before sealing the transcript.
///
/// The prover samples two ζ challenges to satisfy the DEEP consistency checks;
/// verifiers must reject envelopes declaring fewer OOD openings.
pub const PROOF_MIN_OOD_POINTS: usize = 2;

/// Maximum query budget a canonical proof is allowed to declare.
///
/// All shipping profiles stay within 128 FRI queries which bounds the
/// transcript sampling and telemetry reporting.
pub const PROOF_MAX_QUERY_COUNT: usize = 128;

/// Maximum number of FRI layers committed to by a canonical proof.
///
/// Profiles advertise at most twenty folding rounds; exceeding this limit is
/// considered a malformed envelope.
pub const PROOF_MAX_FRI_LAYERS: usize = 20;

/// Maximum cap polynomial degree recorded in the telemetry frame.
///
/// Proof builders cap this value at the advertised FRI depth range which never
/// exceeds twenty in the current specification.
pub const PROOF_TELEMETRY_MAX_CAP_DEGREE: u16 = 20;

/// Maximum final-polynomial cap size recorded in telemetry.
///
/// Query caps are limited to the canonical 128 query budget, so the telemetry
/// payload may not declare a larger commitment.
pub const PROOF_TELEMETRY_MAX_CAP_SIZE: u32 = 128;

/// Maximum query budget mirrored in the telemetry section.
///
/// The telemetry frame mirrors the configured FRI security level and is
/// bounded by the 128-query cap mandated by the specification.
pub const PROOF_TELEMETRY_MAX_QUERY_BUDGET: u16 = 128;

/// Wrapper owning the proof-kind binding section for envelope assembly.
///
/// The handle stores the AIR selection metadata together with the canonical
/// public-input payload and optional composition-commitment digest. All fields
/// are kept together to guarantee that cloning or transporting the wrapper
/// preserves a consistent view of the binding information required by the
/// specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionBinding {
    #[serde(with = "proof_kind_codec")]
    kind: ProofKind,
    air_spec_id: AirSpecId,
    public_inputs: Vec<u8>,
    composition_commit: Option<DigestBytes>,
}

impl CompositionBinding {
    /// Creates a new binding wrapper for the provided components.
    pub fn new(
        kind: ProofKind,
        air_spec_id: AirSpecId,
        public_inputs: Vec<u8>,
        composition_commit: Option<DigestBytes>,
    ) -> Self {
        Self {
            kind,
            air_spec_id,
            public_inputs,
            composition_commit,
        }
    }

    /// Returns the proof kind advertised by this binding.
    pub fn kind(&self) -> &ProofKind {
        &self.kind
    }

    /// Returns a mutable reference to the proof kind advertised by this binding.
    pub fn kind_mut(&mut self) -> &mut ProofKind {
        &mut self.kind
    }

    /// Returns the AIR specification identifier bound to the proof.
    pub fn air_spec_id(&self) -> &AirSpecId {
        &self.air_spec_id
    }

    /// Returns a mutable reference to the AIR specification identifier bound to the proof.
    pub fn air_spec_id_mut(&mut self) -> &mut AirSpecId {
        &mut self.air_spec_id
    }

    /// Returns the public-input payload associated with the binding.
    pub fn public_inputs(&self) -> &[u8] {
        &self.public_inputs
    }

    /// Returns a mutable reference to the public-input payload.
    pub fn public_inputs_mut(&mut self) -> &mut Vec<u8> {
        &mut self.public_inputs
    }

    /// Returns the optional composition commitment digest, if present.
    pub fn composition_commit(&self) -> Option<&DigestBytes> {
        self.composition_commit.as_ref()
    }

    /// Returns a mutable reference to the optional composition commitment digest.
    pub fn composition_commit_mut(&mut self) -> Option<&mut DigestBytes> {
        self.composition_commit.as_mut()
    }

    pub(crate) fn serialize_bytes(&self) -> Result<Vec<u8>, SerError> {
        let mut buffer = Vec::new();
        write_u8(&mut buffer, encode_proof_kind(*self.kind()));
        write_digest(&mut buffer, self.air_spec_id().as_bytes());

        let public_inputs = self.public_inputs();
        let public_len = ensure_u32(public_inputs.len(), SerKind::PublicInputs, "len")?;
        write_u32(&mut buffer, public_len);
        write_bytes(&mut buffer, public_inputs);

        match self.composition_commit() {
            Some(commit) => {
                write_u8(&mut buffer, 1);
                write_digest(&mut buffer, &commit.bytes);
            }
            None => write_u8(&mut buffer, 0),
        }

        Ok(buffer)
    }

    pub(crate) fn deserialize_bytes(bytes: &[u8]) -> Result<Self, VerifyError> {
        let mut cursor = ByteReader::new(bytes);
        let kind_byte = read_u8(&mut cursor, SerKind::Proof, "kind")?;
        let kind = decode_proof_kind(kind_byte)?;

        let air_spec_id = AirSpecId(DigestBytes {
            bytes: read_digest(&mut cursor, SerKind::Proof, "air_spec_id")?,
        });

        let public_len = read_u32(&mut cursor, SerKind::PublicInputs, "len")? as usize;
        let public_inputs = cursor.read_vec(SerKind::PublicInputs, "public_inputs", public_len)?;

        let composition_commit = match read_u8(&mut cursor, SerKind::CompositionCommitment, "flag")?
        {
            0 => None,
            1 => Some(DigestBytes {
                bytes: read_digest(&mut cursor, SerKind::CompositionCommitment, "digest")?,
            }),
            _ => {
                return Err(VerifyError::Serialization(SerKind::CompositionCommitment));
            }
        };

        ensure_consumed(&cursor, SerKind::Proof)?;

        Ok(Self::new(
            kind,
            air_spec_id,
            public_inputs,
            composition_commit,
        ))
    }
}

/// Wrapper storing the low-level FRI proof payload for assembly helpers.
///
/// The `FriHandle` keeps ownership of the decoded FRI proof section so that
/// callers cloning or splitting a [`Proof`] can move the payload without
/// touching unrelated metadata. The handle guarantees that the prover and
/// verifier observe identical layer roots and query responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriHandle {
    fri_proof: FriProof,
}

impl FriHandle {
    /// Creates a new handle for the provided FRI proof payload.
    pub fn new(fri_proof: FriProof) -> Self {
        Self { fri_proof }
    }

    /// Returns an immutable reference to the wrapped FRI proof.
    pub fn fri_proof(&self) -> &FriProof {
        &self.fri_proof
    }

    /// Returns a mutable reference to the wrapped FRI proof.
    pub fn fri_proof_mut(&mut self) -> &mut FriProof {
        &mut self.fri_proof
    }

    pub(crate) fn serialize_bytes(&self) -> Result<Vec<u8>, SerError> {
        self.fri_proof
            .to_bytes()
            .map_err(|_| SerError::invalid_value(SerKind::Fri, "fri_proof"))
    }

    pub(crate) fn deserialize_bytes(bytes: &[u8]) -> Result<Self, VerifyError> {
        let fri_proof =
            FriProof::from_bytes(bytes).map_err(|_| VerifyError::Serialization(SerKind::Fri))?;
        Ok(Self::new(fri_proof))
    }
}

/// Fully decoded proof container mirroring the authoritative specification.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// Declared proof version (currently `1`).
    #[serde(with = "proof_version_codec")]
    version: u16,
    /// Parameter digest binding configuration knobs.
    params_hash: ParamDigest,
    /// Digest binding the canonical public-input payload.
    public_digest: DigestBytes,
    /// Digest mirroring the declared trace commitment.
    trace_commit: DigestBytes,
    /// Wrapper storing proof kind, AIR selection and related bindings.
    composition: CompositionBinding,
    /// Wrapper around the FRI proof payload accompanying the envelope.
    fri: FriHandle,
    /// Wrapper combining Merkle commitments and opening payloads.
    openings: OpeningsDescriptor,
    /// Wrapper combining telemetry availability with the reported frame.
    telemetry: TelemetryOption,
}

/// Read-only container exposing header fields and payload placeholders.
///
/// The struct mirrors the immutable view of a [`Proof`] after decoding. It
/// exposes the header bindings together with the handles wrapping each payload
/// section so verifiers may pass around a lightweight view of the envelope
/// without retaining ownership of the full proof body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofHandles {
    version: u16,
    params_hash: ParamDigest,
    public_digest: DigestBytes,
    trace_commit: DigestBytes,
    composition: CompositionBinding,
    openings: OpeningsDescriptor,
    fri: FriHandle,
    telemetry: TelemetryOption,
}

impl ProofHandles {
    /// Creates a new immutable handle view for the provided components.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: u16,
        params_hash: ParamDigest,
        public_digest: DigestBytes,
        trace_commit: DigestBytes,
        composition: CompositionBinding,
        openings: OpeningsDescriptor,
        fri: FriHandle,
        telemetry: TelemetryOption,
    ) -> Self {
        Self {
            version,
            params_hash,
            public_digest,
            trace_commit,
            composition,
            openings,
            fri,
            telemetry,
        }
    }

    /// Returns the proof version stored in the header.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Returns the parameter digest binding configuration for the proof.
    pub fn params_hash(&self) -> &ParamDigest {
        &self.params_hash
    }

    /// Returns the canonical proof kind binding wrapper.
    pub fn composition(&self) -> &CompositionBinding {
        &self.composition
    }

    /// Returns the canonical proof kind stored in the envelope header.
    pub fn kind(&self) -> &ProofKind {
        self.composition.kind()
    }

    /// Returns the AIR specification identifier bound to the proof kind.
    pub fn air_spec_id(&self) -> &AirSpecId {
        self.composition.air_spec_id()
    }

    /// Returns the digest binding the canonical public-input payload.
    pub fn public_digest(&self) -> &DigestBytes {
        &self.public_digest
    }

    /// Returns the canonical public-input payload encoded in the header.
    pub fn public_inputs(&self) -> &[u8] {
        self.composition.public_inputs()
    }

    /// Returns the digest mirroring the declared trace commitment.
    pub fn trace_commit(&self) -> &DigestBytes {
        &self.trace_commit
    }

    /// Returns the optional composition commitment digest, if present.
    pub fn composition_commit(&self) -> Option<&DigestBytes> {
        self.composition.composition_commit()
    }

    /// Returns the Merkle commitment bundle for the proof.
    pub fn merkle(&self) -> &MerkleProofBundle {
        self.openings.merkle()
    }

    /// Returns the out-of-domain opening payloads accompanying the proof.
    pub fn openings(&self) -> &OpeningsDescriptor {
        &self.openings
    }

    /// Returns the wrapped out-of-domain opening payloads.
    pub fn openings_payload(&self) -> &Openings {
        self.openings.openings()
    }

    /// Returns the FRI handle wrapper describing the payload section.
    pub fn fri(&self) -> &FriHandle {
        &self.fri
    }

    /// Returns the decoded FRI proof stored in the payload section.
    pub fn fri_proof(&self) -> &FriProof {
        self.fri.fri_proof()
    }

    /// Returns the telemetry option describing the telemetry payload.
    pub fn telemetry(&self) -> &TelemetryOption {
        &self.telemetry
    }

    /// Returns `true` when telemetry data is present in the payload.
    pub fn has_telemetry(&self) -> bool {
        self.telemetry.is_present()
    }

    /// Returns the telemetry frame describing declared lengths and digests.
    pub fn telemetry_frame(&self) -> &Telemetry {
        self.telemetry.frame()
    }
}

impl Clone for Proof {
    fn clone(&self) -> Self {
        self.clone_using_parts()
    }

    fn clone_from(&mut self, source: &Self) {
        *self = source.clone_using_parts();
    }
}

impl Proof {
    /// Returns the composition binding wrapper describing proof kind and metadata.
    pub fn composition(&self) -> &CompositionBinding {
        &self.composition
    }

    /// Returns a mutable reference to the composition binding wrapper.
    pub fn composition_mut(&mut self) -> &mut CompositionBinding {
        &mut self.composition
    }

    /// Returns the FRI handle wrapper storing the decoded FRI payload.
    pub fn fri(&self) -> &FriHandle {
        &self.fri
    }

    /// Returns a mutable reference to the FRI handle wrapper.
    pub fn fri_mut(&mut self) -> &mut FriHandle {
        &mut self.fri
    }

    /// Returns the openings descriptor bundling Merkle roots and opening payloads.
    pub fn openings(&self) -> &OpeningsDescriptor {
        &self.openings
    }

    /// Returns a mutable reference to the openings descriptor wrapper.
    pub fn openings_mut(&mut self) -> &mut OpeningsDescriptor {
        &mut self.openings
    }

    /// Returns the telemetry option wrapper describing availability and payload.
    pub fn telemetry(&self) -> &TelemetryOption {
        &self.telemetry
    }

    /// Returns a mutable reference to the telemetry option wrapper.
    pub fn telemetry_mut(&mut self) -> &mut TelemetryOption {
        &mut self.telemetry
    }

    /// Returns the declared proof version stored in the envelope header.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Returns a mutable reference to the declared proof version.
    pub fn version_mut(&mut self) -> &mut u16 {
        &mut self.version
    }

    /// Returns the parameter digest binding configuration for the proof.
    pub fn params_hash(&self) -> &ParamDigest {
        &self.params_hash
    }

    /// Returns a mutable reference to the parameter digest configuration.
    pub fn params_hash_mut(&mut self) -> &mut ParamDigest {
        &mut self.params_hash
    }

    /// Returns the canonical proof kind stored in the envelope header.
    ///
    /// Delegates to the [`CompositionBinding`] wrapper to surface the selected
    /// proof kind while keeping callers on the public accessor.
    pub fn kind(&self) -> &ProofKind {
        self.composition().kind()
    }

    /// Returns a mutable reference to the canonical proof kind.
    ///
    /// Uses the [`CompositionBinding`] wrapper so callers mutate the binding
    /// through the documented handle instead of touching struct fields.
    pub fn kind_mut(&mut self) -> &mut ProofKind {
        self.composition_mut().kind_mut()
    }

    /// Returns the AIR specification identifier for the proof kind.
    ///
    /// Forwarded through [`CompositionBinding`] to keep the selection metadata
    /// encapsulated behind the binding wrapper.
    pub fn air_spec_id(&self) -> &AirSpecId {
        self.composition().air_spec_id()
    }

    /// Returns a mutable reference to the AIR specification identifier.
    ///
    /// Uses [`CompositionBinding`] so mutations flow through the wrapper
    /// instead of exposing internal storage.
    pub fn air_spec_id_mut(&mut self) -> &mut AirSpecId {
        self.composition_mut().air_spec_id_mut()
    }

    /// Returns the canonical public input encoding.
    ///
    /// Delegates to [`CompositionBinding`] to ensure public inputs are always
    /// read through the binding wrapper.
    pub fn public_inputs(&self) -> &[u8] {
        self.composition().public_inputs()
    }

    /// Returns a mutable reference to the canonical public input encoding.
    ///
    /// Calls into [`CompositionBinding`] so mutation sites consistently use the
    /// wrapper accessor.
    pub fn public_inputs_mut(&mut self) -> &mut Vec<u8> {
        self.composition_mut().public_inputs_mut()
    }

    /// Returns the digest binding the canonical public-input payload.
    pub fn public_digest(&self) -> &DigestBytes {
        &self.public_digest
    }

    /// Returns a mutable reference to the public-input digest binding.
    pub fn public_digest_mut(&mut self) -> &mut DigestBytes {
        &mut self.public_digest
    }

    /// Returns the digest mirroring the declared trace commitment.
    pub fn trace_commit(&self) -> &DigestBytes {
        &self.trace_commit
    }

    /// Returns a mutable reference to the trace commitment digest.
    pub fn trace_commit_mut(&mut self) -> &mut DigestBytes {
        &mut self.trace_commit
    }

    /// Returns the optional composition commitment digest, if present.
    ///
    /// The value is retrieved through [`CompositionBinding`] to keep the digest
    /// coupled with the binding wrapper.
    pub fn composition_commit(&self) -> Option<&DigestBytes> {
        self.composition().composition_commit()
    }

    /// Returns a mutable reference to the optional composition commitment digest.
    ///
    /// Accesses [`CompositionBinding`] so callers continue to use the wrapper
    /// for mutating the optional commitment.
    pub fn composition_commit_mut(&mut self) -> Option<&mut DigestBytes> {
        self.composition_mut().composition_commit_mut()
    }

    /// Returns the Merkle commitment bundle for the proof.
    ///
    /// Delegates to [`OpeningsDescriptor`] to expose the Merkle bundle through
    /// the descriptor wrapper.
    pub fn merkle(&self) -> &MerkleProofBundle {
        self.openings().merkle()
    }

    /// Returns a mutable reference to the Merkle commitment bundle.
    ///
    /// Uses the [`OpeningsDescriptor`] wrapper so mutation sites flow through
    /// the descriptor handle.
    pub fn merkle_mut(&mut self) -> &mut MerkleProofBundle {
        self.openings_mut().merkle_mut()
    }

    /// Returns the out-of-domain opening payloads.
    ///
    /// Provided via [`OpeningsDescriptor`] so consumers always access openings
    /// through the wrapper.
    pub fn openings_payload(&self) -> &Openings {
        self.openings().openings()
    }

    /// Returns a mutable reference to the out-of-domain opening payloads.
    ///
    /// Forwarded through [`OpeningsDescriptor`] to centralize mutation through
    /// the wrapper handle.
    pub fn openings_payload_mut(&mut self) -> &mut Openings {
        self.openings_mut().openings_mut()
    }

    /// Returns the FRI proof payload accompanying the envelope.
    ///
    /// The payload lives behind the [`FriHandle`] wrapper so verifiers read it
    /// through the dedicated accessor.
    pub fn fri_proof(&self) -> &FriProof {
        self.fri().fri_proof()
    }

    /// Returns a mutable reference to the FRI proof payload accompanying the envelope.
    ///
    /// Routed via [`FriHandle`] to ensure mutations stay behind the wrapper.
    pub fn fri_proof_mut(&mut self) -> &mut FriProof {
        self.fri_mut().fri_proof_mut()
    }

    /// Returns `true` when the proof payload contains telemetry data.
    ///
    /// Queries the [`TelemetryOption`] wrapper which tracks availability.
    pub fn has_telemetry(&self) -> bool {
        self.telemetry().is_present()
    }

    /// Sets the telemetry presence flag for the proof payload.
    ///
    /// Updates the [`TelemetryOption`] wrapper controlling telemetry presence.
    pub fn set_has_telemetry(&mut self, value: bool) {
        self.telemetry_mut().set_present(value);
    }

    /// Returns the telemetry frame describing declared lengths and digests.
    ///
    /// Delegates to [`TelemetryOption`] so callers read the frame through the
    /// wrapper.
    pub fn telemetry_frame(&self) -> &Telemetry {
        self.telemetry().frame()
    }

    /// Returns a mutable reference to the telemetry frame.
    ///
    /// Accesses the [`TelemetryOption`] wrapper to expose mutable telemetry via
    /// the documented handle.
    pub fn telemetry_frame_mut(&mut self) -> &mut Telemetry {
        self.telemetry_mut().frame_mut()
    }

    /// Clones the proof by reassembling all sections through [`Proof::from_parts`].
    pub fn clone_using_parts(&self) -> Self {
        let binding = self.composition.clone();
        let openings_descriptor = self.openings.clone();
        let fri_handle = self.fri.clone();
        let telemetry_option = self.telemetry.clone();

        Proof::from_parts(
            self.version(),
            self.params_hash().clone(),
            self.public_digest().clone(),
            self.trace_commit().clone(),
            binding,
            openings_descriptor,
            fri_handle,
            telemetry_option,
        )
    }

    /// Converts the proof into an immutable handle view consuming `self`.
    pub fn into_handles(self) -> ProofHandles {
        let Proof {
            version,
            params_hash,
            public_digest,
            trace_commit,
            composition,
            fri,
            openings,
            telemetry,
        } = self;

        ProofHandles::new(
            version,
            params_hash,
            public_digest,
            trace_commit,
            composition,
            openings,
            fri,
            telemetry,
        )
    }

    /// Reassembles a proof from the provided building blocks.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        version: u16,
        params_hash: ParamDigest,
        public_digest: DigestBytes,
        trace_commit: DigestBytes,
        binding: CompositionBinding,
        openings: OpeningsDescriptor,
        fri: FriHandle,
        telemetry: TelemetryOption,
    ) -> Self {
        Self {
            version,
            params_hash,
            public_digest,
            trace_commit,
            composition: binding,
            fri,
            openings,
            telemetry,
        }
    }
}

/// Merkle commitment bundle covering core, auxiliary and FRI layer roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofBundle {
    /// Core commitment root.
    pub core_root: [u8; 32],
    /// Auxiliary commitment root (zero if absent).
    pub aux_root: [u8; 32],
    /// FRI layer roots emitted during the prover pipeline.
    pub fri_layer_roots: Vec<[u8; 32]>,
}

impl MerkleProofBundle {
    /// Constructs a bundle from the provided roots without additional checks.
    pub fn new(core_root: [u8; 32], aux_root: [u8; 32], fri_layer_roots: Vec<[u8; 32]>) -> Self {
        Self {
            core_root,
            aux_root,
            fri_layer_roots,
        }
    }

    /// Returns the core commitment root stored in the bundle.
    pub fn core_root(&self) -> &[u8; 32] {
        &self.core_root
    }

    /// Returns a mutable reference to the core commitment root stored in the bundle.
    pub fn core_root_mut(&mut self) -> &mut [u8; 32] {
        &mut self.core_root
    }

    /// Returns the auxiliary commitment root recorded in the bundle.
    pub fn aux_root(&self) -> &[u8; 32] {
        &self.aux_root
    }

    /// Returns a mutable reference to the auxiliary commitment root recorded in the bundle.
    pub fn aux_root_mut(&mut self) -> &mut [u8; 32] {
        &mut self.aux_root
    }

    /// Returns the FRI layer roots mirrored by the bundle.
    pub fn fri_layer_roots(&self) -> &[[u8; 32]] {
        &self.fri_layer_roots
    }

    /// Returns a mutable reference to the FRI layer roots mirrored by the bundle.
    pub fn fri_layer_roots_mut(&mut self) -> &mut Vec<[u8; 32]> {
        &mut self.fri_layer_roots
    }

    /// Assembles a bundle and validates that the provided FRI proof advertises
    /// compatible layer roots. The layer ordering must be identical.
    pub fn from_fri_proof(
        core_root: [u8; 32],
        aux_root: [u8; 32],
        fri_proof: &crate::fri::FriProof,
    ) -> Result<Self, VerifyError> {
        let bundle = Self::new(core_root, aux_root, fri_proof.layer_roots.clone());
        bundle.ensure_consistency(fri_proof)?;
        Ok(bundle)
    }

    /// Ensures that the bundle roots match the ones advertised by the FRI
    /// proof. Callers may use this helper when the bundle is constructed from
    /// individual roots to verify that the redundant data is internally
    /// consistent.
    pub fn ensure_consistency(&self, fri_proof: &crate::fri::FriProof) -> Result<(), VerifyError> {
        if self.fri_layer_roots() != fri_proof.layer_roots.as_slice() {
            return Err(VerifyError::MerkleVerifyFailed {
                section: MerkleSection::FriRoots,
            });
        }

        Ok(())
    }
}

/// Wrapper collecting the Merkle bundle and opening payloads for assembly helpers.
///
/// A descriptor owns both the Merkle commitment bundle and the associated
/// out-of-domain opening payloads. Keeping the structures coupled ensures the
/// openings and the advertised roots always travel together, preventing callers
/// from mixing mismatched Merkle data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpeningsDescriptor {
    merkle: MerkleProofBundle,
    openings: Openings,
}

impl OpeningsDescriptor {
    /// Constructs a descriptor from the provided Merkle bundle and openings payload.
    pub fn new(merkle: MerkleProofBundle, openings: Openings) -> Self {
        Self { merkle, openings }
    }

    /// Returns the wrapped Merkle commitment bundle.
    pub fn merkle(&self) -> &MerkleProofBundle {
        &self.merkle
    }

    /// Returns a mutable reference to the wrapped Merkle commitment bundle.
    pub fn merkle_mut(&mut self) -> &mut MerkleProofBundle {
        &mut self.merkle
    }

    /// Returns the wrapped out-of-domain opening payloads.
    pub fn openings(&self) -> &Openings {
        &self.openings
    }

    /// Returns a mutable reference to the wrapped out-of-domain opening payloads.
    pub fn openings_mut(&mut self) -> &mut Openings {
        &mut self.openings
    }

    /// Returns the wrapped trace openings describing trace Merkle queries.
    pub fn trace(&self) -> &TraceOpenings {
        self.openings.trace()
    }

    /// Returns a mutable reference to the wrapped trace openings.
    pub fn trace_mut(&mut self) -> &mut TraceOpenings {
        self.openings.trace_mut()
    }

    /// Returns the optional composition openings wrapped by the descriptor.
    pub fn composition(&self) -> Option<&CompositionOpenings> {
        self.openings.composition()
    }

    /// Returns a mutable reference to the optional composition openings.
    pub fn composition_mut(&mut self) -> Option<&mut CompositionOpenings> {
        self.openings.composition_mut()
    }

    /// Returns the wrapped out-of-domain opening payloads accompanying the proof.
    pub fn out_of_domain(&self) -> &Vec<OutOfDomainOpening> {
        self.openings.out_of_domain()
    }

    /// Returns a mutable reference to the wrapped out-of-domain opening payloads.
    pub fn out_of_domain_mut(&mut self) -> &mut Vec<OutOfDomainOpening> {
        self.openings.out_of_domain_mut()
    }

    pub(crate) fn serialize_bytes(&self) -> Result<Vec<u8>, SerError> {
        serialize_openings_descriptor(self)
    }

    pub(crate) fn deserialize_bytes(bytes: &[u8]) -> Result<Self, VerifyError> {
        deserialize_openings_descriptor(bytes)
    }
}

/// Out-of-domain opening container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Openings {
    /// Trace Merkle openings covering core trace queries.
    pub trace: TraceOpenings,
    /// Optional composition openings (mirrors the trace structure).
    pub composition: Option<CompositionOpenings>,
    /// Individual out-of-domain openings.
    pub out_of_domain: Vec<OutOfDomainOpening>,
}

impl Openings {
    /// Returns the Merkle openings covering core trace queries.
    pub fn trace(&self) -> &TraceOpenings {
        &self.trace
    }

    /// Returns a mutable reference to the Merkle openings covering core trace queries.
    pub fn trace_mut(&mut self) -> &mut TraceOpenings {
        &mut self.trace
    }

    /// Returns the optional composition openings, when present.
    pub fn composition(&self) -> Option<&CompositionOpenings> {
        self.composition.as_ref()
    }

    /// Returns a mutable reference to the optional composition openings, when present.
    pub fn composition_mut(&mut self) -> Option<&mut CompositionOpenings> {
        self.composition.as_mut()
    }

    /// Returns the individual out-of-domain openings accompanying the proof.
    pub fn out_of_domain(&self) -> &Vec<OutOfDomainOpening> {
        &self.out_of_domain
    }

    /// Returns a mutable reference to the individual out-of-domain openings.
    pub fn out_of_domain_mut(&mut self) -> &mut Vec<OutOfDomainOpening> {
        &mut self.out_of_domain
    }

    pub(crate) fn serialize_bytes(&self) -> Result<Vec<u8>, SerError> {
        serialize_openings_bytes(self)
    }
}

/// Merkle opening data covering trace commitments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceOpenings {
    /// Query indices sampled from the FRI transcript.
    pub indices: Vec<u32>,
    /// Leaf payloads revealed for each queried index.
    pub leaves: Vec<Vec<u8>>,
    /// Authentication paths proving membership for each query.
    pub paths: Vec<MerkleAuthenticationPath>,
}

impl TraceOpenings {
    /// Returns the query indices sampled from the FRI transcript.
    pub fn indices(&self) -> &[u32] {
        &self.indices
    }

    /// Returns a mutable reference to the query indices sampled from the FRI transcript.
    pub fn indices_mut(&mut self) -> &mut Vec<u32> {
        &mut self.indices
    }

    /// Returns the leaf payloads revealed for each queried index.
    pub fn leaves(&self) -> &[Vec<u8>] {
        &self.leaves
    }

    /// Returns a mutable reference to the leaf payloads revealed for each queried index.
    pub fn leaves_mut(&mut self) -> &mut Vec<Vec<u8>> {
        &mut self.leaves
    }

    /// Returns the authentication paths proving membership for each query.
    pub fn paths(&self) -> &[MerkleAuthenticationPath] {
        &self.paths
    }

    /// Returns a mutable reference to the authentication paths proving membership for each query.
    pub fn paths_mut(&mut self) -> &mut Vec<MerkleAuthenticationPath> {
        &mut self.paths
    }
}

/// Merkle opening data covering composition commitments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionOpenings {
    /// Query indices sampled from the FRI transcript.
    pub indices: Vec<u32>,
    /// Leaf payloads revealed for each queried index.
    pub leaves: Vec<Vec<u8>>,
    /// Authentication paths proving membership for each query.
    pub paths: Vec<MerkleAuthenticationPath>,
}

impl CompositionOpenings {
    /// Returns the query indices sampled from the FRI transcript.
    pub fn indices(&self) -> &[u32] {
        &self.indices
    }

    /// Returns a mutable reference to the query indices sampled from the FRI transcript.
    pub fn indices_mut(&mut self) -> &mut Vec<u32> {
        &mut self.indices
    }

    /// Returns the leaf payloads revealed for each queried index.
    pub fn leaves(&self) -> &[Vec<u8>] {
        &self.leaves
    }

    /// Returns a mutable reference to the leaf payloads revealed for each queried index.
    pub fn leaves_mut(&mut self) -> &mut Vec<Vec<u8>> {
        &mut self.leaves
    }

    /// Returns the authentication paths proving membership for each query.
    pub fn paths(&self) -> &[MerkleAuthenticationPath] {
        &self.paths
    }

    /// Returns a mutable reference to the authentication paths proving membership for each query.
    pub fn paths_mut(&mut self) -> &mut Vec<MerkleAuthenticationPath> {
        &mut self.paths
    }
}

/// Authentication path for a Merkle opening.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleAuthenticationPath {
    /// Sequence of nodes from the leaf to the root.
    pub nodes: Vec<MerklePathNode>,
}

impl MerkleAuthenticationPath {
    /// Returns the sequence of nodes from the leaf to the root.
    pub fn nodes(&self) -> &[MerklePathNode] {
        &self.nodes
    }

    /// Returns a mutable reference to the sequence of nodes from the leaf to the root.
    pub fn nodes_mut(&mut self) -> &mut Vec<MerklePathNode> {
        &mut self.nodes
    }
}

/// Single node within an authentication path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePathNode {
    /// Position of the caller node within the parent (`0` for left, `1` for right).
    pub index: u8,
    /// Sibling digest paired with the caller node at this level.
    pub sibling: [u8; 32],
}

/// Telemetry frame exposing declared lengths and FRI parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Telemetry {
    /// Declared header length (used for sanity checks).
    pub header_length: u32,
    /// Declared body length (includes integrity digest).
    pub body_length: u32,
    /// Optional mirror of the FRI parameters encoded in the proof body.
    pub fri_parameters: FriParametersMirror,
    /// Integrity digest covering the header bytes and body payload.
    pub integrity_digest: DigestBytes,
}

impl Telemetry {
    /// Returns the declared header length for the proof payload.
    pub fn header_length(&self) -> u32 {
        self.header_length
    }

    /// Updates the declared header length for the proof payload.
    pub fn set_header_length(&mut self, value: u32) {
        self.header_length = value;
    }

    /// Returns the declared body length for the proof payload.
    pub fn body_length(&self) -> u32 {
        self.body_length
    }

    /// Updates the declared body length for the proof payload.
    pub fn set_body_length(&mut self, value: u32) {
        self.body_length = value;
    }

    /// Returns the mirrored FRI parameters stored in the telemetry frame.
    pub fn fri_parameters(&self) -> &FriParametersMirror {
        &self.fri_parameters
    }

    /// Returns a mutable reference to the mirrored FRI parameters.
    pub fn fri_parameters_mut(&mut self) -> &mut FriParametersMirror {
        &mut self.fri_parameters
    }

    /// Returns the integrity digest covering the header and body payload.
    pub fn integrity_digest(&self) -> &DigestBytes {
        &self.integrity_digest
    }

    /// Returns a mutable reference to the integrity digest.
    pub fn integrity_digest_mut(&mut self) -> &mut DigestBytes {
        &mut self.integrity_digest
    }

    /// Replaces the integrity digest covering the proof payload.
    pub fn set_integrity_digest(&mut self, digest: DigestBytes) {
        self.integrity_digest = digest;
    }
}

/// Wrapper combining the telemetry presence flag with the telemetry payload.
///
/// The wrapper keeps the availability bit together with the decoded telemetry
/// frame to maintain the invariant that consumers interrogate both pieces of
/// information through a single handle. The flag controls whether the frame is
/// serialized while still allowing builders to pre-populate the structure with
/// canonical defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryOption {
    has_telemetry: bool,
    telemetry: Telemetry,
}

impl TelemetryOption {
    /// Creates a wrapper describing whether telemetry data is present.
    pub fn new(has_telemetry: bool, telemetry: Telemetry) -> Self {
        Self {
            has_telemetry,
            telemetry,
        }
    }

    /// Returns `true` when telemetry data is present in the proof payload.
    pub fn is_present(&self) -> bool {
        self.has_telemetry
    }

    /// Updates the telemetry presence flag for the proof payload.
    pub fn set_present(&mut self, value: bool) {
        self.has_telemetry = value;
    }

    /// Returns the wrapped telemetry frame describing declared lengths.
    pub fn frame(&self) -> &Telemetry {
        &self.telemetry
    }

    /// Returns a mutable reference to the wrapped telemetry frame.
    pub fn frame_mut(&mut self) -> &mut Telemetry {
        &mut self.telemetry
    }

    /// Returns `true` when telemetry data is available.
    pub fn has_telemetry(&self) -> bool {
        self.is_present()
    }

    /// Mutably updates the telemetry presence flag.
    pub fn set_has_telemetry(&mut self, value: bool) {
        self.set_present(value);
    }

    /// Returns the telemetry payload associated with the proof.
    pub fn telemetry(&self) -> &Telemetry {
        self.frame()
    }

    /// Returns a mutable reference to the telemetry payload.
    pub fn telemetry_mut(&mut self) -> &mut Telemetry {
        self.frame_mut()
    }

    pub(crate) fn serialize_bytes(&self) -> Result<Option<Vec<u8>>, SerError> {
        if !self.is_present() {
            return Ok(None);
        }

        let mut out = Vec::new();
        serialize_telemetry_frame_bytes(self.frame(), &mut out)?;
        Ok(Some(out))
    }

    pub(crate) fn deserialize_bytes(
        present: bool,
        bytes: Option<&[u8]>,
    ) -> Result<Self, VerifyError> {
        match (present, bytes) {
            (false, None) => Ok(Self::new(false, Telemetry::default())),
            (true, Some(payload)) => {
                let telemetry = deserialize_telemetry_frame_bytes(payload)?;
                Ok(Self::new(true, telemetry))
            }
            (false, Some(_)) | (true, None) => Err(VerifyError::Serialization(SerKind::Telemetry)),
        }
    }
}

/// Structured verification report describing the outcome of deterministic checks.
///
/// The struct implements [`Default`] so all stage flags fall back to `false`,
/// `total_bytes` defaults to `0`, and `error` becomes `None` when
/// deserialized from older payloads that omit the newer fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VerifyReport {
    /// Flag indicating whether parameter hashing checks succeeded.
    #[serde(default)]
    pub params_ok: bool,
    /// Flag indicating whether public input binding checks succeeded.
    #[serde(default)]
    pub public_ok: bool,
    /// Flag indicating whether Merkle commitment checks succeeded.
    #[serde(default)]
    pub merkle_ok: bool,
    /// Flag indicating whether the FRI verifier accepted the proof.
    #[serde(default)]
    pub fri_ok: bool,
    /// Flag indicating whether composition polynomial openings matched expectations.
    #[serde(default)]
    pub composition_ok: bool,
    /// Total serialized byte length observed during verification.
    #[serde(default)]
    pub total_bytes: u64,
    /// Optional immutable proof view built from header fields and placeholders.
    #[serde(default)]
    pub proof: Option<ProofHandles>,
    /// Optional verification error captured during decoding or checks.
    #[serde(default)]
    pub error: Option<VerifyError>,
    /// Optional telemetry emitted by the verifier.
    #[serde(default)]
    pub telemetry: Option<VerifyTelemetry>,
}

/// Fine-grained timings emitted by the verifier.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VerifyTelemetry {
    /// Time spent decoding and validating the envelope prior to Merkle checks (nanoseconds).
    pub parse_duration_ns: u64,
    /// Time spent validating Merkle commitments and transcript-derived openings (nanoseconds).
    pub merkle_duration_ns: u64,
    /// Time spent inside the FRI verifier (nanoseconds).
    pub fri_duration_ns: u64,
}

impl VerifyTelemetry {
    pub const fn zeroed() -> Self {
        Self {
            parse_duration_ns: 0,
            merkle_duration_ns: 0,
            fri_duration_ns: 0,
        }
    }

    pub fn record_parse(&mut self, duration: Duration) {
        self.parse_duration_ns = saturating_nanos(duration);
    }

    pub fn record_merkle(&mut self, duration: Duration) {
        self.merkle_duration_ns = saturating_nanos(duration);
    }

    pub fn record_fri(&mut self, duration: Duration) {
        self.fri_duration_ns = saturating_nanos(duration);
    }
}

fn saturating_nanos(duration: Duration) -> u64 {
    duration
        .as_nanos()
        .min(u128::from(u64::MAX))
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Errors surfaced while decoding or validating a proof envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MerkleSection {
    /// FRI layer roots emitted by the prover did not line up with the Merkle bundle.
    FriRoots,
    /// Authentication path validation failed while replaying FRI queries.
    FriPath,
    /// Core trace openings failed to verify against the commitment.
    TraceCommit,
    /// Composition openings failed to verify against the commitment.
    CompositionCommit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FriVerifyIssue {
    /// The verifier derived more queries than the envelope advertised or allowed.
    QueryOutOfRange,
    /// Authentication path validation failed for one of the FRI queries.
    PathInvalid,
    /// Layer roots or folding invariants failed inside the FRI verifier.
    LayerMismatch,
    /// Security level recorded in the proof did not match the verifier profile.
    SecurityLevelMismatch,
    /// The envelope declared more layers than the verifier or spec permits.
    LayerBudgetExceeded,
    /// The codeword reconstructed during FRI validation was empty or malformed.
    EmptyCodeword,
    /// The FRI proof encoded an unexpected version identifier.
    VersionMismatch,
    /// The advertised query budget disagreed with the verifier profile.
    QueryBudgetMismatch,
    /// Folding invariants or related constraints were violated.
    FoldingConstraint,
    /// The prover emitted inconsistent out-of-domain samples.
    OodsInvalid,
    /// The verifier rejected the FRI proof for another reason.
    Generic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyError {
    /// The proof version encoded in the header is not supported.
    VersionMismatch { expected: u16, actual: u16 },
    /// The proof kind byte does not match the canonical ordering.
    UnknownProofKind(u8),
    /// Declared header length does not match the observed byte count.
    HeaderLengthMismatch { declared: u32, actual: u32 },
    /// Declared body length does not match the observed byte count.
    BodyLengthMismatch { declared: u32, actual: u32 },
    /// The buffer ended prematurely while parsing a section.
    UnexpectedEndOfBuffer(String),
    /// Integrity digest recomputed from the payload disagreed with the header.
    IntegrityDigestMismatch,
    /// The FRI section contained invalid structure.
    InvalidFriSection(String),
    /// Encountered a non-canonical field element while decoding.
    NonCanonicalFieldElement,
    /// Parameter digest did not match the expected configuration digest.
    ParamsHashMismatch,
    /// Public inputs failed decoding or did not match the expected layout.
    PublicInputMismatch,
    /// Digest derived from the public-input section mismatched the advertised digest.
    PublicDigestMismatch,
    /// Transcript phases were emitted out of order or with missing tags.
    TranscriptOrder,
    /// Out-of-domain openings were malformed or contained inconsistent values.
    OutOfDomainInvalid,
    /// Proof declared a Merkle scheme unsupported by the verifier.
    UnsupportedMerkleScheme,
    /// Merkle roots decoded from the payload disagreed with the header.
    RootMismatch { section: MerkleSection },
    /// Merkle verification failed for a specific section.
    MerkleVerifyFailed { section: MerkleSection },
    /// Trace leaf payload did not match the expected evaluation.
    TraceLeafMismatch,
    /// Composition leaf payload did not match the expected evaluation.
    CompositionLeafMismatch,
    /// Trace out-of-domain evaluation disagreed with the Merkle/Fri binding.
    TraceOodMismatch,
    /// Composition out-of-domain evaluation disagreed with the Merkle/Fri binding.
    CompositionOodMismatch,
    /// Composition openings disagreed with the commitments advertised in the header.
    CompositionInconsistent { reason: String },
    /// FRI verification rejected the envelope.
    FriVerifyFailed { issue: FriVerifyIssue },
    /// Composition polynomial exceeded declared degree bounds.
    DegreeBoundExceeded,
    /// Proof exceeded the configured maximum proof size (values measured in kibibytes).
    ProofTooLarge { max_kb: u32, got_kb: u32 },
    /// Proof declared openings but none were provided in the payload.
    EmptyOpenings,
    /// Query indices were not strictly increasing.
    IndicesNotSorted,
    /// Query indices contained duplicates.
    IndicesDuplicate { index: u32 },
    /// Query indices disagreed with the locally derived transcript indices.
    IndicesMismatch,
    /// Aggregated digest did not match the recomputed digest during batching.
    AggregationDigestMismatch,
    /// Malformed serialization encountered while decoding a proof section.
    Serialization(SerKind),
    /// Deterministic hashing helper failed while sampling queries.
    DeterministicHash(DeterministicHashError),
}

impl From<crate::ser::SerError> for VerifyError {
    fn from(err: crate::ser::SerError) -> Self {
        VerifyError::Serialization(err.kind())
    }
}

impl From<DeterministicHashError> for VerifyError {
    fn from(err: DeterministicHashError) -> Self {
        VerifyError::DeterministicHash(err)
    }
}

/// Mirror of the FRI parameters stored inside the proof body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriParametersMirror {
    /// Folding factor (fixed to two in the current implementation).
    pub fold: u8,
    /// Degree of the cap polynomial.
    pub cap_degree: u16,
    /// Size of the cap commitment.
    pub cap_size: u32,
    /// Query budget consumed during verification.
    pub query_budget: u16,
}

impl Default for FriParametersMirror {
    fn default() -> Self {
        Self {
            fold: 2,
            cap_degree: 0,
            cap_size: 0,
            query_budget: 0,
        }
    }
}

/// Out-of-domain opening description stored in the proof body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutOfDomainOpening {
    /// OOD evaluation point.
    pub point: [u8; 32],
    /// Core trace evaluations at that point.
    pub core_values: Vec<[u8; 32]>,
    /// Auxiliary evaluations.
    pub aux_values: Vec<[u8; 32]>,
    /// Composition polynomial evaluation.
    pub composition_value: [u8; 32],
}

impl OutOfDomainOpening {
    pub(crate) fn serialize_bytes(&self) -> Result<Vec<u8>, SerError> {
        let mut buffer = Vec::new();
        write_digest(&mut buffer, &self.point);
        let core_len = ensure_u32(self.core_values.len(), SerKind::Openings, "core_len")?;
        write_u32(&mut buffer, core_len);
        for value in &self.core_values {
            write_digest(&mut buffer, value);
        }
        let aux_len = ensure_u32(self.aux_values.len(), SerKind::Openings, "aux_len")?;
        write_u32(&mut buffer, aux_len);
        for value in &self.aux_values {
            write_digest(&mut buffer, value);
        }
        write_digest(&mut buffer, &self.composition_value);
        Ok(buffer)
    }

    pub(crate) fn deserialize_bytes(bytes: &[u8]) -> Result<Self, VerifyError> {
        let mut cursor = ByteReader::new(bytes);
        let point = read_digest(&mut cursor, SerKind::Openings, "point")?;
        let core_len = read_u32(&mut cursor, SerKind::Openings, "core_len")? as usize;
        let mut core_values = Vec::with_capacity(core_len);
        for _ in 0..core_len {
            core_values.push(read_digest(&mut cursor, SerKind::Openings, "core_value")?);
        }
        let aux_len = read_u32(&mut cursor, SerKind::Openings, "aux_len")? as usize;
        let mut aux_values = Vec::with_capacity(aux_len);
        for _ in 0..aux_len {
            aux_values.push(read_digest(&mut cursor, SerKind::Openings, "aux_value")?);
        }
        let composition_value = read_digest(&mut cursor, SerKind::Openings, "composition_value")?;
        ensure_consumed(&cursor, SerKind::Openings)?;
        Ok(Self {
            point,
            core_values,
            aux_values,
            composition_value,
        })
    }
}

fn serialize_openings_descriptor(descriptor: &OpeningsDescriptor) -> Result<Vec<u8>, SerError> {
    let merkle_bytes = serialize_merkle_bundle_bytes(descriptor.merkle())?;
    let openings_bytes = serialize_openings_bytes(descriptor.openings())?;

    let mut buffer = Vec::new();
    let merkle_len = ensure_u32(merkle_bytes.len(), SerKind::TraceCommitment, "merkle_len")?;
    write_u32(&mut buffer, merkle_len);
    write_bytes(&mut buffer, &merkle_bytes);

    let openings_len = ensure_u32(openings_bytes.len(), SerKind::Openings, "openings_len")?;
    write_u32(&mut buffer, openings_len);
    write_bytes(&mut buffer, &openings_bytes);
    Ok(buffer)
}

fn deserialize_openings_descriptor(bytes: &[u8]) -> Result<OpeningsDescriptor, VerifyError> {
    let mut cursor = ByteReader::new(bytes);
    let merkle_len = read_u32(&mut cursor, SerKind::TraceCommitment, "merkle_len")? as usize;
    let merkle_bytes = cursor.read_vec(SerKind::TraceCommitment, "merkle_bytes", merkle_len)?;

    let openings_len = read_u32(&mut cursor, SerKind::Openings, "openings_len")? as usize;
    let openings_bytes = cursor.read_vec(SerKind::Openings, "openings_bytes", openings_len)?;

    ensure_consumed(&cursor, SerKind::Proof)?;

    let merkle = deserialize_merkle_bundle_bytes(&merkle_bytes)?;
    let openings = deserialize_openings_bytes(&openings_bytes)?;
    Ok(OpeningsDescriptor::new(merkle, openings))
}

fn serialize_merkle_bundle_bytes(bundle: &MerkleProofBundle) -> Result<Vec<u8>, SerError> {
    let mut out = Vec::new();
    write_digest(&mut out, bundle.core_root());
    write_digest(&mut out, bundle.aux_root());
    let layer_count = ensure_u32(
        bundle.fri_layer_roots().len(),
        SerKind::TraceCommitment,
        "fri_roots",
    )?;
    write_u32(&mut out, layer_count);
    for root in bundle.fri_layer_roots() {
        write_digest(&mut out, root);
    }
    Ok(out)
}

fn deserialize_merkle_bundle_bytes(bytes: &[u8]) -> Result<MerkleProofBundle, VerifyError> {
    let mut cursor = ByteReader::new(bytes);
    let core_root = read_digest(&mut cursor, SerKind::TraceCommitment, "core_root")?;
    let aux_root = read_digest(&mut cursor, SerKind::TraceCommitment, "aux_root")?;
    let layer_count = read_u32(&mut cursor, SerKind::TraceCommitment, "fri_roots")? as usize;
    let mut fri_layer_roots = Vec::with_capacity(layer_count);
    for _ in 0..layer_count {
        fri_layer_roots.push(read_digest(
            &mut cursor,
            SerKind::TraceCommitment,
            "fri_root",
        )?);
    }
    ensure_consumed(&cursor, SerKind::TraceCommitment)?;
    Ok(MerkleProofBundle::new(core_root, aux_root, fri_layer_roots))
}

fn serialize_openings_bytes(openings: &Openings) -> Result<Vec<u8>, SerError> {
    let mut buffer = Vec::new();
    encode_merkle_openings(
        &mut buffer,
        openings.trace().indices(),
        openings.trace().leaves(),
        openings.trace().paths(),
    )?;
    match openings.composition() {
        Some(section) => {
            write_u8(&mut buffer, 1);
            encode_merkle_openings(
                &mut buffer,
                section.indices(),
                section.leaves(),
                section.paths(),
            )?;
        }
        None => write_u8(&mut buffer, 0),
    }

    let count = ensure_u32(openings.out_of_domain().len(), SerKind::Openings, "ood_len")?;
    write_u32(&mut buffer, count);
    for opening in openings.out_of_domain() {
        let encoded = opening.serialize_bytes()?;
        let encoded_len = ensure_u32(encoded.len(), SerKind::Openings, "ood_block")?;
        write_u32(&mut buffer, encoded_len);
        write_bytes(&mut buffer, &encoded);
    }
    Ok(buffer)
}

fn deserialize_openings_bytes(bytes: &[u8]) -> Result<Openings, VerifyError> {
    let mut cursor = ByteReader::new(bytes);
    let (trace_indices, trace_leaves, trace_paths) = decode_merkle_openings(&mut cursor)?;
    let trace = TraceOpenings {
        indices: trace_indices,
        leaves: trace_leaves,
        paths: trace_paths,
    };
    let has_composition = read_u8(&mut cursor, SerKind::Openings, "composition_flag")?;
    let composition = match has_composition {
        0 => None,
        1 => {
            let (indices, leaves, paths) = decode_merkle_openings(&mut cursor)?;
            Some(CompositionOpenings {
                indices,
                leaves,
                paths,
            })
        }
        _ => {
            return Err(VerifyError::Serialization(SerKind::Openings));
        }
    };

    let count = read_u32(&mut cursor, SerKind::Openings, "ood_len")? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let block_len = read_u32(&mut cursor, SerKind::Openings, "ood_block")? as usize;
        let block = cursor.read_vec(SerKind::Openings, "ood_bytes", block_len)?;
        let opening = OutOfDomainOpening::deserialize_bytes(&block)?;
        out.push(opening);
    }
    ensure_consumed(&cursor, SerKind::Openings)?;
    Ok(Openings {
        trace,
        composition,
        out_of_domain: out,
    })
}

fn encode_merkle_openings(
    buffer: &mut Vec<u8>,
    indices: &[u32],
    leaves: &[Vec<u8>],
    paths: &[MerkleAuthenticationPath],
) -> Result<(), SerError> {
    let indices_len = ensure_u32(indices.len(), SerKind::Openings, "indices_len")?;
    write_u32(buffer, indices_len);
    for index in indices {
        write_u32(buffer, *index);
    }

    let leaves_len = ensure_u32(leaves.len(), SerKind::Openings, "leaves_len")?;
    write_u32(buffer, leaves_len);
    for leaf in leaves {
        let leaf_len = ensure_u32(leaf.len(), SerKind::Openings, "leaf_len")?;
        write_u32(buffer, leaf_len);
        write_bytes(buffer, leaf);
    }

    let paths_len = ensure_u32(paths.len(), SerKind::Openings, "paths_len")?;
    write_u32(buffer, paths_len);
    for path in paths {
        let nodes_len = ensure_u32(path.nodes.len(), SerKind::Openings, "path_len")?;
        write_u32(buffer, nodes_len);
        for node in &path.nodes {
            write_u8(buffer, node.index);
            write_digest(buffer, &node.sibling);
        }
    }
    Ok(())
}

type DecodedMerkleOpenings = (Vec<u32>, Vec<Vec<u8>>, Vec<MerkleAuthenticationPath>);

fn decode_merkle_openings(
    cursor: &mut ByteReader<'_>,
) -> Result<DecodedMerkleOpenings, VerifyError> {
    let indices_len = read_u32(cursor, SerKind::Openings, "indices_len")? as usize;
    let mut indices = Vec::with_capacity(indices_len);
    for _ in 0..indices_len {
        indices.push(read_u32(cursor, SerKind::Openings, "index")?);
    }

    let leaves_len = read_u32(cursor, SerKind::Openings, "leaves_len")? as usize;
    let mut leaves = Vec::with_capacity(leaves_len);
    for _ in 0..leaves_len {
        let leaf_len = read_u32(cursor, SerKind::Openings, "leaf_len")? as usize;
        let bytes = cursor.read_vec(SerKind::Openings, "leaf_bytes", leaf_len)?;
        leaves.push(bytes);
    }

    let paths_len = read_u32(cursor, SerKind::Openings, "paths_len")? as usize;
    let mut paths = Vec::with_capacity(paths_len);
    for _ in 0..paths_len {
        let nodes_len = read_u32(cursor, SerKind::Openings, "path_len")? as usize;
        let mut nodes = Vec::with_capacity(nodes_len);
        for _ in 0..nodes_len {
            let index = read_u8(cursor, SerKind::Openings, "path_index")?;
            let sibling = read_digest(cursor, SerKind::Openings, "path_sibling")?;
            nodes.push(MerklePathNode { index, sibling });
        }
        paths.push(MerkleAuthenticationPath { nodes });
    }

    Ok((indices, leaves, paths))
}

fn serialize_telemetry_frame_bytes(
    telemetry: &Telemetry,
    buffer: &mut Vec<u8>,
) -> Result<(), SerError> {
    write_u32(buffer, telemetry.header_length());
    write_u32(buffer, telemetry.body_length());
    write_u8(buffer, telemetry.fri_parameters().fold);
    write_u16(buffer, telemetry.fri_parameters().cap_degree);
    write_u32(buffer, telemetry.fri_parameters().cap_size);
    write_u16(buffer, telemetry.fri_parameters().query_budget);
    write_digest(buffer, &telemetry.integrity_digest().bytes);
    Ok(())
}

fn deserialize_telemetry_frame_bytes(bytes: &[u8]) -> Result<Telemetry, VerifyError> {
    let mut cursor = ByteReader::new(bytes);
    let header_length = read_u32(&mut cursor, SerKind::Telemetry, "header_length")?;
    let body_length = read_u32(&mut cursor, SerKind::Telemetry, "body_length")?;
    let fold = read_u8(&mut cursor, SerKind::Telemetry, "fri.fold")?;
    let cap_degree = read_u16(&mut cursor, SerKind::Telemetry, "fri.cap_degree")?;
    let cap_size = read_u32(&mut cursor, SerKind::Telemetry, "fri.cap_size")?;
    let query_budget = read_u16(&mut cursor, SerKind::Telemetry, "fri.query_budget")?;
    let integrity_digest = read_digest(&mut cursor, SerKind::Telemetry, "integrity_digest")?;
    ensure_consumed(&cursor, SerKind::Telemetry)?;
    Ok(Telemetry {
        header_length,
        body_length,
        fri_parameters: FriParametersMirror {
            fold,
            cap_degree,
            cap_size,
            query_budget,
        },
        integrity_digest: DigestBytes {
            bytes: integrity_digest,
        },
    })
}

fn encode_proof_kind(kind: ProofKind) -> u8 {
    match kind {
        ProofKind::Tx => 0,
        ProofKind::State => 1,
        ProofKind::Pruning => 2,
        ProofKind::Uptime => 3,
        ProofKind::Consensus => 4,
        ProofKind::Identity => 5,
        ProofKind::Aggregation => 6,
        ProofKind::VRF => 7,
    }
}

fn decode_proof_kind(byte: u8) -> Result<ProofKind, VerifyError> {
    Ok(match byte {
        0 => ProofKind::Tx,
        1 => ProofKind::State,
        2 => ProofKind::Pruning,
        3 => ProofKind::Uptime,
        4 => ProofKind::Consensus,
        5 => ProofKind::Identity,
        6 => ProofKind::Aggregation,
        7 => ProofKind::VRF,
        other => return Err(VerifyError::UnknownProofKind(other)),
    })
}

mod proof_kind_codec {
    use super::ProofKind;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &ProofKind, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(encode(*value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ProofKind, D::Error>
    where
        D: Deserializer<'de>,
    {
        let byte = u8::deserialize(deserializer)?;
        decode(byte).map_err(serde::de::Error::custom)
    }

    fn encode(kind: ProofKind) -> u8 {
        match kind {
            ProofKind::Tx => 0,
            ProofKind::State => 1,
            ProofKind::Pruning => 2,
            ProofKind::Uptime => 3,
            ProofKind::Consensus => 4,
            ProofKind::Identity => 5,
            ProofKind::Aggregation => 6,
            ProofKind::VRF => 7,
        }
    }

    fn decode(byte: u8) -> Result<ProofKind, &'static str> {
        Ok(match byte {
            0 => ProofKind::Tx,
            1 => ProofKind::State,
            2 => ProofKind::Pruning,
            3 => ProofKind::Uptime,
            4 => ProofKind::Consensus,
            5 => ProofKind::Identity,
            6 => ProofKind::Aggregation,
            7 => ProofKind::VRF,
            _ => return Err("unknown proof kind"),
        })
    }
}

mod proof_version_codec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u16, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(*value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u16, D::Error>
    where
        D: Deserializer<'de>,
    {
        u16::deserialize(deserializer)
    }
}
