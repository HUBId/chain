#![cfg(feature = "backend-rpp-stark")]

mod error;
mod report;

pub use error::{
    RppStarkFriIssue, RppStarkMerkleSection, RppStarkSerializationContext, RppStarkVerifierError,
    RppStarkVerifyFailure,
};
pub use report::{
    RppStarkStageTimings, RppStarkVerificationFlags, RppStarkVerificationReport,
};

use rpp_stark::backend::{ensure_proof_size_consistency, params_limit_to_node_bytes};
use rpp_stark::config::{
    build_proof_system_config, build_verifier_context, compute_param_digest, CommonIdentifiers,
    ProfileConfig, COMMON_IDENTIFIERS, COMMON_IDENTIFIERS_ARITY4, PROFILE_HIGH_SECURITY_CONFIG,
    PROFILE_STANDARD_ARITY4_CONFIG, PROFILE_STANDARD_CONFIG, PROFILE_THROUGHPUT_CONFIG,
};
use rpp_stark::params::{deserialize_params, StarkParams};
use rpp_stark::proof::params::canonical_stark_params;
use rpp_stark::proof::public_inputs::{ExecutionHeaderV1, PublicInputVersion, PublicInputs};
use rpp_stark::proof::ser::map_public_to_config_kind;
use rpp_stark::proof::types::VerifyReport;
use rpp_stark::proof::verifier;
use rpp_stark::utils::serialization::{DigestBytes, ProofBytes};

/// Thin facade around the vendored `rpp-stark` verifier.
#[derive(Debug, Default, Clone, Copy)]
pub struct RppStarkVerifier;

impl RppStarkVerifier {
    /// Creates a new verifier instance.
    #[inline]
    pub const fn new() -> Self {
        Self
    }

    /// Returns the backend identifier for logging and metrics.
    #[inline]
    pub const fn backend_name(&self) -> &'static str {
        "rpp-stark"
    }

    /// Indicates whether the backend wiring is complete.
    #[inline]
    pub const fn is_ready(&self) -> bool {
        true
    }

    /// Verifies a proof against the provided parameters and node size limit.
    pub fn verify(
        &self,
        params: &[u8],
        public_inputs: &[u8],
        proof: &[u8],
        node_limit_bytes: u32,
    ) -> Result<RppStarkVerificationReport, RppStarkVerifierError> {
        let stark_params = decode_stark_params(params)?;
        let (profile, identifiers) = resolve_profile(&stark_params)?;

        ensure_proof_size_consistency(&stark_params, node_limit_bytes)
            .map_err(RppStarkVerifierError::from_size_mapping_error)?;

        let param_digest = compute_param_digest(profile, identifiers);
        let config = build_proof_system_config(profile, &param_digest);
        let verifier_context = build_verifier_context(profile, identifiers, &param_digest, None);

        let decoded_inputs = DecodedExecutionInputs::decode(public_inputs)?;
        let public_inputs_view = decoded_inputs.as_public_inputs();
        let declared_kind = map_public_to_config_kind(public_inputs_view.kind());

        let proof_bytes = ProofBytes::new(proof.to_vec());
        let backend_report = verifier::verify(
            declared_kind,
            &public_inputs_view,
            &proof_bytes,
            &config,
            &verifier_context,
        );
        finalize_report(backend_report)
    }

    /// Convenience helper for the vendored golden-vector suite.
    pub fn verify_golden_vector(
        &self,
        params: &[u8],
        public_inputs: &[u8],
        proof: &[u8],
    ) -> Result<RppStarkVerificationReport, RppStarkVerifierError> {
        let stark_params = decode_stark_params(params)?;
        let node_limit = params_limit_to_node_bytes(&stark_params)
            .map_err(RppStarkVerifierError::from_size_mapping_error)?;
        self.verify(params, public_inputs, proof, node_limit)
    }
}

/// Convenience function mirroring [`RppStarkVerifier::verify_golden_vector`].
pub fn verify_golden_vector(
    params: &[u8],
    public_inputs: &[u8],
    proof: &[u8],
) -> Result<RppStarkVerificationReport, RppStarkVerifierError> {
    RppStarkVerifier::new().verify_golden_vector(params, public_inputs, proof)
}

fn finalize_report(
    backend_report: VerifyReport,
) -> Result<RppStarkVerificationReport, RppStarkVerifierError> {
    let report = RppStarkVerificationReport::from_backend(&backend_report);
    if let Some(error) = backend_report.error {
        let failure = RppStarkVerifyFailure::from(error);
        return Err(RppStarkVerifierError::VerificationFailed { failure, report });
    }
    Ok(report)
}

fn decode_stark_params(bytes: &[u8]) -> Result<StarkParams, RppStarkVerifierError> {
    deserialize_params(bytes).map_err(|err| RppStarkVerifierError::MalformedParams {
        context: err.kind().into(),
    })
}

fn resolve_profile(
    params: &StarkParams,
) -> Result<(&'static ProfileConfig, &'static CommonIdentifiers), RppStarkVerifierError> {
    const CANDIDATES: &[(&ProfileConfig, &CommonIdentifiers)] = &[
        (&PROFILE_STANDARD_CONFIG, &COMMON_IDENTIFIERS),
        (&PROFILE_STANDARD_ARITY4_CONFIG, &COMMON_IDENTIFIERS_ARITY4),
        (&PROFILE_HIGH_SECURITY_CONFIG, &COMMON_IDENTIFIERS),
        (&PROFILE_THROUGHPUT_CONFIG, &COMMON_IDENTIFIERS),
    ];

    for (profile, identifiers) in CANDIDATES {
        let canonical = canonical_stark_params(profile);
        if params == &canonical {
            return Ok((*profile, *identifiers));
        }
    }

    Err(RppStarkVerifierError::UnsupportedParamsProfile {
        profile_id: params.profile_id(),
    })
}

#[derive(Debug, Clone)]
struct DecodedExecutionInputs {
    header: ExecutionHeaderV1,
    body: Vec<u8>,
}

impl DecodedExecutionInputs {
    fn decode(bytes: &[u8]) -> Result<Self, RppStarkVerifierError> {
        const MIN_HEADER_LEN: usize = 1 + 32 + 4 + 4 + 4;
        if bytes.len() < MIN_HEADER_LEN {
            return Err(RppStarkVerifierError::MalformedPublicInputs {
                reason: "public inputs shorter than execution header",
            });
        }

        if bytes[0] != 1 {
            return Err(RppStarkVerifierError::MalformedPublicInputs {
                reason: "unsupported execution header version",
            });
        }

        let mut offset = 1;
        let mut program_digest = [0u8; 32];
        program_digest.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        let mut trace_length_bytes = [0u8; 4];
        trace_length_bytes.copy_from_slice(&bytes[offset..offset + 4]);
        let trace_length = u32::from_le_bytes(trace_length_bytes);
        offset += 4;

        let mut trace_width_bytes = [0u8; 4];
        trace_width_bytes.copy_from_slice(&bytes[offset..offset + 4]);
        let trace_width = u32::from_le_bytes(trace_width_bytes);
        offset += 4;

        let mut body_len_bytes = [0u8; 4];
        body_len_bytes.copy_from_slice(&bytes[offset..offset + 4]);
        let body_len = u32::from_le_bytes(body_len_bytes) as usize;
        offset += 4;

        if bytes.len() != offset + body_len {
            return Err(RppStarkVerifierError::MalformedPublicInputs {
                reason: "execution body length mismatch",
            });
        }

        let body = bytes[offset..].to_vec();
        let header = ExecutionHeaderV1 {
            version: PublicInputVersion::V1,
            program_digest: DigestBytes {
                bytes: program_digest,
            },
            trace_length,
            trace_width,
        };

        Ok(Self { header, body })
    }

    fn as_public_inputs(&self) -> PublicInputs<'_> {
        PublicInputs::Execution {
            header: self.header.clone(),
            body: &self.body,
        }
    }
}
