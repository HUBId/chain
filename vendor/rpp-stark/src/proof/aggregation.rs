//! Batch aggregation rules for combining multiple proofs deterministically.
//!
//! All items in this module are declarative contracts capturing ordering,
//! hashing domains and failure signalling for the batch verification API.
#![allow(dead_code, clippy::too_many_arguments)]

use crate::config::{ProofSystemConfig, VerifierContext};
use crate::hash::Hasher;
use crate::proof::public_inputs::ProofKind;
use crate::proof::ser::{map_public_to_config_kind, serialize_public_inputs};
use crate::ser::SerError;
use crate::utils::serialization::ProofBytes;

use super::public_inputs::PublicInputs;
#[cfg(test)]
use super::types::MerkleSection;
use super::types::{VerifyError, VerifyReport};
use super::verifier;

/// Domain prefix used when deriving aggregation seeds.
pub const AGGREGATION_DOMAIN_PREFIX: &str = "RPP-AGG";

/// Block context bound into the aggregation transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockContext {
    /// Canonical rollup height.
    pub block_height: u64,
    /// Previous state root.
    pub previous_state_root: [u8; 32],
    /// Network identifier used by the rollup chain.
    pub network_id: u32,
}

/// Record describing a proof participating in a batch verification call.
#[derive(Debug, Clone)]
pub struct BatchProofRecord<'a> {
    /// Declared proof kind using the canonical RPP encoding.
    pub kind: ProofKind,
    /// Public inputs (Phase-2 layout) supplied by the caller.
    pub public_inputs: &'a PublicInputs<'a>,
    /// Serialized proof bytes (envelope) for the proof.
    pub proof_bytes: &'a ProofBytes,
}

/// Outcome returned by batch verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchVerificationOutcome {
    /// All proofs were accepted.
    Accept,
    /// Verification aborted because a proof failed.
    Reject {
        /// Index of the failing proof in the input slice.
        failing_proof_index: usize,
        /// Documented failure class.
        error: VerifyError,
    },
}

/// Batch verification specification capturing deterministic orchestration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchVerificationSpec;

impl BatchVerificationSpec {
    /// Steps performed by batch verification.
    pub const STEPS: &'static [&'static str] = &[
        "derive_block_seed",
        "precheck_envelopes_and_parameters",
        "derive_per_proof_seeds",
        "schedule_queries",
        "execute_fri_batch",
        "aggregate_digests",
    ];

    /// Description of the block seed derivation formula.
    pub const BLOCK_SEED_RULE: &'static str =
        "block_seed = BLAKE3('RPP-AGG' || block_context || sorted ProofKind codes)";

    /// Description of the per proof seed derivation formula.
    pub const PER_PROOF_SEED_RULE: &'static str =
        "seed_i = BLAKE3(block_seed || u32_le(i) || proof_kind_code)";

    /// Description of the query scheduling rule.
    pub const QUERY_SELECTION_RULE: &'static str =
        "interpret seed_i as little-endian stream; map to domain via modulo";

    /// Description of the aggregation digest rule.
    pub const AGGREGATION_DIGEST_RULE: &'static str =
        "BLAKE3(concat(sorted individual digests by (ProofKind, PI digest)))";
}

/// Verifies a batch of proofs under a shared block context.
pub fn batch_verify(
    block_context: &BlockContext,
    proofs: &[BatchProofRecord<'_>],
    config: &ProofSystemConfig,
    verifier_context: &VerifierContext,
) -> BatchVerificationOutcome {
    let sorted = match sort_batch_proofs(proofs) {
        Ok(sorted) => sorted,
        Err((failing_proof_index, error)) => {
            return BatchVerificationOutcome::Reject {
                failing_proof_index,
                error,
            }
        }
    };
    run_batch_with_callbacks(
        block_context,
        &sorted,
        config,
        verifier_context,
        |item, config, context| {
            let config_kind = map_public_to_config_kind(item.record.kind);
            verifier::verify(
                config_kind,
                item.record.public_inputs,
                item.record.proof_bytes,
                config,
                context,
            )
        },
    )
}

fn run_batch_with_callbacks<'a, VerifyFn>(
    block_context: &BlockContext,
    sorted: &[SortedProof<'a>],
    config: &ProofSystemConfig,
    verifier_context: &VerifierContext,
    mut verify_fn: VerifyFn,
) -> BatchVerificationOutcome
where
    VerifyFn: FnMut(&SortedProof<'a>, &ProofSystemConfig, &VerifierContext) -> VerifyReport,
{
    let block_seed = derive_block_seed(block_context, sorted);
    let _per_proof_seeds = derive_per_proof_seeds(&block_seed, sorted);

    for item in sorted {
        let report = verify_fn(item, config, verifier_context);
        if let Some(error) = report.error {
            return BatchVerificationOutcome::Reject {
                failing_proof_index: item.original_index,
                error,
            };
        }
    }

    let _aggregate_digest = compute_aggregate_digest(sorted);

    BatchVerificationOutcome::Accept
}

#[derive(Debug, Clone)]
struct SortedProof<'a> {
    record: &'a BatchProofRecord<'a>,
    pi_digest: [u8; 32],
    original_index: usize,
}

fn sort_batch_proofs<'a>(
    proofs: &'a [BatchProofRecord<'a>],
) -> Result<Vec<SortedProof<'a>>, (usize, VerifyError)> {
    let mut entries: Vec<SortedProof<'a>> = Vec::with_capacity(proofs.len());
    for (index, record) in proofs.iter().enumerate() {
        let pi_digest = compute_public_input_digest(record.kind, record.public_inputs)
            .map_err(|err| (index, VerifyError::from(err)))?;
        entries.push(SortedProof {
            record,
            pi_digest,
            original_index: index,
        });
    }

    entries.sort_by(|a, b| {
        a.record
            .kind
            .cmp(&b.record.kind)
            .then_with(|| a.pi_digest.cmp(&b.pi_digest))
            .then_with(|| a.original_index.cmp(&b.original_index))
    });

    Ok(entries)
}

fn compute_public_input_digest(
    kind: ProofKind,
    inputs: &PublicInputs<'_>,
) -> Result<[u8; 32], SerError> {
    let mut hasher = Hasher::new();
    hasher.update(b"RPP-PI-V1");
    hasher.update(&[kind.code()]);
    let serialized = serialize_public_inputs(inputs)?;
    hasher.update(&serialized);
    Ok(*hasher.finalize().as_bytes())
}

fn derive_block_seed(block_context: &BlockContext, sorted: &[SortedProof<'_>]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(AGGREGATION_DOMAIN_PREFIX.as_bytes());
    hasher.update(&block_context.block_height.to_le_bytes());
    hasher.update(&block_context.previous_state_root);
    hasher.update(&block_context.network_id.to_le_bytes());
    let mut codes: Vec<u8> = sorted.iter().map(|item| item.record.kind.code()).collect();
    codes.sort_unstable();
    hasher.update(&codes);
    *hasher.finalize().as_bytes()
}

fn derive_per_proof_seeds(block_seed: &[u8; 32], sorted: &[SortedProof<'_>]) -> Vec<[u8; 32]> {
    sorted
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let mut hasher = Hasher::new();
            hasher.update(block_seed);
            hasher.update(&(index as u32).to_le_bytes());
            hasher.update(&[item.record.kind.code()]);
            *hasher.finalize().as_bytes()
        })
        .collect()
}

fn compute_aggregate_digest(sorted: &[SortedProof<'_>]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    for item in sorted {
        hasher.update(&item.pi_digest);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        CommonIdentifiers, ParamDigest, ProfileConfig, ProofSystemConfig, ProofVersion,
        PROFILE_STANDARD_CONFIG,
    };
    use crate::proof::public_inputs::{
        AggregationHeaderV1, ExecutionHeaderV1, PublicInputVersion, PublicInputs, RecursionHeaderV1,
    };
    use crate::proof::types::PROOF_VERSION;
    use crate::utils::serialization::{DigestBytes, FieldElementBytes, ProofBytes};

    fn dummy_config() -> (ProofSystemConfig, VerifierContext) {
        let profile: ProfileConfig = PROFILE_STANDARD_CONFIG.clone();
        let param_digest = ParamDigest(DigestBytes { bytes: [1u8; 32] });
        let config = ProofSystemConfig {
            proof_version: ProofVersion(PROOF_VERSION as u8),
            profile: profile.clone(),
            param_digest: param_digest.clone(),
        };
        let verifier_context = VerifierContext {
            profile,
            param_digest,
            common_ids: CommonIdentifiers {
                field_id: crate::config::FIELD_ID_GOLDILOCKS_64,
                merkle_scheme_id: crate::config::MERKLE_SCHEME_ID_BLAKE3_2ARY_V1,
                transcript_version_id: crate::config::TRANSCRIPT_VERSION_ID_RPP_FS_V1,
                fri_plan_id: crate::config::FRI_PLAN_ID_FOLD2_V1,
            },
            limits: PROFILE_STANDARD_CONFIG.limits.clone(),
            metrics: None,
        };
        (config, verifier_context)
    }

    fn sample_public_inputs() -> Vec<PublicInputs<'static>> {
        vec![
            PublicInputs::Execution {
                header: ExecutionHeaderV1 {
                    version: PublicInputVersion::V1,
                    program_digest: DigestBytes { bytes: [2u8; 32] },
                    trace_length: 8,
                    trace_width: 4,
                },
                body: b"exec",
            },
            PublicInputs::Aggregation {
                header: AggregationHeaderV1 {
                    version: PublicInputVersion::V1,
                    circuit_digest: DigestBytes { bytes: [3u8; 32] },
                    leaf_count: 2,
                    root_digest: DigestBytes { bytes: [4u8; 32] },
                },
                body: b"agg",
            },
            PublicInputs::Recursion {
                header: RecursionHeaderV1 {
                    version: PublicInputVersion::V1,
                    depth: 1,
                    boundary_digest: DigestBytes { bytes: [5u8; 32] },
                    recursion_seed: FieldElementBytes { bytes: [6u8; 32] },
                },
                body: b"rec",
            },
        ]
    }

    fn sample_records<'a>(inputs: &'a [PublicInputs<'a>]) -> Vec<BatchProofRecord<'a>> {
        let proofs: Vec<&'static ProofBytes> = vec![
            Box::leak(Box::new(ProofBytes::new(vec![0u8; 4]))),
            Box::leak(Box::new(ProofBytes::new(vec![1u8; 4]))),
            Box::leak(Box::new(ProofBytes::new(vec![2u8; 4]))),
        ];

        vec![
            BatchProofRecord {
                kind: ProofKind::Execution,
                public_inputs: &inputs[0],
                proof_bytes: proofs[0],
            },
            BatchProofRecord {
                kind: ProofKind::Aggregation,
                public_inputs: &inputs[1],
                proof_bytes: proofs[1],
            },
            BatchProofRecord {
                kind: ProofKind::Recursion,
                public_inputs: &inputs[2],
                proof_bytes: proofs[2],
            },
        ]
    }

    fn dummy_report() -> VerifyReport {
        VerifyReport {
            params_ok: true,
            public_ok: true,
            merkle_ok: false,
            fri_ok: false,
            composition_ok: false,
            total_bytes: 0,
            proof: None,
            error: None,
        }
    }

    #[test]
    fn batch_sort_orders_by_kind_pi_digest_then_index_ok() {
        let inputs = sample_public_inputs();
        let records = sample_records(&inputs);

        // Shuffle the sample records and duplicate them so we observe ordering
        // guarantees across distinct kinds, public-input digests and original
        // indices.
        let mut unsorted = vec![records[2].clone(), records[0].clone(), records[1].clone()];
        unsorted.extend(records.iter().cloned());

        let sorted = sort_batch_proofs(&unsorted).expect("sorting should succeed");
        let mut previous: Option<(ProofKind, [u8; 32], usize)> = None;
        for entry in sorted {
            let current = (entry.record.kind, entry.pi_digest, entry.original_index);
            if let Some(prev) = previous {
                assert!(
                    prev <= current,
                    "sorted order must be lexicographic over (kind, pi_digest, original_index)"
                );
            }
            previous = Some(current);
        }
    }

    #[test]
    fn batch_fast_path_rejects_and_reports_index_ok() {
        let inputs = sample_public_inputs();
        let records = sample_records(&inputs);
        let sorted = sort_batch_proofs(&records).expect("sorting should succeed");
        let (config, verifier_context) = dummy_config();
        let block_context = BlockContext {
            block_height: 42,
            previous_state_root: [11u8; 32],
            network_id: 7,
        };

        let outcome = run_batch_with_callbacks(
            &block_context,
            &sorted,
            &config,
            &verifier_context,
            |item, _, _| {
                if item.original_index == 1 {
                    let mut report = dummy_report();
                    report.error = Some(VerifyError::ParamsHashMismatch);
                    report
                } else {
                    dummy_report()
                }
            },
        );

        assert_eq!(
            outcome,
            BatchVerificationOutcome::Reject {
                failing_proof_index: 1,
                error: VerifyError::ParamsHashMismatch,
            }
        );
    }

    #[test]
    fn batch_executor_bubbles_fri_failures_ok() {
        let inputs = sample_public_inputs();
        let records = sample_records(&inputs);
        let sorted = sort_batch_proofs(&records).expect("sorting should succeed");
        let (config, verifier_context) = dummy_config();
        let block_context = BlockContext {
            block_height: 5,
            previous_state_root: [12u8; 32],
            network_id: 9,
        };

        let outcome = run_batch_with_callbacks(
            &block_context,
            &sorted,
            &config,
            &verifier_context,
            |item, _, _| {
                if item.original_index == 2 {
                    let mut report = dummy_report();
                    report.error = Some(VerifyError::MerkleVerifyFailed {
                        section: MerkleSection::FriPath,
                    });
                    report
                } else {
                    dummy_report()
                }
            },
        );

        assert_eq!(
            outcome,
            BatchVerificationOutcome::Reject {
                failing_proof_index: 2,
                error: VerifyError::MerkleVerifyFailed {
                    section: MerkleSection::FriPath,
                },
            }
        );
    }

    #[test]
    fn batch_accepts_when_all_checks_pass_ok() {
        let inputs = sample_public_inputs();
        let records = sample_records(&inputs);
        let sorted = sort_batch_proofs(&records).expect("sorting should succeed");
        let (config, verifier_context) = dummy_config();
        let block_context = BlockContext {
            block_height: 9,
            previous_state_root: [13u8; 32],
            network_id: 3,
        };

        let outcome = run_batch_with_callbacks(
            &block_context,
            &sorted,
            &config,
            &verifier_context,
            |_, _, _| dummy_report(),
        );

        assert_eq!(outcome, BatchVerificationOutcome::Accept);
    }
}
