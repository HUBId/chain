use insta::assert_json_snapshot;
use rpp_stark::config::{
    build_proof_system_config, build_prover_context, compute_param_digest, ChunkingPolicy,
    CommonIdentifiers, ProfileConfig, ProofSystemConfig, ProverContext, ThreadPoolProfile,
    COMMON_IDENTIFIERS, PROFILE_STANDARD_CONFIG,
};
use rpp_stark::field::prime_field::{CanonicalSerialize, FieldElementOps};
use rpp_stark::field::FieldElement;
use rpp_stark::proof::public_inputs::{
    ExecutionHeaderV1, ProofKind, PublicInputVersion, PublicInputs,
};
use rpp_stark::utils::serialization::{ProofBytes, WitnessBlob};
use std::collections::BTreeMap;

fn hex<const N: usize>(bytes: &[u8; N]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn make_public_inputs<'a>(header: &'a ExecutionHeaderV1, body: &'a [u8]) -> PublicInputs<'a> {
    PublicInputs::Execution {
        header: header.clone(),
        body,
    }
}

struct SnapshotSetup {
    config: ProofSystemConfig,
    prover_context: ProverContext,
    header: ExecutionHeaderV1,
    body: Vec<u8>,
    witness: Vec<u8>,
}

impl SnapshotSetup {
    fn new() -> Self {
        let profile: ProfileConfig = PROFILE_STANDARD_CONFIG.clone();
        let common: CommonIdentifiers = COMMON_IDENTIFIERS.clone();
        let param_digest = compute_param_digest(&profile, &common);
        let config = build_proof_system_config(&profile, &param_digest);
        let prover_context = build_prover_context(
            &profile,
            &common,
            &param_digest,
            ThreadPoolProfile::SingleThread,
            ChunkingPolicy {
                min_chunk_items: 4,
                max_chunk_items: 32,
                stride: 1,
            },
        );

        let seed = FieldElement::from(3u64);
        let length = 128usize;
        let header = ExecutionHeaderV1 {
            version: PublicInputVersion::V1,
            program_digest: rpp_stark::utils::serialization::DigestBytes { bytes: [0u8; 32] },
            trace_length: length as u32,
            trace_width: 1,
        };
        let body = seed
            .to_bytes()
            .expect("fixture seed must be canonical")
            .to_vec();
        let witness = build_witness(seed, length);

        Self {
            config,
            prover_context,
            header,
            body,
            witness,
        }
    }
}

const LFSR_ALPHA: u64 = 5;
const LFSR_BETA: u64 = 7;

fn build_witness(seed: FieldElement, rows: usize) -> Vec<u8> {
    let alpha = FieldElement::from(LFSR_ALPHA);
    let beta = FieldElement::from(LFSR_BETA);
    let mut column = Vec::with_capacity(rows);
    let mut state = seed;
    column.push(state);
    for _ in 1..rows {
        state = state.mul(&alpha).add(&beta);
        column.push(state);
    }

    let mut bytes = Vec::with_capacity(20 + rows * 8);
    bytes.extend_from_slice(&(rows as u32).to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    for value in column {
        let encoded = value.to_bytes().expect("fixture values must be canonical");
        bytes.extend_from_slice(&encoded);
    }
    bytes
}

fn decode_proof(bytes: &ProofBytes) -> rpp_stark::Proof {
    rpp_stark::Proof::from_bytes(bytes.as_slice()).expect("decode proof")
}

#[test]
fn snapshot_execution_proof_artifacts() {
    let setup = SnapshotSetup::new();
    let witness = WitnessBlob {
        bytes: &setup.witness,
    };
    let public_inputs = make_public_inputs(&setup.header, &setup.body);

    let proof_bytes = rpp_stark::generate_proof(
        ProofKind::Execution,
        &public_inputs,
        witness,
        &setup.config,
        &setup.prover_context,
    )
    .expect("proof generation succeeds");
    let decoded = decode_proof(&proof_bytes);

    let trace_paths: Vec<usize> = decoded
        .openings()
        .trace()
        .paths()
        .iter()
        .map(|path| path.nodes().len())
        .collect();
    let composition_paths: Option<Vec<usize>> = decoded
        .openings()
        .composition()
        .map(|comp| comp.paths().iter().map(|path| path.nodes().len()).collect());
    let trace_indices = {
        let mut indices = decoded.openings().trace().indices().to_vec();
        indices.sort_unstable();
        indices
    };
    let composition_indices = decoded.openings().composition().map(|comp| {
        let mut indices = comp.indices().to_vec();
        indices.sort_unstable();
        indices
    });
    let fri_positions: Vec<usize> = decoded
        .fri_proof()
        .queries
        .iter()
        .map(|query| query.position)
        .collect();
    let fri_layer_path_lengths: Vec<usize> = decoded
        .fri_proof()
        .queries
        .iter()
        .flat_map(|query| query.layers.iter().map(|layer| layer.path.len()))
        .collect();

    let trace_path_summary = summarize_lengths(&trace_paths);
    let composition_path_summary = composition_paths
        .as_ref()
        .map(|paths| summarize_lengths(paths))
        .unwrap_or_else(|| serde_json::json!({"total": 0, "histogram": {}}));
    let fri_path_summary = summarize_lengths(&fri_layer_path_lengths);

    let artifact = serde_json::json!({
        "trace_root": hex(decoded.merkle().core_root()),
        "composition_root": hex(decoded.merkle().aux_root()),
        "fri_roots": decoded
            .merkle()
            .fri_layer_roots()
            .iter()
            .map(hex)
            .collect::<Vec<_>>(),
        "trace_query_indices": trace_indices,
        "composition_query_indices": composition_indices,
        "fri_query_positions": fri_positions,
        "trace_path_lengths": trace_path_summary,
        "composition_path_lengths": composition_path_summary,
        "fri_path_lengths": fri_path_summary,
    });

    assert_json_snapshot!("execution_proof_artifacts", artifact);
}

fn summarize_lengths(lengths: &[usize]) -> serde_json::Value {
    let mut histogram: BTreeMap<usize, usize> = BTreeMap::new();
    for &len in lengths {
        *histogram.entry(len).or_insert(0) += 1;
    }
    serde_json::json!({
        "total": lengths.len(),
        "histogram": histogram,
    })
}
