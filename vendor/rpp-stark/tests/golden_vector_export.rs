mod _fixtures;

use _fixtures::mini_fixture;
use rpp_stark::config::{ProofKind as ConfigProofKind, VerifierContext};
use rpp_stark::field::prime_field::CanonicalSerialize;
use rpp_stark::field::FieldElement;
use rpp_stark::hash::{hash, Blake2sXof, FiatShamirChallengeRules};
use rpp_stark::params::{serialize_params, StarkParams};
use rpp_stark::proof::params::canonical_stark_params;
use rpp_stark::proof::public_inputs::PublicInputs;
use rpp_stark::proof::ser::{
    compute_public_digest, map_public_to_config_kind, serialize_public_inputs,
};
use rpp_stark::proof::transcript::{Transcript, TranscriptHeader};
use rpp_stark::proof::types::{ProofHandles, PROOF_ALPHA_VECTOR_LEN, PROOF_MIN_OOD_POINTS};
use rpp_stark::proof::verifier::verify;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

#[test]
fn export_and_verify_golden_vectors() {
    let first = generate_artifacts();
    let second = generate_artifacts();
    assert_eq!(first, second, "artifact generation must be deterministic");

    let base_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/stwo/mini");
    fs::create_dir_all(&base_dir).expect("create golden vector directory");

    for (name, bytes) in first.into_iter() {
        let path = base_dir.join(name);
        if let Ok(existing) = fs::read(&path) {
            assert_eq!(
                existing, bytes,
                "existing artifact {:?} mismatches regenerated output",
                path
            );
        } else {
            fs::write(&path, &bytes).expect("write golden artifact");
            let roundtrip = fs::read(&path).expect("read back freshly written artifact");
            assert_eq!(roundtrip, bytes, "roundtrip mismatch for {:?}", path);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactSet(BTreeMap<String, Vec<u8>>);

impl ArtifactSet {
    fn insert(mut self, name: &str, bytes: Vec<u8>) -> Self {
        self.0.insert(name.to_string(), bytes);
        self
    }
}

impl IntoIterator for ArtifactSet {
    type Item = (String, Vec<u8>);
    type IntoIter = std::collections::btree_map::IntoIter<String, Vec<u8>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

fn generate_artifacts() -> ArtifactSet {
    let fixture = mini_fixture();

    let config = fixture.config();
    let verifier_context = fixture.verifier_context();
    let public_inputs = fixture.public_inputs();

    let params = canonical_stark_params(&config.profile);
    let params_bytes = serialize_params(&params);

    let config_digest = config.param_digest.as_bytes();

    let public_input_bytes = serialize_public_inputs(&public_inputs).expect("encode public inputs");
    let public_digest = compute_public_digest(&public_input_bytes);

    let proof_bytes = fixture.proof_bytes();
    let proof_vec = proof_bytes.as_slice().to_vec();

    let declared_kind = declared_kind(&public_inputs);
    let report = verify(
        declared_kind,
        &public_inputs,
        &proof_bytes,
        &config,
        &verifier_context,
    );

    assert!(
        report.error.is_none(),
        "verification must succeed: {:?}",
        report.error
    );
    assert!(report.params_ok, "parameter stage must succeed");
    assert!(report.public_ok, "public-input stage must succeed");
    assert!(report.merkle_ok, "merkle stage must succeed");
    assert!(report.fri_ok, "fri stage must succeed");
    assert!(report.composition_ok, "composition stage must succeed");
    assert_eq!(
        report.total_bytes as usize,
        proof_vec.len(),
        "reported proof length must match serialized bytes",
    );

    let handles = report.proof.as_ref().expect("proof handles available");

    assert_eq!(
        handles.params_hash().as_bytes(),
        config_digest,
        "proof header param digest must match verifier configuration",
    );
    assert_eq!(
        handles.public_digest().bytes,
        public_digest,
        "proof header public digest must match recomputed digest",
    );

    let indices = rebuild_transcript(&params, &verifier_context, handles, &public_input_bytes);

    assert_eq!(
        indices,
        handles.openings().trace().indices(),
        "derived indices must match trace openings",
    );

    let artifacts = ArtifactSet(BTreeMap::new())
        .insert("params.bin", encode_binary_artifact(&params_bytes))
        .insert(
            "public_inputs.bin",
            encode_binary_artifact(&public_input_bytes),
        )
        .insert("proof.bin", encode_binary_artifact(&proof_vec))
        .insert("public_digest.hex", hex_bytes(&public_digest).into_bytes())
        .insert(
            "proof_report.json",
            serde_json::to_vec_pretty(&ProofReportExport::from_handles(&report, handles))
                .expect("encode proof report"),
        )
        .insert(
            "roots.json",
            serde_json::to_vec_pretty(&RootsExport::from_handles(handles)).expect("encode roots"),
        )
        .insert(
            "challenges.json",
            serde_json::to_vec_pretty(&ChallengesExport::from_transcript(&params, handles))
                .expect("encode challenges"),
        )
        .insert(
            "indices.json",
            serde_json::to_vec_pretty(&indices).expect("encode indices"),
        );

    // Ensure the exported indices are sorted and deduplicated.
    assert!(indices.windows(2).all(|w| w[0] < w[1]));

    artifacts
}

fn declared_kind(inputs: &PublicInputs<'_>) -> ConfigProofKind {
    map_public_to_config_kind(inputs.kind())
}

fn rebuild_transcript(
    params: &StarkParams,
    verifier_context: &VerifierContext,
    handles: &ProofHandles,
    public_inputs: &[u8],
) -> Vec<u32> {
    let header = TranscriptHeader {
        version: verifier_context.common_ids.transcript_version_id.clone(),
        poseidon_param_id: verifier_context.profile.poseidon_param_id.clone(),
        air_spec_id: handles.air_spec_id().clone(),
        proof_kind: *handles.kind(),
        params_hash: verifier_context.param_digest.clone(),
    };

    let mut transcript = Transcript::new(header).expect("transcript header accepted");
    transcript
        .absorb_public_inputs(public_inputs)
        .expect("absorb public inputs");

    let trace_root = handles.trace_commit().bytes;
    let composition_root = handles.composition_commit().map(|digest| digest.bytes);
    transcript
        .absorb_commitment_roots(trace_root, composition_root)
        .expect("absorb commitments");
    transcript
        .absorb_air_spec_id(handles.air_spec_id().clone())
        .expect("absorb air spec id");
    transcript
        .absorb_block_context(None)
        .expect("absorb empty block context");

    let mut stream = transcript.finalize().expect("finalize transcript");
    stream
        .draw_alpha_vector(PROOF_ALPHA_VECTOR_LEN)
        .expect("draw alpha vector");
    stream
        .draw_ood_points(PROOF_MIN_OOD_POINTS)
        .expect("draw ood points");
    let _ood_seed = stream.draw_ood_seed().expect("draw ood seed");
    let fri_seed = stream.draw_fri_seed().expect("draw fri seed");

    let fri_proof = handles.fri().fri_proof();
    for layer_index in 0..fri_proof.layer_roots.len() {
        stream
            .draw_fri_eta(layer_index)
            .expect("draw fri fold challenge");
    }
    let _query_seed = stream.draw_query_seed().expect("draw query seed");

    derive_trace_query_indices(fri_proof, fri_seed, params.fri().queries as usize)
}

fn derive_trace_query_indices(
    fri_proof: &rpp_stark::fri::FriProof,
    fri_seed: [u8; 32],
    query_count: usize,
) -> Vec<u32> {
    assert!(fri_proof.initial_domain_size > 0);
    assert!(fri_proof.initial_domain_size <= u32::MAX as usize);
    assert_eq!(
        fri_proof.fold_challenges.len(),
        fri_proof.layer_roots.len(),
        "layer and challenge count must match",
    );

    let mut state = fri_seed;
    for (layer_index, root) in fri_proof.layer_roots.iter().enumerate() {
        let mut layer_payload = Vec::with_capacity(state.len() + 8 + root.len());
        layer_payload.extend_from_slice(&state);
        layer_payload.extend_from_slice(&(layer_index as u64).to_le_bytes());
        layer_payload.extend_from_slice(root);
        state = hash(&layer_payload).into();

        let label = format!("{}ETA-{layer_index}", FiatShamirChallengeRules::SALT_PREFIX);
        let mut eta_payload = Vec::with_capacity(state.len() + label.len());
        eta_payload.extend_from_slice(&state);
        eta_payload.extend_from_slice(label.as_bytes());
        let challenge: [u8; 32] = hash(&eta_payload).into();
        state = hash(&challenge).into();

        let derived_eta = field_from_hash(&challenge);
        let expected_eta = fri_proof
            .fold_challenges
            .get(layer_index)
            .expect("fold challenge present");
        assert_eq!(
            &derived_eta, expected_eta,
            "fold challenge mismatch at layer {layer_index}"
        );
    }

    let mut final_payload = Vec::with_capacity(state.len() + b"RPP-FS/FINAL".len() + 32);
    final_payload.extend_from_slice(&state);
    final_payload.extend_from_slice(b"RPP-FS/FINAL");
    final_payload.extend_from_slice(&fri_proof.final_polynomial_digest);
    state = hash(&final_payload).into();

    let mut query_payload = Vec::with_capacity(state.len() + b"RPP-FS/QUERY-SEED".len());
    query_payload.extend_from_slice(&state);
    query_payload.extend_from_slice(b"RPP-FS/QUERY-SEED");
    let query_seed: [u8; 32] = hash(&query_payload).into();

    derive_query_positions(query_seed, query_count, fri_proof.initial_domain_size)
        .into_iter()
        .map(|value| value as u32)
        .collect()
}

fn derive_query_positions(seed: [u8; 32], count: usize, domain_size: usize) -> Vec<usize> {
    assert!(domain_size > 0, "domain size must be positive");
    let mut xof = Blake2sXof::new(&seed);
    let target = count.min(domain_size);
    let mut seen = vec![false; domain_size];
    let mut indices = Vec::with_capacity(target);
    while indices.len() < target {
        let word = xof.next_u64().expect("xof output");
        let position = (word % (domain_size as u64)) as usize;
        if !seen[position] {
            seen[position] = true;
            indices.push(position);
        }
    }
    indices.sort_unstable();
    indices
}

fn field_from_hash(bytes: &[u8; 32]) -> FieldElement {
    let mut acc = 0u128;
    for chunk in bytes.chunks(8).take(4) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        let value = u64::from_le_bytes(buf);
        acc = (acc << 64) ^ value as u128;
        acc %= FieldElement::MODULUS.value as u128;
    }
    FieldElement(acc as u64)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

fn encode_binary_artifact(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = hex_bytes(bytes);
    encoded.push('\n');
    encoded.into_bytes()
}

#[derive(Serialize)]
struct ProofReportExport {
    params_ok: bool,
    public_ok: bool,
    merkle_ok: bool,
    fri_ok: bool,
    composition_ok: bool,
    total_bytes: u64,
    proof_version: u16,
    params_hash: String,
    public_digest: String,
}

impl ProofReportExport {
    fn from_handles(
        report: &rpp_stark::proof::types::VerifyReport,
        handles: &ProofHandles,
    ) -> Self {
        Self {
            params_ok: report.params_ok,
            public_ok: report.public_ok,
            merkle_ok: report.merkle_ok,
            fri_ok: report.fri_ok,
            composition_ok: report.composition_ok,
            total_bytes: report.total_bytes,
            proof_version: handles.version(),
            params_hash: hex_bytes(handles.params_hash().as_bytes()),
            public_digest: hex_bytes(&handles.public_digest().bytes),
        }
    }
}

#[derive(Serialize)]
struct RootsExport {
    trace_commit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comp_commit: Option<String>,
    fri_roots: Vec<String>,
}

impl RootsExport {
    fn from_handles(handles: &ProofHandles) -> Self {
        let comp_commit = handles
            .composition_commit()
            .map(|digest| hex_bytes(&digest.bytes));
        let fri_roots = handles
            .merkle()
            .fri_layer_roots()
            .iter()
            .map(|root| hex_bytes(root))
            .collect();
        Self {
            trace_commit: hex_bytes(&handles.trace_commit().bytes),
            comp_commit,
            fri_roots,
        }
    }
}

#[derive(Serialize)]
struct ChallengesExport {
    fri_fold_challenges: Vec<String>,
    query_count: u16,
    domain_log2: u16,
    protocol_tag: String,
    seed: String,
}

impl ChallengesExport {
    fn from_transcript(params: &StarkParams, handles: &ProofHandles) -> Self {
        let fri_fold_challenges = handles
            .fri()
            .fri_proof()
            .fold_challenges
            .iter()
            .map(|challenge| hex_bytes(&challenge.to_bytes().expect("canonical felt")))
            .collect();
        let transcript_seed = params.transcript().seed;
        Self {
            fri_fold_challenges,
            query_count: params.fri().queries,
            domain_log2: params.fri().domain_log2,
            protocol_tag: params.transcript().protocol_tag.to_string(),
            seed: hex_bytes(&transcript_seed),
        }
    }
}
