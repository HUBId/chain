//! Snapshot aggregation for the failure matrix fixture.
//!
//! The snapshot captures all byte-level artefacts demanded by the B7 gate.
//! To update it, run `cargo insta review` after executing the affected tests
//! and bump `PROOF_VERSION` whenever the serialized layout changes.

use super::fixture::header_layout;
use super::FailMatrixFixture;
use insta::assert_json_snapshot;
use rpp_stark::field::prime_field::CanonicalSerialize;
use rpp_stark::field::FieldElement;
use rpp_stark::proof::types::PROOF_VERSION;
use serde_json::json;

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

fn field_hex(value: &FieldElement) -> String {
    hex_encode(&value.to_bytes().expect("field element encoding"))
}

#[test]
fn freeze_fixture_artifacts() {
    let fixture = FailMatrixFixture::new();
    let proof_bytes = fixture.proof_bytes();
    let proof = fixture.proof();
    let config = fixture.config();
    let layout = header_layout(proof_bytes.as_slice());
    let telemetry_option = proof.telemetry();
    let telemetry_frame = telemetry_option.frame();

    let openings = proof.openings();
    let trace_indices = openings.trace().indices().to_vec();
    let composition_indices = openings.composition().map(|c| c.indices().to_vec());

    let trace_path_lengths = openings
        .trace()
        .paths()
        .iter()
        .map(|path| path.nodes().len())
        .collect::<Vec<_>>();
    let composition_path_lengths = openings.composition().map(|c| {
        c.paths()
            .iter()
            .map(|path| path.nodes().len())
            .collect::<Vec<_>>()
    });

    let fri_proof = proof.fri_proof();
    let fri_query_positions = fri_proof
        .queries
        .iter()
        .map(|query| query.position)
        .collect::<Vec<_>>();
    let fri_query_path_lengths = fri_proof
        .queries
        .iter()
        .map(|query| {
            query
                .layers
                .iter()
                .map(|layer| layer.path.len())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let snapshot = json!({
        "proof_version": PROOF_VERSION,
        "proof_bytes_hex": hex_encode(proof_bytes.as_slice()),
        "param_digest_hex": hex_encode(config.param_digest.as_bytes()),
        "roots": {
            "core": hex_encode(proof.merkle().core_root()),
            "aux": hex_encode(proof.merkle().aux_root()),
            "fri_from_merkle": proof
                .merkle()
                .fri_layer_roots()
                .iter()
                .map(hex_encode)
                .collect::<Vec<_>>(),
            "fri_from_proof": fri_proof
                .layer_roots
                .iter()
                .map(hex_encode)
                .collect::<Vec<_>>(),
            "final_polynomial_digest": hex_encode(&fri_proof.final_polynomial_digest),
        },
        "challenges": {
            "fri_fold": fri_proof
                .fold_challenges
                .iter()
                .map(field_hex)
                .collect::<Vec<_>>(),
            "fri_final_polynomial": fri_proof
                .final_polynomial
                .iter()
                .map(field_hex)
                .collect::<Vec<_>>(),
            "deep_oods": fri_proof.deep_oods.as_ref().map(|oods| json!({
                "point": field_hex(&oods.point),
                "evaluations": oods
                    .evaluations
                    .iter()
                    .map(field_hex)
                    .collect::<Vec<_>>(),
            })),
        },
        "queries": {
            "trace_indices": trace_indices,
            "composition_indices": composition_indices,
            "fri_positions": fri_query_positions,
        },
        "path_lengths": {
            "trace": trace_path_lengths,
            "composition": composition_path_lengths,
            "fri_layers": fri_query_path_lengths,
        },
        "payload_handles": {
            "openings": {
                "offset": layout.openings().offset(),
                "length": layout.openings().length(),
            },
            "fri": {
                "offset": layout.fri().offset(),
                "length": layout.fri().length(),
            },
            "telemetry": layout.telemetry().handle().map(|handle| json!({
                "offset": handle.offset(),
                "length": handle.length(),
            })),
        },
        "telemetry": {
            "present": telemetry_option.is_present(),
            "header_length": telemetry_frame.header_length(),
            "body_length": telemetry_frame.body_length(),
            "integrity_digest_hex": hex_encode(&telemetry_frame.integrity_digest().bytes),
        },
    });

    assert_json_snapshot!("fail_matrix_fixture_artifacts", snapshot);
}

#[test]
fn proof_version_guard_matches_snapshot() {
    const SNAPSHOT: &str =
        include_str!("snapshots/fail_matrix__snapshots__fail_matrix_fixture_artifacts.snap");

    let mut lines = SNAPSHOT.lines();
    // Skip leading delimiter.
    assert_eq!(lines.next(), Some("---"));
    // Consume metadata until the payload delimiter.
    for line in &mut lines {
        if line == "---" {
            break;
        }
    }
    let payload = lines.collect::<Vec<_>>().join("\n");
    let value: serde_json::Value = serde_json::from_str(&payload).expect("parse snapshot JSON");
    let snapshot_version = value["proof_version"]
        .as_u64()
        .expect("snapshot proof_version") as u16;

    assert_eq!(
        snapshot_version, PROOF_VERSION,
        "Snapshots changed without bumping PROOF_VERSION"
    );
}
