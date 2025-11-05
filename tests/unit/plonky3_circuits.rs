#![cfg(feature = "backend-plonky3")]

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use blake3::hash as blake3_hash;
use flate2::read::GzDecoder;
use once_cell::sync::Lazy;
use plonky3_backend::AirMetadata;
use rpp_chain::plonky3::circuit::{
    consensus::ConsensusCircuit,
    identity::{IdentityCircuit, IdentityWitness},
    pruning::PruningCircuit,
    recursive::RecursiveCircuit,
    state::StateCircuit,
    transaction::TransactionCircuit,
    uptime::{UptimeCircuit, UptimeWitness},
    CircuitParams, Plonky3CircuitWitness,
};
use rpp_chain::plonky3::crypto;
use rpp_chain::types::IdentityGenesis;
use serde::Deserialize;

const IDENTITY_WITNESS_JSON: &str = include_str!("data/plonky3/identity_witness.json");
const UPTIME_WITNESS_JSON: &str = include_str!("data/plonky3/uptime_witness.json");

#[derive(Deserialize)]
#[serde(untagged)]
enum ArtifactLocation {
    Inline(String),
    Descriptor(ArtifactDescriptor),
}

#[derive(Deserialize, Default)]
struct ArtifactDescriptor {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    encoding: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    base64: Option<String>,
    #[serde(default)]
    hex: Option<String>,
    #[serde(default)]
    compression: Option<String>,
    #[serde(default)]
    byte_length: Option<u64>,
}

#[derive(Deserialize)]
struct CircuitSetup {
    circuit: String,
    verifying_key: ArtifactLocation,
    proving_key: ArtifactLocation,
    #[serde(default)]
    metadata: Option<AirMetadata>,
}

struct CircuitFixture {
    verifying_key: Vec<u8>,
    proving_key: Vec<u8>,
    metadata: Option<AirMetadata>,
}

static CIRCUIT_FIXTURES: Lazy<HashMap<String, CircuitFixture>> = Lazy::new(|| {
    let base = fixtures_base_dir();
    let mut fixtures = HashMap::new();
    for circuit in [
        "consensus",
        "identity",
        "pruning",
        "recursive",
        "state",
        "transaction",
        "uptime",
    ] {
        let setup = load_circuit_setup(&base, circuit);
        let metadata = setup.metadata.clone();
        fixtures.insert(
            circuit.to_string(),
            CircuitFixture {
                verifying_key: decode_artifact(
                    &base,
                    circuit,
                    "verifying key",
                    &setup.verifying_key,
                ),
                proving_key: decode_artifact(&base, circuit, "proving key", &setup.proving_key),
                metadata,
            },
        );
    }
    fixtures
});

fn fixtures_base_dir() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("config/plonky3/setup");
    path
}

fn load_circuit_setup(base: &Path, circuit: &str) -> CircuitSetup {
    let path = base.join(format!("{circuit}.json"));
    let contents = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "failed to read {circuit} setup from {}: {err}",
            path.display()
        )
    });
    serde_json::from_str(&contents).unwrap_or_else(|err| {
        panic!(
            "failed to decode {circuit} setup from {}: {err}",
            path.display()
        )
    })
}

fn decode_artifact(base: &Path, circuit: &str, kind: &str, location: &ArtifactLocation) -> Vec<u8> {
    match location {
        ArtifactLocation::Inline(value) => decode_blob(value, None, None, circuit, kind),
        ArtifactLocation::Descriptor(descriptor) => {
            let mut bytes =
                if let Some(path) = descriptor.path.as_deref().or(descriptor.file.as_deref()) {
                    let path = resolve_candidate_path(base, path);
                    fs::read(&path).unwrap_or_else(|err| {
                        panic!(
                            "failed to read {kind} for {circuit} circuit from {}: {err}",
                            path.display()
                        )
                    })
                } else if let Some(value) = descriptor.base64.as_deref() {
                    decode_blob(
                        value,
                        Some("base64"),
                        descriptor.compression.as_deref(),
                        circuit,
                        kind,
                    )
                } else if let Some(value) = descriptor.hex.as_deref() {
                    decode_blob(
                        value,
                        Some("hex"),
                        descriptor.compression.as_deref(),
                        circuit,
                        kind,
                    )
                } else if let Some(value) = descriptor.value.as_deref() {
                    let encoding = descriptor
                        .encoding
                        .as_deref()
                        .or(descriptor.format.as_deref());
                    decode_blob(
                        value,
                        encoding,
                        descriptor.compression.as_deref(),
                        circuit,
                        kind,
                    )
                } else {
                    panic!("{kind} for {circuit} circuit is missing data");
                };

            if let Some(expected) = descriptor.byte_length {
                assert_eq!(
                    bytes.len() as u64,
                    expected,
                    "decoded {kind} length mismatch for {circuit} circuit"
                );
            }
            bytes
        }
    }
}

fn resolve_candidate_path(base: &Path, path: &str) -> PathBuf {
    let trimmed = path.trim_start_matches('@');
    let candidate = Path::new(trimmed);
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base.join(candidate)
    }
}

fn decode_blob(
    value: &str,
    encoding_hint: Option<&str>,
    compression: Option<&str>,
    circuit: &str,
    kind: &str,
) -> Vec<u8> {
    let encoding = encoding_hint
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "base64".to_string());

    let trimmed = value.trim();
    assert!(!trimmed.is_empty(), "{kind} for {circuit} circuit is empty");

    let mut bytes = match encoding.as_str() {
        "base64" => BASE64_STANDARD
            .decode(trimmed)
            .unwrap_or_else(|err| panic!("invalid base64 {kind} for {circuit} circuit: {err}")),
        "hex" => hex::decode(trimmed)
            .unwrap_or_else(|err| panic!("invalid hex {kind} for {circuit} circuit: {err}")),
        "binary" | "raw" => trimmed.as_bytes().to_vec(),
        other => panic!("unsupported encoding {other} for {kind} in {circuit} circuit"),
    };

    if let Some(compression) = compression
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
    {
        bytes = match compression.as_str() {
            "gzip" | "gz" => {
                let mut decoder = GzDecoder::new(bytes.as_slice());
                let mut decompressed = Vec::new();
                decoder
                    .read_to_end(&mut decompressed)
                    .unwrap_or_else(|err| {
                        panic!("failed to decompress {kind} for {circuit} circuit: {err}")
                    });
                decompressed
            }
            other => panic!("unsupported compression {other} for {kind} in {circuit} circuit"),
        };
    }

    bytes
}

fn circuit_fixture(name: &str) -> &'static CircuitFixture {
    CIRCUIT_FIXTURES
        .get(name)
        .unwrap_or_else(|| panic!("missing fixture for {name} circuit"))
}

fn circuit_matrix() -> [(&'static str, &'static CircuitParams); 7] {
    [
        ("consensus", &ConsensusCircuit::PARAMS),
        ("identity", &IdentityCircuit::PARAMS),
        ("pruning", &PruningCircuit::PARAMS),
        ("recursive", &RecursiveCircuit::PARAMS),
        ("state", &StateCircuit::PARAMS),
        ("transaction", &TransactionCircuit::PARAMS),
        ("uptime", &UptimeCircuit::PARAMS),
    ]
}

fn sample_genesis() -> IdentityGenesis {
    IdentityGenesis {
        wallet_address: "wallet-alpha".to_string(),
        genesis_block: "block-0001".to_string(),
    }
}

#[test]
fn identity_witness_reports_circuit_name() {
    let genesis = sample_genesis();
    let witness = IdentityWitness::new(&genesis);
    assert_eq!(witness.circuit(), "identity");
}

#[test]
fn identity_fixture_roundtrip() {
    let witness: IdentityWitness =
        serde_json::from_str(IDENTITY_WITNESS_JSON).expect("decode identity fixture");
    assert_eq!(witness.circuit(), "identity");
    let inputs = witness.public_inputs().expect("public inputs encode");
    let object = inputs.as_object().expect("public inputs object");
    assert!(object.contains_key("witness"));
    assert_eq!(witness.genesis.wallet_address, "fixture-wallet-0001");
    assert_eq!(witness.genesis.genesis_block, "fixture-block-0001");
}

#[test]
fn identity_public_inputs_embed_genesis_payload() {
    let genesis = sample_genesis();
    let witness = IdentityWitness::new(&genesis);
    let inputs = witness.public_inputs().expect("public inputs encode");
    let object = inputs.as_object().expect("object inputs");
    let payload = object
        .get("witness")
        .and_then(|value| value.as_object())
        .expect("witness payload");
    assert_eq!(
        payload
            .get("genesis")
            .and_then(|value| value.get("wallet_address"))
            .and_then(|value| value.as_str()),
        Some("wallet-alpha"),
    );
    assert_eq!(
        payload
            .get("genesis")
            .and_then(|value| value.get("genesis_block"))
            .and_then(|value| value.as_str()),
        Some("block-0001"),
    );
    assert!(
        object.get("block_height").is_none(),
        "block height metadata remains optional"
    );
}

#[test]
fn identity_witness_serialisation_is_stable() {
    let genesis = sample_genesis();
    let witness = IdentityWitness::new(&genesis);
    let encoded = serde_json::to_string(&witness).expect("encode witness");
    assert!(encoded.contains("wallet-alpha"));
    assert!(encoded.contains("block-0001"));
    let roundtrip: IdentityWitness = serde_json::from_str(&encoded).expect("decode witness");
    assert_eq!(roundtrip.genesis.wallet_address, "wallet-alpha");
    assert_eq!(roundtrip.genesis.genesis_block, "block-0001");
}

#[test]
fn uptime_fixture_roundtrip() {
    let witness: UptimeWitness =
        serde_json::from_str(UPTIME_WITNESS_JSON).expect("decode uptime fixture");
    assert_eq!(witness.circuit(), "uptime");
    assert_eq!(witness.wallet_address, "fixture-validator-0001");
    assert_eq!(witness.node_clock, 1024);
    assert_eq!(witness.window_start, 1000);
    assert_eq!(witness.window_end, 1100);
}

#[test]
fn plonky3_param_digests_match_setup() {
    for (name, params) in circuit_matrix() {
        let fixture = circuit_fixture(name);
        let verifying_key = crypto::verifying_key(name).expect("load verifying key");
        let verifying_bytes = verifying_key.bytes();
        assert_eq!(verifying_bytes, fixture.verifying_key.as_slice());
        assert!(
            verifying_bytes.len() >= 96,
            "verifying key must expose FRI/domain digests"
        );
        assert_eq!(&verifying_bytes[0..32], &params.domain_root);
        assert_eq!(&verifying_bytes[32..64], &params.quotient_root);
        assert_eq!(&verifying_bytes[64..96], &params.fri_digest);

        let (verifying_key, proving_key) = crypto::circuit_keys(name).expect("load circuit keys");
        assert_eq!(verifying_key.bytes(), fixture.verifying_key.as_slice());
        assert_eq!(proving_key.bytes(), fixture.proving_key.as_slice());
        assert_eq!(
            blake3_hash(verifying_key.bytes()).as_bytes(),
            &params.verifying_key_hash
        );
        assert_eq!(
            blake3_hash(proving_key.bytes()).as_bytes(),
            &params.proving_key_hash
        );
        if let Some(expected_metadata) = fixture.metadata.as_ref() {
            assert_eq!(
                verifying_key.metadata().as_ref(),
                expected_metadata,
                "verifying key metadata must match fixture"
            );
            assert_eq!(
                proving_key.metadata().as_ref(),
                expected_metadata,
                "proving key metadata must match fixture"
            );
        }
    }
}
