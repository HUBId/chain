use std::convert::TryInto;
use std::fs;
use std::path::Path;

use rpp_stark::hash::deterministic::DeterministicHasherBackend;
use rpp_stark::hash::{
    hash, hash_with_backend, Blake2sInteropHasher, Hasher, PoseidonInteropHasher,
    RescueInteropHasher,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct HashVectorFixture {
    leaves: Vec<String>,
    root: String,
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err(format!("hex payload has odd length: {}", input.len()));
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    for chunk in bytes.chunks(2) {
        let high = (chunk[0] as char)
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex char '{}' in {}", chunk[0] as char, input))?;
        let low = (chunk[1] as char)
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex char '{}' in {}", chunk[1] as char, input))?;
        out.push(((high << 4) | low) as u8);
    }
    Ok(out)
}

fn load_fixture(base: &Path) -> Result<(Vec<Vec<u8>>, [u8; 32]), String> {
    let json_path = base.join("hash_vectors.json");
    let bin_path = base.join("hash_vectors.bin");

    let json_data = fs::read_to_string(&json_path)
        .map_err(|err| format!("failed to read {json_path:?}: {err}"))?;
    let fixture: HashVectorFixture = serde_json::from_str(&json_data)
        .map_err(|err| format!("failed to decode fixture JSON: {err}"))?;

    let leaves = fixture
        .leaves
        .iter()
        .map(|entry| decode_hex(entry))
        .collect::<Result<Vec<_>, _>>()?;

    let root_vec = decode_hex(&fixture.root)?;
    if root_vec.len() != 32 {
        return Err(format!("expected 32-byte root, got {}", root_vec.len()));
    }
    let root: [u8; 32] = root_vec
        .as_slice()
        .try_into()
        .expect("root length was checked");

    let bin_root = fs::read(&bin_path)
        .map_err(|err| format!("failed to read {bin_path:?}: {err}"))?;
    if bin_root.len() != 32 {
        return Err(format!("binary root length mismatch: {}", bin_root.len()));
    }
    if bin_root.as_slice() != root {
        return Err("binary and JSON roots differ".to_string());
    }

    Ok((leaves, root))
}

fn verify_backend<B: DeterministicHasherBackend>(
    name: &str,
    leaves: &[Vec<u8>],
    flattened: &[u8],
    expected: &[u8; 32],
) {
    let mut hasher = Hasher::<B>::with_backend();
    for leaf in leaves {
        hasher.update(leaf);
    }
    let digest = hasher.finalize();
    assert_eq!(digest.as_bytes(), expected, "streamed digest mismatch for {name}");
    assert_eq!(digest.as_bytes().len(), expected.len(), "digest length gate failed for {name}");

    let direct: [u8; 32] = hash_with_backend::<B>(flattened).into();
    assert_eq!(&direct, expected, "direct digest mismatch for {name}");
}

#[test]
fn stwo_blake2s_vectors_match() {
    let base = Path::new("tests/fixtures/stwo");
    let (leaves, expected_root) = load_fixture(base).expect("fixture must load");

    let mut flattened = Vec::new();
    for leaf in &leaves {
        flattened.extend_from_slice(leaf);
    }

    let default_digest = hash(&flattened);
    assert_eq!(default_digest.as_bytes(), &expected_root);

    verify_backend::<Blake2sInteropHasher>("blake2s", &leaves, &flattened, &expected_root);
    verify_backend::<PoseidonInteropHasher>("poseidon-adapter", &leaves, &flattened, &expected_root);
    verify_backend::<RescueInteropHasher>("rescue-adapter", &leaves, &flattened, &expected_root);
}
