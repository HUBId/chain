use crate::{AirMetadata, BackendError, BackendResult};

use p3_baby_bear::{
    default_babybear_poseidon2_16, default_babybear_poseidon2_24, BabyBear, Poseidon2BabyBear,
};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{extension::BinomialExtensionField, Field};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;
use serde_json::{Map, Value};

const EXPECTED_CHALLENGE_EXTENSION_DEGREE: usize = 4;

const DEFAULT_LOG_BLOWUP: usize = 5;
const DEFAULT_LOG_FINAL_POLY_LEN: usize = 0;
const DEFAULT_NUM_QUERIES: usize = 120;
const DEFAULT_PROOF_OF_WORK_BITS: usize = 16;

/// Base field used by the vendor circuits.
pub type CircuitBaseField = BabyBear;

/// Extension field used for transcript challenges.
pub type CircuitChallengeField =
    BinomialExtensionField<CircuitBaseField, EXPECTED_CHALLENGE_EXTENSION_DEGREE>;

type CircuitPackedBaseField = <CircuitBaseField as Field>::Packing;

type CircuitPoseidonHash = PaddingFreeSponge<Poseidon2BabyBear<16>, 16, 8, 8>;
type CircuitPoseidonCompress = TruncatedPermutation<Poseidon2BabyBear<24>, 2, 8, 24>;

/// Merkle tree commitment scheme used by the Plonky3 fixtures.
pub type CircuitMerkleTreeMmcs = MerkleTreeMmcs<
    CircuitPackedBaseField,
    CircuitPackedBaseField,
    CircuitPoseidonHash,
    CircuitPoseidonCompress,
    8,
>;

/// Challenge MMCS derived from the base-field MMCS.
pub type CircuitChallengeMmcs =
    ExtensionMmcs<CircuitBaseField, CircuitChallengeField, CircuitMerkleTreeMmcs>;

/// Polynomial commitment stack matching the toolchain output.
pub type CircuitFriPcs = TwoAdicFriPcs<
    CircuitBaseField,
    Radix2DitParallel<CircuitBaseField>,
    CircuitMerkleTreeMmcs,
    CircuitChallengeMmcs,
>;

/// Challenger used by the fixtures.
pub type CircuitChallenger = DuplexChallenger<CircuitBaseField, Poseidon2BabyBear<24>, 24, 16>;

/// Stark configuration tied to the Plonky3 circuit artifacts.
pub type CircuitStarkConfig = StarkConfig<CircuitFriPcs, CircuitChallengeField, CircuitChallenger>;

fn parse_usize_field(map: Option<&Map<String, Value>>, key: &str) -> BackendResult<Option<usize>> {
    let Some(map) = map else {
        return Ok(None);
    };
    let Some(value) = map.get(key) else {
        return Ok(None);
    };

    match value {
        Value::Null => Ok(None),
        Value::Number(number) => {
            let Some(raw) = number.as_u64() else {
                return Err(BackendError::InvalidAirMetadata(format!(
                    "field `{key}` must be a non-negative integer",
                )));
            };
            usize::try_from(raw).map(Some).map_err(|_| {
                BackendError::InvalidAirMetadata(format!(
                    "field `{key}` exceeds usize range ({raw})",
                ))
            })
        }
        other => Err(BackendError::InvalidAirMetadata(format!(
            "field `{key}` must be an integer, found {}",
            other
        ))),
    }
}

fn ensure_extension_degree(metadata: Option<&Map<String, Value>>) -> BackendResult<()> {
    let Some(map) = metadata else {
        return Ok(());
    };

    let reported = parse_usize_field(Some(map), "challenge_extension_degree")?.or_else(|| {
        parse_usize_field(Some(map), "extension_degree")
            .ok()
            .flatten()
    });

    if let Some(degree) = reported {
        if degree != EXPECTED_CHALLENGE_EXTENSION_DEGREE {
            return Err(BackendError::InvalidAirMetadata(format!(
                "unsupported challenge extension degree {degree}"
            )));
        }
    }

    Ok(())
}

fn validate_challenger(metadata: Option<&Map<String, Value>>) -> BackendResult<()> {
    let Some(challenger) =
        metadata.and_then(|map| map.get("challenger").and_then(Value::as_object))
    else {
        return Ok(());
    };

    if let Some(width) = parse_usize_field(Some(challenger), "width")? {
        if width != 24 {
            return Err(BackendError::InvalidAirMetadata(format!(
                "unsupported challenger width {width}"
            )));
        }
    }

    if let Some(rate) = parse_usize_field(Some(challenger), "rate")? {
        if rate != 16 {
            return Err(BackendError::InvalidAirMetadata(format!(
                "unsupported challenger rate {rate}"
            )));
        }
    }

    Ok(())
}

fn fri_knob(air: Option<&Map<String, Value>>, key: &str, default: usize) -> BackendResult<usize> {
    let fri = air.and_then(|map| map.get("fri").and_then(Value::as_object));
    let nested = parse_usize_field(fri, key)?;
    let direct = parse_usize_field(air, key)?;
    Ok(nested.or(direct).unwrap_or(default))
}

/// Builds the circuit configuration matching the vendor fixtures.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FriConfigKnobs {
    pub log_blowup: usize,
    pub log_final_poly_len: usize,
    pub num_queries: usize,
    pub proof_of_work_bits: usize,
}

pub(crate) fn extract_fri_config(metadata: &AirMetadata) -> BackendResult<FriConfigKnobs> {
    let air = metadata.air();

    ensure_extension_degree(air)?;
    validate_challenger(air)?;

    let log_blowup = fri_knob(air, "log_blowup", DEFAULT_LOG_BLOWUP)?;
    let log_final_poly_len = fri_knob(air, "log_final_poly_len", DEFAULT_LOG_FINAL_POLY_LEN)?;
    let num_queries = fri_knob(air, "num_queries", DEFAULT_NUM_QUERIES)?;
    let proof_of_work_bits = fri_knob(air, "proof_of_work_bits", DEFAULT_PROOF_OF_WORK_BITS)?;

    Ok(FriConfigKnobs {
        log_blowup,
        log_final_poly_len,
        num_queries,
        proof_of_work_bits,
    })
}

pub fn build_circuit_stark_config(metadata: &AirMetadata) -> BackendResult<CircuitStarkConfig> {
    let fri = extract_fri_config(metadata)?;

    let hash_perm = default_babybear_poseidon2_16();
    let hash = CircuitPoseidonHash::new(hash_perm);
    let compress_perm = default_babybear_poseidon2_24();
    let compress = CircuitPoseidonCompress::new(compress_perm);
    let val_mmcs = CircuitMerkleTreeMmcs::new(hash, compress);
    let challenge_mmcs = CircuitChallengeMmcs::new(val_mmcs.clone());

    let fri_params = FriParameters {
        log_blowup: fri.log_blowup,
        log_final_poly_len: fri.log_final_poly_len,
        num_queries: fri.num_queries,
        proof_of_work_bits: fri.proof_of_work_bits,
        mmcs: challenge_mmcs,
    };

    let pcs = CircuitFriPcs::new(Radix2DitParallel::default(), val_mmcs, fri_params);
    let challenger = CircuitChallenger::new(default_babybear_poseidon2_24());

    Ok(CircuitStarkConfig::new(pcs, challenger))
}
