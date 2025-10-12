use proptest::prelude::*;
use rpp_stark::params::{
    deserialize_params, params_hash, serialize_params, BuiltinProfile, FieldKind, HashKind,
    ParamsError, StarkParams, StarkParamsBuilder,
};

fn arb_params() -> impl Strategy<Value = StarkParams> {
    prop_oneof![
        Just(StarkParamsBuilder::new()),
        Just(StarkParamsBuilder::from_profile(
            BuiltinProfile::PROFILE_HISEC_X16
        )),
    ]
    .prop_flat_map(|base| {
        (
            0u32..=4u32,
            0u16..=32u16,
            0u16..=8u16,
            0u8..=4u8,
            0u8..=8u8,
            0u32..=512u32,
            64u16..=256u16,
            0u8..=64u8,
            prop_oneof![Just(false), Just(true)],
        )
            .prop_map(
                move |(
                    extra_blowup,
                    extra_queries,
                    extra_domain,
                    extra_layers,
                    extra_leaf,
                    extra_size,
                    target_bits,
                    slack_bits,
                    flip_hash,
                )| {
                    let mut builder = base.clone();
                    builder.lde.blowup = (builder.lde.blowup + extra_blowup).max(2);
                    builder.fri.queries = (builder.fri.queries + extra_queries).max(1);
                    builder.fri.domain_log2 = (builder.fri.domain_log2 + extra_domain).max(8);
                    builder.fri.num_layers = (builder.fri.num_layers + extra_layers).max(1);
                    builder.merkle.leaf_width = (builder.merkle.leaf_width + extra_leaf).max(1);
                    builder.proof.max_size_kb = builder.proof.max_size_kb + extra_size;
                    builder.security.target_bits = target_bits;
                    let slack_limit = (builder.security.target_bits / 2) as u8;
                    builder.security.soundness_slack_bits = slack_bits.min(slack_limit);
                    if flip_hash {
                        builder.hash = HashKind::Blake2s { digest_size: 32 };
                    } else {
                        builder.hash = match builder.field {
                            FieldKind::Goldilocks => HashKind::Poseidon2 { parameter_set: 0 },
                            FieldKind::Bn254 => HashKind::Rescue { parameter_set: 1 },
                        };
                    }
                    builder.build().expect("valid randomized params")
                },
            )
    })
}

#[test]
fn canonical_roundtrip() {
    let params = StarkParamsBuilder::new().build().expect("valid");
    let bytes = serialize_params(&params);
    let decoded = deserialize_params(&bytes).expect("deserialise");
    assert_eq!(params, decoded);
}

#[test]
fn bincode_roundtrip() {
    let params = StarkParamsBuilder::from_profile(BuiltinProfile::PROFILE_HISEC_X16)
        .build()
        .expect("valid profile");
    let bytes = bincode::serialize(&params).expect("serialize");
    let decoded: StarkParams = bincode::deserialize(&bytes).expect("deserialize");
    assert_eq!(params, decoded);
}

#[test]
fn compatibility_relaxes_non_critical() {
    let mut builder = StarkParamsBuilder::new();
    let base = builder.build().unwrap();
    builder.proof.max_size_kb += 128;
    let tweaked = builder.build().unwrap();
    assert!(base.is_compatible_with(&tweaked));
}

#[test]
fn compatibility_rejects_hash_change() {
    let base = StarkParamsBuilder::new().build().unwrap();
    let mut builder = StarkParamsBuilder::new();
    builder.hash = HashKind::Blake2s { digest_size: 32 };
    let altered = builder.build().unwrap();
    assert!(!base.is_compatible_with(&altered));
}

#[test]
fn invalid_blowup() {
    let mut builder = StarkParamsBuilder::new();
    builder.lde.blowup = 1;
    let err = builder.build().unwrap_err();
    assert!(matches!(err, ParamsError::InvalidBlowup { min: 2, got: 1 }));
}

#[test]
fn invalid_queries() {
    let mut builder = StarkParamsBuilder::new();
    builder.fri.queries = 0;
    let err = builder.build().unwrap_err();
    assert!(matches!(
        err,
        ParamsError::InvalidQueries { min: 1, got: 0 }
    ));
}

#[test]
fn invalid_leaf_width() {
    let mut builder = StarkParamsBuilder::new();
    builder.merkle.leaf_width = 0;
    let err = builder.build().unwrap_err();
    assert!(matches!(err, ParamsError::LeafWidthZero));
}

#[test]
fn version_mismatch() {
    let mut builder = StarkParamsBuilder::new();
    builder.proof.version = builder.params_version + 1;
    let err = builder.build().unwrap_err();
    assert!(matches!(err, ParamsError::VersionMismatch { .. }));
}

#[test]
fn domain_log2_too_small() {
    let mut builder = StarkParamsBuilder::new();
    builder.fri.domain_log2 = 4;
    let err = builder.build().unwrap_err();
    assert!(matches!(err, ParamsError::DomainTooSmall { .. }));
}

#[test]
fn params_hash_stable_for_profile() {
    let params = StarkParamsBuilder::new().build().unwrap();
    let hash = params.params_hash();
    let bytes = serialize_params(&params);
    let decoded = deserialize_params(&bytes).unwrap();
    assert_eq!(hash, decoded.params_hash());
}

proptest! {
    #[test]
    fn prop_roundtrip_idempotent(params in arb_params()) {
        let bytes = serialize_params(&params);
        let decoded = deserialize_params(&bytes).unwrap();
        let decoded_clone = decoded.clone();
        prop_assert_eq!(params, decoded_clone);
        let bytes_again = serialize_params(&decoded);
        prop_assert_eq!(bytes, bytes_again);
    }

    #[test]
    fn prop_hash_deterministic(params in arb_params()) {
        let hash1 = params_hash(&params);
        let hash2 = params_hash(&params);
        prop_assert_eq!(hash1, hash2);
    }
}

#[test]
fn snapshot_profiles() {
    let profile_x8 = StarkParamsBuilder::new().build().unwrap();
    let hisec = StarkParamsBuilder::from_profile(BuiltinProfile::PROFILE_HISEC_X16)
        .build()
        .unwrap();
    insta::assert_json_snapshot!("profile_x8_params", &profile_x8);
    insta::assert_snapshot!(
        "profile_x8_hash",
        format!("{:02x?}", profile_x8.params_hash())
    );
    insta::assert_json_snapshot!("profile_hisec_params", &hisec);
    insta::assert_snapshot!(
        "profile_hisec_hash",
        format!("{:02x?}", hisec.params_hash())
    );
}
