use crate::ser::{
    ensure_consumed, read_exact_bytes, read_u16, read_u32, read_u64, read_u8, write_bytes,
    write_u16, write_u32, write_u64, write_u8, ByteReader, SerError, SerKind,
};

use super::types::{
    ChallengeBounds, Endianness, FieldKind, FriFolding, FriParams, HashFamily, HashKind, LdeOrder,
    LdeParams, MerkleArity, MerkleParams, ProofParams, SecurityBudget, TranscriptParams,
};
use super::StarkParams;

const PARAMS_SER_KIND: SerKind = SerKind::Params;

/// Canonical binary serialisation for [`StarkParams`].
pub fn serialize_params(params: &StarkParams) -> Vec<u8> {
    let mut out = Vec::with_capacity(89);
    write_u16(&mut out, params.params_version());
    write_u16(&mut out, params.field().code());
    write_u8(&mut out, params.hash().family().code());
    write_u16(&mut out, params.hash().parameter_id());
    write_u32(&mut out, params.lde().blowup);
    write_u8(&mut out, params.lde().order.code());
    write_u64(&mut out, params.lde().coset_tag);
    write_u8(&mut out, params.fri().r);
    write_u16(&mut out, params.fri().queries);
    write_u16(&mut out, params.fri().domain_log2);
    write_u8(&mut out, params.fri().folding.code());
    write_u8(&mut out, params.fri().num_layers);
    write_u8(&mut out, params.merkle().leaf_encoding.code());
    write_u8(&mut out, params.merkle().leaf_width);
    write_u8(&mut out, params.merkle().arity.code());
    write_u64(&mut out, params.merkle().domain_sep);
    write_u64(&mut out, params.transcript().protocol_tag);
    write_bytes(&mut out, &params.transcript().seed);
    write_u8(&mut out, params.transcript().challenge_bounds.minimum);
    write_u8(&mut out, params.transcript().challenge_bounds.maximum);
    write_u16(&mut out, params.proof().version);
    write_u32(&mut out, params.proof().max_size_kb);
    write_u16(&mut out, params.security().target_bits);
    write_u8(&mut out, params.security().soundness_slack_bits);
    out
}

/// Deserialises a parameter set from canonical bytes.
pub fn deserialize_params(bytes: &[u8]) -> Result<StarkParams, SerError> {
    let mut cursor = ByteReader::new(bytes);

    let params_version = read_u16(&mut cursor, PARAMS_SER_KIND, "params_version")?;
    let field_code = read_u16(&mut cursor, PARAMS_SER_KIND, "field")?;
    let field = FieldKind::from_code(field_code)
        .ok_or_else(|| SerError::invalid_value(PARAMS_SER_KIND, "field"))?;

    let family_code = read_u8(&mut cursor, PARAMS_SER_KIND, "hash.family")?;
    let family = HashFamily::from_code(family_code)
        .ok_or_else(|| SerError::invalid_value(PARAMS_SER_KIND, "hash.family"))?;
    let hash_param = read_u16(&mut cursor, PARAMS_SER_KIND, "hash.parameter_id")?;
    let hash = HashKind::from_codes(family, hash_param);

    let lde_blowup = read_u32(&mut cursor, PARAMS_SER_KIND, "lde.blowup")?;
    let lde_order_code = read_u8(&mut cursor, PARAMS_SER_KIND, "lde.order")?;
    let lde_order = LdeOrder::from_code(lde_order_code)
        .ok_or_else(|| SerError::invalid_value(PARAMS_SER_KIND, "lde.order"))?;
    let lde_coset = read_u64(&mut cursor, PARAMS_SER_KIND, "lde.coset_tag")?;

    let fri_r = read_u8(&mut cursor, PARAMS_SER_KIND, "fri.r")?;
    let fri_queries = read_u16(&mut cursor, PARAMS_SER_KIND, "fri.queries")?;
    let fri_domain = read_u16(&mut cursor, PARAMS_SER_KIND, "fri.domain_log2")?;
    let fri_folding_code = read_u8(&mut cursor, PARAMS_SER_KIND, "fri.folding")?;
    let fri_folding = FriFolding::from_code(fri_folding_code)
        .ok_or_else(|| SerError::invalid_value(PARAMS_SER_KIND, "fri.folding"))?;
    let fri_layers = read_u8(&mut cursor, PARAMS_SER_KIND, "fri.num_layers")?;

    let merkle_encoding_code = read_u8(&mut cursor, PARAMS_SER_KIND, "merkle.leaf_encoding")?;
    let merkle_encoding = Endianness::from_code(merkle_encoding_code)
        .ok_or_else(|| SerError::invalid_value(PARAMS_SER_KIND, "merkle.leaf_encoding"))?;
    let merkle_leaf_width = read_u8(&mut cursor, PARAMS_SER_KIND, "merkle.leaf_width")?;
    let merkle_arity_code = read_u8(&mut cursor, PARAMS_SER_KIND, "merkle.arity")?;
    let merkle_arity = MerkleArity::from_code(merkle_arity_code)
        .ok_or_else(|| SerError::invalid_value(PARAMS_SER_KIND, "merkle.arity"))?;
    let merkle_domain_sep = read_u64(&mut cursor, PARAMS_SER_KIND, "merkle.domain_sep")?;

    let transcript_protocol = read_u64(&mut cursor, PARAMS_SER_KIND, "transcript.protocol_tag")?;
    let transcript_seed = {
        let bytes = read_exact_bytes(&mut cursor, PARAMS_SER_KIND, "transcript.seed", 32)?;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(bytes);
        seed
    };
    let transcript_ch_min = read_u8(
        &mut cursor,
        PARAMS_SER_KIND,
        "transcript.challenge_bounds.minimum",
    )?;
    let transcript_ch_max = read_u8(
        &mut cursor,
        PARAMS_SER_KIND,
        "transcript.challenge_bounds.maximum",
    )?;

    let proof_version = read_u16(&mut cursor, PARAMS_SER_KIND, "proof.version")?;
    let proof_max_size = read_u32(&mut cursor, PARAMS_SER_KIND, "proof.max_size_kb")?;
    let security_target = read_u16(&mut cursor, PARAMS_SER_KIND, "security.target_bits")?;
    let security_slack = read_u8(
        &mut cursor,
        PARAMS_SER_KIND,
        "security.soundness_slack_bits",
    )?;

    ensure_consumed(&cursor, PARAMS_SER_KIND)?;

    Ok(StarkParams {
        params_version,
        field,
        hash,
        lde: LdeParams {
            blowup: lde_blowup,
            order: lde_order,
            coset_tag: lde_coset,
        },
        fri: FriParams {
            r: fri_r,
            queries: fri_queries,
            domain_log2: fri_domain,
            folding: fri_folding,
            num_layers: fri_layers,
        },
        merkle: MerkleParams {
            leaf_encoding: merkle_encoding,
            leaf_width: merkle_leaf_width,
            arity: merkle_arity,
            domain_sep: merkle_domain_sep,
        },
        transcript: TranscriptParams {
            protocol_tag: transcript_protocol,
            seed: transcript_seed,
            challenge_bounds: ChallengeBounds {
                minimum: transcript_ch_min,
                maximum: transcript_ch_max,
            },
        },
        proof: ProofParams {
            version: proof_version,
            max_size_kb: proof_max_size,
        },
        security: SecurityBudget {
            target_bits: security_target,
            soundness_slack_bits: security_slack,
        },
    })
}
