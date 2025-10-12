#![allow(dead_code)]
#![allow(unused_imports)]

use once_cell::sync::Lazy;
use rpp_stark::field::FieldElement;
use rpp_stark::proof::ser::{compute_integrity_digest, serialize_proof};
use rpp_stark::proof::types::Proof;
use rpp_stark::utils::serialization::{DigestBytes, ProofBytes};
use std::convert::{TryFrom, TryInto};

#[path = "fail_matrix/fixture.rs"]
mod fail_matrix_fixture;

pub use fail_matrix_fixture::{
    flip_header_version, flip_param_digest_byte, flip_public_digest_byte, mismatch_fri_offset,
    mismatch_openings_offset, mismatch_telemetry_flag, mismatch_telemetry_offset,
    FailMatrixFixture,
};

#[path = "fixtures/mod.rs"]
mod fixtures;

pub use fixtures::mini_proof::MINI_PROOF_BYTES as MINI_PROOF_BYTE_ARRAY;

pub const MINI_PROOF_BYTES: &[u8] = &MINI_PROOF_BYTE_ARRAY;

pub static MINI_FIXTURE: Lazy<FailMatrixFixture> = Lazy::new(FailMatrixFixture::new);

pub fn mini_fixture() -> &'static FailMatrixFixture {
    &MINI_FIXTURE
}

pub fn reencode_proof(proof: &mut Proof) -> ProofBytes {
    if proof.has_telemetry() {
        let mut canonical = proof.clone_using_parts();
        let telemetry = canonical.telemetry_frame_mut();
        telemetry.set_header_length(0);
        telemetry.set_body_length(0);
        telemetry.set_integrity_digest(Default::default());
        let payload = canonical
            .serialize_payload()
            .expect("serialize canonical payload");
        let header = canonical
            .serialize_header(&payload)
            .expect("serialize canonical header");
        let integrity = compute_integrity_digest(&header, &payload);
        let telemetry = proof.telemetry_frame_mut();
        telemetry.set_header_length(header.len() as u32);
        telemetry.set_body_length((payload.len() + 32) as u32);
        telemetry.set_integrity_digest(DigestBytes { bytes: integrity });
    }

    ProofBytes::new(serialize_proof(proof).expect("serialize proof"))
}

pub fn flip_trace_root_byte(bytes: &ProofBytes) -> ProofBytes {
    let mut mutated = bytes.as_slice().to_vec();
    let offset = header_trace_root_offset(&mutated);
    mutated[offset] ^= 0x01;
    ProofBytes::new(mutated)
}

fn header_trace_root_offset(_bytes: &[u8]) -> usize {
    let mut cursor = 0usize;
    cursor += 2; // version
    cursor += 32; // params hash
    cursor += 32; // public digest
    cursor
}

pub fn flip_composition_root_byte(bytes: &ProofBytes) -> ProofBytes {
    let mut mutated = bytes.as_slice().to_vec();
    let mut cursor = header_trace_root_offset(&mutated);
    cursor += 32; // trace commitment digest

    let binding_len = u32::from_le_bytes(
        mutated[cursor..cursor + 4]
            .try_into()
            .expect("binding length"),
    ) as usize;
    cursor += 4;

    let mut binding_cursor = cursor;
    binding_cursor += 1; // kind
    binding_cursor += 32; // air spec id
    let public_len = u32::from_le_bytes(
        mutated[binding_cursor..binding_cursor + 4]
            .try_into()
            .expect("public length"),
    ) as usize;
    binding_cursor += 4 + public_len;

    let flag = mutated[binding_cursor];
    assert_eq!(flag, 1, "expected composition commit to be present");
    binding_cursor += 1;
    assert!(
        binding_cursor < cursor + binding_len,
        "composition commit digest missing"
    );
    mutated[binding_cursor] ^= 0x01;
    ProofBytes::new(mutated)
}

pub fn clear_composition_commit_flag(bytes: &ProofBytes) -> ProofBytes {
    let mut mutated = bytes.as_slice().to_vec();
    let mut cursor = header_trace_root_offset(&mutated);
    cursor += 32; // trace commitment digest

    let binding_len_offset = cursor;
    let binding_len = u32::from_le_bytes(
        mutated[binding_len_offset..binding_len_offset + 4]
            .try_into()
            .expect("binding length"),
    );
    assert!(binding_len >= 32, "binding too small for commit digest");
    cursor += 4;

    let mut binding_cursor = cursor;
    binding_cursor += 1; // kind
    binding_cursor += 32; // air spec id
    let public_len = u32::from_le_bytes(
        mutated[binding_cursor..binding_cursor + 4]
            .try_into()
            .expect("public length"),
    ) as usize;
    binding_cursor += 4 + public_len;

    let flag_position = binding_cursor;
    assert_eq!(mutated[flag_position], 1, "expected commit flag to be set");
    mutated[flag_position] = 0;
    binding_cursor += 1;

    let digest_end = binding_cursor + 32;
    mutated.drain(binding_cursor..digest_end);

    let new_binding_len = binding_len - 32;
    mutated[binding_len_offset..binding_len_offset + 4]
        .copy_from_slice(&new_binding_len.to_le_bytes());

    ProofBytes::new(mutated)
}

pub fn clear_composition_openings_section(bytes: &ProofBytes) -> ProofBytes {
    let mut mutated = bytes.as_slice().to_vec();
    let layout = fail_matrix_fixture::header_layout(&mutated);
    let payload_start = layout.payload_start();
    let openings_handle = layout.openings();
    let openings_len = openings_handle.length() as usize;
    let openings_start = payload_start;

    let merkle_len = read_u32_le(&mutated, openings_start) as usize;
    let openings_payload_len_offset = openings_start + 4 + merkle_len;
    let openings_payload_len = read_u32_le(&mutated, openings_payload_len_offset) as usize;
    let openings_payload_start = openings_payload_len_offset + 4;

    let trace_len = merkle_openings_len(&mutated[openings_payload_start..]);
    let flag_index = openings_payload_start + trace_len;
    assert_eq!(
        mutated[flag_index], 1,
        "expected composition flag to be set"
    );
    mutated[flag_index] = 0;

    let comp_start = flag_index + 1;
    let comp_len = merkle_openings_len(&mutated[comp_start..]);
    let comp_end = comp_start + comp_len;

    mutated.drain(comp_start..comp_end);

    let new_openings_payload_len = openings_payload_len - comp_len;
    let new_openings_len = openings_len - comp_len;

    let new_payload_len_u32 =
        u32::try_from(new_openings_payload_len).expect("openings payload fits u32");
    mutated[openings_payload_len_offset..openings_payload_len_offset + 4]
        .copy_from_slice(&new_payload_len_u32.to_le_bytes());

    let new_openings_len_u32 = u32::try_from(new_openings_len).expect("descriptor len fits u32");
    mutated[layout.openings().len_idx()..layout.openings().len_idx() + 4]
        .copy_from_slice(&new_openings_len_u32.to_le_bytes());

    ProofBytes::new(mutated)
}

fn read_u32_le(bytes: &[u8], start: usize) -> u32 {
    u32::from_le_bytes(bytes[start..start + 4].try_into().expect("u32 slice"))
}

fn merkle_openings_len(bytes: &[u8]) -> usize {
    let mut cursor = 0usize;
    let indices_len = read_u32_le(bytes, cursor) as usize;
    cursor += 4 + 4 * indices_len;

    let leaves_len = read_u32_le(bytes, cursor) as usize;
    cursor += 4;
    for _ in 0..leaves_len {
        let leaf_len = read_u32_le(bytes, cursor) as usize;
        cursor += 4 + leaf_len;
    }

    let paths_len = read_u32_le(bytes, cursor) as usize;
    cursor += 4;
    for _ in 0..paths_len {
        let nodes_len = read_u32_le(bytes, cursor) as usize;
        cursor += 4;
        cursor += nodes_len * (1 + 32);
    }

    cursor
}

pub const MINI_FRI_ROOTS: [[u8; 32]; 5] = [
    [
        0x7c, 0xdd, 0x47, 0x5d, 0x1e, 0xc7, 0xb8, 0x6c, 0xb0, 0xe3, 0xbe, 0xf7, 0x74, 0x88, 0x8d,
        0x2b, 0x2d, 0x35, 0x5f, 0x56, 0xef, 0xa9, 0xd5, 0x36, 0x54, 0xaa, 0x90, 0x70, 0x62, 0x52,
        0xd8, 0xe2,
    ],
    [
        0x50, 0x9a, 0x62, 0x3e, 0x8d, 0xc3, 0x6c, 0xa2, 0x78, 0x31, 0x5e, 0xfb, 0xff, 0x26, 0xa3,
        0xfb, 0x52, 0xb2, 0xd8, 0x83, 0x86, 0xaa, 0x1f, 0x4a, 0x49, 0xbd, 0x81, 0x7f, 0xd4, 0xb3,
        0x9e, 0x60,
    ],
    [
        0x2a, 0xd3, 0xdf, 0xf0, 0xe4, 0x1f, 0xe4, 0x9c, 0xf9, 0xcc, 0x3f, 0xe0, 0x63, 0x31, 0xbf,
        0xab, 0x0b, 0x61, 0xc0, 0xc6, 0x02, 0xf6, 0x49, 0xfc, 0x0e, 0xac, 0x7d, 0x2d, 0x44, 0x72,
        0x9f, 0x2f,
    ],
    [
        0xfe, 0xa7, 0x44, 0x6d, 0x67, 0x37, 0xfe, 0x89, 0x28, 0x6e, 0x51, 0x40, 0xff, 0x91, 0x81,
        0xeb, 0x48, 0x48, 0x7e, 0x84, 0xf9, 0x6d, 0x85, 0xb6, 0x6e, 0x51, 0x77, 0xfa, 0xe2, 0xa5,
        0x95, 0xc7,
    ],
    [
        0x86, 0x40, 0x3a, 0xbd, 0xd7, 0x30, 0x32, 0xec, 0x19, 0xab, 0xb8, 0xe7, 0x6d, 0x83, 0xa2,
        0x9d, 0x12, 0x84, 0xed, 0xfb, 0x1f, 0x04, 0xf8, 0x32, 0x05, 0x7b, 0xb9, 0x84, 0x55, 0x6f,
        0xa8, 0x55,
    ],
];

pub const MINI_FRI_FOLD_CHALLENGES_HEX: [&str; 5] = [
    "d0d04d611e7361fd",
    "dd6c703596f5c64f",
    "7ca9692e64124c1b",
    "08c1ad2c267b2e64",
    "884282e6afced8dc",
];

pub const MINI_TRACE_INDICES: [u32; 64] = [
    15, 56, 58, 83, 92, 118, 122, 127, 132, 138, 145, 148, 211, 228, 246, 252, 265, 278, 294, 311,
    314, 316, 350, 368, 382, 384, 389, 393, 431, 449, 458, 475, 479, 480, 501, 516, 530, 550, 557,
    588, 629, 656, 663, 671, 676, 765, 792, 800, 805, 860, 862, 863, 870, 873, 881, 927, 928, 930,
    932, 948, 968, 973, 991, 1020,
];

pub const MINI_COMPOSITION_INDICES: [u32; 64] = [
    15, 56, 58, 83, 92, 118, 122, 127, 132, 138, 145, 148, 211, 228, 246, 252, 265, 278, 294, 311,
    314, 316, 350, 368, 382, 384, 389, 393, 431, 449, 458, 475, 479, 480, 501, 516, 530, 550, 557,
    588, 629, 656, 663, 671, 676, 765, 792, 800, 805, 860, 862, 863, 870, 873, 881, 927, 928, 930,
    932, 948, 968, 973, 991, 1020,
];

pub const MINI_TRACE_PATH_LENGTHS: [u8; 64] = [
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
];

pub const MINI_COMPOSITION_PATH_LENGTHS: [u8; 64] = [
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
];
