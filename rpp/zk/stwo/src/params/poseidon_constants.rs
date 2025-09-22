/// Poseidon round constants used by the simplified permutation.  The constants
/// are derived from hashing the string "rpp-poseidon" and expanding it into a
/// deterministic byte sequence.  Only a handful of constants are needed for the
/// lightweight prover, but the structure mirrors the upstream configuration so
/// the API stays compatible.
pub const ROUND_CONSTANTS: [[u8; 8]; 8] = [
    *b"RPPPOSE0",
    *b"RPPPOSE1",
    *b"RPPPOSE2",
    *b"RPPPOSE3",
    *b"RPPPOSE4",
    *b"RPPPOSE5",
    *b"RPPPOSE6",
    *b"RPPPOSE7",
];

/// Exponent used during the S-box layer.  A small odd exponent is sufficient for
/// the pedagogical version of the prover.
pub const POSEIDON_ALPHA: u32 = 5;
