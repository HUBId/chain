//! Hashing and commitment specifications for the `rpp-stark` engine.
//!
//! This module does not provide executable hashing code.  Instead it freezes the
//! contracts, constants and documentation that the proving and verification
//! stacks must implement in host environments.  Every item is stable Rust and is
//! designed to be auditable without hidden dependencies or implicit behaviour.
//!
//! The submodules cover three complementary domains:
//!
//! * [`poseidon`] – field-arithmetic hashing based on the Poseidon sponge
//!   construction with fully enumerated constants and domain-separation tags.
//! * [`blake3`] – byte-oriented transcripts relying on BLAKE3 with deterministic
//!   framing rules and Fiat–Shamir challenge derivation.
//! * [`deterministic`] – fully deterministic Blake2s helpers used by the
//!   reference implementation to avoid external dependencies.
//! * [`merkle`] – external and optional arithmetic Merkle commitment layouts for
//!   both BLAKE3 and Poseidon back-ends.
//!
//! Downstream implementations are expected to consume these declarations to
//! ensure that prover and verifier agree on padding, endianness, parameter
//! digests and aggregation rules.  The absence of implementation logic is
//! intentional; all behaviour is expressed declaratively to keep the
//! specification self-contained.

pub mod blake3;
pub mod config;
pub mod deterministic;
pub mod merkle;
pub mod poseidon;

pub use blake3::{
    Blake3Domain, Blake3TranscriptSection, Blake3TranscriptSpec, Blake3TranscriptVersion,
    FiatShamirChallengeRules, TranscriptPhaseTag,
};
pub use deterministic::{
    hash, hash_with_backend, Blake2sInteropHasher, Blake2sXof, Hash, Hasher, HexOutput,
    OutputReader, PoseidonInteropHasher, RescueInteropHasher,
};
pub use merkle::{
    compute_root_from_path, encode_leaf, verify_path, Blake3MerkleTree, MerkleError, MerkleIndex,
    MerklePathElement, DIGEST_SIZE, EMPTY_DIGEST, MERKLE_SCHEME_ID,
};
pub use poseidon::{
    PoseidonArithmeticDomain, PoseidonConstantsV1, PoseidonDomainTag, PoseidonParametersV1,
    PoseidonSpongeContract, PoseidonSpongePadding, PoseidonSpongeStateGeometry,
};
