//! Canonical serialization helpers for the proof system.
//!
//! The helpers in this module implement the little-endian layouts documented
//! in the repository README. They provide a shared vocabulary for encoding and
//! decoding primitive values and higher-level containers such as `Vec` and
//! `Option`.

mod bytes;
mod collections;
mod cursor;
mod digest;
mod error;
mod felt;
mod ints;

pub use bytes::{
    ensure_consumed, read_exact_bytes, read_prefixed_bytes, write_bytes, write_prefixed_bytes,
};
pub use collections::{read_option, read_vec, write_option, write_vec};
pub use cursor::ByteReader;
pub use digest::{read_digest, write_digest, DIGEST_SIZE};
pub use error::{SerError, SerKind, SerResult};
pub use felt::{read_felt, read_felt_vec, write_felt, write_felt_vec};
pub use ints::{
    ensure_u32, read_bool, read_u128, read_u16, read_u32, read_u64, read_u8, write_bool,
    write_u128, write_u16, write_u32, write_u64, write_u8,
};
