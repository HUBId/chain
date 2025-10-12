use super::cursor::ByteReader;
use super::error::{SerKind, SerResult};

/// Canonical digest width used across the proof system.
pub const DIGEST_SIZE: usize = 32;

/// Writes a raw digest to the output buffer.
pub fn write_digest(out: &mut Vec<u8>, digest: &[u8; DIGEST_SIZE]) {
    out.extend_from_slice(digest);
}

/// Reads a digest from the byte cursor.
pub fn read_digest(
    cursor: &mut ByteReader<'_>,
    kind: SerKind,
    field: &'static str,
) -> SerResult<[u8; DIGEST_SIZE]> {
    cursor.read_array::<DIGEST_SIZE>(kind, field)
}
