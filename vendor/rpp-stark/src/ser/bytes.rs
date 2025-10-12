use super::cursor::ByteReader;
use super::error::{SerError, SerKind, SerResult};
use super::ints;

/// Appends raw bytes to the output buffer.
pub fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes);
}

/// Writes a `u32` length prefix followed by the provided bytes.
pub fn write_prefixed_bytes(
    out: &mut Vec<u8>,
    bytes: &[u8],
    kind: SerKind,
    field: &'static str,
) -> SerResult<()> {
    let len = ints::ensure_u32(bytes.len(), kind, field)?;
    ints::write_u32(out, len);
    write_bytes(out, bytes);
    Ok(())
}

/// Reads a `u32` length prefix and returns the owned payload bytes.
pub fn read_prefixed_bytes(
    cursor: &mut ByteReader<'_>,
    kind: SerKind,
    field: &'static str,
) -> SerResult<Vec<u8>> {
    let len = ints::read_u32(cursor, kind, field)? as usize;
    cursor.read_vec(kind, field, len)
}

/// Reads a fixed-length byte slice, erroring if the buffer is shorter than expected.
pub fn read_exact_bytes<'a>(
    cursor: &mut ByteReader<'a>,
    kind: SerKind,
    field: &'static str,
    len: usize,
) -> SerResult<&'a [u8]> {
    cursor.read_exact(len, kind, field)
}

/// Ensures that the reader consumed all bytes, otherwise returns a trailing-bytes error.
pub fn ensure_consumed(cursor: &ByteReader<'_>, kind: SerKind) -> SerResult<()> {
    let remaining = cursor.remaining();
    if remaining == 0 {
        Ok(())
    } else {
        Err(SerError::trailing_bytes(kind, cursor.position(), remaining))
    }
}
