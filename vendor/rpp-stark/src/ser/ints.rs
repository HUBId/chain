use super::cursor::ByteReader;
use super::error::{SerError, SerKind, SerResult};

/// Encodes a `u8` into the output buffer.
pub fn write_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

/// Encodes a `u16` in little-endian order.
pub fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Encodes a `u32` in little-endian order.
pub fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Encodes a `u64` in little-endian order.
pub fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Encodes a `u128` in little-endian order.
pub fn write_u128(out: &mut Vec<u8>, value: u128) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Writes a boolean flag as a single byte (`0` or `1`).
pub fn write_bool(out: &mut Vec<u8>, value: bool) {
    write_u8(out, value as u8);
}

/// Converts a `usize` into a `u32` length prefix.
pub fn ensure_u32(value: usize, kind: SerKind, field: &'static str) -> SerResult<u32> {
    u32::try_from(value).map_err(|_| SerError::invalid_length(kind, field))
}

/// Reads a `u8` from the cursor.
pub fn read_u8(cursor: &mut ByteReader<'_>, kind: SerKind, field: &'static str) -> SerResult<u8> {
    Ok(cursor.read_array::<1>(kind, field)?[0])
}

/// Reads a `u16` in little-endian order.
pub fn read_u16(cursor: &mut ByteReader<'_>, kind: SerKind, field: &'static str) -> SerResult<u16> {
    let bytes = cursor.read_array::<2>(kind, field)?;
    Ok(u16::from_le_bytes(bytes))
}

/// Reads a `u32` in little-endian order.
pub fn read_u32(cursor: &mut ByteReader<'_>, kind: SerKind, field: &'static str) -> SerResult<u32> {
    let bytes = cursor.read_array::<4>(kind, field)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Reads a `u64` in little-endian order.
pub fn read_u64(cursor: &mut ByteReader<'_>, kind: SerKind, field: &'static str) -> SerResult<u64> {
    let bytes = cursor.read_array::<8>(kind, field)?;
    Ok(u64::from_le_bytes(bytes))
}

/// Reads a `u128` in little-endian order.
pub fn read_u128(
    cursor: &mut ByteReader<'_>,
    kind: SerKind,
    field: &'static str,
) -> SerResult<u128> {
    let bytes = cursor.read_array::<16>(kind, field)?;
    Ok(u128::from_le_bytes(bytes))
}

/// Reads a boolean flag encoded as `0` or `1`.
pub fn read_bool(
    cursor: &mut ByteReader<'_>,
    kind: SerKind,
    field: &'static str,
) -> SerResult<bool> {
    match read_u8(cursor, kind, field)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(SerError::invalid_value(kind, field)),
    }
}
