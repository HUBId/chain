use super::cursor::ByteReader;
use super::error::{SerKind, SerResult};
use super::ints;
use crate::field::FieldElement;

/// Writes a field element in canonical little-endian order.
pub fn write_felt(out: &mut Vec<u8>, value: FieldElement) {
    ints::write_u64(out, value.0);
}

/// Reads a canonical field element from the byte cursor.
pub fn read_felt(
    cursor: &mut ByteReader<'_>,
    kind: SerKind,
    field: &'static str,
) -> SerResult<FieldElement> {
    let raw = ints::read_u64(cursor, kind, field)?;
    Ok(FieldElement(raw))
}

/// Writes a slice of field elements with a `u32` length prefix.
pub fn write_felt_vec(
    out: &mut Vec<u8>,
    values: &[FieldElement],
    kind: SerKind,
    field: &'static str,
) -> SerResult<()> {
    let count = ints::ensure_u32(values.len(), kind, field)?;
    ints::write_u32(out, count);
    for value in values {
        write_felt(out, *value);
    }
    Ok(())
}

/// Reads a length-prefixed vector of field elements.
pub fn read_felt_vec(
    cursor: &mut ByteReader<'_>,
    kind: SerKind,
    field: &'static str,
) -> SerResult<Vec<FieldElement>> {
    let count = ints::read_u32(cursor, kind, field)? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(read_felt(cursor, kind, field)?);
    }
    Ok(out)
}
