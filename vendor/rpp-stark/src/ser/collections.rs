use super::cursor::ByteReader;
use super::error::{SerError, SerKind, SerResult};
use super::ints;

/// Writes a `Vec<T>` using a `u32` item count prefix.
pub fn write_vec<T, F>(
    out: &mut Vec<u8>,
    items: &[T],
    kind: SerKind,
    field: &'static str,
    mut write_item: F,
) -> SerResult<()>
where
    F: FnMut(&mut Vec<u8>, &T) -> SerResult<()>,
{
    let count = ints::ensure_u32(items.len(), kind, field)?;
    ints::write_u32(out, count);
    for item in items {
        write_item(out, item)?;
    }
    Ok(())
}

/// Reads a `Vec<T>` encoded with a `u32` length prefix.
pub fn read_vec<T, F>(
    cursor: &mut ByteReader<'_>,
    kind: SerKind,
    field: &'static str,
    mut read_item: F,
) -> SerResult<Vec<T>>
where
    F: FnMut(&mut ByteReader<'_>, usize) -> SerResult<T>,
{
    let count = ints::read_u32(cursor, kind, field)? as usize;
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        out.push(read_item(cursor, index)?);
    }
    Ok(out)
}

/// Writes an optional value with a `u8` discriminant (0 = None, 1 = Some).
pub fn write_option<T, F>(out: &mut Vec<u8>, value: &Option<T>, mut write: F) -> SerResult<()>
where
    F: FnMut(&mut Vec<u8>, &T) -> SerResult<()>,
{
    match value {
        Some(inner) => {
            ints::write_u8(out, 1);
            write(out, inner)?;
        }
        None => ints::write_u8(out, 0),
    }
    Ok(())
}

/// Reads an optional value encoded with a `u8` discriminant.
pub fn read_option<T, F>(
    cursor: &mut ByteReader<'_>,
    kind: SerKind,
    field: &'static str,
    mut read: F,
) -> SerResult<Option<T>>
where
    F: FnMut(&mut ByteReader<'_>) -> SerResult<T>,
{
    match ints::read_u8(cursor, kind, field)? {
        0 => Ok(None),
        1 => Ok(Some(read(cursor)?)),
        _ => Err(SerError::invalid_value(kind, field)),
    }
}
