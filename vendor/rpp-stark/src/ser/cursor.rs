use super::error::{SerError, SerKind, SerResult};

/// Simple cursor over a byte slice providing structured reads with error context.
#[derive(Debug, Clone, Copy)]
pub struct ByteReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    /// Creates a new cursor over the provided byte slice.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    /// Returns the current offset within the slice.
    pub fn position(&self) -> usize {
        self.offset
    }

    /// Returns the number of bytes remaining in the cursor.
    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    /// Reads exactly `len` bytes from the cursor.
    pub fn read_exact(
        &mut self,
        len: usize,
        kind: SerKind,
        field: &'static str,
    ) -> SerResult<&'a [u8]> {
        if self.offset + len > self.bytes.len() {
            return Err(SerError::unexpected_end(kind, field));
        }
        let start = self.offset;
        self.offset += len;
        Ok(&self.bytes[start..start + len])
    }

    /// Reads a fixed-size byte array from the cursor.
    pub fn read_array<const N: usize>(
        &mut self,
        kind: SerKind,
        field: &'static str,
    ) -> SerResult<[u8; N]> {
        let bytes = self.read_exact(N, kind, field)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Reads an owned byte vector of the requested length.
    pub fn read_vec(
        &mut self,
        kind: SerKind,
        field: &'static str,
        len: usize,
    ) -> SerResult<Vec<u8>> {
        let slice = self.read_exact(len, kind, field)?;
        Ok(slice.to_vec())
    }
}

impl<'a> From<&'a [u8]> for ByteReader<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        ByteReader::new(bytes)
    }
}
