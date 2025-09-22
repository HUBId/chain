use std::{
    cell::RefCell,
    collections::BTreeMap,
    error::Error as StdError,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    iter::Iterator,
    path::{Path, PathBuf},
};

/// Core interface for the Firewood key-value engine.
pub trait KeyValueEngine {
    /// Engine-specific error type.
    type Error;

    /// Append or update the value associated with `key`.
    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Self::Error>;

    /// Fetch the value associated with `key`.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Remove the value associated with `key`.
    fn delete(&mut self, key: &[u8]) -> Result<(), Self::Error>;

    /// Flush any buffered state to durable storage.
    fn flush(&mut self) -> Result<(), Self::Error>;

    /// Iterate over all key/value pairs that share the provided prefix.
    fn scan_prefix(
        &self,
        prefix: &[u8],
    ) -> Result<Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + '_>, Self::Error>;
}

/// Error type emitted by [`FirewoodKv`].
#[derive(Debug)]
pub enum FirewoodKvError {
    /// Wrapper around I/O failures.
    Io(io::Error),
    /// The on-disk log is corrupted and cannot be parsed safely.
    Corrupt,
}

impl fmt::Display for FirewoodKvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FirewoodKvError::Io(err) => write!(f, "i/o error: {}", err),
            FirewoodKvError::Corrupt => f.write_str("corrupted key-value log"),
        }
    }
}

impl StdError for FirewoodKvError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            FirewoodKvError::Io(err) => Some(err),
            FirewoodKvError::Corrupt => None,
        }
    }
}

impl From<io::Error> for FirewoodKvError {
    fn from(err: io::Error) -> Self {
        FirewoodKvError::Io(err)
    }
}

const RECORD_HEADER_LEN: usize = 9;
const FLAG_TOMBSTONE: u8 = 0x01;

#[derive(Clone, Copy)]
struct ValuePointer {
    offset: u64,
    len: u32,
}

/// Simple append-only Firewood key-value engine backed by a single log file.
///
/// The engine maintains an in-memory index mapping keys to their most recent
/// value location in the on-disk log. Values are read lazily from disk on
/// demand and new mutations are appended to the end of the log, enabling fast
/// sequential writes while keeping the implementation minimal.
pub struct FirewoodKv {
    log_path: PathBuf,
    writer: BufWriter<File>,
    reader: RefCell<File>,
    index: BTreeMap<Vec<u8>, ValuePointer>,
}

impl FirewoodKv {
    /// Open a Firewood key-value instance rooted at `directory`.
    pub fn open<P: AsRef<Path>>(directory: P) -> Result<Self, FirewoodKvError> {
        let directory = directory.as_ref();
        fs::create_dir_all(directory)?;
        let log_path = directory.join("firewood.kv");

        if !log_path.exists() {
            File::create(&log_path)?;
        }

        let reader_file = OpenOptions::new().read(true).open(&log_path)?;
        let writer_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&log_path)?;

        let mut kv = FirewoodKv {
            log_path,
            writer: BufWriter::new(writer_file),
            reader: RefCell::new(reader_file),
            index: BTreeMap::new(),
        };

        kv.rebuild_index()?;
        Ok(kv)
    }

    fn rebuild_index(&mut self) -> Result<(), FirewoodKvError> {
        self.index.clear();

        let reader_file = File::open(&self.log_path)?;
        let mut reader = BufReader::new(reader_file);
        let mut offset = 0u64;

        loop {
            let mut header = [0u8; RECORD_HEADER_LEN];
            match reader.read_exact(&mut header) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(err) => return Err(FirewoodKvError::Io(err)),
            }

            let flags = header[0];
            let key_len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
            let value_len = u32::from_le_bytes([header[5], header[6], header[7], header[8]]) as usize;

            let mut key = vec![0u8; key_len];
            reader.read_exact(&mut key).map_err(|err| match err.kind() {
                io::ErrorKind::UnexpectedEof => FirewoodKvError::Corrupt,
                _ => FirewoodKvError::Io(err),
            })?;

            let value_offset = offset + RECORD_HEADER_LEN as u64 + key_len as u64;
            if value_len > 0 {
                reader
                    .seek(SeekFrom::Current(value_len as i64))
                    .map_err(FirewoodKvError::Io)?;
            }

            if flags & FLAG_TOMBSTONE != 0 {
                self.index.remove(&key);
            } else {
                self.index.insert(
                    key,
                    ValuePointer {
                        offset: value_offset,
                        len: value_len as u32,
                    },
                );
            }

            offset += RECORD_HEADER_LEN as u64 + key_len as u64 + value_len as u64;
        }

        Ok(())
    }

    fn read_value(&self, pointer: ValuePointer) -> Result<Vec<u8>, FirewoodKvError> {
        let mut reader = self.reader.borrow_mut();
        reader.seek(SeekFrom::Start(pointer.offset))?;
        let mut buf = vec![0u8; pointer.len as usize];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn append_record(&mut self, key: &[u8], value: Option<&[u8]>) -> Result<(), FirewoodKvError> {
        let flags = if value.is_some() { 0 } else { FLAG_TOMBSTONE };
        let value_len = value.map(|v| v.len()).unwrap_or(0) as u32;
        let key_len = key.len() as u32;

        let mut header = [0u8; RECORD_HEADER_LEN];
        header[0] = flags;
        header[1..5].copy_from_slice(&key_len.to_le_bytes());
        header[5..9].copy_from_slice(&value_len.to_le_bytes());

        let offset = self.writer.seek(SeekFrom::End(0))?;
        self.writer.write_all(&header)?;
        self.writer.write_all(key)?;
        if let Some(value) = value {
            self.writer.write_all(value)?;
        }
        self.writer.flush()?;

        if let Some(value) = value {
            self.index.insert(
                key.to_vec(),
                ValuePointer {
                    offset: offset + RECORD_HEADER_LEN as u64 + key.len() as u64,
                    len: value.len() as u32,
                },
            );
        } else {
            self.index.remove(key);
        }

        Ok(())
    }
}

impl KeyValueEngine for FirewoodKv {
    type Error = FirewoodKvError;

    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Self::Error> {
        self.append_record(&key, Some(&value))
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        if let Some(pointer) = self.index.get(key) {
            Ok(Some(self.read_value(*pointer)?))
        } else {
            Ok(None)
        }
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), Self::Error> {
        self.append_record(key, None)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.writer.flush()?;
        self.writer.get_ref().sync_data()?;
        Ok(())
    }

    fn scan_prefix(
        &self,
        prefix: &[u8],
    ) -> Result<Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + '_>, Self::Error> {
        let mut results = Vec::new();
        let start = prefix.to_vec();
        for (key, pointer) in self.index.range(start..) {
            if !key.starts_with(prefix) {
                break;
            }
            results.push((key.clone(), self.read_value(*pointer)?));
        }
        Ok(Box::new(results.into_iter()))
    }
}

#[cfg(test)]
mod tests {
    use super::{FirewoodKv, KeyValueEngine};
    use std::{
        env,
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicUsize, Ordering},
    };

    static NEXT_DIR_ID: AtomicUsize = AtomicUsize::new(0);

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new() -> Self {
            let mut path = env::temp_dir();
            let id = NEXT_DIR_ID.fetch_add(1, Ordering::Relaxed);
            path.push(format!("firewood-test-{}", id));
            fs::create_dir_all(&path).expect("create temp dir");
            TestDir { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn put_get_roundtrip_persists() {
        let tempdir = TestDir::new();
        {
            let mut kv = FirewoodKv::open(tempdir.path()).expect("open");
            kv.put(b"alpha".to_vec(), b"one".to_vec()).expect("put");
            kv.flush().expect("flush");
        }

        let kv = FirewoodKv::open(tempdir.path()).expect("reopen");
        assert_eq!(kv.get(b"alpha").expect("get"), Some(b"one".to_vec()));
    }

    #[test]
    fn delete_writes_tombstone() {
        let tempdir = TestDir::new();
        let mut kv = FirewoodKv::open(tempdir.path()).expect("open");
        kv.put(b"key".to_vec(), b"value".to_vec()).expect("put");
        kv.delete(b"key").expect("delete");
        kv.flush().expect("flush");
        drop(kv);

        let kv = FirewoodKv::open(tempdir.path()).expect("reopen");
        assert!(kv.get(b"key").expect("get").is_none());
    }

    #[test]
    fn scan_prefix_returns_ordered_results() {
        let tempdir = TestDir::new();
        let mut kv = FirewoodKv::open(tempdir.path()).expect("open");
        kv.put(b"user:1".to_vec(), b"alice".to_vec()).expect("put1");
        kv.put(b"user:2".to_vec(), b"bob".to_vec()).expect("put2");
        kv.put(b"order:1".to_vec(), b"pizza".to_vec()).expect("put3");

        let results: Vec<_> = kv
            .scan_prefix(b"user:")
            .expect("scan")
            .collect();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0], (b"user:1".to_vec(), b"alice".to_vec()));
        assert_eq!(results[1], (b"user:2".to_vec(), b"bob".to_vec()));
    }
}
