use hex::FromHex;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const VECTORS_DIR: &str = "vendor/rpp-stark/vectors/stwo/mini";

pub fn vector_path(name: &str) -> PathBuf {
    Path::new(VECTORS_DIR).join(name)
}

pub fn load_hex_bytes(name: &str) -> Vec<u8> {
    let contents = fs::read_to_string(vector_path(name)).expect("read hex vector");
    Vec::from_hex(contents.trim()).expect("valid hex payload")
}

pub fn load_hex_string(name: &str) -> String {
    fs::read_to_string(vector_path(name))
        .expect("read digest vector")
        .trim()
        .to_lowercase()
}

pub fn load_bytes(name: &str) -> io::Result<Vec<u8>> {
    fs::read(vector_path(name))
}

pub fn load_hex_digest(name: &str) -> io::Result<String> {
    let contents = fs::read_to_string(vector_path(name))?;
    Ok(contents.trim().to_lowercase())
}

static CHECKSUM_LOGGER: OnceLock<()> = OnceLock::new();

pub fn log_vector_checksums() -> io::Result<()> {
    CHECKSUM_LOGGER
        .get_or_try_init(|| {
            write_vector_checksums()?;
            Ok(())
        })
        .map(|_| ())
}

fn write_vector_checksums() -> io::Result<()> {
    let mut entries = Vec::new();
    for name in [
        "params.bin",
        "public_inputs.bin",
        "proof.bin",
        "public_digest.hex",
        "indices.json",
    ] {
        let bytes = fs::read(vector_path(name))?;
        let digest = Sha256::digest(&bytes);
        entries.push((name, hex::encode(digest)));
    }

    let log_dir = Path::new("logs");
    fs::create_dir_all(log_dir)?;
    let log_path = log_dir.join("rpp_golden_vector_checksums.log");
    let writer = BufWriter::new(
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log_path)?,
    );
    let mut writer = writer;
    writeln!(
        writer,
        "# RPP STWO mini vector checksums (sha256) — stored at {}",
        log_path.display()
    )?;
    for (name, digest) in &entries {
        writeln!(writer, "{name}: {digest}")?;
        println!("[rpp-golden-vector-checksum] {name}: {digest}");
    }

    Ok(())
}
