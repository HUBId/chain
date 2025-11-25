use hex::FromHex;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use rpp_chain::zk::rpp_verifier::RppStarkVerificationReport;

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
static VECTOR_LOG: OnceLock<Mutex<GoldenVectorLog>> = OnceLock::new();

pub fn log_vector_checksums() -> io::Result<()> {
    CHECKSUM_LOGGER
        .get_or_try_init(|| {
            let log = load_vector_log()?;
            let log = log.lock().expect("vector log mutex poisoned");
            log.write_current_snapshot()?;
            Ok(())
        })
        .map(|_| ())
}

pub fn log_vector_report(report: &RppStarkVerificationReport) -> io::Result<()> {
    let log = load_vector_log()?;
    {
        let mut log = log.lock().expect("vector log mutex poisoned");
        log.attach_report(report);
        log.write_current_snapshot()?;
    }

    Ok(())
}

fn load_vector_log() -> io::Result<&'static Mutex<GoldenVectorLog>> {
    VECTOR_LOG.get_or_try_init(|| {
        let mut digests = Vec::new();
        for name in [
            "params.bin",
            "public_inputs.bin",
            "proof.bin",
            "public_digest.hex",
            "indices.json",
        ] {
            let bytes = fs::read(vector_path(name))?;
            let digest = Sha256::digest(&bytes);
            digests.push((name.to_string(), hex::encode(digest)));
        }

        let proof_size_bytes = fs::metadata(vector_path("proof.bin"))?.len() as usize;

        Ok(Mutex::new(GoldenVectorLog {
            digests,
            proof_size_bytes,
            report: None,
        }))
    })
}

struct GoldenVectorLog {
    digests: Vec<(String, String)>,
    proof_size_bytes: usize,
    report: Option<ReportSnapshot>,
}

impl GoldenVectorLog {
    fn attach_report(&mut self, report: &RppStarkVerificationReport) {
        self.report = Some(ReportSnapshot::from_report(report));
    }

    fn write_current_snapshot(&self) -> io::Result<()> {
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
        for (name, digest) in &self.digests {
            writeln!(writer, "{name}: {digest}")?;
            println!("[rpp-golden-vector-checksum] {name}: {digest}");
        }

        writeln!(writer, "proof.bin.size_bytes: {}", self.proof_size_bytes)?;
        println!(
            "[rpp-golden-vector-checksum] proof.bin.size_bytes: {}",
            self.proof_size_bytes
        );

        if let Some(report) = &self.report {
            report.write(&mut writer)?;
        }

        Ok(())
    }
}

struct ReportSnapshot {
    total_bytes: u64,
    flags: FlagsSnapshot,
    trace_indices_len: Option<usize>,
    stage_timings: Option<StageTimingSnapshot>,
}

impl ReportSnapshot {
    fn from_report(report: &RppStarkVerificationReport) -> Self {
        let flags = report.flags();
        let trace_indices_len = report.trace_query_indices().map(|indices| indices.len());
        let stage_timings = report.stage_timings().map(StageTimingSnapshot::from);
        Self {
            total_bytes: report.total_bytes(),
            flags: FlagsSnapshot::from(flags),
            trace_indices_len,
            stage_timings,
        }
    }

    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writeln!(writer, "report.total_bytes: {}", self.total_bytes)?;
        println!(
            "[rpp-golden-vector-checksum] report.total_bytes: {}",
            self.total_bytes
        );

        writeln!(writer, "report.flags.params: {}", self.flags.params)?;
        writeln!(writer, "report.flags.public: {}", self.flags.public)?;
        writeln!(writer, "report.flags.merkle: {}", self.flags.merkle)?;
        writeln!(writer, "report.flags.fri: {}", self.flags.fri)?;
        writeln!(
            writer,
            "report.flags.composition: {}",
            self.flags.composition
        )?;
        writeln!(writer, "report.flags.all_passed: {}", self.flags.all_passed)?;

        if let Some(len) = self.trace_indices_len {
            writeln!(writer, "report.trace_query_indices.len: {len}")?;
        } else {
            writeln!(writer, "report.trace_query_indices.len: <none>")?;
        }

        match &self.stage_timings {
            Some(timings) => {
                writeln!(
                    writer,
                    "report.stage_timings.parse_ns: {}",
                    timings.parse_ns
                )?;
                writeln!(
                    writer,
                    "report.stage_timings.merkle_ns: {}",
                    timings.merkle_ns
                )?;
                writeln!(writer, "report.stage_timings.fri_ns: {}", timings.fri_ns)?;
                writeln!(
                    writer,
                    "report.stage_timings.total_ns: {}",
                    timings.total_ns
                )?;
            }
            None => {
                writeln!(writer, "report.stage_timings: <none>")?;
            }
        }

        Ok(())
    }
}

struct FlagsSnapshot {
    params: bool,
    public: bool,
    merkle: bool,
    fri: bool,
    composition: bool,
    all_passed: bool,
}

impl From<rpp_chain::zk::rpp_verifier::RppStarkVerificationFlags> for FlagsSnapshot {
    fn from(flags: rpp_chain::zk::rpp_verifier::RppStarkVerificationFlags) -> Self {
        Self {
            params: flags.params(),
            public: flags.public(),
            merkle: flags.merkle(),
            fri: flags.fri(),
            composition: flags.composition(),
            all_passed: flags.all_passed(),
        }
    }
}

struct StageTimingSnapshot {
    parse_ns: u128,
    merkle_ns: u128,
    fri_ns: u128,
    total_ns: u128,
}

impl From<rpp_chain::zk::rpp_verifier::RppStarkStageTimings> for StageTimingSnapshot {
    fn from(timings: rpp_chain::zk::rpp_verifier::RppStarkStageTimings) -> Self {
        Self {
            parse_ns: timings.parse.as_nanos(),
            merkle_ns: timings.merkle.as_nanos(),
            fri_ns: timings.fri.as_nanos(),
            total_ns: timings.total().as_nanos(),
        }
    }
}
