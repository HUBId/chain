use std::env;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use rand::RngCore;
use storage_firewood::wal::{FileWal, WalError};
use tempfile::TempDir;

mod support;

use support::seeded_rng;

const HELPER_ENV: &str = "FIREWOOD_WAL_HELPER";
const DIR_ENV: &str = "FIREWOOD_WAL_DIR";
const LEN_ENV: &str = "FIREWOOD_WAL_PENDING_LEN";
const READY_MESSAGE: &str = "helper_ready";

#[test]
fn wal_recovery_handles_partial_record() {
    if env::var(HELPER_ENV).as_deref() == Ok("1") {
        run_helper();
    }

    env::remove_var(HELPER_ENV);
    env::remove_var(DIR_ENV);
    env::remove_var(LEN_ENV);

    let mut rng = seeded_rng("recovery_wal");
    let temp_dir = TempDir::new().expect("create wal temp dir");
    let wal_path = temp_dir.path().join("firewood.wal");

    let expected_records = [random_bytes(&mut rng, 32), random_bytes(&mut rng, 48)];

    {
        let wal = FileWal::open(temp_dir.path()).expect("open wal");
        let first_seq = wal.append(&expected_records[0]).expect("append first record");
        assert_eq!(first_seq, 0);
        let second_seq = wal.append(&expected_records[1]).expect("append second record");
        assert_eq!(second_seq, 1);
        wal.sync().expect("sync wal after initial appends");
    }

    let original_len = fs::metadata(&wal_path)
        .expect("wal metadata after initial appends")
        .len();

    let pending_payload = random_bytes(&mut rng, 64);
    let mut child = Command::new(env::current_exe().expect("current test executable"))
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .env(HELPER_ENV, "1")
        .env(DIR_ENV, temp_dir.path())
        .env(LEN_ENV, pending_payload.len().to_string())
        .spawn()
        .expect("spawn wal helper");

    {
        let stdout = child.stdout.take().expect("capture helper stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .expect("read helper readiness signal");
        assert_eq!(line.trim(), READY_MESSAGE);
    }

    child.kill().expect("kill wal helper child");
    let _ = child.wait();

    match FileWal::open(temp_dir.path()) {
        Err(WalError::Corrupt) => {}
        other => panic!("expected WalError::Corrupt reopening wal, got {:?}", other),
    }

    let mut wal_file = OpenOptions::new()
        .write(true)
        .open(&wal_path)
        .expect("open wal file for truncation");
    wal_file
        .set_len(original_len)
        .expect("truncate wal to original length");
    wal_file
        .sync_data()
        .expect("sync wal after truncation");

    let wal = FileWal::open(temp_dir.path()).expect("reopen wal after truncation");
    let recovered = wal.replay_from(0).expect("replay wal after recovery");

    assert_eq!(recovered.len(), expected_records.len());
    for (index, (sequence, payload)) in recovered.iter().enumerate() {
        assert_eq!(*sequence as usize, index);
        assert_eq!(*payload, expected_records[index]);
    }
}

fn run_helper() -> ! {
    let wal_dir = PathBuf::from(env::var(DIR_ENV).expect("wal dir env not set"));
    let pending_len: u32 = env::var(LEN_ENV)
        .expect("pending len env not set")
        .parse()
        .expect("pending len should parse as u32");
    let wal_path = wal_dir.join("firewood.wal");

    let mut wal_file = OpenOptions::new()
        .write(true)
        .open(&wal_path)
        .expect("open wal file for helper");
    wal_file
        .seek(SeekFrom::End(0))
        .expect("seek to wal end in helper");
    wal_file
        .write_all(&pending_len.to_le_bytes())
        .expect("write pending record length");
    wal_file.flush().expect("flush partial record length");
    wal_file
        .sync_data()
        .expect("sync wal after partial write");

    {
        let mut stdout = std::io::stdout();
        writeln!(stdout, "{}", READY_MESSAGE).expect("write helper readiness signal");
        stdout.flush().expect("flush helper readiness signal");
    }
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

fn random_bytes(rng: &mut impl RngCore, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    buf
}
