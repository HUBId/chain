use std::env;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rand::RngCore;
use storage_firewood::{
    kv::FirewoodKv,
    wal::{FileWal, WalError},
};
use tempfile::TempDir;

mod support;

use support::seeded_rng;

const HELPER_ENV: &str = "FIREWOOD_WAL_HELPER";
const DIR_ENV: &str = "FIREWOOD_WAL_DIR";
const LEN_ENV: &str = "FIREWOOD_WAL_PENDING_LEN";
const READY_MESSAGE: &str = "helper_ready";
const TX_HELPER_ENV: &str = "FIREWOOD_WAL_TX_HELPER";
const TX_DIR_ENV: &str = "FIREWOOD_WAL_TX_DIR";
const COMMIT_PAUSE_ENV_VAR: &str = "FIREWOOD_KV_COMMIT_PAUSE_PATH";
const BASELINE_KEY: &[u8] = b"baseline";
const BASELINE_VALUE: &[u8] = b"committed";
const TX_KEY: &[u8] = b"tx-key";
const TX_VALUE: &[u8] = b"tx-value";

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

#[test]
fn wal_replay_discards_inflight_transaction_without_commit() {
    if env::var(TX_HELPER_ENV).as_deref() == Ok("1") {
        run_transaction_helper();
    }

    env::remove_var(TX_HELPER_ENV);
    env::remove_var(TX_DIR_ENV);
    env::remove_var(COMMIT_PAUSE_ENV_VAR);

    let temp_dir = TempDir::new().expect("create transaction wal temp dir");
    let data_dir = temp_dir.path().join("kv");
    fs::create_dir_all(&data_dir).expect("create kv data dir");
    let pause_path = temp_dir.path().join("commit.pause");

    {
        let mut kv = FirewoodKv::open(&data_dir).expect("open kv for baseline");
        kv.put(BASELINE_KEY.to_vec(), BASELINE_VALUE.to_vec());
        kv.commit().expect("commit baseline state");
    }

    let mut child = Command::new(env::current_exe().expect("current test executable"))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .env(TX_HELPER_ENV, "1")
        .env(TX_DIR_ENV, &data_dir)
        .env(COMMIT_PAUSE_ENV_VAR, &pause_path)
        .spawn()
        .expect("spawn transaction helper");

    wait_for_pause_file(&pause_path, Duration::from_secs(5));

    child.kill().expect("kill paused transaction helper");
    let _ = child.wait();

    if pause_path.exists() {
        fs::remove_file(&pause_path).expect("remove pause file after crash");
    }

    let kv = FirewoodKv::open(&data_dir).expect("reopen kv after crash");
    assert_eq!(kv.get(BASELINE_KEY), Some(BASELINE_VALUE.to_vec()));
    assert_eq!(kv.get(TX_KEY), None);
}

#[test]
fn wal_replay_applies_committed_transaction_after_pause() {
    if env::var(TX_HELPER_ENV).as_deref() == Ok("1") {
        run_transaction_helper();
    }

    env::remove_var(TX_HELPER_ENV);
    env::remove_var(TX_DIR_ENV);
    env::remove_var(COMMIT_PAUSE_ENV_VAR);

    let temp_dir = TempDir::new().expect("create transaction wal temp dir");
    let data_dir = temp_dir.path().join("kv");
    fs::create_dir_all(&data_dir).expect("create kv data dir");
    let pause_path = temp_dir.path().join("commit.pause");

    {
        let mut kv = FirewoodKv::open(&data_dir).expect("open kv for baseline");
        kv.put(BASELINE_KEY.to_vec(), BASELINE_VALUE.to_vec());
        kv.commit().expect("commit baseline state");
    }

    let mut child = Command::new(env::current_exe().expect("current test executable"))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .env(TX_HELPER_ENV, "1")
        .env(TX_DIR_ENV, &data_dir)
        .env(COMMIT_PAUSE_ENV_VAR, &pause_path)
        .spawn()
        .expect("spawn transaction helper");

    wait_for_pause_file(&pause_path, Duration::from_secs(5));
    fs::remove_file(&pause_path).expect("remove pause file to allow commit");

    let status = child.wait().expect("wait for transaction helper");
    assert!(status.success(), "transaction helper should exit cleanly");

    let kv = FirewoodKv::open(&data_dir).expect("reopen kv after commit");
    assert_eq!(kv.get(BASELINE_KEY), None);
    assert_eq!(kv.get(TX_KEY), Some(TX_VALUE.to_vec()));
}

fn wait_for_pause_file(path: &std::path::Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for commit pause file at {:?}", path);
}

fn run_transaction_helper() -> ! {
    let data_dir = PathBuf::from(env::var(TX_DIR_ENV).expect("transaction dir env not set"));
    let mut kv = FirewoodKv::open(&data_dir).expect("open kv in helper");
    kv.delete(BASELINE_KEY);
    kv.put(TX_KEY.to_vec(), TX_VALUE.to_vec());
    kv.commit().expect("commit staged transaction");
    std::process::exit(0);
}

fn random_bytes(rng: &mut impl RngCore, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    buf
}
