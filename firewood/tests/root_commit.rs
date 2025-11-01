use std::path::PathBuf;

use firewood::db::{Db, DbConfig};
use firewood::v2::api::{BatchOp, Db as _, DbView as _, Proposal as _};
use firewood_storage::noop_storage_metrics;

fn temp_db_path() -> tempfile::TempDir {
    tempfile::tempdir().expect("create temporary directory for firewood db tests")
}

fn open_db(path: &PathBuf) -> Db {
    Db::new(
        path.clone(),
        DbConfig::builder().truncate(false).build(),
        noop_storage_metrics(),
    )
    .expect("open firewood database")
}

#[test]
fn commit_roundtrip_updates_root_hash() {
    let tempdir = temp_db_path();
    let path = tempdir.path().join("db");
    let db = open_db(&path);

    let empty_root = db.root_hash().expect("query initial root hash");

    let proposal = db
        .propose([BatchOp::Put {
            key: b"account:alice".to_vec(),
            value: b"balance=1".to_vec(),
        }])
        .expect("create proposal");
    proposal.commit().expect("commit proposal");

    let committed_root = db
        .root_hash()
        .expect("fetch committed root hash")
        .expect("committed root hash must be populated");
    assert_ne!(
        Some(committed_root.clone()),
        empty_root,
        "committing a proposal must update the root hash",
    );

    let revision = db
        .revision(committed_root)
        .expect("open committed revision for verification");
    let stored = revision
        .val("account:alice")
        .expect("lookup committed value")
        .expect("value must be present after commit");
    assert_eq!(stored.as_ref(), b"balance=1");
}

#[test]
fn committed_revision_survives_restart() {
    let tempdir = temp_db_path();
    let path = tempdir.path().join("db");

    {
        let db = open_db(&path);
        let proposal = db
            .propose([BatchOp::Put {
                key: b"account:bob".to_vec(),
                value: b"balance=5".to_vec(),
            }])
            .expect("create proposal before restart");
        proposal.commit().expect("commit proposal");
    }

    let reopened = open_db(&path);
    let committed_root = reopened
        .root_hash()
        .expect("fetch root hash after restart")
        .expect("root hash must persist after restart");

    let revision = reopened
        .revision(committed_root.clone())
        .expect("open revision after restart");
    let stored = revision
        .val("account:bob")
        .expect("lookup committed value after restart")
        .expect("value must persist after restart");
    assert_eq!(stored.as_ref(), b"balance=5");
}
