// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE.md for licensing terms.

use std::fmt;
use std::path::PathBuf;

use clap::Args;
use firewood::db::{Db, DbConfig};
use firewood::v2::api::{self, Db as _};
use firewood_storage::TrieHash;
use firewood_storage::noop_storage_metrics;

#[derive(Debug, Args)]
pub struct Options {
    /// Path to the database captured before pruning or checkpointing
    #[arg(long, value_name = "BEFORE_DB", help = "Path to state before pruning or checkpointing")]
    pub before_db: PathBuf,

    /// Path to the database after pruning or checkpointing
    #[arg(long, value_name = "AFTER_DB", help = "Path to state after pruning or checkpointing")]
    pub after_db: PathBuf,
}

pub(super) fn run(opts: &Options) -> Result<(), api::Error> {
    let before_hash = root_hash(&opts.before_db)?;
    let after_hash = root_hash(&opts.after_db)?;

    if before_hash == after_hash {
        println!(
            "State roots match: {hash}",
            hash = format_hash(&before_hash)
        );
        return Ok(());
    }

    println!("State roots differ:");
    println!(
        "    before ({path}): {hash}",
        path = opts.before_db.display(),
        hash = format_hash(&before_hash)
    );
    println!(
        "    after  ({path}): {hash}",
        path = opts.after_db.display(),
        hash = format_hash(&after_hash)
    );

    Err(StateMismatchError { before_hash, after_hash }.into())
}

fn root_hash(db_path: &PathBuf) -> Result<Option<TrieHash>, api::Error> {
    let cfg = DbConfig::builder().create_if_missing(false).truncate(false);

    let db = Db::new(db_path.clone(), cfg.build(), noop_storage_metrics())?;
    db.root_hash()
}

fn format_hash(hash: &Option<TrieHash>) -> String {
    hash.as_ref()
        .map(|hash| hash.to_string())
        .unwrap_or_else(|| "<empty>".to_string())
}

#[derive(Debug)]
struct StateMismatchError {
    before_hash: Option<TrieHash>,
    after_hash: Option<TrieHash>,
}

impl fmt::Display for StateMismatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "state roots differ (before={before}, after={after})",
            before = format_hash(&self.before_hash),
            after = format_hash(&self.after_hash)
        )
    }
}

impl std::error::Error for StateMismatchError {}

impl From<StateMismatchError> for api::Error {
    fn from(value: StateMismatchError) -> Self {
        api::Error::InternalError(Box::new(value))
    }
}
