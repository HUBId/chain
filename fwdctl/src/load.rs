// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE.md for licensing terms.

use std::fs::File;
use std::io::{self, ErrorKind};
use std::path::PathBuf;

use clap::Args;
use firewood::db::BatchOp;
use firewood::v2::api;
use serde_json::Value;

use crate::{insert, DatabasePath};

#[derive(Debug, Args)]
pub struct Options {
    #[command(flatten)]
    pub database: DatabasePath,

    /// Path to a JSON file describing key/value pairs to load.
    #[arg(
        long,
        short = 'f',
        value_name = "FILE",
        help = "Path to JSON file containing key/value fixtures"
    )]
    pub file: PathBuf,
}

pub(super) fn run(opts: &Options) -> Result<(), api::Error> {
    log::debug!("loading fixtures from {:?}", opts.file);

    let file = File::open(&opts.file)?;
    let payload: Value =
        serde_json::from_reader(file).map_err(|err| api::Error::InternalError(Box::new(err)))?;

    let object = payload.as_object().ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidData,
            "fixture file must be a JSON object mapping keys to string values",
        )
    })?;

    let entry_count = object.len();
    if entry_count == 0 {
        println!(
            "Loaded 0 entries from {} (no operations applied)",
            opts.file.display()
        );
        return Ok(());
    }

    let mut batch = Vec::with_capacity(entry_count);
    for (key, value) in object.iter() {
        let value_str = value.as_str().ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("value for key '{key}' must be a JSON string"),
            )
        })?;
        batch.push(BatchOp::Put {
            key: key.clone().into_bytes(),
            value: value_str.as_bytes().to_vec(),
        });
    }

    insert::commit_batch(opts.database.dbpath.clone(), batch)?;
    println!(
        "Loaded {} entries from {}",
        entry_count,
        opts.file.display()
    );
    Ok(())
}
