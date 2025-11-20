// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE.md for licensing terms.

use std::fs::File;
use std::io::{self, ErrorKind};
use std::path::PathBuf;

use clap::Args;
use firewood::db::BatchOp;
use firewood::v2::api;
use serde_json::{Map, Value};

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

const FIXTURE_SCHEMA_VERSION: u64 = 1;

pub(super) fn run(opts: &Options) -> Result<(), api::Error> {
    log::debug!("loading fixtures from {:?}", opts.file);

    let file = File::open(&opts.file)?;
    let fixture: Fixture = serde_json::from_reader(file).map_err(|err| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "failed to parse fixture file (expected object with `schema.version` and `entries`): {err}"
            ),
        )
    })?;

    if fixture.schema.version != FIXTURE_SCHEMA_VERSION {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "unsupported fixture schema version {} (expected {})",
                fixture.schema.version, FIXTURE_SCHEMA_VERSION
            ),
        )
        .into());
    }

    let entry_count = fixture.entries.len();
    if entry_count == 0 {
        println!(
            "Loaded 0 entries from {} (no operations applied)",
            opts.file.display()
        );
        return Ok(());
    }

    let mut batch = Vec::with_capacity(entry_count);
    for (key, value) in fixture.entries.iter() {
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

#[derive(Debug, serde::Deserialize)]
struct Fixture {
    schema: FixtureSchema,
    entries: Map<String, Value>,
}

#[derive(Debug, serde::Deserialize)]
struct FixtureSchema {
    version: u64,
}
