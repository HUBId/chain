use std::borrow::Cow;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use log::warn;
use once_cell::sync::{Lazy, OnceCell};
use thiserror::Error;
use toml::Value;

#[derive(Debug, Clone, Default)]
pub struct MessageCatalog {
    overrides: HashMap<String, String>,
}

impl MessageCatalog {
    pub fn from_file(path: &Path) -> Result<Self, MessageCatalogError> {
        let contents = fs::read_to_string(path)?;
        let overrides = parse_catalog(&contents)?;
        Ok(Self { overrides })
    }

    pub fn text(&self, key: &str) -> String {
        self.template(key).into_owned()
    }

    pub fn render<'a, I, V>(&self, key: &str, pairs: I) -> String
    where
        I: IntoIterator<Item = (&'a str, V)>,
        V: Into<String>,
    {
        let mut output = self.template(key).into_owned();
        for (needle, value) in pairs {
            let token = format!("{{{needle}}}");
            output = output.replace(&token, &value.into());
        }
        output
    }

    fn template(&self, key: &str) -> Cow<'_, str> {
        if let Some(value) = self.overrides.get(key) {
            Cow::Borrowed(value)
        } else if let Some(default) = DEFAULT_MESSAGES.get(key) {
            Cow::Borrowed(default.as_str())
        } else {
            Cow::Owned(key.to_string())
        }
    }
}

#[derive(Debug, Error)]
pub enum MessageCatalogError {
    #[error("failed to read wallet message catalog: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse wallet message catalog: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("wallet message catalog root must be a table")]
    RootNotTable,
    #[error("wallet message catalog entry `{key}` must be a string or table")]
    InvalidValue { key: String },
}

static DEFAULT_MESSAGES: Lazy<HashMap<String, String>> = Lazy::new(|| {
    parse_catalog(include_str!("../wallet_messages.toml"))
        .expect("embedded wallet_messages.toml must be valid")
});

static CLI_MESSAGES: OnceCell<MessageCatalog> = OnceCell::new();
static UI_MESSAGES: OnceCell<MessageCatalog> = OnceCell::new();

pub fn cli_messages() -> &'static MessageCatalog {
    CLI_MESSAGES.get_or_init(|| load_catalog_for_scope("cli"))
}

pub fn ui_messages() -> &'static MessageCatalog {
    UI_MESSAGES.get_or_init(|| load_catalog_for_scope("ui"))
}

fn load_catalog_for_scope(scope: &str) -> MessageCatalog {
    let path = catalog_path_from_env();
    load_catalog_from_optional_path(path.as_deref()).unwrap_or_else(|err| {
        warn!("wallet {scope} messages unavailable: {err}");
        MessageCatalog::default()
    })
}

pub(crate) fn load_catalog_from_optional_path(
    path: Option<&Path>,
) -> Result<MessageCatalog, MessageCatalogError> {
    if let Some(path) = path {
        MessageCatalog::from_file(path)
    } else {
        Ok(MessageCatalog::default())
    }
}

fn catalog_path_from_env() -> Option<PathBuf> {
    if let Some(value) = env::var_os("WALLET_MESSAGES_PATH") {
        return Some(PathBuf::from(value));
    }
    let candidate = PathBuf::from("wallet_messages.toml");
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

fn parse_catalog(input: &str) -> Result<HashMap<String, String>, MessageCatalogError> {
    let value: Value = toml::from_str(input)?;
    let table = value.as_table().ok_or(MessageCatalogError::RootNotTable)?;
    let mut flattened = HashMap::new();
    for (key, value) in table {
        flatten_value(&mut flattened, key, value)?;
    }
    Ok(flattened)
}

fn flatten_value(
    target: &mut HashMap<String, String>,
    prefix: &str,
    value: &Value,
) -> Result<(), MessageCatalogError> {
    match value {
        Value::Table(table) => {
            for (child, child_value) in table {
                let next_key = if prefix.is_empty() {
                    child.clone()
                } else {
                    format!("{prefix}.{child}")
                };
                flatten_value(target, &next_key, child_value)?;
            }
            Ok(())
        }
        Value::String(text) => {
            target.insert(prefix.to_string(), text.clone());
            Ok(())
        }
        _ => Err(MessageCatalogError::InvalidValue {
            key: prefix.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    const REQUIRED_KEYS: &[&str] = &[
        "cli.prompt.confirmation",
        "cli.prompt.operation_aborted",
        "cli.rpc.wallet_policy_violation_multiple",
        "cli.rpc.wallet_policy_violation_generic",
        "cli.rpc.fee_too_low_required",
        "cli.rpc.fee_too_low_minimum",
        "cli.rpc.pending_lock_conflict_with_amounts",
        "cli.rpc.pending_lock_conflict_generic",
        "cli.rpc.prover_timeout",
        "cli.rpc.rescan_in_progress_with_pending",
        "cli.rpc.rescan_in_progress_generic",
        "cli.rpc.draft_not_found",
        "cli.rpc.draft_unsigned",
        "ui.identity.account_missing",
        "ui.identity.zsi_required",
        "ui.identity.insufficient_balance",
        "ui.identity.snapshot_missing",
        "ui.identity.inputs_unavailable",
        "ui.identity.ledger_input_missing",
        "ui.identity.selected_inputs_insufficient",
        "ui.identity.timetoke_insufficient",
        "ui.identity.reputation_below_minimum",
        "ui.identity.reputation_below_required",
        "ui.identity.utxo_value_overflow",
    ];

    #[test]
    fn defaults_cover_all_required_keys() {
        for key in REQUIRED_KEYS {
            assert!(DEFAULT_MESSAGES.contains_key(*key), "missing key {key}");
        }
    }

    #[test]
    fn missing_catalog_path_uses_defaults() {
        let catalog = load_catalog_from_optional_path(None).expect("missing path");
        let key = "cli.rpc.draft_not_found";
        assert_eq!(
            catalog.text(key),
            DEFAULT_MESSAGES.get(key).unwrap().as_str()
        );
    }

    #[test]
    fn invalid_catalog_reverts_to_defaults() {
        let mut temp = NamedTempFile::new().expect("temp file");
        std::io::Write::write_all(&mut temp, b"[cli]\ninvalid = 1\n").expect("write temp");
        let catalog = load_catalog_from_optional_path(Some(temp.path())).unwrap_or_default();
        let key = "cli.rpc.draft_unsigned";
        assert_eq!(
            catalog.text(key),
            DEFAULT_MESSAGES.get(key).unwrap().as_str()
        );
    }
}
