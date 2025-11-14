use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThemePreference {
    System,
    Light,
    Dark,
}

impl Default for ThemePreference {
    fn default() -> Self {
        ThemePreference::System
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Preferences {
    pub theme: ThemePreference,
    pub clipboard_opt_in: bool,
    pub telemetry_opt_in: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            theme: ThemePreference::System,
            clipboard_opt_in: false,
            telemetry_opt_in: false,
        }
    }
}

impl Preferences {
    pub fn theme(&self) -> ThemePreference {
        self.theme
    }
}

pub fn default_path(config_path: Option<&Path>) -> PathBuf {
    if let Some(path) = config_path {
        if let Some(parent) = path.parent() {
            return parent.join("wallet-gui-preferences.toml");
        }
    }
    PathBuf::from("./config/wallet-gui-preferences.toml")
}

pub fn load(path: &Path) -> io::Result<Preferences> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            toml::from_str(&contents).map_err(|error| io::Error::new(io::ErrorKind::Other, error))
        }
        Err(error) => {
            if error.kind() == io::ErrorKind::NotFound {
                Ok(Preferences::default())
            } else {
                Err(error)
            }
        }
    }
}

pub fn store(path: &Path, preferences: &Preferences) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let encoded = toml::to_string_pretty(preferences)
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
    fs::write(path, encoded)
}
