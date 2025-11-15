use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{WalletGuiConfig, WalletGuiTheme};

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
    pub poll_interval_ms: u64,
    pub max_history_rows: u32,
    pub confirm_clipboard: bool,
    pub telemetry_opt_in: bool,
    pub security_controls_enabled: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        WalletGuiConfig::default().into()
    }
}

impl Preferences {
    pub fn theme(&self) -> ThemePreference {
        self.theme
    }

    pub fn poll_interval(&self) -> Duration {
        Duration::from_millis(self.poll_interval_ms.max(1))
    }

    pub fn history_page_size(&self) -> u32 {
        self.max_history_rows.max(1)
    }

    pub fn clipboard_allowed(&self) -> bool {
        !self.confirm_clipboard
    }

    pub fn set_clipboard_allowed(&mut self, allowed: bool) {
        self.confirm_clipboard = !allowed;
    }

    pub fn sanitized(self) -> Self {
        Preferences::from(WalletGuiConfig::from(&self).sanitized())
    }
}

pub fn default_path(config_path: Option<&Path>, data_dir: Option<&Path>) -> PathBuf {
    if let Some(dir) = data_dir {
        if !dir.as_os_str().is_empty() {
            return dir.join("wallet-gui-settings.toml");
        }
    }
    if let Some(path) = config_path {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                return parent.join("wallet-gui-settings.toml");
            }
        }
    }
    PathBuf::from("./data/wallet/wallet-gui-settings.toml")
}

pub fn load(path: &Path, fallback: &Preferences) -> io::Result<Preferences> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            #[derive(Debug, Default, Deserialize)]
            #[serde(default)]
            struct PartialPreferences {
                theme: Option<ThemePreference>,
                poll_interval_ms: Option<u64>,
                max_history_rows: Option<u32>,
                confirm_clipboard: Option<bool>,
                telemetry_opt_in: Option<bool>,
                security_controls_enabled: Option<bool>,
            }

            let overrides: PartialPreferences = toml::from_str(&contents)
                .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;

            let mut merged = fallback.clone();
            if let Some(theme) = overrides.theme {
                merged.theme = theme;
            }
            if let Some(poll_interval_ms) = overrides.poll_interval_ms {
                merged.poll_interval_ms = poll_interval_ms;
            }
            if let Some(max_history_rows) = overrides.max_history_rows {
                merged.max_history_rows = max_history_rows;
            }
            if let Some(confirm_clipboard) = overrides.confirm_clipboard {
                merged.confirm_clipboard = confirm_clipboard;
            }
            if let Some(telemetry_opt_in) = overrides.telemetry_opt_in {
                merged.telemetry_opt_in = telemetry_opt_in;
            }
            if let Some(security_controls_enabled) = overrides.security_controls_enabled {
                merged.security_controls_enabled = security_controls_enabled;
            }

            Ok(merged.sanitized())
        }
        Err(error) => {
            if error.kind() == io::ErrorKind::NotFound {
                Ok(fallback.clone())
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
    let encoded = toml::to_string_pretty(&preferences.clone().sanitized())
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
    fs::write(path, encoded)
}

impl From<WalletGuiConfig> for Preferences {
    fn from(value: WalletGuiConfig) -> Self {
        let sanitized = value.sanitized();
        Self {
            theme: ThemePreference::from(sanitized.theme),
            poll_interval_ms: sanitized.poll_interval_ms,
            max_history_rows: sanitized.max_history_rows,
            confirm_clipboard: sanitized.confirm_clipboard,
            telemetry_opt_in: sanitized.telemetry_opt_in,
            security_controls_enabled: sanitized.security_controls_enabled,
        }
    }
}

impl From<&Preferences> for WalletGuiConfig {
    fn from(value: &Preferences) -> Self {
        WalletGuiConfig {
            poll_interval_ms: value.poll_interval_ms,
            max_history_rows: value.max_history_rows,
            theme: WalletGuiTheme::from(value.theme),
            confirm_clipboard: value.confirm_clipboard,
            telemetry_opt_in: value.telemetry_opt_in,
            security_controls_enabled: value.security_controls_enabled,
        }
    }
}

impl From<WalletGuiTheme> for ThemePreference {
    fn from(value: WalletGuiTheme) -> Self {
        match value {
            WalletGuiTheme::System => ThemePreference::System,
            WalletGuiTheme::Light => ThemePreference::Light,
            WalletGuiTheme::Dark => ThemePreference::Dark,
        }
    }
}

impl From<ThemePreference> for WalletGuiTheme {
    fn from(value: ThemePreference) -> Self {
        match value {
            ThemePreference::System => WalletGuiTheme::System,
            ThemePreference::Light => WalletGuiTheme::Light,
            ThemePreference::Dark => WalletGuiTheme::Dark,
        }
    }
}
