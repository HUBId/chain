use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::region::Region;
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Error)]
pub enum WormExportError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("command export failed: {0}")]
    Command(String),
    #[error("s3 export error: {0}")]
    S3(String),
    #[error("invalid retention settings: {0}")]
    InvalidRetention(String),
    #[error("encoding error: {0}")]
    Encoding(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WormEntryMetadata {
    pub id: u64,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WormRetentionMode {
    Compliance,
    Governance,
}

impl WormRetentionMode {
    fn header_value(self) -> &'static str {
        match self {
            Self::Compliance => "COMPLIANCE",
            Self::Governance => "GOVERNANCE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WormRetention {
    pub min_days: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_days: Option<u64>,
    pub mode: WormRetentionMode,
}

impl WormRetention {
    pub fn validate(self) -> Result<Self, WormExportError> {
        if self.min_days == 0 {
            return Err(WormExportError::InvalidRetention(
                "retention.min_days must be greater than zero".into(),
            ));
        }
        if let Some(max) = self.max_days {
            if max < self.min_days {
                return Err(WormExportError::InvalidRetention(
                    "retention.max_days must be >= retention.min_days".into(),
                ));
            }
        }
        Ok(self)
    }

    pub fn retain_until(self, timestamp_ms: u64) -> Result<SystemTime, WormExportError> {
        let base = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_millis(timestamp_ms))
            .ok_or_else(|| WormExportError::InvalidRetention("timestamp overflow".into()))?;
        let min_extension = Duration::from_secs(self.min_days.saturating_mul(86_400));
        let retain_min = base
            .checked_add(min_extension)
            .ok_or_else(|| WormExportError::InvalidRetention("retention overflow".into()))?;
        if let Some(max) = self.max_days {
            let max_extension = Duration::from_secs(max.saturating_mul(86_400));
            let retain_max = base
                .checked_add(max_extension)
                .ok_or_else(|| WormExportError::InvalidRetention("retention overflow".into()))?;
            if retain_min > retain_max {
                return Err(WormExportError::InvalidRetention(
                    "computed min retention exceeds max retention".into(),
                ));
            }
        }
        Ok(retain_min)
    }

    pub fn retain_until_string(self, timestamp_ms: u64) -> Result<String, WormExportError> {
        let retain_until = self.retain_until(timestamp_ms)?;
        let datetime: OffsetDateTime = retain_until.into();
        datetime
            .format(&Rfc3339)
            .map_err(|err| WormExportError::Encoding(err.to_string()))
    }
}

pub trait WormExporter: Send + Sync {
    fn append(
        &self,
        payload: &[u8],
        metadata: &WormEntryMetadata,
        retention: WormRetention,
    ) -> Result<(), WormExportError>;

    fn enforce_retention(&self, _retention: WormRetention) -> Result<(), WormExportError> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct WormExportSettings {
    exporter: Arc<dyn WormExporter>,
    retention: WormRetention,
    require_signature: bool,
}

impl WormExportSettings {
    pub fn new(
        exporter: Arc<dyn WormExporter>,
        retention: WormRetention,
        require_signature: bool,
    ) -> Result<Self, WormExportError> {
        Ok(Self {
            exporter,
            retention: retention.validate()?,
            require_signature,
        })
    }

    pub fn exporter(&self) -> &Arc<dyn WormExporter> {
        &self.exporter
    }

    pub fn retention(&self) -> WormRetention {
        self.retention
    }

    pub fn require_signature(&self) -> bool {
        self.require_signature
    }
}

#[derive(Debug, Clone)]
pub struct CommandWormExporter {
    program: PathBuf,
    args: Vec<String>,
    env: BTreeMap<String, String>,
}

impl CommandWormExporter {
    pub fn new(program: PathBuf, args: Vec<String>, env: BTreeMap<String, String>) -> Self {
        Self { program, args, env }
    }

    fn resolve_program(&self) -> &Path {
        &self.program
    }
}

impl WormExporter for CommandWormExporter {
    fn append(
        &self,
        payload: &[u8],
        metadata: &WormEntryMetadata,
        retention: WormRetention,
    ) -> Result<(), WormExportError> {
        let program = self.resolve_program();
        let mut command = Command::new(program);
        command.args(&self.args);
        command.stdin(Stdio::piped());
        command.stdout(Stdio::inherit());
        command.stderr(Stdio::inherit());
        for (key, value) in &self.env {
            command.env(key, value);
        }
        command.env("WORM_RETENTION_MIN_DAYS", retention.min_days.to_string());
        if let Some(max_days) = retention.max_days {
            command.env("WORM_RETENTION_MAX_DAYS", max_days.to_string());
        }
        command.env("WORM_RETENTION_MODE", retention.mode.header_value());
        command.env("WORM_EXPORT_ID", metadata.id.to_string());
        command.env(
            "WORM_EXPORT_TIMESTAMP_MS",
            metadata.timestamp_ms.to_string(),
        );
        let retain_until = retention.retain_until_string(metadata.timestamp_ms)?;
        command.env("WORM_RETAIN_UNTIL", retain_until);
        command.env(
            "WORM_EXPORT_OBJECT",
            format!("{:020}-{}.json", metadata.timestamp_ms, metadata.id),
        );
        let mut child = command
            .spawn()
            .map_err(|err| WormExportError::Command(err.to_string()))?;
        {
            let stdin = child.stdin.as_mut().ok_or_else(|| {
                WormExportError::Command("worm-export wrapper missing stdin".into())
            })?;
            use std::io::Write as _;
            stdin.write_all(payload)?;
        }
        let status = child
            .wait()
            .map_err(|err| WormExportError::Command(err.to_string()))?;
        if status.success() {
            Ok(())
        } else {
            Err(WormExportError::Command(format!(
                "worm-export wrapper exited with status {status}"
            )))
        }
    }
}

#[derive(Clone)]
pub struct S3WormExporter {
    bucket: Bucket,
    prefix: Option<String>,
    path_style: bool,
}

impl S3WormExporter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bucket: String,
        region: String,
        endpoint: Option<String>,
        prefix: Option<String>,
        access_key: String,
        secret_key: String,
        session_token: Option<String>,
        path_style: bool,
    ) -> Result<Self, WormExportError> {
        let credentials = Credentials::new(
            Some(&access_key),
            Some(&secret_key),
            session_token.as_deref(),
            None,
            None,
        )
        .map_err(|err| WormExportError::S3(err.to_string()))?;
        let region = if let Some(endpoint) = endpoint {
            Region::Custom { region, endpoint }
        } else {
            Region::from_str(&region).map_err(|err| WormExportError::S3(err.to_string()))?
        };
        let bucket = Bucket::new(&bucket, region, credentials)
            .map_err(|err| WormExportError::S3(err.to_string()))?;
        Ok(Self {
            bucket,
            prefix: prefix.filter(|prefix| !prefix.is_empty()),
            path_style,
        })
    }

    fn object_key(&self, metadata: &WormEntryMetadata) -> String {
        let object = format!("{:020}-{}.json", metadata.timestamp_ms, metadata.id);
        if let Some(prefix) = &self.prefix {
            format!("{prefix}/{object}")
        } else {
            object
        }
    }

    fn bucket(&self) -> Bucket {
        if self.path_style {
            self.bucket.clone().with_path_style()
        } else {
            self.bucket.clone()
        }
    }
}

impl WormExporter for S3WormExporter {
    fn append(
        &self,
        payload: &[u8],
        metadata: &WormEntryMetadata,
        retention: WormRetention,
    ) -> Result<(), WormExportError> {
        let retain_until = retention.retain_until_string(metadata.timestamp_ms)?;
        let key = self.object_key(metadata);
        let headers_vec = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            (
                "x-amz-object-lock-mode".to_string(),
                retention.mode.header_value().to_string(),
            ),
            (
                "x-amz-object-lock-retain-until-date".to_string(),
                retain_until,
            ),
        ];
        let headers: Vec<(&str, &str)> = headers_vec
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        let bucket = self.bucket();
        bucket
            .put_object_with_headers(&key, payload, &headers)
            .map_err(|err| WormExportError::S3(err.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_validate_checks_bounds() {
        let retention = WormRetention {
            min_days: 30,
            max_days: Some(90),
            mode: WormRetentionMode::Compliance,
        };
        assert!(retention.validate().is_ok());
        let invalid = WormRetention {
            min_days: 0,
            max_days: None,
            mode: WormRetentionMode::Compliance,
        };
        assert!(invalid.validate().is_err());
    }
}
