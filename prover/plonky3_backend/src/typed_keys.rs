//! Strongly typed wrappers around the toolchain-specific Plonky3 keys.
//!
//! The metadata emitted by the Plonky3 key generator includes enough
//! information to determine which AIR definition backed the proving and
//! verifying keys.  The helpers in this module decode those discriminator
//! fields and attach the resolved circuit flavour to the key handles so
//! downstream code can reason about the concrete toolchain artefacts that are
//! being used.

use crate::{
    AirMetadata, BackendError, BackendResult, CircuitStarkProvingKey, CircuitStarkVerifyingKey,
};
use std::sync::Arc;

/// Enumeration describing the Plonky3 circuits that the backend currently
/// understands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolchainAir {
    /// BFT consensus AIR emitted by the `consensus` module.
    ///
    /// Metadata requirements:
    /// - `air.module`: contains the string `"consensus"`.
    /// - `air.name`: contains the string `"consensus"`.
    /// - `air.version`: must be present.
    Consensus,
    /// Identity attestations AIR produced by the `identity` module.
    ///
    /// Metadata requirements:
    /// - `air.module`: contains the string `"identity"`.
    /// - `air.name`: contains the string `"identity"`.
    /// - `air.version`: must be present.
    Identity,
    /// Ledger pruning AIR emitted by the `pruning` module.
    ///
    /// Metadata requirements:
    /// - `air.module`: contains the string `"pruning"`.
    /// - `air.name`: contains the string `"pruning"`.
    /// - `air.version`: must be present.
    Pruning,
    /// Recursive aggregation AIR emitted by the `recursive` module.
    ///
    /// Metadata requirements:
    /// - `air.module`: contains the string `"recursive"`.
    /// - `air.name`: contains the string `"recursive"`.
    /// - `air.version`: must be present.
    Recursive,
    /// Global state transition AIR emitted by the `state` module.
    ///
    /// Metadata requirements:
    /// - `air.module`: contains the string `"state"`.
    /// - `air.name`: contains the string `"state"`.
    /// - `air.version`: must be present.
    State,
    /// Transaction execution AIR emitted by the `transaction` module.
    ///
    /// Metadata requirements:
    /// - `air.module`: contains the string `"transaction"`.
    /// - `air.name`: contains the string `"transaction"`.
    /// - `air.version`: must be present.
    Transaction,
    /// Uptime attestation AIR emitted by the `uptime` module.
    ///
    /// Metadata requirements:
    /// - `air.module`: contains the string `"uptime"`.
    /// - `air.name`: contains the string `"uptime"`.
    /// - `air.version`: must be present.
    Uptime,
}

impl ToolchainAir {
    fn slug(self) -> &'static str {
        match self {
            Self::Consensus => "consensus",
            Self::Identity => "identity",
            Self::Pruning => "pruning",
            Self::Recursive => "recursive",
            Self::State => "state",
            Self::Transaction => "transaction",
            Self::Uptime => "uptime",
        }
    }

    fn from_circuit_name(name: &str) -> Option<Self> {
        let trimmed = name.trim().to_ascii_lowercase();
        match trimmed.as_str() {
            "consensus" => Some(Self::Consensus),
            "identity" => Some(Self::Identity),
            "pruning" => Some(Self::Pruning),
            "recursive" => Some(Self::Recursive),
            "state" => Some(Self::State),
            "transaction" => Some(Self::Transaction),
            "uptime" => Some(Self::Uptime),
            _ => None,
        }
    }
}

fn metadata_field<'a>(metadata: &'a AirMetadata, key: &str) -> BackendResult<Option<&'a str>> {
    Ok(metadata
        .air()
        .and_then(|object| object.get(key))
        .map(|value| value.as_str())
        .transpose()
        .map_err(|_| {
            BackendError::InvalidAirMetadata(format!("field `{key}` must be a string when present"))
        })?)
}

fn ensure_present(value: Option<&str>, key: &str, circuit: &str) -> BackendResult<&str> {
    value.ok_or_else(|| {
        BackendError::InvalidAirMetadata(format!(
            "{circuit} AIR metadata missing required `{key}` field"
        ))
    })
}

/// Determines the circuit flavour encoded by the metadata payload.
///
/// The helper performs a best-effort match based on the `air.module` and
/// `air.name` string fields.  When the metadata blob is empty (legacy
/// fixtures), the dispatch falls back to the circuit identifier provided by the
/// caller.
pub fn resolve_toolchain_air(circuit: &str, metadata: &AirMetadata) -> BackendResult<ToolchainAir> {
    if let Some(air) = metadata.air() {
        let module = metadata_field(metadata, "module")?;
        let name = metadata_field(metadata, "name")?;
        let version = metadata_field(metadata, "version")?;

        let module_str = ensure_present(module, "module", circuit)?;
        let name_str = ensure_present(name, "name", circuit)?;
        let _ = ensure_present(version, "version", circuit)?;

        for candidate in [
            ToolchainAir::Consensus,
            ToolchainAir::Identity,
            ToolchainAir::Pruning,
            ToolchainAir::Recursive,
            ToolchainAir::State,
            ToolchainAir::Transaction,
            ToolchainAir::Uptime,
        ] {
            let slug = candidate.slug();
            if module_str.to_ascii_lowercase().contains(slug)
                || name_str.to_ascii_lowercase().contains(slug)
            {
                return Ok(candidate);
            }
        }

        return Err(BackendError::InvalidAirMetadata(format!(
            "{circuit} AIR metadata references unsupported module `{module_str}`"
        )));
    }

    ToolchainAir::from_circuit_name(circuit).ok_or_else(|| {
        BackendError::InvalidAirMetadata(format!(
            "unknown circuit `{circuit}` with empty AIR metadata"
        ))
    })
}

/// Strongly typed verifying key annotated with its originating AIR.
#[derive(Clone)]
pub struct TypedStarkVerifyingKey {
    air: ToolchainAir,
    key: Arc<CircuitStarkVerifyingKey>,
}

impl TypedStarkVerifyingKey {
    pub fn air(&self) -> ToolchainAir {
        self.air
    }

    pub fn key(&self) -> Arc<CircuitStarkVerifyingKey> {
        Arc::clone(&self.key)
    }
}

/// Strongly typed proving key annotated with its originating AIR.
#[derive(Clone)]
pub struct TypedStarkProvingKey {
    air: ToolchainAir,
    key: Arc<CircuitStarkProvingKey>,
}

impl TypedStarkProvingKey {
    pub fn air(&self) -> ToolchainAir {
        self.air
    }

    pub fn key(&self) -> Arc<CircuitStarkProvingKey> {
        Arc::clone(&self.key)
    }
}

/// Trait implemented by typed key wrappers so [`decode_typed_key`] can operate
/// generically over verifying and proving keys.
pub trait ToolchainKey: Sized {
    type Raw;

    fn from_parts(air: ToolchainAir, raw: Self::Raw) -> BackendResult<Self>;
}

impl ToolchainKey for TypedStarkVerifyingKey {
    type Raw = CircuitStarkVerifyingKey;

    fn from_parts(air: ToolchainAir, raw: Self::Raw) -> BackendResult<Self> {
        Ok(Self {
            air,
            key: Arc::new(raw),
        })
    }
}

impl ToolchainKey for TypedStarkProvingKey {
    type Raw = CircuitStarkProvingKey;

    fn from_parts(air: ToolchainAir, raw: Self::Raw) -> BackendResult<Self> {
        Ok(Self {
            air,
            key: Arc::new(raw),
        })
    }
}

/// Dispatches the raw Plonky3 key to the appropriate typed wrapper based on
/// the circuit metadata.
pub fn decode_typed_key<K>(circuit: &str, metadata: &AirMetadata, raw: K::Raw) -> BackendResult<K>
where
    K: ToolchainKey,
{
    let air = resolve_toolchain_air(circuit, metadata)?;
    K::from_parts(air, raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn build_metadata(module: &str, name: &str) -> AirMetadata {
        serde_json::from_value(json!({
            "air": {
                "module": module,
                "name": name,
                "version": "v0",
            }
        }))
        .expect("metadata deserialises")
    }

    #[test]
    fn resolve_prefers_metadata() {
        let metadata = build_metadata("toolchain::consensus", "ConsensusAir");
        assert_eq!(
            resolve_toolchain_air("consensus", &metadata).unwrap(),
            ToolchainAir::Consensus
        );
    }

    #[test]
    fn empty_metadata_falls_back_to_circuit_name() {
        let metadata = AirMetadata::default();
        assert_eq!(
            resolve_toolchain_air("identity", &metadata).unwrap(),
            ToolchainAir::Identity
        );
    }

    #[test]
    fn invalid_module_is_rejected() {
        let metadata = build_metadata("toolchain::unknown", "MysteryAir");
        assert!(resolve_toolchain_air("consensus", &metadata).is_err());
    }
}
