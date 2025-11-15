//! Firewood column family and namespace definitions for wallet state.

/// File-system bucket storing backup metadata exports.
pub const BUCKET_BACKUP_META: &str = "wallet/backup_meta";
/// File-system bucket storing watch-only artefacts mirrored in Firewood.
pub const BUCKET_WATCH_ONLY: &str = "wallet/watch_only";
/// File-system bucket storing multisig scope exports and checkpoints.
pub const BUCKET_MULTISIG_SCOPE: &str = "wallet/multisig_scope";
/// File-system bucket storing cached Zero Sync identity artefacts.
pub const BUCKET_ZSI: &str = "wallet/zsi";
/// File-system bucket storing RBAC assignments for wallet security.
pub const BUCKET_SECURITY_RBAC: &str = "wallet/security/rbac";
/// File-system bucket storing mutual TLS metadata for wallet security.
pub const BUCKET_SECURITY_MTLS: &str = "wallet/security/mtls";
/// File-system bucket storing registered hardware signer metadata.
pub const BUCKET_HW_REGISTRY: &str = "wallet/hw_registry";

/// Root namespace storing general wallet metadata entries.
pub const META_NAMESPACE: &[u8] = b"wallet/meta/";
/// Namespace for encrypted or raw key material managed by the wallet.
pub const KEYS_NAMESPACE: &[u8] = b"wallet/keys/";
/// Namespace capturing backup metadata entries.
pub const BACKUP_META_NAMESPACE: &[u8] = b"wallet/backup_meta/";
/// Namespace for externally facing receive addresses.
pub const ADDR_EXTERNAL_NAMESPACE: &[u8] = b"wallet/addr_external/";
/// Namespace for change or internally generated addresses.
pub const ADDR_INTERNAL_NAMESPACE: &[u8] = b"wallet/addr_internal/";
/// Namespace for materialised UTXO records tracked by the wallet.
pub const UTXOS_NAMESPACE: &[u8] = b"wallet/utxos/";
/// Namespace tracking pending spend locks for wallet-controlled UTXOs.
pub const PENDING_LOCKS_NAMESPACE: &[u8] = b"wallet/pending_locks/";
/// Namespace for cached serialized transactions.
pub const TX_CACHE_NAMESPACE: &[u8] = b"wallet/tx_cache/";
/// Namespace for persisted policy snapshots.
pub const POLICIES_NAMESPACE: &[u8] = b"wallet/policies/";
/// Namespace for progress checkpoints (e.g. sync heights).
pub const CHECKPOINTS_NAMESPACE: &[u8] = b"wallet/checkpoints/";
/// Namespace storing watch-only configuration records.
pub const WATCH_ONLY_NAMESPACE: &[u8] = b"wallet/watch_only/";
/// Namespace storing serialized multisig scope state.
pub const MULTISIG_SCOPE_NAMESPACE: &[u8] = b"wallet/multisig_scope/";
/// Namespace storing serialized security RBAC assignments.
pub const SECURITY_RBAC_NAMESPACE: &[u8] = b"wallet/security/rbac/";
/// Namespace storing serialized security mTLS metadata.
pub const SECURITY_MTLS_NAMESPACE: &[u8] = b"wallet/security/mtls/";
/// Namespace storing cached Zero Sync identity artefacts.
pub const ZSI_NAMESPACE: &[u8] = b"wallet/zsi/";
/// Namespace storing hardware signer registry snapshots.
pub const HW_REGISTRY_NAMESPACE: &[u8] = b"wallet/hw_registry/";

/// File-system extension for pending lock snapshots.
pub const EXTENSION_PENDING_LOCKS: &str = "wallet/pending_locks";
/// File-system extension carrying prover metadata.
pub const EXTENSION_PROVER_META: &str = "wallet/prover_meta";
/// File-system extension capturing checkpoint exports.
pub const EXTENSION_CHECKPOINTS: &str = "wallet/checkpoints";

/// Metadata entry storing the timestamp of the last user-initiated rescan.
pub const META_LAST_RESCAN_TS_KEY: &str = "last_rescan_ts";
/// Metadata entry tracking when the fee cache was last refreshed.
pub const META_FEE_CACHE_FETCHED_TS_KEY: &str = "fee_cache/fetched_ts";
/// Metadata entry tracking when the fee cache expires.
pub const META_FEE_CACHE_EXPIRES_TS_KEY: &str = "fee_cache/expires_ts";

/// Storage key carrying the schema version marker for the wallet layout.
pub const SCHEMA_VERSION_KEY: &[u8] = b"wallet/schema_version";

/// Backup metadata entry storing the schema revision exported in backups.
pub const BACKUP_META_SCHEMA_VERSION_KEY: &str = "schema_version";
/// Backup metadata entry storing the timestamp of the last export.
pub const BACKUP_META_EXPORT_TS_KEY: &str = "exported_at";

/// Storage key storing the watch-only configuration record.
pub const WATCH_ONLY_STATE_KEY: &str = "state";

/// Current on-disk schema version supported by the wallet store.
pub const SCHEMA_VERSION_V1: u32 = 1;
pub const SCHEMA_VERSION_V2: u32 = 2;
pub const SCHEMA_VERSION_V3: u32 = 3;
pub const SCHEMA_VERSION_LATEST: u32 = SCHEMA_VERSION_V3;
