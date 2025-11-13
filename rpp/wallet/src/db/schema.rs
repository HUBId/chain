//! Firewood column family and namespace definitions for wallet state.

/// Root namespace storing general wallet metadata entries.
pub const META_NAMESPACE: &[u8] = b"wallet/meta/";
/// Namespace for encrypted or raw key material managed by the wallet.
pub const KEYS_NAMESPACE: &[u8] = b"wallet/keys/";
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

/// Storage key carrying the schema version marker for the wallet layout.
pub const SCHEMA_VERSION_KEY: &[u8] = b"wallet/schema_version";

/// Current on-disk schema version supported by the wallet store.
pub const SCHEMA_VERSION_V1: u32 = 1;
