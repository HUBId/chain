/// Errors that can occur when encoding or decoding schema-specific values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    /// The provided input could not be represented within the schema.
    Encode(&'static str),
    /// Stored data failed to decode into the expected schema type.
    Decode(&'static str),
}

pub type SchemaResult<T> = Result<T, SchemaError>;

/// Trait implemented by logical schemas stored inside Firewood.
pub trait Schema {
    /// Logical name of the schema (e.g. "utxo", "reputation").
    fn name() -> &'static str;
    /// Key type stored in the schema.
    type Key;
    /// Value type stored in the schema.
    type Value;

    /// Encode a logical key into its storage representation.
    fn encode_key(key: &Self::Key) -> SchemaResult<Vec<u8>>;
    /// Encode a logical value into its storage representation.
    fn encode_value(value: &Self::Value) -> SchemaResult<Vec<u8>>;
    /// Decode a stored key back into its logical form.
    fn decode_key(data: &[u8]) -> SchemaResult<Self::Key>;
    /// Decode a stored value back into its logical form.
    fn decode_value(data: &[u8]) -> SchemaResult<Self::Value>;
}

/// Registry that tracks the schemas made available to the storage backend.
pub trait SchemaRegistry {
    /// Error type raised by registry implementations.
    type Error;

    /// Register a schema with the registry.
    fn register<S>(&mut self) -> Result<(), Self::Error>
    where
        S: Schema;

    /// Determine whether a schema with the supplied `name` is registered.
    fn is_registered(&self, name: &str) -> bool;
}
