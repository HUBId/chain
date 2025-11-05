use blake3::Hasher;
use serde::Serialize;
use serde_json::Value;

pub fn compute_commitment_and_inputs(
    public_inputs: &Value,
) -> serde_json::Result<(String, Vec<u8>)> {
    let encoded = encode_canonical_json(public_inputs)?;
    let mut hasher = Hasher::new();
    hasher.update(&encoded);
    let commitment = hasher.finalize().to_hex().to_string();
    Ok((commitment, encoded))
}

pub fn encode_canonical_json(value: &Value) -> serde_json::Result<Vec<u8>> {
    let canonical = CanonicalValue(value);
    let mut buffer = Vec::new();
    {
        let mut serializer = serde_json::Serializer::new(&mut buffer);
        canonical.serialize(&mut serializer)?;
    }
    Ok(buffer)
}

struct CanonicalValue<'a>(&'a Value);

impl<'a> serde::Serialize for CanonicalValue<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::{SerializeMap, SerializeSeq};
        match self.0 {
            Value::Null => serializer.serialize_unit(),
            Value::Bool(value) => serializer.serialize_bool(*value),
            Value::Number(value) => value.serialize(serializer),
            Value::String(value) => serializer.serialize_str(value),
            Value::Array(values) => {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    seq.serialize_element(&CanonicalValue(value))?;
                }
                seq.end()
            }
            Value::Object(map) => {
                let mut entries: Vec<_> = map.iter().collect();
                entries.sort_by(|(left, _), (right, _)| left.cmp(right));
                let mut object = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    object.serialize_entry(key, &CanonicalValue(value))?;
                }
                object.end()
            }
        }
    }
}
