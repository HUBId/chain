use insta::assert_snapshot;
use rpp_stark::field::FieldElement;
use rpp_stark::ser::{
    read_bool, read_digest, read_felt, read_prefixed_bytes, read_u16, read_u32, write_bool,
    write_digest, write_felt, write_prefixed_bytes, write_u16, write_u32, write_u8, ByteReader,
    SerError, SerKind,
};

#[test]
fn roundtrip_unsigned_integers() {
    let mut buffer = Vec::new();
    write_u16(&mut buffer, 0x1234);
    write_u32(&mut buffer, 0xdead_beef);
    let mut cursor = ByteReader::new(&buffer);
    assert_eq!(
        read_u16(&mut cursor, SerKind::Proof, "u16").unwrap(),
        0x1234
    );
    assert_eq!(
        read_u32(&mut cursor, SerKind::Proof, "u32").unwrap(),
        0xdead_beef
    );
    assert_eq!(cursor.remaining(), 0);
}

#[test]
fn bool_roundtrip_and_invalid() {
    let mut buffer = Vec::new();
    write_bool(&mut buffer, true);
    write_bool(&mut buffer, false);
    let mut cursor = ByteReader::new(&buffer);
    assert!(read_bool(&mut cursor, SerKind::Proof, "flag").unwrap());
    assert!(!read_bool(&mut cursor, SerKind::Proof, "flag").unwrap());

    let invalid = [2u8];
    let mut cursor = ByteReader::new(&invalid);
    let err = read_bool(&mut cursor, SerKind::Proof, "flag").expect_err("invalid flag");
    assert!(matches!(err, SerError::InvalidValue { .. }));
}

#[test]
fn felt_roundtrip() {
    let element = FieldElement(0xfeed_beefu64);
    let mut buffer = Vec::new();
    write_felt(&mut buffer, element);
    let mut cursor = ByteReader::new(&buffer);
    let restored = read_felt(&mut cursor, SerKind::Proof, "felt").unwrap();
    assert_eq!(restored, element);
}

#[test]
fn length_prefixed_bytes_roundtrip() {
    let payload = [1u8, 2, 3, 4, 5];
    let mut buffer = Vec::new();
    write_prefixed_bytes(&mut buffer, &payload, SerKind::PublicInputs, "bytes").unwrap();
    let mut cursor = ByteReader::new(&buffer);
    let restored = read_prefixed_bytes(&mut cursor, SerKind::PublicInputs, "bytes").unwrap();
    assert_eq!(restored, payload);
}

#[test]
fn snapshot_digest_encoding() {
    let mut buffer = Vec::new();
    write_digest(&mut buffer, &[0xabu8; 32]);
    write_u8(&mut buffer, 7);
    let hex = buffer
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<_>>()
        .join(" ");
    assert_snapshot!("digest_with_tag", hex);
}

#[test]
fn read_prefixed_bytes_short_buffer() {
    let data = [0x05, 0x00, 0x00, 0x00, 1, 2, 3];
    let mut cursor = ByteReader::new(&data);
    let err =
        read_prefixed_bytes(&mut cursor, SerKind::Telemetry, "payload").expect_err("short buffer");
    assert!(matches!(err, SerError::UnexpectedEnd { .. }));
}

#[test]
fn read_digest_truncated() {
    let mut cursor = ByteReader::new(&[0u8; 16]);
    let err = read_digest(&mut cursor, SerKind::Params, "digest").expect_err("truncated digest");
    assert!(matches!(err, SerError::UnexpectedEnd { .. }));
}
