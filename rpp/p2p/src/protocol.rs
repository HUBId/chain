use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Block = 1,
    Vote = 2,
    Proof = 3,
    Snapshot = 4,
    Meta = 5,
}

impl MessageType {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(MessageType::Block),
            2 => Some(MessageType::Vote),
            3 => Some(MessageType::Proof),
            4 => Some(MessageType::Snapshot),
            5 => Some(MessageType::Meta),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockMsg {
    pub height: u64,
    pub proposal: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteMsg {
    pub height: u64,
    pub round: u64,
    pub voter: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofMsg {
    pub kind: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotMsg {
    pub version: u64,
    pub state_digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaMsg {
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Block(BlockMsg),
    Vote(VoteMsg),
    Proof(ProofMsg),
    Snapshot(SnapshotMsg),
    Meta(MetaMsg),
}

impl Message {
    pub fn message_type(&self) -> MessageType {
        match self {
            Message::Block(_) => MessageType::Block,
            Message::Vote(_) => MessageType::Vote,
            Message::Proof(_) => MessageType::Proof,
            Message::Snapshot(_) => MessageType::Snapshot,
            Message::Meta(_) => MessageType::Meta,
        }
    }

    pub fn block_proposal(height: u64, proposal: &[u8]) -> Self {
        Message::Block(BlockMsg {
            height,
            proposal: proposal.to_vec(),
        })
    }

    pub fn vote(height: u64, round: u64, voter: impl Into<String>, signature: &[u8]) -> Self {
        Message::Vote(VoteMsg {
            height,
            round,
            voter: voter.into(),
            signature: signature.to_vec(),
        })
    }

    pub fn proof(kind: impl Into<String>, payload: &[u8]) -> Self {
        Message::Proof(ProofMsg {
            kind: kind.into(),
            payload: payload.to_vec(),
        })
    }

    pub fn snapshot(version: u64, state_digest: &[u8]) -> Self {
        Message::Snapshot(SnapshotMsg {
            version,
            state_digest: state_digest.to_vec(),
        })
    }

    pub fn meta(description: impl Into<String>) -> Self {
        Message::Meta(MetaMsg {
            description: description.into(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![self.message_type() as u8];
        match self {
            Message::Block(msg) => {
                push_u64(&mut bytes, msg.height);
                push_bytes(&mut bytes, &msg.proposal);
            }
            Message::Vote(msg) => {
                push_u64(&mut bytes, msg.height);
                push_u64(&mut bytes, msg.round);
                push_string(&mut bytes, &msg.voter);
                push_bytes(&mut bytes, &msg.signature);
            }
            Message::Proof(msg) => {
                push_string(&mut bytes, &msg.kind);
                push_bytes(&mut bytes, &msg.payload);
            }
            Message::Snapshot(msg) => {
                push_u64(&mut bytes, msg.version);
                push_bytes(&mut bytes, &msg.state_digest);
            }
            Message::Meta(msg) => {
                push_string(&mut bytes, &msg.description);
            }
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.is_empty() {
            return Err(ProtocolError::Malformed("empty frame".into()));
        }
        let message_type = MessageType::from_byte(bytes[0]).ok_or_else(|| {
            ProtocolError::Malformed(format!("unknown message type: {}", bytes[0]))
        })?;
        let mut cursor = 1;
        match message_type {
            MessageType::Block => {
                let height = read_u64(bytes, &mut cursor)?;
                let proposal = read_bytes(bytes, &mut cursor)?;
                Ok(Message::Block(BlockMsg { height, proposal }))
            }
            MessageType::Vote => {
                let height = read_u64(bytes, &mut cursor)?;
                let round = read_u64(bytes, &mut cursor)?;
                let voter = read_string(bytes, &mut cursor)?;
                let signature = read_bytes(bytes, &mut cursor)?;
                Ok(Message::Vote(VoteMsg {
                    height,
                    round,
                    voter,
                    signature,
                }))
            }
            MessageType::Proof => {
                let kind = read_string(bytes, &mut cursor)?;
                let payload = read_bytes(bytes, &mut cursor)?;
                Ok(Message::Proof(ProofMsg { kind, payload }))
            }
            MessageType::Snapshot => {
                let version = read_u64(bytes, &mut cursor)?;
                let state_digest = read_bytes(bytes, &mut cursor)?;
                Ok(Message::Snapshot(SnapshotMsg {
                    version,
                    state_digest,
                }))
            }
            MessageType::Meta => {
                let description = read_string(bytes, &mut cursor)?;
                Ok(Message::Meta(MetaMsg { description }))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    Malformed(String),
    UnexpectedEnd,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::Malformed(msg) => write!(f, "malformed message: {}", msg),
            ProtocolError::UnexpectedEnd => write!(f, "unexpected end of frame"),
        }
    }
}

impl std::error::Error for ProtocolError {}

fn push_u64(buffer: &mut Vec<u8>, value: u64) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn push_bytes(buffer: &mut Vec<u8>, data: &[u8]) {
    push_u32(buffer, data.len() as u32);
    buffer.extend_from_slice(data);
}

fn push_string(buffer: &mut Vec<u8>, value: &str) {
    push_bytes(buffer, value.as_bytes());
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, ProtocolError> {
    if *cursor + 8 > bytes.len() {
        return Err(ProtocolError::UnexpectedEnd);
    }
    let mut array = [0u8; 8];
    array.copy_from_slice(&bytes[*cursor..*cursor + 8]);
    *cursor += 8;
    Ok(u64::from_le_bytes(array))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, ProtocolError> {
    if *cursor + 4 > bytes.len() {
        return Err(ProtocolError::UnexpectedEnd);
    }
    let mut array = [0u8; 4];
    array.copy_from_slice(&bytes[*cursor..*cursor + 4]);
    *cursor += 4;
    Ok(u32::from_le_bytes(array))
}

fn read_bytes(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>, ProtocolError> {
    let len = read_u32(bytes, cursor)? as usize;
    if *cursor + len > bytes.len() {
        return Err(ProtocolError::UnexpectedEnd);
    }
    let data = bytes[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(data)
}

fn read_string(bytes: &[u8], cursor: &mut usize) -> Result<String, ProtocolError> {
    let data = read_bytes(bytes, cursor)?;
    String::from_utf8(data).map_err(|err| ProtocolError::Malformed(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_block_message() {
        let message = Message::block_proposal(42, b"proposal");
        let encoded = message.encode();
        let decoded = Message::decode(&encoded).expect("decode block");
        assert_eq!(message, decoded);
    }

    #[test]
    fn rejects_unknown_type() {
        let data = vec![9u8];
        let err = Message::decode(&data).expect_err("unknown type");
        assert!(matches!(err, ProtocolError::Malformed(_)));
    }
}
