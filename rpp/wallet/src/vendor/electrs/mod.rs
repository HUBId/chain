#![allow(dead_code)]

//! Platzhalter-Integration für Electrs-Upstream-Code.
//!
//! Die hier enthaltenen Module spiegeln den Electrs-Status zum Commit
//! `4a5af61668a1414f112fe8b07b23bff554779a4f` wider, sind jedoch auf
//! `rpp-ledger`-Typen abgestimmt. Die Implementierungen bilden einen
//! deterministischen, VRF-basierten Header- und Transaktionsaufbau nach,
//! der in Tests verwendet wird, bis die echten Ledger-Typen bereitstehen.

pub mod rpp_ledger {
    //! Minimaler Satz an Typen, die die erwarteten `rpp-ledger`-Interfaces
    //! widerspiegeln. Sämtliche Hashes werden deterministisch über SHA-256
    //! berechnet, wodurch die Index- und DB-Tests reproduzierbar bleiben.

    pub mod bitcoin {

        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
        pub struct BlockHash(pub [u8; 32]);

        impl BlockHash {
            pub fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
        pub struct Txid(pub [u8; 32]);

        impl Txid {
            pub fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        #[derive(Clone, Debug, Default, PartialEq, Eq)]
        pub struct Script(Vec<u8>);

        impl Script {
            pub fn new(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct OutPoint {
            pub txid: Txid,
            pub vout: u32,
        }

        impl OutPoint {
            pub fn new(txid: Txid, vout: u32) -> Self {
                Self { txid, vout }
            }
        }

        #[derive(Clone, Copy, Debug, Default)]
        pub enum Network {
            #[default]
            Regtest,
            Testnet,
            Signet,
            Bitcoin,
        }

        pub mod blockdata {
            pub mod block {
                use super::super::BlockHash;
                use sha2::{Digest, Sha256};

                #[derive(Clone, Debug, PartialEq, Eq)]
                pub struct Header {
                    pub parent: BlockHash,
                    pub state_root: [u8; 32],
                    pub tx_root: [u8; 32],
                    pub vrf_output: [u8; 32],
                    pub stark_proof: [u8; 64],
                    pub producer: [u8; 32],
                    pub timestamp: u64,
                }

                impl Header {
                    pub fn new(
                        parent: BlockHash,
                        state_root: [u8; 32],
                        tx_root: [u8; 32],
                        vrf_output: [u8; 32],
                        stark_proof: [u8; 64],
                        producer: [u8; 32],
                        timestamp: u64,
                    ) -> Self {
                        Self {
                            parent,
                            state_root,
                            tx_root,
                            vrf_output,
                            stark_proof,
                            producer,
                            timestamp,
                        }
                    }

                    pub fn block_hash(&self) -> BlockHash {
                        let mut hasher = Sha256::new();
                        hasher.update(self.parent.as_bytes());
                        hasher.update(self.state_root);
                        hasher.update(self.tx_root);
                        hasher.update(self.vrf_output);
                        hasher.update(self.stark_proof);
                        hasher.update(self.producer);
                        hasher.update(self.timestamp.to_le_bytes());
                        BlockHash(hasher.finalize().into())
                    }

                    pub fn prev_blockhash(&self) -> BlockHash {
                        self.parent
                    }
                }

                impl Default for Header {
                    fn default() -> Self {
                        Self {
                            parent: BlockHash([0; 32]),
                            state_root: [0; 32],
                            tx_root: [0; 32],
                            vrf_output: [0; 32],
                            stark_proof: [0; 64],
                            producer: [0; 32],
                            timestamp: 0,
                        }
                    }
                }
            }

            pub mod constants {
                use super::block::Header;
                use crate::vendor::electrs::rpp_ledger::bitcoin::{BlockHash, Network};
                use sha2::{Digest, Sha256};

                pub struct GenesisBlock {
                    pub header: Header,
                }

                fn tag(network: Network) -> [u8; 32] {
                    let mut hasher = Sha256::new();
                    hasher.update(b"rpp-ledger-genesis");
                    hasher.update(match network {
                        Network::Regtest => b"regtest".as_slice(),
                        Network::Testnet => b"testnet".as_slice(),
                        Network::Signet => b"signet".as_slice(),
                        Network::Bitcoin => b"mainnet".as_slice(),
                    });
                    hasher.finalize().into()
                }

                pub fn genesis_block(network: Network) -> GenesisBlock {
                    let mut header = Header::default();
                    header.state_root = tag(network);
                    header.tx_root = tag(network);
                    header.vrf_output = tag(network);
                    header.stark_proof = [0; 64];
                    header.producer = tag(network);
                    header.timestamp = 0;
                    header.parent = BlockHash::from_bytes(tag(network));
                    GenesisBlock { header }
                }
            }
        }

        pub mod hashes {
            pub mod sha256 {
                #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
                pub struct Hash(pub [u8; 32]);

                impl Hash {
                    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
                        bytes.try_into().ok().map(Self)
                    }

                    pub fn as_bytes(&self) -> &[u8; 32] {
                        &self.0
                    }
                }
            }
        }

        pub mod consensus {
            pub mod encode {
                use std::io::{self, Read, Write};

                use crate::vendor::electrs::rpp_ledger::bitcoin::blockdata::block::Header;
                use crate::vendor::electrs::rpp_ledger::bitcoin::{BlockHash, Txid};

                #[derive(Debug)]
                pub struct Error(pub io::Error);

                impl From<io::Error> for Error {
                    fn from(value: io::Error) -> Self {
                        Self(value)
                    }
                }

                pub trait Encodable {
                    fn consensus_encode<S: Write + ?Sized>(
                        &self,
                        s: &mut S,
                    ) -> Result<usize, io::Error>;
                }

                pub trait Decodable: Sized {
                    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, Error>;
                }

                impl Encodable for BlockHash {
                    fn consensus_encode<S: Write + ?Sized>(
                        &self,
                        s: &mut S,
                    ) -> Result<usize, io::Error> {
                        s.write_all(&self.0)?;
                        Ok(self.0.len())
                    }
                }

                impl Decodable for BlockHash {
                    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, Error> {
                        let mut buf = [0u8; 32];
                        d.read_exact(&mut buf)?;
                        Ok(BlockHash(buf))
                    }
                }

                impl Encodable for Txid {
                    fn consensus_encode<S: Write + ?Sized>(
                        &self,
                        s: &mut S,
                    ) -> Result<usize, io::Error> {
                        s.write_all(&self.0)?;
                        Ok(self.0.len())
                    }
                }

                impl Decodable for Txid {
                    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, Error> {
                        let mut buf = [0u8; 32];
                        d.read_exact(&mut buf)?;
                        Ok(Txid(buf))
                    }
                }

                impl Encodable for Header {
                    fn consensus_encode<S: Write + ?Sized>(
                        &self,
                        s: &mut S,
                    ) -> Result<usize, io::Error> {
                        let mut written = 0usize;
                        written += self.parent.consensus_encode(s)?;
                        s.write_all(&self.state_root)?;
                        written += self.state_root.len();
                        s.write_all(&self.tx_root)?;
                        written += self.tx_root.len();
                        s.write_all(&self.vrf_output)?;
                        written += self.vrf_output.len();
                        s.write_all(&self.stark_proof)?;
                        written += self.stark_proof.len();
                        s.write_all(&self.producer)?;
                        written += self.producer.len();
                        s.write_all(&self.timestamp.to_le_bytes())?;
                        written += std::mem::size_of_val(&self.timestamp);
                        Ok(written)
                    }
                }

                impl Decodable for Header {
                    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, Error> {
                        let parent = BlockHash::consensus_decode(d)?;
                        let mut state_root = [0u8; 32];
                        d.read_exact(&mut state_root)?;
                        let mut tx_root = [0u8; 32];
                        d.read_exact(&mut tx_root)?;
                        let mut vrf_output = [0u8; 32];
                        d.read_exact(&mut vrf_output)?;
                        let mut stark_proof = [0u8; 64];
                        d.read_exact(&mut stark_proof)?;
                        let mut producer = [0u8; 32];
                        d.read_exact(&mut producer)?;
                        let mut timestamp_buf = [0u8; 8];
                        d.read_exact(&mut timestamp_buf)?;
                        let timestamp = u64::from_le_bytes(timestamp_buf);
                        Ok(Header {
                            parent,
                            state_root,
                            tx_root,
                            vrf_output,
                            stark_proof,
                            producer,
                            timestamp,
                        })
                    }
                }

                impl Encodable for u32 {
                    fn consensus_encode<S: Write + ?Sized>(
                        &self,
                        s: &mut S,
                    ) -> Result<usize, io::Error> {
                        s.write_all(&self.to_le_bytes())?;
                        Ok(4)
                    }
                }

                impl Decodable for u32 {
                    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, Error> {
                        let mut buf = [0u8; 4];
                        d.read_exact(&mut buf)?;
                        Ok(u32::from_le_bytes(buf))
                    }
                }

                impl Encodable for u64 {
                    fn consensus_encode<S: Write + ?Sized>(
                        &self,
                        s: &mut S,
                    ) -> Result<usize, io::Error> {
                        s.write_all(&self.to_le_bytes())?;
                        Ok(8)
                    }
                }

                impl Decodable for u64 {
                    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, Error> {
                        let mut buf = [0u8; 8];
                        d.read_exact(&mut buf)?;
                        Ok(u64::from_le_bytes(buf))
                    }
                }

                pub fn serialize<T: Encodable>(value: &T) -> Vec<u8> {
                    let mut buf = Vec::new();
                    value
                        .consensus_encode(&mut buf)
                        .expect("serialization must succeed");
                    buf
                }

                pub fn deserialize<T: Decodable>(bytes: &[u8]) -> Result<T, Error> {
                    let mut cursor = io::Cursor::new(bytes);
                    T::consensus_decode(&mut cursor)
                }
            }
        }

        pub mod io {
            pub use std::io::*;
        }
    }

    pub mod bitcoin_slices {

        use crate::vendor::electrs::rpp_ledger::bitcoin::{
            hashes::sha256::Hash, OutPoint, Script,
        };

        pub mod bsl {
            use super::{Hash, OutPoint, Script};
            use sha2::{Digest, Sha256};

            #[derive(Clone, Debug, Default)]
            pub struct Transaction {
                inputs: Vec<OutPoint>,
                outputs: Vec<Script>,
                memo: Vec<u8>,
            }

            impl Transaction {
                pub fn new(inputs: Vec<OutPoint>, outputs: Vec<Script>, memo: Vec<u8>) -> Self {
                    Self {
                        inputs,
                        outputs,
                        memo,
                    }
                }

                pub fn push_output(&mut self, script: Script) {
                    self.outputs.push(script);
                }

                pub fn outputs(&self) -> &[Script] {
                    &self.outputs
                }

                pub fn inputs(&self) -> &[OutPoint] {
                    &self.inputs
                }

                pub fn memo(&self) -> &[u8] {
                    &self.memo
                }

                pub fn txid_sha2(&self) -> Hash {
                    let mut hasher = Sha256::new();
                    hasher.update(&(self.inputs.len() as u32).to_le_bytes());
                    for input in &self.inputs {
                        hasher.update(input.txid.as_bytes());
                        hasher.update(input.vout.to_le_bytes());
                    }
                    hasher.update(&(self.outputs.len() as u32).to_le_bytes());
                    for output in &self.outputs {
                        hasher.update(&(output.as_bytes().len() as u32).to_le_bytes());
                        hasher.update(output.as_bytes());
                    }
                    hasher.update(&(self.memo.len() as u32).to_le_bytes());
                    hasher.update(&self.memo);
                    Hash(hasher.finalize().into())
                }
            }
        }
    }
}

pub mod firewood_adapter;

pub mod chain {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/electrs/2024-05-20/src/chain.rs"
    ));
}

pub mod db {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/electrs/2024-05-20/src/db.rs"
    ));
}

pub mod index {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/electrs/2024-05-20/src/index.rs"
    ));
}

pub mod daemon {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/electrs/2024-05-20/src/daemon.rs"
    ));
}

pub mod status {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/electrs/2024-05-20/src/status.rs"
    ));
}

pub mod tracker {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/electrs/2024-05-20/src/tracker.rs"
    ));
}

pub mod types {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/electrs/2024-05-20/src/types.rs"
    ));
}

pub use self::daemon::Daemon;
pub use self::status::{Balance, HistoryEntry, ScriptHashStatus, UnspentEntry};
pub use self::tracker::Tracker;
