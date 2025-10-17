#![allow(dead_code)]

//! Platzhalter-Integration für Electrs-Upstream-Code.
//!
//! Die hier enthaltenen Module spiegeln den Electrs-Status zum Commit
//! `4a5af61668a1414f112fe8b07b23bff554779a4f` wider, sind jedoch auf
//! `rpp-ledger`-Typen abgestimmt und enthalten bewusst `todo!()`-Stubs.

pub mod rpp_ledger {
    //! Minimaler Satz an Typ-Platzhaltern, bis `rpp-ledger` verfügbar ist.

    pub mod bitcoin {
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
        pub struct BlockHash(pub [u8; 32]);

        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
        pub struct Txid(pub [u8; 32]);

        #[derive(Clone, Copy, Debug, Default)]
        pub struct Script;

        #[derive(Clone, Copy, Debug, Default)]
        pub struct OutPoint {
            pub txid: Txid,
            pub vout: u32,
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

                #[derive(Clone, Copy, Debug, Default)]
                pub struct Header;

                impl Header {
                    pub fn block_hash(&self) -> BlockHash {
                        todo!("vendor_electrs: block hash placeholder wird über rpp-ledger implementiert");
                    }

                    pub fn prev_blockhash(&self) -> BlockHash {
                        todo!("vendor_electrs: prev blockhash placeholder wird über rpp-ledger implementiert");
                    }
                }
            }

            pub mod constants {
                use super::block::Header;
                use super::super::Network;

                pub struct GenesisBlock {
                    pub header: Header,
                }

                pub fn genesis_block(_network: Network) -> GenesisBlock {
                    GenesisBlock {
                        header: Header::default(),
                    }
                }
            }
        }

        pub mod hashes {
            pub mod sha256 {
                #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
                pub struct Hash(pub [u8; 32]);
            }
        }

        pub mod consensus {
            pub mod encode {
                use std::io;

                #[derive(Debug)]
                pub struct Error;

                pub trait Encodable {
                    fn consensus_encode<S: io::Write + ?Sized>(
                        &self,
                        _s: &mut S,
                    ) -> Result<usize, io::Error>;
                }

                pub trait Decodable: Sized {
                    fn consensus_decode<D: io::Read + ?Sized>(
                        d: &mut D,
                    ) -> Result<Self, Error>;
                }

                pub fn deserialize<T: Decodable>(_bytes: &[u8]) -> Result<T, Error> {
                    Err(Error)
                }
            }
        }

        pub mod io {
            pub use std::io::*;
        }
    }

    pub mod bitcoin_slices {
        pub mod bsl {
            use crate::vendor::electrs::rpp_ledger::bitcoin::hashes::sha256::Hash;

            #[derive(Clone, Debug, Default)]
            pub struct Transaction;

            impl Transaction {
                pub fn txid_sha2(&self) -> Hash {
                    todo!("vendor_electrs: transaction hashing placeholder wird über rpp-ledger implementiert");
                }
            }
        }
    }
}

pub mod chain {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/electrs/2024-05-20/src/chain.rs"
    ));
}

pub mod types {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/electrs/2024-05-20/src/types.rs"
    ));
}
