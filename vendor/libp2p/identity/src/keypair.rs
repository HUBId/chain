// Copyright 2023 Protocol Labs.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

#[cfg(any(
    feature = "ecdsa",
    feature = "secp256k1",
    feature = "ed25519",
    feature = "rsa"
))]
use quick_protobuf::{BytesReader, Writer};

#[cfg(feature = "ecdsa")]
use crate::ecdsa;
#[cfg(any(
    feature = "ecdsa",
    feature = "secp256k1",
    feature = "ed25519",
    feature = "rsa"
))]
#[cfg(feature = "ed25519")]
use crate::ed25519;
#[cfg(any(
    feature = "ecdsa",
    feature = "secp256k1",
    feature = "ed25519",
    feature = "rsa"
))]
use crate::error::OtherVariantError;
#[cfg(any(
    feature = "ecdsa",
    feature = "secp256k1",
    feature = "ed25519",
    feature = "rsa"
))]
use crate::proto;
#[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
use crate::rsa;
#[cfg(feature = "secp256k1")]
use crate::secp256k1;
use crate::{
    error::{DecodingError, SigningError},
    KeyType,
};

/// Identity keypair of a node.
///
/// # Example: Generating RSA keys with OpenSSL
///
/// ```text
/// openssl genrsa -out private.pem 2048
/// openssl pkcs8 -in private.pem -inform PEM -topk8 -out private.pk8 -outform DER -nocrypt
/// rm private.pem      # optional
/// ```
///
/// Loading the keys:
///
/// ```text
/// let mut bytes = std::fs::read("private.pk8").unwrap();
/// let keypair = Keypair::rsa_from_pkcs8(&mut bytes);
/// ```
#[derive(Debug, Clone)]
pub struct Keypair {
    keypair: KeyPairInner,
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum KeyPairInner {
    /// An Ed25519 keypair.
    #[cfg(feature = "ed25519")]
    Ed25519(ed25519::Keypair),
    /// An RSA keypair.
    #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
    Rsa(rsa::Keypair),
    /// A Secp256k1 keypair.
    #[cfg(feature = "secp256k1")]
    Secp256k1(secp256k1::Keypair),
    /// An ECDSA keypair.
    #[cfg(feature = "ecdsa")]
    Ecdsa(ecdsa::Keypair),
}

impl Keypair {
    /// Generate a new Ed25519 keypair.
    #[cfg(all(feature = "ed25519", feature = "rand"))]
    pub fn generate_ed25519() -> Keypair {
        Keypair {
            keypair: KeyPairInner::Ed25519(ed25519::Keypair::generate()),
        }
    }

    /// Generate a new Secp256k1 keypair.
    #[cfg(all(feature = "secp256k1", feature = "rand"))]
    pub fn generate_secp256k1() -> Keypair {
        Keypair {
            keypair: KeyPairInner::Secp256k1(secp256k1::Keypair::generate()),
        }
    }

    /// Generate a new ECDSA keypair.
    #[cfg(all(feature = "ecdsa", feature = "rand"))]
    pub fn generate_ecdsa() -> Keypair {
        Keypair {
            keypair: KeyPairInner::Ecdsa(ecdsa::Keypair::generate()),
        }
    }

    #[cfg(feature = "ed25519")]
    pub fn try_into_ed25519(self) -> Result<ed25519::Keypair, OtherVariantError> {
        self.try_into()
    }

    #[cfg(feature = "secp256k1")]
    pub fn try_into_secp256k1(self) -> Result<secp256k1::Keypair, OtherVariantError> {
        self.try_into()
    }

    #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
    pub fn try_into_rsa(self) -> Result<rsa::Keypair, OtherVariantError> {
        self.try_into()
    }

    #[cfg(feature = "ecdsa")]
    pub fn try_into_ecdsa(self) -> Result<ecdsa::Keypair, OtherVariantError> {
        self.try_into()
    }

    /// Decode an keypair from a DER-encoded secret key in PKCS#8 PrivateKeyInfo
    /// format (i.e. unencrypted) as defined in [RFC5208].
    ///
    /// [RFC5208]: https://tools.ietf.org/html/rfc5208#section-5
    #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
    pub fn rsa_from_pkcs8(pkcs8_der: &mut [u8]) -> Result<Keypair, DecodingError> {
        rsa::Keypair::try_decode_pkcs8(pkcs8_der).map(|kp| Keypair {
            keypair: KeyPairInner::Rsa(kp),
        })
    }

    /// Decode a keypair from a DER-encoded Secp256k1 secret key in an ECPrivateKey
    /// structure as defined in [RFC5915].
    ///
    /// [RFC5915]: https://tools.ietf.org/html/rfc5915
    #[cfg(feature = "secp256k1")]
    pub fn secp256k1_from_der(der: &mut [u8]) -> Result<Keypair, DecodingError> {
        secp256k1::SecretKey::from_der(der).map(|sk| Keypair {
            keypair: KeyPairInner::Secp256k1(secp256k1::Keypair::from(sk)),
        })
    }

    #[cfg(feature = "ed25519")]
    pub fn ed25519_from_bytes(bytes: impl AsMut<[u8]>) -> Result<Keypair, DecodingError> {
        Ok(Keypair {
            keypair: KeyPairInner::Ed25519(ed25519::Keypair::from(
                ed25519::SecretKey::try_from_bytes(bytes)?,
            )),
        })
    }

    /// Sign a message using the private key of this keypair, producing
    /// a signature that can be verified using the corresponding public key.
    #[allow(unused_variables)]
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, SigningError> {
        match self.keypair {
            #[cfg(feature = "ed25519")]
            KeyPairInner::Ed25519(ref pair) => Ok(pair.sign(msg)),
            #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
            KeyPairInner::Rsa(ref pair) => pair.sign(msg),
            #[cfg(feature = "secp256k1")]
            KeyPairInner::Secp256k1(ref pair) => Ok(pair.secret().sign(msg)),
            #[cfg(feature = "ecdsa")]
            KeyPairInner::Ecdsa(ref pair) => Ok(pair.secret().sign(msg)),
        }
    }

    /// Get the public key of this keypair.
    pub fn public(&self) -> PublicKey {
        match self.keypair {
            #[cfg(feature = "ed25519")]
            KeyPairInner::Ed25519(ref pair) => PublicKey {
                publickey: PublicKeyInner::Ed25519(pair.public()),
            },
            #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
            KeyPairInner::Rsa(ref pair) => PublicKey {
                publickey: PublicKeyInner::Rsa(pair.public()),
            },
            #[cfg(feature = "secp256k1")]
            KeyPairInner::Secp256k1(ref pair) => PublicKey {
                publickey: PublicKeyInner::Secp256k1(pair.public().clone()),
            },
            #[cfg(feature = "ecdsa")]
            KeyPairInner::Ecdsa(ref pair) => PublicKey {
                publickey: PublicKeyInner::Ecdsa(pair.public().clone()),
            },
        }
    }

    /// Encode a private key as protobuf structure.
    pub fn to_protobuf_encoding(&self) -> Result<Vec<u8>, DecodingError> {
        #[cfg(any(
            feature = "ecdsa",
            feature = "secp256k1",
            feature = "ed25519",
            feature = "rsa"
        ))]
        {
            use quick_protobuf::MessageWrite;
            let pk: proto::PrivateKey = match self.keypair {
                #[cfg(feature = "ed25519")]
                KeyPairInner::Ed25519(ref data) => proto::PrivateKey {
                    Type: proto::KeyType::Ed25519,
                    Data: data.to_bytes().to_vec(),
                },
                #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
                KeyPairInner::Rsa(_) => return Err(DecodingError::encoding_unsupported("RSA")),
                #[cfg(feature = "secp256k1")]
                KeyPairInner::Secp256k1(ref data) => proto::PrivateKey {
                    Type: proto::KeyType::Secp256k1,
                    Data: data.secret().to_bytes().to_vec(),
                },
                #[cfg(feature = "ecdsa")]
                KeyPairInner::Ecdsa(ref data) => proto::PrivateKey {
                    Type: proto::KeyType::ECDSA,
                    Data: data.secret().encode_der(),
                },
            };

            let mut buf = Vec::with_capacity(pk.get_size());
            let mut writer = Writer::new(&mut buf);
            pk.write_message(&mut writer).expect("Encoding to succeed");

            Ok(buf)
        }

        #[cfg(not(any(
            feature = "ecdsa",
            feature = "secp256k1",
            feature = "ed25519",
            feature = "rsa"
        )))]
        unreachable!()
    }

    /// Decode a private key from a protobuf structure and parse it as a [`Keypair`].
    #[allow(unused_variables)]
    pub fn from_protobuf_encoding(bytes: &[u8]) -> Result<Keypair, DecodingError> {
        #[cfg(any(
            feature = "ecdsa",
            feature = "secp256k1",
            feature = "ed25519",
            feature = "rsa"
        ))]
        {
            use quick_protobuf::MessageRead;

            let mut reader = BytesReader::from_bytes(bytes);
            let mut private_key = proto::PrivateKey::from_reader(&mut reader, bytes)
                .map_err(|e| DecodingError::bad_protobuf("private key bytes", e))
                .map(zeroize::Zeroizing::new)?;

            #[allow(unreachable_code)]
            match private_key.Type {
                proto::KeyType::Ed25519 => {
                    #[cfg(feature = "ed25519")]
                    return ed25519::Keypair::try_from_bytes(&mut private_key.Data).map(|sk| {
                        Keypair {
                            keypair: KeyPairInner::Ed25519(sk),
                        }
                    });
                    Err(DecodingError::missing_feature("ed25519"))
                }
                proto::KeyType::RSA => {
                    #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
                    return rsa::Keypair::try_decode_pkcs1(&mut private_key.Data).map(|sk| {
                        Keypair {
                            keypair: KeyPairInner::Rsa(sk),
                        }
                    });
                    Err(DecodingError::missing_feature("rsa"))
                }
                proto::KeyType::Secp256k1 => {
                    #[cfg(feature = "secp256k1")]
                    return secp256k1::SecretKey::try_from_bytes(&mut private_key.Data).map(
                        |key| Keypair {
                            keypair: KeyPairInner::Secp256k1(key.into()),
                        },
                    );

                    Err(DecodingError::missing_feature("secp256k1"))
                }
                proto::KeyType::ECDSA => {
                    #[cfg(feature = "ecdsa")]
                    return ecdsa::SecretKey::try_decode_der(&mut private_key.Data).map(|key| {
                        Keypair {
                            keypair: KeyPairInner::Ecdsa(key.into()),
                        }
                    });

                    Err(DecodingError::missing_feature("ecdsa"))
                }
            }
        }

        #[cfg(not(any(
            feature = "ecdsa",
            feature = "secp256k1",
            feature = "ed25519",
            feature = "rsa"
        )))]
        unreachable!()
    }

    /// Return a [`KeyType`] of the [`Keypair`].
    pub fn key_type(&self) -> KeyType {
        match self.keypair {
            #[cfg(feature = "ed25519")]
            KeyPairInner::Ed25519(_) => KeyType::Ed25519,
            #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
            KeyPairInner::Rsa(_) => KeyType::RSA,
            #[cfg(feature = "secp256k1")]
            KeyPairInner::Secp256k1(_) => KeyType::Secp256k1,
            #[cfg(feature = "ecdsa")]
            KeyPairInner::Ecdsa(_) => KeyType::Ecdsa,
        }
    }

    /// Deterministically derive a new secret from this [`Keypair`],
    /// taking into account the provided domain.
    ///
    /// This works for all key types except RSA where it returns `None`.
    ///
    /// # Example
    ///
    /// ```
    /// # fn main() {
    /// # use libp2p_identity as identity;
    /// let key = identity::Keypair::generate_ed25519();
    ///
    /// let new_key = key
    ///     .derive_secret(b"my encryption key")
    ///     .expect("can derive secret for ed25519");
    /// # }
    /// ```
    #[cfg(any(
        feature = "ecdsa",
        feature = "secp256k1",
        feature = "ed25519",
        feature = "rsa"
    ))]
    pub fn derive_secret(&self, domain: &[u8]) -> Option<[u8; 32]> {
        let mut okm = [0u8; 32];
        hkdf::Hkdf::<sha2::Sha256>::new(None, &self.secret()?)
            .expand(domain, &mut okm)
            .expect("okm.len() == 32");

        Some(okm)
    }

    // We build docs with all features so this doesn't need to have any docs.
    #[cfg(not(any(
        feature = "ecdsa",
        feature = "secp256k1",
        feature = "ed25519",
        feature = "rsa"
    )))]
    pub fn derive_secret(&self, _: &[u8]) -> Option<[u8; 32]> {
        None
    }

    /// Return the secret key of the [`Keypair`].
    #[allow(dead_code)]
    pub(crate) fn secret(&self) -> Option<[u8; 32]> {
        match self.keypair {
            #[cfg(feature = "ed25519")]
            KeyPairInner::Ed25519(ref inner) => Some(inner.secret().to_bytes()),
            #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
            KeyPairInner::Rsa(_) => None,
            #[cfg(feature = "secp256k1")]
            KeyPairInner::Secp256k1(ref inner) => Some(inner.secret().to_bytes()),
            #[cfg(feature = "ecdsa")]
            KeyPairInner::Ecdsa(ref inner) => Some(
                inner
                    .secret()
                    .to_bytes()
                    .try_into()
                    .expect("Ecdsa's private key should be 32 bytes"),
            ),
        }
    }
}

#[cfg(feature = "ecdsa")]
impl From<ecdsa::Keypair> for Keypair {
    fn from(kp: ecdsa::Keypair) -> Self {
        Keypair {
            keypair: KeyPairInner::Ecdsa(kp),
        }
    }
}

#[cfg(feature = "ed25519")]
impl From<ed25519::Keypair> for Keypair {
    fn from(kp: ed25519::Keypair) -> Self {
        Keypair {
            keypair: KeyPairInner::Ed25519(kp),
        }
    }
}

#[cfg(feature = "secp256k1")]
impl From<secp256k1::Keypair> for Keypair {
    fn from(kp: secp256k1::Keypair) -> Self {
        Keypair {
            keypair: KeyPairInner::Secp256k1(kp),
        }
    }
}

#[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
impl From<rsa::Keypair> for Keypair {
    fn from(kp: rsa::Keypair) -> Self {
        Keypair {
            keypair: KeyPairInner::Rsa(kp),
        }
    }
}

#[cfg(feature = "ed25519")]
impl TryInto<ed25519::Keypair> for Keypair {
    type Error = OtherVariantError;

    fn try_into(self) -> Result<ed25519::Keypair, Self::Error> {
        match self.keypair {
            KeyPairInner::Ed25519(inner) => Ok(inner),
            #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
            KeyPairInner::Rsa(_) => Err(OtherVariantError::new(crate::KeyType::RSA)),
            #[cfg(feature = "secp256k1")]
            KeyPairInner::Secp256k1(_) => Err(OtherVariantError::new(crate::KeyType::Secp256k1)),
            #[cfg(feature = "ecdsa")]
            KeyPairInner::Ecdsa(_) => Err(OtherVariantError::new(crate::KeyType::Ecdsa)),
        }
    }
}

#[cfg(feature = "ecdsa")]
impl TryInto<ecdsa::Keypair> for Keypair {
    type Error = OtherVariantError;

    fn try_into(self) -> Result<ecdsa::Keypair, Self::Error> {
        match self.keypair {
            KeyPairInner::Ecdsa(inner) => Ok(inner),
            #[cfg(feature = "ed25519")]
            KeyPairInner::Ed25519(_) => Err(OtherVariantError::new(crate::KeyType::Ed25519)),
            #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
            KeyPairInner::Rsa(_) => Err(OtherVariantError::new(crate::KeyType::RSA)),
            #[cfg(feature = "secp256k1")]
            KeyPairInner::Secp256k1(_) => Err(OtherVariantError::new(crate::KeyType::Secp256k1)),
        }
    }
}

#[cfg(feature = "secp256k1")]
impl TryInto<secp256k1::Keypair> for Keypair {
    type Error = OtherVariantError;

    fn try_into(self) -> Result<secp256k1::Keypair, Self::Error> {
        match self.keypair {
            KeyPairInner::Secp256k1(inner) => Ok(inner),
            #[cfg(feature = "ed25519")]
            KeyPairInner::Ed25519(_) => Err(OtherVariantError::new(crate::KeyType::Ed25519)),
            #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
            KeyPairInner::Rsa(_) => Err(OtherVariantError::new(crate::KeyType::RSA)),
            #[cfg(feature = "ecdsa")]
            KeyPairInner::Ecdsa(_) => Err(OtherVariantError::new(crate::KeyType::Ecdsa)),
        }
    }
}

#[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
impl TryInto<rsa::Keypair> for Keypair {
    type Error = OtherVariantError;

    fn try_into(self) -> Result<rsa::Keypair, Self::Error> {
        match self.keypair {
            KeyPairInner::Rsa(inner) => Ok(inner),
            #[cfg(feature = "ed25519")]
            KeyPairInner::Ed25519(_) => Err(OtherVariantError::new(crate::KeyType::Ed25519)),
            #[cfg(feature = "secp256k1")]
            KeyPairInner::Secp256k1(_) => Err(OtherVariantError::new(crate::KeyType::Secp256k1)),
            #[cfg(feature = "ecdsa")]
            KeyPairInner::Ecdsa(_) => Err(OtherVariantError::new(crate::KeyType::Ecdsa)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum PublicKeyInner {
    /// A public Ed25519 key.
    #[cfg(feature = "ed25519")]
    Ed25519(ed25519::PublicKey),
    #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
    /// A public RSA key.
    Rsa(rsa::PublicKey),
    #[cfg(feature = "secp256k1")]
    /// A public Secp256k1 key.
    Secp256k1(secp256k1::PublicKey),
    /// A public ECDSA key.
    #[cfg(feature = "ecdsa")]
    Ecdsa(ecdsa::PublicKey),
}

/// The public key of a node's identity keypair.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey {
    pub(crate) publickey: PublicKeyInner,
}

impl PublicKey {
    /// Verify a signature for a message using this public key, i.e. check
    /// that the signature has been produced by the corresponding
    /// private key (authenticity), and that the message has not been
    /// tampered with (integrity).
    #[must_use]
    #[allow(unused_variables)]
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        match self.publickey {
            #[cfg(feature = "ed25519")]
            PublicKeyInner::Ed25519(ref pk) => pk.verify(msg, sig),
            #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
            PublicKeyInner::Rsa(ref pk) => pk.verify(msg, sig),
            #[cfg(feature = "secp256k1")]
            PublicKeyInner::Secp256k1(ref pk) => pk.verify(msg, sig),
            #[cfg(feature = "ecdsa")]
            PublicKeyInner::Ecdsa(ref pk) => pk.verify(msg, sig),
        }
    }

    #[cfg(feature = "ed25519")]
    pub fn try_into_ed25519(self) -> Result<ed25519::PublicKey, OtherVariantError> {
        self.try_into()
    }

    #[cfg(feature = "secp256k1")]
    pub fn try_into_secp256k1(self) -> Result<secp256k1::PublicKey, OtherVariantError> {
        self.try_into()
    }

    #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
    pub fn try_into_rsa(self) -> Result<rsa::PublicKey, OtherVariantError> {
        self.try_into()
    }

    #[cfg(feature = "ecdsa")]
    pub fn try_into_ecdsa(self) -> Result<ecdsa::PublicKey, OtherVariantError> {
        self.try_into()
    }

    /// Encode the public key into a protobuf structure for storage or
    /// exchange with other nodes.
    pub fn encode_protobuf(&self) -> Vec<u8> {
        #[cfg(any(
            feature = "ecdsa",
            feature = "secp256k1",
            feature = "ed25519",
            feature = "rsa"
        ))]
        {
            use quick_protobuf::MessageWrite;
            let public_key = proto::PublicKey::from(self);

            let mut buf = Vec::with_capacity(public_key.get_size());
            let mut writer = Writer::new(&mut buf);
            public_key
                .write_message(&mut writer)
                .expect("Encoding to succeed");

            buf
        }

        #[cfg(not(any(
            feature = "ecdsa",
            feature = "secp256k1",
            feature = "ed25519",
            feature = "rsa"
        )))]
        unreachable!()
    }

    /// Decode a public key from a protobuf structure, e.g. read from storage
    /// or received from another node.
    #[allow(unused_variables)]
    pub fn try_decode_protobuf(bytes: &[u8]) -> Result<PublicKey, DecodingError> {
        #[cfg(any(
            feature = "ecdsa",
            feature = "secp256k1",
            feature = "ed25519",
            feature = "rsa"
        ))]
        {
            use quick_protobuf::MessageRead;
            let mut reader = BytesReader::from_bytes(bytes);

            let pubkey = proto::PublicKey::from_reader(&mut reader, bytes)
                .map_err(|e| DecodingError::bad_protobuf("public key bytes", e))?;

            pubkey.try_into()
        }

        #[cfg(not(any(
            feature = "ecdsa",
            feature = "secp256k1",
            feature = "ed25519",
            feature = "rsa"
        )))]
        unreachable!()
    }

    /// Convert the `PublicKey` into the corresponding `PeerId`.
    #[cfg(feature = "peerid")]
    pub fn to_peer_id(&self) -> crate::PeerId {
        self.into()
    }

    /// Return a [`KeyType`] of the [`PublicKey`].
    pub fn key_type(&self) -> KeyType {
        match self.publickey {
            #[cfg(feature = "ed25519")]
            PublicKeyInner::Ed25519(_) => KeyType::Ed25519,
            #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
            PublicKeyInner::Rsa(_) => KeyType::RSA,
            #[cfg(feature = "secp256k1")]
            PublicKeyInner::Secp256k1(_) => KeyType::Secp256k1,
            #[cfg(feature = "ecdsa")]
            PublicKeyInner::Ecdsa(_) => KeyType::Ecdsa,
        }
    }
}

#[cfg(any(
    feature = "ecdsa",
    feature = "secp256k1",
    feature = "ed25519",
    feature = "rsa"
))]
impl TryFrom<proto::PublicKey> for PublicKey {
    type Error = DecodingError;

    fn try_from(pubkey: proto::PublicKey) -> Result<Self, Self::Error> {
        match pubkey.Type {
            #[cfg(feature = "ed25519")]
            proto::KeyType::Ed25519 => Ok(ed25519::PublicKey::try_from_bytes(&pubkey.Data).map(
                |kp| PublicKey {
                    publickey: PublicKeyInner::Ed25519(kp),
                },
            )?),
            #[cfg(not(feature = "ed25519"))]
            proto::KeyType::Ed25519 => {
                tracing::debug!("support for ed25519 was disabled at compile-time");
                Err(DecodingError::missing_feature("ed25519"))
            }
            #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
            proto::KeyType::RSA => {
                Ok(
                    rsa::PublicKey::try_decode_x509(&pubkey.Data).map(|kp| PublicKey {
                        publickey: PublicKeyInner::Rsa(kp),
                    })?,
                )
            }
            #[cfg(any(not(feature = "rsa"), target_arch = "wasm32"))]
            proto::KeyType::RSA => {
                tracing::debug!("support for RSA was disabled at compile-time");
                Err(DecodingError::missing_feature("rsa"))
            }
            #[cfg(feature = "secp256k1")]
            proto::KeyType::Secp256k1 => Ok(secp256k1::PublicKey::try_from_bytes(&pubkey.Data)
                .map(|kp| PublicKey {
                    publickey: PublicKeyInner::Secp256k1(kp),
                })?),
            #[cfg(not(feature = "secp256k1"))]
            proto::KeyType::Secp256k1 => {
                tracing::debug!("support for secp256k1 was disabled at compile-time");
                Err(DecodingError::missing_feature("secp256k1"))
            }
            #[cfg(feature = "ecdsa")]
            proto::KeyType::ECDSA => Ok(ecdsa::PublicKey::try_decode_der(&pubkey.Data).map(
                |kp| PublicKey {
                    publickey: PublicKeyInner::Ecdsa(kp),
                },
            )?),
            #[cfg(not(feature = "ecdsa"))]
            proto::KeyType::ECDSA => {
                tracing::debug!("support for ECDSA was disabled at compile-time");
                Err(DecodingError::missing_feature("ecdsa"))
            }
        }
    }
}

#[cfg(feature = "ed25519")]
impl TryInto<ed25519::PublicKey> for PublicKey {
    type Error = OtherVariantError;

    fn try_into(self) -> Result<ed25519::PublicKey, Self::Error> {
        match self.publickey {
            PublicKeyInner::Ed25519(inner) => Ok(inner),
            #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
            PublicKeyInner::Rsa(_) => Err(OtherVariantError::new(crate::KeyType::RSA)),
            #[cfg(feature = "secp256k1")]
            PublicKeyInner::Secp256k1(_) => Err(OtherVariantError::new(crate::KeyType::Secp256k1)),
            #[cfg(feature = "ecdsa")]
            PublicKeyInner::Ecdsa(_) => Err(OtherVariantError::new(crate::KeyType::Ecdsa)),
        }
    }
}

#[cfg(feature = "ecdsa")]
impl TryInto<ecdsa::PublicKey> for PublicKey {
    type Error = OtherVariantError;

    fn try_into(self) -> Result<ecdsa::PublicKey, Self::Error> {
        match self.publickey {
            PublicKeyInner::Ecdsa(inner) => Ok(inner),
            #[cfg(feature = "ed25519")]
            PublicKeyInner::Ed25519(_) => Err(OtherVariantError::new(crate::KeyType::Ed25519)),
            #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
            PublicKeyInner::Rsa(_) => Err(OtherVariantError::new(crate::KeyType::RSA)),
            #[cfg(feature = "secp256k1")]
            PublicKeyInner::Secp256k1(_) => Err(OtherVariantError::new(crate::KeyType::Secp256k1)),
        }
    }
}

#[cfg(feature = "secp256k1")]
impl TryInto<secp256k1::PublicKey> for PublicKey {
    type Error = OtherVariantError;

    fn try_into(self) -> Result<secp256k1::PublicKey, Self::Error> {
        match self.publickey {
            PublicKeyInner::Secp256k1(inner) => Ok(inner),
            #[cfg(feature = "ed25519")]
            PublicKeyInner::Ed25519(_) => Err(OtherVariantError::new(crate::KeyType::Ed25519)),
            #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
            PublicKeyInner::Rsa(_) => Err(OtherVariantError::new(crate::KeyType::RSA)),
            #[cfg(feature = "ecdsa")]
            PublicKeyInner::Ecdsa(_) => Err(OtherVariantError::new(crate::KeyType::Ecdsa)),
        }
    }
}

#[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
impl TryInto<rsa::PublicKey> for PublicKey {
    type Error = OtherVariantError;

    fn try_into(self) -> Result<rsa::PublicKey, Self::Error> {
        match self.publickey {
            PublicKeyInner::Rsa(inner) => Ok(inner),
            #[cfg(feature = "ed25519")]
            PublicKeyInner::Ed25519(_) => Err(OtherVariantError::new(crate::KeyType::Ed25519)),
            #[cfg(feature = "secp256k1")]
            PublicKeyInner::Secp256k1(_) => Err(OtherVariantError::new(crate::KeyType::Secp256k1)),
            #[cfg(feature = "ecdsa")]
            PublicKeyInner::Ecdsa(_) => Err(OtherVariantError::new(crate::KeyType::Ecdsa)),
        }
    }
}

#[cfg(feature = "ed25519")]
impl From<ed25519::PublicKey> for PublicKey {
    fn from(key: ed25519::PublicKey) -> Self {
        PublicKey {
            publickey: PublicKeyInner::Ed25519(key),
        }
    }
}

#[cfg(feature = "secp256k1")]
impl From<secp256k1::PublicKey> for PublicKey {
    fn from(key: secp256k1::PublicKey) -> Self {
        PublicKey {
            publickey: PublicKeyInner::Secp256k1(key),
        }
    }
}

#[cfg(feature = "ecdsa")]
impl From<ecdsa::PublicKey> for PublicKey {
    fn from(key: ecdsa::PublicKey) -> Self {
        PublicKey {
            publickey: PublicKeyInner::Ecdsa(key),
        }
    }
}

#[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
impl From<rsa::PublicKey> for PublicKey {
    fn from(key: rsa::PublicKey) -> Self {
        PublicKey {
            publickey: PublicKeyInner::Rsa(key),
        }
    }
}
