pub mod block;
pub mod blockchain;
pub mod p2p;
pub mod script;
pub mod transaction;
pub mod wallet;

/// A wrapper around blake3::Hash that implements Serialize and Deserialize
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Blake3Hash(pub blake3::Hash);

impl Blake3Hash {
    pub fn new(hash: blake3::Hash) -> Self {
        Blake3Hash(hash)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn into_inner(self) -> blake3::Hash {
        self.0
    }
}

impl From<blake3::Hash> for Blake3Hash {
    fn from(hash: blake3::Hash) -> Self {
        Blake3Hash(hash)
    }
}

impl From<Blake3Hash> for blake3::Hash {
    fn from(hash: Blake3Hash) -> Self {
        hash.0
    }
}

impl serde::Serialize for Blake3Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for Blake3Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Blake3HashVisitor;

        impl<'de> serde::de::Visitor<'de> for Blake3HashVisitor {
            type Value = Blake3Hash;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a byte array of length 32")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() == 32 {
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(v);
                    Ok(Blake3Hash(blake3::Hash::from_bytes(bytes)))
                } else {
                    Err(serde::de::Error::invalid_length(v.len(), &self))
                }
            }
        }

        deserializer.deserialize_bytes(Blake3HashVisitor)
    }
}
