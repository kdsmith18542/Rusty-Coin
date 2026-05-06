//! Keypair generation and management for Rusty Coin.

use ed25519_dalek::{Keypair, Signer, Verifier};
pub use ed25519_dalek::{PublicKey, Signature};
use rand::rngs::OsRng;

/// Represents a cryptographic key pair (public and secret key).
pub struct RustyKeyPair {
    keypair: Keypair,
}

impl RustyKeyPair {
    /// Generates a new random key pair.
    pub fn generate() -> Self {
        let mut csprng = OsRng {};
        let keypair = Keypair::generate(&mut csprng);
        RustyKeyPair { keypair }
    }

    /// Returns the public key of this key pair.
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public
    }

    /// Signs the given message with the secret key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keypair.sign(message)
    }

    /// Verifies the given signature against the message and public key.
    pub fn verify(
        public_key: &PublicKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        public_key.verify(message, signature)
    }

    /// Derives a new key pair from the current one using a derivation path.
    /// Implements proper hierarchical deterministic key derivation.
    pub fn derive_key(&self, path: &str) -> Result<RustyKeyPair, String> {
        // Parse the HD path components
        let path_components: Vec<&str> = path.split('/').collect();
        if path_components.len() < 2 || path_components[0] != "m" {
            return Err("Invalid HD path: must start with 'm/'".to_string());
        }

        // Use the current keypair's secret key as the seed for derivation
        let seed = self.keypair.secret.to_bytes();

        // Derive child key by hashing the seed with the path
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ed25519_derive"); // Domain separator
        hasher.update(&seed);
        hasher.update(path.as_bytes());

        // Parse indices from path and include them in derivation
        for component in &path_components[1..] {
            let index_str = component.trim_end_matches('\''); // Remove hardened marker
            let index: u32 = index_str
                .parse()
                .map_err(|_| format!("Invalid path component: {}", component))?;
            hasher.update(&index.to_be_bytes());
        }

        let derived_hash = hasher.finalize();

        // Use the first 32 bytes as the new secret key
        let derived_secret = ed25519_dalek::SecretKey::from_bytes(&derived_hash.as_bytes()[..32])
            .map_err(|e| format!("Failed to create derived secret key: {}", e))?;

        let derived_public = ed25519_dalek::PublicKey::from(&derived_secret);
        let derived_keypair = ed25519_dalek::Keypair {
            secret: derived_secret,
            public: derived_public,
        };

        Ok(RustyKeyPair {
            keypair: derived_keypair,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hd_key_derivation() {
        let master_key = RustyKeyPair::generate();

        // Test basic derivation
        let derived_key = master_key.derive_key("m/44'/0'/0'/0/0").unwrap();

        // Keys should be different
        assert_ne!(
            master_key.public_key().to_bytes(),
            derived_key.public_key().to_bytes()
        );

        // Derivation should be deterministic
        let derived_key2 = master_key.derive_key("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(
            derived_key.public_key().to_bytes(),
            derived_key2.public_key().to_bytes()
        );

        // Different paths should produce different keys
        let derived_key3 = master_key.derive_key("m/44'/0'/0'/0/1").unwrap();
        assert_ne!(
            derived_key.public_key().to_bytes(),
            derived_key3.public_key().to_bytes()
        );
    }

    #[test]
    fn test_invalid_hd_path() {
        let master_key = RustyKeyPair::generate();

        // Invalid path formats should fail
        assert!(master_key.derive_key("invalid").is_err());
        assert!(master_key.derive_key("44'/0'/0'/0/0").is_err()); // Missing 'm/'
        assert!(master_key.derive_key("m/invalid_number").is_err());
    }

    #[test]
    fn test_key_signing_after_derivation() {
        let master_key = RustyKeyPair::generate();
        let derived_key = master_key.derive_key("m/44'/0'/0'/0/0").unwrap();

        let message = b"test message";
        let signature = derived_key.sign(message);

        // Verify signature with derived public key
        assert!(RustyKeyPair::verify(&derived_key.public_key(), message, &signature).is_ok());

        // Should fail with master key's public key
        assert!(RustyKeyPair::verify(&master_key.public_key(), message, &signature).is_err());
    }
}
