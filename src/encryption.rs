use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use thiserror::Error;

pub const KEY_SIZE_BYTES: usize = 32; // 256 bits

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
}

pub struct EncryptionService {}

impl EncryptionService {
    pub fn new() -> Self {
        Self {}
    }

    /// Generate a new random encryption key
    pub fn generate_key() -> Result<Vec<u8>, EncryptionError> {
        let key = Aes256Gcm::generate_key(OsRng);
        Ok(key.to_vec())
    }

    /// Encrypt data with the given key
    pub fn encrypt(&self, data: &[u8], key_bytes: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        // Validate key
        if key_bytes.len() != KEY_SIZE_BYTES {
            return Err(EncryptionError::InvalidKey(format!(
                "Key must be {} bytes, but was {} bytes",
                KEY_SIZE_BYTES,
                key_bytes.len()
            )));
        }

        // Create cipher
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);

        // Generate a random nonce
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let nonce_bytes = nonce.as_slice();

        // Encrypt the data
        let ciphertext = cipher
            .encrypt(&nonce, data)
            .map_err(|e| EncryptionError::Encryption(e.to_string()))?;

        // Combine nonce and ciphertext
        let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        result.extend_from_slice(nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data 
    pub fn decrypt(&self, encrypted_data: &[u8], key_bytes: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if encrypted_data.is_empty() {
            return Ok(Vec::new());
        }

        // Validate key
        if key_bytes.len() != KEY_SIZE_BYTES {
            return Err(EncryptionError::InvalidKey(format!(
                "Key must be {} bytes, but was {} bytes",
                KEY_SIZE_BYTES,
                key_bytes.len()
            )));
        }

        // Validate encrypted data length
        if encrypted_data.len() <= 12 {
            return Err(EncryptionError::Decryption(
                "Encrypted data too short".to_string(),
            ));
        }

        // Split nonce and ciphertext
        let nonce_bytes = &encrypted_data[..12];
        let ciphertext = &encrypted_data[12..];

        // Create cipher
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt data
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| EncryptionError::Decryption(e.to_string()))?;

        Ok(plaintext)
    }
}