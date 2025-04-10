use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
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

    pub fn generate_shared_key(&self) -> String {
        let key = Aes256Gcm::generate_key(OsRng);
        general_purpose::STANDARD.encode(key)
    }

    pub fn encrypt_string(&self, plaintext: &str, base64_key: &str) -> Result<String, EncryptionError> {
        if plaintext.is_empty() {
            return Ok(String::new());
        }

        // Decode key from Base64
        let key_bytes = general_purpose::STANDARD
            .decode(base64_key)
            .map_err(|e| EncryptionError::InvalidKey(e.to_string()))?;

        if key_bytes.len() != KEY_SIZE_BYTES {
            return Err(EncryptionError::InvalidKey(format!(
                "Key must be {} bytes, but was {} bytes",
                KEY_SIZE_BYTES,
                key_bytes.len()
            )));
        }

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        // Generate a random nonce
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let nonce_bytes = nonce.as_slice();

        let plaintext_bytes = plaintext.as_bytes();
        let ciphertext = cipher
            .encrypt(&nonce, plaintext_bytes)
            .map_err(|e| EncryptionError::Encryption(e.to_string()))?;

        // Combine nonce and ciphertext and encode as Base64
        let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        result.extend_from_slice(nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(general_purpose::STANDARD.encode(result))
    }

    pub fn decrypt_string(&self, base64_ciphertext: &str, base64_key: &str) -> Result<String, EncryptionError> {
        if base64_ciphertext.is_empty() {
            return Ok(String::new());
        }

        // Decode key from Base64
        let key_bytes = general_purpose::STANDARD
            .decode(base64_key)
            .map_err(|e| EncryptionError::InvalidKey(e.to_string()))?;

        if key_bytes.len() != KEY_SIZE_BYTES {
            return Err(EncryptionError::InvalidKey(format!(
                "Key must be {} bytes, but was {} bytes",
                KEY_SIZE_BYTES,
                key_bytes.len()
            )));
        }

        // Decode ciphertext from Base64
        let combined = general_purpose::STANDARD
            .decode(base64_ciphertext)
            .map_err(|e| EncryptionError::Decryption(e.to_string()))?;

        if combined.len() <= 12 {
            return Err(EncryptionError::Decryption(
                "Ciphertext too short".to_string(),
            ));
        }

        // Split nonce and ciphertext
        let nonce_bytes = &combined[..12]; // AES-GCM nonce is 12 bytes
        let ciphertext = &combined[12..];

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| EncryptionError::Decryption(e.to_string()))?;

        String::from_utf8(plaintext).map_err(|e| EncryptionError::Decryption(e.to_string()))
    }

    pub fn encrypt_binary(&self, data: &[u8], base64_key: &str) -> Result<String, EncryptionError> {
        let base64_data = general_purpose::STANDARD.encode(data);
        self.encrypt_string(&base64_data, base64_key)
    }

    pub fn decrypt_binary(&self, base64_ciphertext: &str, base64_key: &str) -> Result<Vec<u8>, EncryptionError> {
        let base64_data = self.decrypt_string(base64_ciphertext, base64_key)?;
        general_purpose::STANDARD
            .decode(base64_data)
            .map_err(|e| EncryptionError::Decryption(e.to_string()))
    }
}