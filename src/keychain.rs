use crate::encryption::{EncryptionService, EncryptionError};
use std::collections::HashMap;

/// KeyChain maintains a collection of encryption keys by ID
pub struct KeyChain {
    current_key_id: u32,
    pub keys: HashMap<u32, Vec<u8>>,
}

impl KeyChain {
    /// Create a new keychain
    pub fn new() -> Self {
        let mut keychain = KeyChain {
            current_key_id: 0,
            keys: HashMap::new(),
        };
        let _ = keychain.add_rotation_key();
        keychain
    }

    /// Add a new key and make it the current key
    pub fn add_rotation_key(&mut self) -> Result<u32, EncryptionError> {
        let key = EncryptionService::generate_key()?;
        
        self.current_key_id += 1;
        
        self.keys.insert(self.current_key_id, key);
        
        Ok(self.current_key_id)
    }
}