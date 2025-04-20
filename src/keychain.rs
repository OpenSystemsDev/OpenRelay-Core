use crate::encryption::{EncryptionService, EncryptionError};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::sync::Arc;

const MAX_KEY_AGE_DAYS: u64 = 7;  // Rotate keys every 7 days
const MAX_OFFLINE_DAYS: u64 = 14;  // Require re-authentication after 14 days of a device being offline

pub struct KeyEntry {
    pub key: Vec<u8>,
    pub generated_time: u64,
    pub expiry_time: u64,
}

pub struct KeyChain {
    current_key_id: u32,
    pub keys: HashMap<u32, KeyEntry>,
    encryption_service: Arc<EncryptionService>,
}

pub struct KeyUpdatePackage {
    pub keys: HashMap<u32, KeyEntry>,
    pub current_key_id: u32,
}

impl KeyChain {
    pub fn new(encryption_service: Arc<EncryptionService>) -> Self {
        let mut keychain = KeyChain {
            current_key_id: 0,
            keys: HashMap::new(),
            encryption_service,
        };
        let _ = keychain.add_rotation_key();
        keychain
    }

    pub fn get_current_key_id(&self) -> u32 {
        self.current_key_id
    }

    pub fn set_current_key_id(&mut self, key_id: u32) {
        self.current_key_id = key_id;
    }

    pub fn get_current_key(&self) -> Option<&Vec<u8>> {
        self.keys.get(&self.current_key_id).map(|entry| &entry.key)
    }

    pub fn get_key(&self, key_id: u32) -> Option<&Vec<u8>> {
        self.keys.get(&key_id).map(|entry| &entry.key)
    }

    pub fn add_rotation_key(&mut self) -> Result<u32, EncryptionError> {
        let key = EncryptionService::generate_key()?;
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
            
        let expiry = now + (MAX_KEY_AGE_DAYS * 24 * 60 * 60);
        
        self.current_key_id += 1;
        
        self.keys.insert(self.current_key_id, KeyEntry {
            key,
            generated_time: now,
            expiry_time: expiry,
        });
        
        self.prune_old_keys();
        
        Ok(self.current_key_id)
    }

    fn prune_old_keys(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
            
        let cutoff = now - (MAX_OFFLINE_DAYS * 24 * 60 * 60);
        
        self.keys.retain(|key_id, entry| {
            *key_id == self.current_key_id || entry.generated_time >= cutoff
        });
    }

    pub fn get_key_update_package(&self, last_known_id: u32) -> Option<KeyUpdatePackage> {
        if last_known_id < self.current_key_id.saturating_sub(4) {
            return None; // Too old. Need to authenticate gain
        }
        
        let mut update_keys = HashMap::new();
        for (&id, entry) in &self.keys {
            if id > last_known_id {
                update_keys.insert(id, KeyEntry {
                    key: entry.key.clone(),
                    generated_time: entry.generated_time,
                    expiry_time: entry.expiry_time,
                });
            }
        }
        
        // Always include the current key
        if let Some(current_entry) = self.keys.get(&self.current_key_id) {
            update_keys.insert(self.current_key_id, KeyEntry {
                key: current_entry.key.clone(),
                generated_time: current_entry.generated_time,
                expiry_time: current_entry.expiry_time,
            });
        }
        
        Some(KeyUpdatePackage {
            keys: update_keys,
            current_key_id: self.current_key_id,
        })
    }

    pub fn is_key_expired(&self, key_id: u32) -> bool {
        if let Some(entry) = self.keys.get(&key_id) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs();
                
            entry.expiry_time < now
        } else {
            true // Key not found, consider it expired
        }
    }

    pub fn should_rotate_current_key(&self) -> bool {
        if let Some(entry) = self.keys.get(&self.current_key_id) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs();
            
            // If key is older than MAX_KEY_AGE_DAYS indicating its expired
            (now - entry.generated_time) >= (MAX_KEY_AGE_DAYS * 24 * 60 * 60)
        } else {
            true // No key currently, it should generate a new one
        }
    }
}