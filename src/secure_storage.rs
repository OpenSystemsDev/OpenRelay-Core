use crate::encryption::{EncryptionService, EncryptionError};
use std::sync::Arc;

pub struct SecureStorage {
    encryption_service: Arc<EncryptionService>,
    master_key: Vec<u8>,
}

// Implement Clone for SecureStorage to fix the move issue
impl Clone for SecureStorage {
    fn clone(&self) -> Self {
        Self {
            encryption_service: self.encryption_service.clone(),
            master_key: self.master_key.clone(),
        }
    }
}

impl SecureStorage {
    pub fn new(encryption_service: Arc<EncryptionService>, master_key: Vec<u8>) -> Self {
        Self {
            encryption_service,
            master_key,
        }
    }

    pub fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        self.encryption_service.encrypt(data, &self.master_key)
    }

    pub fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        self.encryption_service.decrypt(encrypted_data, &self.master_key)
    }
}

pub struct DeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub shared_key: Vec<u8>,
    pub last_seen: u64,
}

pub struct SecureDeviceStorage {
    secure_storage: SecureStorage,
}

impl SecureDeviceStorage {
    pub fn new(secure_storage: SecureStorage) -> Self {
        Self {
            secure_storage,
        }
    }

    pub fn encrypt_device_info(&self, device: &DeviceInfo) -> Result<Vec<u8>, EncryptionError> {
        // In a real implementation, serialize the device info properly
        // For simplicity, we just concatenate the fields
        let mut data = Vec::new();

        // Add device ID
        data.extend_from_slice(device.device_id.as_bytes());
        data.push(0); // Null terminator

        // Add device name
        data.extend_from_slice(device.device_name.as_bytes());
        data.push(0); // Null terminator

        // Add shared key
        data.extend_from_slice(&device.shared_key);

        // Add last seen
        data.extend_from_slice(&device.last_seen.to_le_bytes());

        // Encrypt the data
        self.secure_storage.encrypt_data(&data)
    }

    pub fn decrypt_device_info(&self, encrypted_data: &[u8]) -> Result<DeviceInfo, EncryptionError> {
        // Decrypt the data
        let data = self.secure_storage.decrypt_data(encrypted_data)?;

        // Parse the device info
        let mut parts = data.split(|&b| b == 0);

        let device_id_bytes = parts.next().ok_or_else(||
            EncryptionError::Decryption("Invalid device info format".to_string()))?;
        let device_id = String::from_utf8_lossy(device_id_bytes).to_string();

        let device_name_bytes = parts.next().ok_or_else(||
            EncryptionError::Decryption("Invalid device info format".to_string()))?;
        let device_name = String::from_utf8_lossy(device_name_bytes).to_string();

        let remaining = parts.next().ok_or_else(||
            EncryptionError::Decryption("Invalid device info format".to_string()))?;

        if remaining.len() < 8 {
            return Err(EncryptionError::Decryption("Invalid device info format".to_string()));
        }

        let shared_key = remaining[..remaining.len() - 8].to_vec();

        let mut last_seen_bytes = [0u8; 8];
        last_seen_bytes.copy_from_slice(&remaining[remaining.len() - 8..]);
        let last_seen = u64::from_le_bytes(last_seen_bytes);

        Ok(DeviceInfo {
            device_id,
            device_name,
            shared_key,
            last_seen,
        })
    }
}