use crate::encryption::EncryptionService;
use crate::keychain::KeyChain;
use crate::secure_storage::{SecureStorage, SecureDeviceStorage, DeviceInfo};
use std::slice;
use std::sync::{Arc, RwLock};
use std::ptr;

static mut ENCRYPTION_SERVICE: Option<Arc<EncryptionService>> = None;
static mut KEYCHAIN: Option<Arc<RwLock<KeyChain>>> = None;
static mut SECURE_STORAGE: Option<Arc<SecureStorage>>   = None;
static mut DEVICE_STORAGE: Option<Arc<SecureDeviceStorage>> = None;

/// Initialize the encryption service
#[unsafe(no_mangle)]
pub extern "C" fn encryption_init() -> i32 {
    unsafe {
        let service = Arc::new(EncryptionService::new());
        ENCRYPTION_SERVICE = Some(service.clone());

        let keychain = KeyChain::new();
        KEYCHAIN = Some(Arc::new(RwLock::new(keychain)));

        // Initialize master key for secure storage
        let encryption_service_ptr = &raw const ENCRYPTION_SERVICE;
        if let Some(service_ref) = ptr::read(encryption_service_ptr) {
            match EncryptionService::generate_key() {
                Ok(master_key) => {
                    let storage = SecureStorage::new(service_ref.clone(), master_key);
                    SECURE_STORAGE = Some(Arc::new(storage.clone()));
                    
                    let device_storage = SecureDeviceStorage::new(storage);
                    DEVICE_STORAGE = Some(Arc::new(device_storage));
                }
                Err(_) => return 1,
            }
        }
    }
    0
}

/// Generate a new encryption key
#[unsafe(no_mangle)]
pub extern "C" fn encryption_generate_key(key_size: *mut usize) -> *mut u8 {
    if key_size.is_null() {
        return std::ptr::null_mut();
    }

    // Generate a new key
    let key_result = EncryptionService::generate_key();

    match key_result {
        Ok(key) => {
            // Copy the key to a new buffer
            let key_len = key.len();
            let mut key_buffer = Vec::with_capacity(key_len);
            key_buffer.extend_from_slice(&key);

            // Set the key size
            unsafe {
                *key_size = key_len;
            }

            // Transfer ownership to caller
            let ptr = key_buffer.as_mut_ptr();
            std::mem::forget(key_buffer);
            ptr
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Encrypt data with the given key
#[unsafe(no_mangle)]
pub extern "C" fn encryption_encrypt(
    data: *const u8,
    data_size: usize,
    key: *const u8,
    key_size: usize,
    encrypted_size: *mut usize,
) -> *mut u8 {
    // Ensure params are valid
    if data.is_null() || key.is_null() || encrypted_size.is_null() {
        return std::ptr::null_mut();
    }

    // Create slices from the input pointers
    let data_slice = unsafe { slice::from_raw_parts(data, data_size) };
    let key_slice = unsafe { slice::from_raw_parts(key, key_size) };

    // Get the encryption service
    let service = unsafe {
        let encryption_service_ptr = &raw const ENCRYPTION_SERVICE;
        if let Some(service) = ptr::read(encryption_service_ptr) {
            service
        } else {
            return std::ptr::null_mut();
        }
    };

    // Encrypt the data
    match service.encrypt(data_slice, key_slice) {
        Ok(encrypted) => {
            let encrypted_len = encrypted.len();
            let mut encrypted_buffer = Vec::with_capacity(encrypted_len);
            encrypted_buffer.extend_from_slice(&encrypted);

            unsafe {
                *encrypted_size = encrypted_len;
            }

            // Transfer ownership to caller
            let ptr = encrypted_buffer.as_mut_ptr();
            std::mem::forget(encrypted_buffer);
            ptr
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Decrypt data with the given key
#[unsafe(no_mangle)]
pub extern "C" fn encryption_decrypt(
    encrypted_data: *const u8,
    encrypted_size: usize,
    key: *const u8,
    key_size: usize,
    decrypted_size: *mut usize,
) -> *mut u8 {
    // Ensure params are valid
    if encrypted_data.is_null() || key.is_null() || decrypted_size.is_null() {
        return std::ptr::null_mut();
    }

    // Create slices from the input pointers
    let encrypted_slice = unsafe { slice::from_raw_parts(encrypted_data, encrypted_size) };
    let key_slice = unsafe { slice::from_raw_parts(key, key_size) };

    // Get the encryption service
    let service = unsafe {
        let encryption_service_ptr = &raw const ENCRYPTION_SERVICE;
        if let Some(service) = ptr::read(encryption_service_ptr) {
            service
        } else {
            return std::ptr::null_mut();
        }
    };

    // Decrypt the data
    match service.decrypt(encrypted_slice, key_slice) {
        Ok(decrypted) => {
            let decrypted_len = decrypted.len();
            let mut decrypted_buffer = Vec::with_capacity(decrypted_len);
            decrypted_buffer.extend_from_slice(&decrypted);

            unsafe {
                *decrypted_size = decrypted_len;
            }

            // Transfer ownership to caller
            let ptr = decrypted_buffer.as_mut_ptr();
            std::mem::forget(decrypted_buffer);
            ptr
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a buffer allocated by the encryption functions
#[unsafe(no_mangle)]
pub extern "C" fn encryption_free_buffer(buffer: *mut u8, buffer_size: usize) {
    if !buffer.is_null() && buffer_size > 0 {
        unsafe {
            Vec::from_raw_parts(buffer, buffer_size, buffer_size);
            // Buffer is freed when it goes out of scope
        }
    }
}

/// Cleanup and free all resources
#[unsafe(no_mangle)]
pub extern "C" fn encryption_cleanup() {
    unsafe {
        ENCRYPTION_SERVICE = None;
        KEYCHAIN = None;
        SECURE_STORAGE = None;
        DEVICE_STORAGE = None;
    }
}

/// Securely store device info
#[unsafe(no_mangle)]
pub extern "C" fn securely_store_device_info(
    device_id: *const u8,
    device_id_len: usize,
    device_name: *const u8,
    device_name_len: usize,
    shared_key: *const u8,
    shared_key_len: usize,
    last_seen: u64,
    output_buffer: *mut *mut u8,
    output_size: *mut usize
) -> bool {
    if device_id.is_null() || device_name.is_null() || shared_key.is_null() ||
       output_buffer.is_null() || output_size.is_null() {
        return false;
    }

    unsafe {
        // Create slices from the input pointers
        let device_id_slice = std::slice::from_raw_parts(device_id, device_id_len);
        let device_name_slice = std::slice::from_raw_parts(device_name, device_name_len);
        let shared_key_slice = std::slice::from_raw_parts(shared_key, shared_key_len);

        let device_id_str = match std::str::from_utf8(device_id_slice) {
            Ok(s) => s.to_string(),
            Err(_) => return false,
        };

        let device_name_str = match std::str::from_utf8(device_name_slice) {
            Ok(s) => s.to_string(),
            Err(_) => return false,
        };

        let device_info = DeviceInfo {
            device_id: device_id_str,
            device_name: device_name_str,
            shared_key: shared_key_slice.to_vec(),
            last_seen,
        };

        // Encrypt the device info
        let device_storage_ptr = &raw const DEVICE_STORAGE;
        if let Some(device_storage) = ptr::read(device_storage_ptr) {
            match device_storage.encrypt_device_info(&device_info) {
                Ok(encrypted) => {
                    // Set output
                    *output_size = encrypted.len();
                    let mut output = Vec::with_capacity(encrypted.len());
                    output.extend_from_slice(&encrypted);
                    let ptr = output.as_mut_ptr();
                    *output_buffer = ptr;
                    std::mem::forget(output);

                    return true;
                }
                Err(_) => return false,
            }
        }

        false
    }
}

/// Securely retrieve device info
#[unsafe(no_mangle)]
pub extern "C" fn securely_retrieve_device_info(
    encrypted_data: *const u8,
    encrypted_data_len: usize,
    device_id: *mut *mut u8,
    device_id_size: *mut usize,
    device_name: *mut *mut u8,
    device_name_size: *mut usize,
    shared_key: *mut *mut u8,
    shared_key_size: *mut usize,
    last_seen: *mut u64
) -> bool {
    if encrypted_data.is_null() || device_id.is_null() || device_name.is_null() ||
       shared_key.is_null() || last_seen.is_null() || device_id_size.is_null() ||
       device_name_size.is_null() || shared_key_size.is_null() {
        return false;
    }

    unsafe {
        // Create slice from the input pointer
        let encrypted_slice = std::slice::from_raw_parts(encrypted_data, encrypted_data_len);

        // Decrypt the device info
        let device_storage_ptr = &raw const DEVICE_STORAGE;
        if let Some(device_storage) = ptr::read(device_storage_ptr) {
            match device_storage.decrypt_device_info(encrypted_slice) {
                Ok(device_info) => {
                    // Set device ID
                    let id_bytes = device_info.device_id.as_bytes();
                    let mut id_output = Vec::with_capacity(id_bytes.len());
                    id_output.extend_from_slice(id_bytes);
                    *device_id_size = id_output.len();
                    let id_ptr = id_output.as_mut_ptr();
                    *device_id = id_ptr;
                    std::mem::forget(id_output);

                    // Set device name
                    let name_bytes = device_info.device_name.as_bytes();
                    let mut name_output = Vec::with_capacity(name_bytes.len());
                    name_output.extend_from_slice(name_bytes);
                    *device_name_size = name_output.len();
                    let name_ptr = name_output.as_mut_ptr();
                    *device_name = name_ptr;
                    std::mem::forget(name_output);

                    // Set shared key
                    let mut key_output = Vec::with_capacity(device_info.shared_key.len());
                    key_output.extend_from_slice(&device_info.shared_key);
                    *shared_key_size = key_output.len();
                    let key_ptr = key_output.as_mut_ptr();
                    *shared_key = key_ptr;
                    std::mem::forget(key_output);

                    // Set last seen
                    *last_seen = device_info.last_seen;

                    return true;
                }
                Err(_) => return false,
            }
        }

        false
    }
}