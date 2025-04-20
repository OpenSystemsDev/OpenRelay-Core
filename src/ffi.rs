use crate::encryption::EncryptionService;
use crate::keychain::{KeyChain, KeyEntry};
use crate::secure_storage::{SecureStorage, SecureDeviceStorage, DeviceInfo};
use std::slice;
use std::sync::{Arc, RwLock};
use std::ptr;

static mut ENCRYPTION_SERVICE: Option<Arc<EncryptionService>> = None;
static mut KEYCHAIN: Option<Arc<RwLock<KeyChain>>> = None;
static mut SECURE_STORAGE: Option<Arc<SecureStorage>> = None;
static mut DEVICE_STORAGE: Option<Arc<SecureDeviceStorage>> = None;

/// Initialize the encryption service
#[unsafe(no_mangle)]
pub extern "C" fn encryption_init() -> i32 {
    unsafe {
        let service = Arc::new(EncryptionService::new());
        ENCRYPTION_SERVICE = Some(service.clone());

        let keychain = KeyChain::new(service.clone());
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

/// Get the current key ID
#[unsafe(no_mangle)]
pub extern "C" fn get_current_key_id() -> u32 {
    unsafe {
        let keychain_ptr = &raw const KEYCHAIN;
        if let Some(keychain) = ptr::read(keychain_ptr) {
            if let Ok(keychain_read) = keychain.read() {
                return keychain_read.get_current_key_id();
            }
        }
        0
    }
}

/// Check if the current key should be rotated
#[unsafe(no_mangle)]
pub extern "C" fn should_rotate_key() -> bool {
    unsafe {
        let keychain_ptr = &raw const KEYCHAIN;
        if let Some(keychain) = ptr::read(keychain_ptr) {
            if let Ok(keychain_read) = keychain.read() {
                return keychain_read.should_rotate_current_key();
            }
        }
        false
    }
}

/// Create a new rotation key
#[unsafe(no_mangle)]
pub extern "C" fn create_rotation_key() -> u32 {
    unsafe {
        let keychain_ptr = &raw const KEYCHAIN;
        if let Some(keychain) = ptr::read(keychain_ptr) {
            if let Ok(mut keychain_write) = keychain.write() {
                if let Ok(key_id) = keychain_write.add_rotation_key() {
                    return key_id;
                }
            }
        }
        0
    }
}

/// Check if a key is expired
#[unsafe(no_mangle)]
pub extern "C" fn is_key_expired(key_id: u32) -> bool {
    unsafe {
        let keychain_ptr = &raw const KEYCHAIN;
        if let Some(keychain) = ptr::read(keychain_ptr) {
            if let Ok(keychain_read) = keychain.read() {
                return keychain_read.is_key_expired(key_id);
            }
        }
        true
    }
}

/// Get a key update package
#[unsafe(no_mangle)]
pub extern "C" fn get_key_update_package(
    last_known_id: u32,
    output_buffer: *mut *mut u8,
    output_size: *mut usize
) -> bool {
    if output_buffer.is_null() || output_size.is_null() {
        return false;
    }

    unsafe {
        let keychain_ptr = &raw const KEYCHAIN;
        if let Some(keychain) = ptr::read(keychain_ptr) {
            if let Ok(keychain_read) = keychain.read() {
                if let Some(package) = keychain_read.get_key_update_package(last_known_id) {
                    let mut data = Vec::new();

                    data.extend_from_slice(&package.current_key_id.to_le_bytes());

                    let num_keys = package.keys.len() as u32;
                    data.extend_from_slice(&num_keys.to_le_bytes());

                    // Add each key
                    for (&id, entry) in &package.keys {
                        data.extend_from_slice(&id.to_le_bytes());
                        data.extend_from_slice(&entry.generated_time.to_le_bytes());
                        data.extend_from_slice(&entry.expiry_time.to_le_bytes());

                        let key_len = entry.key.len() as u32;
                        data.extend_from_slice(&key_len.to_le_bytes());
                        data.extend_from_slice(&entry.key);
                    }

                    *output_size = data.len();
                    let ptr = data.as_mut_ptr();
                    *output_buffer = ptr;
                    std::mem::forget(data);

                    return true;
                }
            }
        }
        false
    }
}

/// Import a key update package
#[unsafe(no_mangle)]
pub extern "C" fn import_key_update_package(
    data: *const u8,
    data_len: usize
) -> u32 {
    if data.is_null() || data_len == 0 {
        return 0;
    }

    unsafe {
        let data_slice = std::slice::from_raw_parts(data, data_len);

        if data_len < 8 {
            return 0;
        }

        let mut pos = 0;

        // Key ID
        let mut id_bytes = [0u8; 4];
        id_bytes.copy_from_slice(&data_slice[pos..pos+4]);
        let current_key_id = u32::from_le_bytes(id_bytes);
        pos += 4;

        // Number of keys
        let mut num_keys_bytes = [0u8; 4];
        num_keys_bytes.copy_from_slice(&data_slice[pos..pos+4]);
        let num_keys = u32::from_le_bytes(num_keys_bytes);
        pos += 4;

        let keychain_ptr = &raw const KEYCHAIN;
        if let Some(keychain) = ptr::read(keychain_ptr) {
            if let Ok(mut keychain_write) = keychain.write() {
                for _ in 0..num_keys {
                    if pos + 20 > data_len { // 4 bytes ID + 8 bytes gen time + 8 bytes expiry time = 20
                        break; // Prevent reading past the end
                    }

                    // Read key ID
                    let mut id_bytes = [0u8; 4];
                    id_bytes.copy_from_slice(&data_slice[pos..pos+4]);
                    let key_id = u32::from_le_bytes(id_bytes);
                    pos += 4;

                    // Read generated time
                    let mut gen_bytes = [0u8; 8];
                    gen_bytes.copy_from_slice(&data_slice[pos..pos+8]);
                    let generated_time = u64::from_le_bytes(gen_bytes);
                    pos += 8;

                    // Read expiry time
                    let mut exp_bytes = [0u8; 8];
                    exp_bytes.copy_from_slice(&data_slice[pos..pos+8]);
                    let expiry_time = u64::from_le_bytes(exp_bytes);
                    pos += 8;

                    // Read key length
                    let mut key_len_bytes = [0u8; 4];
                    key_len_bytes.copy_from_slice(&data_slice[pos..pos+4]);
                    let key_len = u32::from_le_bytes(key_len_bytes) as usize;
                    pos += 4;

                    if pos + key_len > data_len {
                        break; // Prevent reading past the end
                    }

                    // Read key
                    let key = data_slice[pos..pos+key_len].to_vec();
                    pos += key_len;

                    // Add key to keychain
                    keychain_write.keys.insert(key_id, KeyEntry {
                        key,
                        generated_time,
                        expiry_time,
                    });
                }

                keychain_write.set_current_key_id(current_key_id);

                return current_key_id;
            }
        }

        0
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