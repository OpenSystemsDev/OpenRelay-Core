use crate::encryption::EncryptionService;
use std::slice;

// Global encryption service
static mut ENCRYPTION_SERVICE: Option<EncryptionService> = None;

/// Initialize the encryption service
/// 
/// Returns 0 on success, non-zero on error
#[unsafe(no_mangle)]
pub extern "C" fn encryption_init() -> i32 {
    unsafe {
        ENCRYPTION_SERVICE = Some(EncryptionService::new());
    }
    0
}

/// Generate a new encryption key
/// 
/// # Safety
/// - The caller must call `encryption_free_buffer` on the returned pointer when done
/// - The key_size parameter will be set to the size of the key in bytes
/// 
/// Returns a pointer to the key buffer, or null on error
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
/// 
/// # Safety
/// - The caller must call `encryption_free_buffer` on the returned pointer when done
/// - The encrypted_size parameter will be set to the size of the encrypted data in bytes
/// 
/// Returns a pointer to the encrypted data buffer, or null on error
#[unsafe(no_mangle)]
pub extern "C" fn encryption_encrypt(
    data: *const u8,
    data_size: usize,
    key: *const u8,
    key_size: usize,
    encrypted_size: *mut usize,
) -> *mut u8 {
    // Validate parameters
    if data.is_null() || key.is_null() || encrypted_size.is_null() {
        return std::ptr::null_mut();
    }

    // Create slices from the input pointers
    let data_slice = unsafe { slice::from_raw_parts(data, data_size) };
    let key_slice = unsafe { slice::from_raw_parts(key, key_size) };

    // Get the encryption service using the raw pointer approach for Rust 2024
    let service = unsafe {
        // Need to dereference the raw pointer first
        let option_ref = &raw const ENCRYPTION_SERVICE;
        match *option_ref {
            Some(ref service) => service,
            None => return std::ptr::null_mut(),
        }
    };

    // Encrypt the data
    match service.encrypt(data_slice, key_slice) {
        Ok(encrypted) => {
            let encrypted_len = encrypted.len();
            let mut encrypted_buffer = Vec::with_capacity(encrypted_len);
            encrypted_buffer.extend_from_slice(&encrypted);
            
            // Set the encrypted size
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
/// 
/// # Safety
/// - The caller must call `encryption_free_buffer` on the returned pointer when done
/// - The decrypted_size parameter will be set to the size of the decrypted data in bytes
/// 
/// Returns a pointer to the decrypted data buffer, or null on error
#[unsafe(no_mangle)]
pub extern "C" fn encryption_decrypt(
    encrypted_data: *const u8,
    encrypted_size: usize,
    key: *const u8,
    key_size: usize,
    decrypted_size: *mut usize,
) -> *mut u8 {
    // Validate parameters
    if encrypted_data.is_null() || key.is_null() || decrypted_size.is_null() {
        return std::ptr::null_mut();
    }

    // Create slices from the input pointers
    let encrypted_slice = unsafe { slice::from_raw_parts(encrypted_data, encrypted_size) };
    let key_slice = unsafe { slice::from_raw_parts(key, key_size) };

    // Get the encryption service using the raw pointer approach for Rust 2024
    let service = unsafe {
        // Need to dereference the raw pointer first
        let option_ref = &raw const ENCRYPTION_SERVICE;
        match *option_ref {
            Some(ref service) => service,
            None => return std::ptr::null_mut(),
        }
    };

    // Decrypt the data
    match service.decrypt(encrypted_slice, key_slice) {
        Ok(decrypted) => {
            let decrypted_len = decrypted.len();
            let mut decrypted_buffer = Vec::with_capacity(decrypted_len);
            decrypted_buffer.extend_from_slice(&decrypted);
            
            // Set the decrypted size
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
/// 
/// # Safety
/// - The pointer must have been returned by one of the encryption functions
/// - The pointer must not be used after this call
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
    }
}