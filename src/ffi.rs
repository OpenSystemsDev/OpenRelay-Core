use crate::clipboard::ClipboardManager;
use crate::device_manager::{DeviceManager, DeviceManagerEvent};
use crate::encryption::EncryptionService;
use crate::models::{ClipboardData, ClipboardFormat};
use crate::network::{NetworkCommand, NetworkService};
use libc::{c_char, c_int, size_t};
use log::{error, info};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot};

// Global runtime
static RUNTIME: OnceCell<Runtime> = OnceCell::new();

// Global channels
static CLIPBOARD_TX: OnceCell<mpsc::Sender<ClipboardData>> = OnceCell::new();
static NETWORK_TX: OnceCell<mpsc::Sender<NetworkCommand>> = OnceCell::new();

// Callback function types
type ClipboardChangedCallback = extern "C" fn(*const c_char, *const u8, size_t);
type PairingRequestCallback = extern "C" fn(*const c_char, *const c_char, *const c_char, c_int, *const c_char) -> c_int;
type DeviceAddedCallback = extern "C" fn(*const c_char, *const c_char, *const c_char, c_int);
type DeviceRemovedCallback = extern "C" fn(*const c_char);

// Callback storage
static mut CLIPBOARD_CHANGED_CALLBACK: Option<ClipboardChangedCallback> = None;
static mut PAIRING_REQUEST_CALLBACK: Option<PairingRequestCallback> = None;
static mut DEVICE_ADDED_CALLBACK: Option<DeviceAddedCallback> = None;
static mut DEVICE_REMOVED_CALLBACK: Option<DeviceRemovedCallback> = None;

// Helper to convert Rust string to C string
fn to_c_string(s: &str) -> *const c_char {
    CString::new(s).unwrap_or_default().into_raw() as *const c_char
}

#[derive(Serialize, Deserialize)]
struct JsonClipboardData {
    format: String,
    text_data: Option<String>,
    binary_length: usize,
    timestamp: u64,
}

// Initialize the library
#[unsafe(no_mangle)]
pub extern "C" fn openrelay_init() -> c_int {
    // Initialize logger
    env_logger::init();
    
    // Create runtime
    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to create runtime: {}", e);
            return -1;
        }
    };
    
    let _ = RUNTIME.set(runtime);
    
    // Success
    0
}

// Set the clipboard changed callback
#[unsafe(no_mangle)]
pub extern "C" fn openrelay_set_clipboard_changed_callback(callback: ClipboardChangedCallback) {
    unsafe {
        CLIPBOARD_CHANGED_CALLBACK = Some(callback);
    }
}

// Set the pairing request callback
#[unsafe(no_mangle)]
pub extern "C" fn openrelay_set_pairing_request_callback(callback: PairingRequestCallback) {
    unsafe {
        PAIRING_REQUEST_CALLBACK = Some(callback);
    }
}

// Set the device added callback
#[unsafe(no_mangle)]
pub extern "C" fn openrelay_set_device_added_callback(callback: DeviceAddedCallback) {
    unsafe {
        DEVICE_ADDED_CALLBACK = Some(callback);
    }
}

// Set the device removed callback
#[unsafe(no_mangle)]
pub extern "C" fn openrelay_set_device_removed_callback(callback: DeviceRemovedCallback) {
    unsafe {
        DEVICE_REMOVED_CALLBACK = Some(callback);
    }
}

// Start the OpenRelay services
#[unsafe(no_mangle)]
pub extern "C" fn openrelay_start() -> c_int {
    let runtime = match RUNTIME.get() {
        Some(rt) => rt,
        None => {
            error!("Runtime not initialized");
            return -1;
        }
    };
    
    // Start the OpenRelay services
    runtime.block_on(async {
        // Create encryption service
        let encryption_service = Arc::new(EncryptionService::new());
        
        // Create device manager
        let (device_manager, mut device_events_rx) = match DeviceManager::new() {
            Ok((dm, rx)) => (Arc::new(dm), rx),
            Err(e) => {
                error!("Failed to create device manager: {}", e);
                return -1;
            }
        };
        
        // Create clipboard manager
        let (clipboard_manager, mut clipboard_rx) = match ClipboardManager::new() {
            Ok((cm, rx)) => (cm, rx),
            Err(e) => {
                error!("Failed to create clipboard manager: {}", e);
                return -1;
            }
        };
        
        // Create a channel for receiving clipboard data from the network
        let (clipboard_data_tx, mut clipboard_data_rx) = mpsc::channel(100);
        
        // Store global sender
        let _ = CLIPBOARD_TX.set(clipboard_data_tx.clone());
        
        // Create network service
        let (mut network_service, network_rx) = match NetworkService::new(
            device_manager.clone(),
            encryption_service.clone(),
            clipboard_data_tx.clone(),
        ) {
            Ok((ns, rx)) => (ns, rx),
            Err(e) => {
                error!("Failed to create network service: {}", e);
                return -1;
            }
        };
        
        // Store network command sender
        let _ = NETWORK_TX.set(network_service.command_sender());
        
        // Start clipboard monitoring
        if let Err(e) = clipboard_manager.start_monitoring() {
            error!("Failed to start clipboard monitoring: {}", e);
            return -1;
        }
        
        // Start network service
        if let Err(e) = network_service.start(network_rx).await {
            error!("Failed to start network service: {}", e);
            return -1;
        }
        
        // Spawn task to handle clipboard changes
        tokio::spawn(async move {
            while let Some(data) = clipboard_rx.recv().await {
                // Skip if we're updating the clipboard
                match NETWORK_TX.get() {
                    Some(tx) => {
                        if let Err(e) = tx.send(NetworkCommand::SendClipboardData(data)).await {
                            error!("Failed to send clipboard data: {}", e);
                        }
                    }
                    None => {
                        error!("Network sender not initialized");
                    }
                }
            }
        });
        
        // Spawn task to handle network clipboard data
        tokio::spawn(async move {
            while let Some(data) = clipboard_data_rx.recv().await {
                // Convert to FFI-friendly format
                let format = match data.format {
                    ClipboardFormat::Text => "text/plain",
                    ClipboardFormat::Image => "image/png",
                    ClipboardFormat::Files => "files/paths",
                };
                
                let json_data = JsonClipboardData {
                    format: format.to_string(),
                    text_data: data.text_data.clone(),
                    binary_length: data.binary_data.as_ref().map_or(0, |d| d.len()),
                    timestamp: data.timestamp,
                };
                
                let json_str = match serde_json::to_string(&json_data) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to serialize clipboard data: {}", e);
                        continue;
                    }
                };
                
                unsafe {
                    if let Some(callback) = CLIPBOARD_CHANGED_CALLBACK {
                        let c_str = to_c_string(&json_str);
                        
                        // For binary data
                        let (ptr, len) = if let Some(bin) = &data.binary_data {
                            (bin.as_ptr(), bin.len())
                        } else {
                            (ptr::null(), 0)
                        };
                        
                        callback(c_str, ptr, len);
                        
                        // Free the C string
                        let _ = CString::from_raw(c_str as *mut c_char);
                    }
                }
                
                // Update local clipboard
                if let Err(e) = clipboard_manager.update_clipboard(&data) {
                    error!("Failed to update clipboard: {}", e);
                }
            }
        });
        
        // Spawn task to handle device events
        tokio::spawn(async move {
            while let Some(event) = device_events_rx.recv().await {
                match event {
                    DeviceManagerEvent::PairingRequest(request) => {
                        // Capture original request_id as a Rust String
                        let request_id_str = request.request_id.clone();
                        unsafe {
                            if let Some(callback) = PAIRING_REQUEST_CALLBACK {
                                let device_id = to_c_string(&request.device_id);
                                let device_name = to_c_string(&request.device_name);
                                let ip_address = to_c_string(&request.ip_address);
                                let request_id_c = to_c_string(&request.request_id);
                                
                                let result = callback(
                                    device_id,
                                    device_name,
                                    ip_address,
                                    request.port as c_int,
                                    request_id_c,
                                );
                                
                                // Free C strings
                                let _ = CString::from_raw(device_id as *mut c_char);
                                let _ = CString::from_raw(device_name as *mut c_char);
                                let _ = CString::from_raw(ip_address as *mut c_char);
                                let _ = CString::from_raw(request_id_c as *mut c_char);
                                
                                let accepted = result > 0;
                                // Removed event_tx handling since 'event_tx' field is not present in PairingRequest.
                                info!("Pairing response for request_id {}: accepted = {}", request_id_str, accepted);
                            }
                        }
                    }
                    DeviceManagerEvent::PairingResponse(request_id, accepted) => {
                        // Forward this to the network service
                        if let Some(tx) = NETWORK_TX.get() {
                            tx.send(NetworkCommand::HandleDeviceEvent(
                                DeviceManagerEvent::PairingResponse(request_id.clone(), accepted)
                            )).await.unwrap_or_else(|e| {
                                error!("Failed to forward pairing response: {}", e);
                            });
                        }
                    },
                    DeviceManagerEvent::DeviceAdded(device) => {
                        unsafe {
                            if let Some(callback) = DEVICE_ADDED_CALLBACK {
                                let device_id = to_c_string(&device.device_id);
                                let device_name = to_c_string(&device.device_name);
                                let ip_address = to_c_string(&device.ip_address);
                                
                                callback(
                                    device_id,
                                    device_name,
                                    ip_address,
                                    device.port as c_int,
                                );
                                
                                // Free C strings
                                let _ = CString::from_raw(device_id as *mut c_char);
                                let _ = CString::from_raw(device_name as *mut c_char);
                                let _ = CString::from_raw(ip_address as *mut c_char);
                            }
                        }
                    }
                    DeviceManagerEvent::DeviceRemoved(device_id) => {
                        unsafe {
                            if let Some(callback) = DEVICE_REMOVED_CALLBACK {
                                let c_device_id = to_c_string(&device_id);
                                callback(c_device_id);
                                let _ = CString::from_raw(c_device_id as *mut c_char);
                            }
                        }
                    }
                    _ => {} // Handle other events as needed
                }
            }
        });
        
        0
    })
}

// Get local device ID
#[unsafe(no_mangle)]
pub extern "C" fn openrelay_get_local_device_id() -> *const c_char {
    let runtime = match RUNTIME.get() {
        Some(rt) => rt,
        None => {
            error!("Runtime not initialized");
            return ptr::null();
        }
    };
    
    runtime.block_on(async {
        // This would need to be implemented properly to access the device manager
        // For now, return a placeholder
        to_c_string("device_id_placeholder")
    })
}

// Get local device name
#[unsafe(no_mangle)]
pub extern "C" fn openrelay_get_local_device_name() -> *const c_char {
    let runtime = match RUNTIME.get() {
        Some(rt) => rt,
        None => {
            error!("Runtime not initialized");
            return ptr::null();
        }
    };
    
    runtime.block_on(async {
        // This would need to be implemented properly to access the device manager
        // For now, return a placeholder
        to_c_string("device_name_placeholder")
    })
}

// Get paired devices as JSON
#[unsafe(no_mangle)]
pub extern "C" fn openrelay_get_paired_devices() -> *const c_char {
    let runtime = match RUNTIME.get() {
        Some(rt) => rt,
        None => {
            error!("Runtime not initialized");
            return ptr::null();
        }
    };
    
    runtime.block_on(async {
        // This would need to be implemented properly to access the device manager
        // For now, return an empty array
        to_c_string("[]")
    })
}

// Send pairing request
#[unsafe(no_mangle)]
pub extern "C" fn openrelay_send_pairing_request(ip_address: *const c_char, port: c_int) -> c_int {
    if ip_address.is_null() {
        return -1;
    }
    
    let ip = unsafe {
        match CStr::from_ptr(ip_address).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        }
    };
    
    let port = port as u16;
    
    let runtime = match RUNTIME.get() {
        Some(rt) => rt,
        None => {
            error!("Runtime not initialized");
            return -1;
        }
    };
    
    let network_tx = match NETWORK_TX.get() {
        Some(tx) => tx.clone(),
        None => {
            error!("Network sender not initialized");
            return -1;
        }
    };
    
    runtime.block_on(async {
        let (response_tx, response_rx) = oneshot::channel();
        
        if let Err(e) = network_tx.send(NetworkCommand::SendPairingRequest(ip, port, response_tx)).await {
            error!("Failed to send pairing request: {}", e);
            return -1;
        }
        
        match response_rx.await {
            Ok(true) => 1,  // Success
            Ok(false) => 0, // Declined
            Err(_) => -1,   // Error
        }
    })
}

// Remove paired device
#[unsafe(no_mangle)]
pub extern "C" fn openrelay_remove_device(device_id: *const c_char) -> c_int {
    if device_id.is_null() {
        return -1;
    }
    
    let id = unsafe {
        match CStr::from_ptr(device_id).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        }
    };
    
    // This would need to be implemented properly to access the device manager
    // For now, return success
    0
}

// Cleanup and shut down
#[unsafe(no_mangle)]
pub extern "C" fn openrelay_cleanup() {
    // Clean up global state
    if let Some(runtime) = RUNTIME.get() {
        // Shut down the runtime
        let _ = runtime;
    }
}

// Free a C string allocated by Rust
#[unsafe(no_mangle)]
pub extern "C" fn openrelay_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}