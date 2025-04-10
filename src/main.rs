use openrelay_core::{
    openrelay_init, 
    openrelay_start, 
    openrelay_set_clipboard_changed_callback,
    openrelay_set_pairing_request_callback,
};
use std::ffi::CString;
use std::{thread, time::Duration};
use std::os::raw::{c_char, c_int};

// Clipboard callback
extern "C" fn on_clipboard_changed(json_data: *const c_char, binary_data: *const u8, binary_len: usize) {
    unsafe {
        if !json_data.is_null() {
            let c_str = std::ffi::CStr::from_ptr(json_data);
            let data = c_str.to_string_lossy().into_owned();
            println!("Clipboard data received: {}", data);
        }
    }
}

// Pairing callback
extern "C" fn on_pairing_request(
    device_id: *const c_char,
    device_name: *const c_char,
    ip_address: *const c_char,
    port: c_int,
    request_id: *const c_char,
) -> c_int {
    unsafe {
        let device_id_str = std::ffi::CStr::from_ptr(device_id).to_string_lossy();
        let device_name_str = std::ffi::CStr::from_ptr(device_name).to_string_lossy();
        let ip_str = std::ffi::CStr::from_ptr(ip_address).to_string_lossy();
        let request_id_str = std::ffi::CStr::from_ptr(request_id).to_string_lossy();
        
        println!("Pairing request from: {} ({})", device_name_str, device_id_str);
        println!("IP: {}:{}, Request ID: {}", ip_str, port, request_id_str);
        
        // Accept the pairing request
        return 1;
    }
}

fn main() {
    // Initialize the library
    unsafe {
        let result = openrelay_init();
        if result != 0 {
            println!("Failed to initialize OpenRelay");
            return;
        }
        
        // Set up callbacks
        openrelay_set_clipboard_changed_callback(on_clipboard_changed);
        openrelay_set_pairing_request_callback(on_pairing_request);
        
        // Start the OpenRelay service
        let result = openrelay_start();
        if result != 0 {
            println!("Failed to start OpenRelay");
            return;
        }
        
        println!("OpenRelay started successfully. Running for 60 seconds...");
        
        // Run for some time to observe activity
        thread::sleep(Duration::from_secs(60));
        
        println!("Test completed.");
    }
}