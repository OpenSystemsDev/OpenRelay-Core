use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClipboardFormat {
    Text,
    Image,
    Files,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardData {
    pub format: ClipboardFormat,
    pub text_data: Option<String>,
    pub binary_data: Option<Vec<u8>>,
    pub timestamp: u64,
}

impl ClipboardData {
    pub fn new_text(text: String) -> Self {
        Self {
            format: ClipboardFormat::Text,
            text_data: Some(text),
            binary_data: None,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn new_image(data: Vec<u8>) -> Self {
        Self {
            format: ClipboardFormat::Image,
            text_data: None,
            binary_data: Some(data),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedDevice {
    pub device_id: String,
    pub device_name: String,
    pub platform: String,
    pub ip_address: String,
    pub port: u16,
    pub shared_key: String,
    pub last_seen: DateTime<Utc>,
}

impl PairedDevice {
    pub fn new(device_id: String, device_name: String, ip_address: String, port: u16) -> Self {
        Self {
            device_id,
            device_name,
            platform: "Unknown".to_string(),
            ip_address,
            port,
            shared_key: String::new(),
            last_seen: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingRequest {
    pub device_id: String,
    pub device_name: String,
    pub ip_address: String,
    pub port: u16,
    pub request_id: String,
}

impl PairingRequest {
    pub fn new(device_id: String, device_name: String, ip_address: String, port: u16) -> Self {
        Self {
            device_id,
            device_name,
            ip_address,
            port,
            request_id: Uuid::new_v4().to_string(),
        }
    }
}