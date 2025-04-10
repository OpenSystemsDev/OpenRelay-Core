use crate::models::{PairedDevice, PairingRequest};
use chrono::Utc;
use log::error;
use serde_json::{from_str, to_string_pretty};
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{self, Receiver, Sender};
use uuid::Uuid;
use hostname;

#[derive(Debug)]
pub enum DeviceManagerEvent {
    PairingRequest(PairingRequest),
    PairingResponse(String, bool),
    DeviceAdded(PairedDevice),
    DeviceRemoved(String),
    DeviceUpdated(PairedDevice),
}

pub struct DeviceManager {
    devices: Arc<Mutex<HashMap<String, PairedDevice>>>,
    local_device_id: String,
    local_device_name: String,
    storage_path: PathBuf,
    event_tx: Sender<DeviceManagerEvent>,
}

impl DeviceManager {
    pub fn new() -> Result<(Self, Receiver<DeviceManagerEvent>), Box<dyn Error>> {
        let app_data = dirs::data_dir().ok_or("Could not find app data directory")?;
        let app_folder = app_data.join("OpenRelay");
        
        // Create directory if it doesn't exist
        fs::create_dir_all(&app_folder)?;
        
        let storage_path = app_folder.join("paired_devices.json");
        let device_id_path = app_folder.join("device_id.txt");
        
        // Generate or load device ID
        let (local_device_id, local_device_name) = if device_id_path.exists() {
            let mut content = String::new();
            File::open(&device_id_path)?.read_to_string(&mut content)?;
            let lines: Vec<&str> = content.lines().collect();
            
            if lines.len() >= 2 {
                (lines[0].to_string(), lines[1].to_string())
            } else {
                let id = Uuid::new_v4().to_string();
                let name = hostname::get()?
                    .to_string_lossy()
                    .into_owned();
                
                let content = format!("{}\n{}", id, name);
                File::create(&device_id_path)?.write_all(content.as_bytes())?;
                
                (id, name)
            }
        } else {
            let id = Uuid::new_v4().to_string();
            let name = hostname::get()?
                .to_string_lossy()
                .into_owned();
            
            let content = format!("{}\n{}", id, name);
            File::create(&device_id_path)?.write_all(content.as_bytes())?;
            
            (id, name)
        };
        
        // Load paired devices
        let devices = if storage_path.exists() {
            let mut content = String::new();
            File::open(&storage_path)?.read_to_string(&mut content)?;
            
            match from_str::<Vec<PairedDevice>>(&content) {
                Ok(device_list) => {
                    let mut map = HashMap::new();
                    for device in device_list {
                        map.insert(device.device_id.clone(), device);
                    }
                    map
                }
                Err(e) => {
                    error!("Failed to parse paired devices: {}", e);
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };
        
        let (event_tx, event_rx) = mpsc::channel(100);
        
        Ok((
            Self {
                devices: Arc::new(Mutex::new(devices)),
                local_device_id,
                local_device_name,
                storage_path,
                event_tx,
            },
            event_rx,
        ))
    }
    
    pub fn get_local_device_id(&self) -> &str {
        &self.local_device_id
    }
    
    pub fn get_local_device_name(&self) -> &str {
        &self.local_device_name
    }
    
    pub fn get_paired_devices(&self) -> Vec<PairedDevice> {
        let devices = self.devices.lock().unwrap();
        devices.values().cloned().collect()
    }
    
    pub fn get_device_by_id(&self, device_id: &str) -> Option<PairedDevice> {
        let devices = self.devices.lock().unwrap();
        devices.get(device_id).cloned()
    }
    
    pub fn get_device_by_ip(&self, ip_address: &str) -> Option<PairedDevice> {
        let devices = self.devices.lock().unwrap();
        devices
            .values()
            .find(|d| d.ip_address == ip_address)
            .cloned()
    }
    
    pub fn is_paired_device(&self, device_id: &str) -> bool {
        let devices = self.devices.lock().unwrap();
        devices.contains_key(device_id)
    }
    
    pub fn add_or_update_device(&self, device: PairedDevice) -> Result<(), Box<dyn Error>> {
        let device_id = device.device_id.clone();
        let mut devices = self.devices.lock().unwrap();
        
        let event = if devices.contains_key(&device_id) {
            // Update existing device
            devices.insert(device_id.clone(), device.clone());
            DeviceManagerEvent::DeviceUpdated(device)
        } else {
            // Add new device
            devices.insert(device_id.clone(), device.clone());
            DeviceManagerEvent::DeviceAdded(device)
        };
        
        // Save changes
        self.save_devices()?;
        
        // Notify listeners
        let event_tx = self.event_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = event_tx.send(event).await {
                error!("Failed to send device event: {}", e);
            }
        });
        
        Ok(())
    }
    
    pub fn remove_device(&self, device_id: &str) -> Result<(), Box<dyn Error>> {
        let mut devices = self.devices.lock().unwrap();
        devices.remove(device_id);
        
        // Save changes
        self.save_devices()?;
        
        // Notify listeners
        let event_tx = self.event_tx.clone();
        let device_id = device_id.to_string();
        tokio::spawn(async move {
            if let Err(e) = event_tx.send(DeviceManagerEvent::DeviceRemoved(device_id)).await {
                error!("Failed to send device removed event: {}", e);
            }
        });
        
        Ok(())
    }
    
    pub fn update_device_last_seen(&self, device_id: &str) -> Result<(), Box<dyn Error>> {
        let mut devices = self.devices.lock().unwrap();
        
        if let Some(device) = devices.get_mut(device_id) {
            device.last_seen = Utc::now();
            self.save_devices()?;
        }
        
        Ok(())
    }
    
    pub fn handle_pairing_request(
        &self,
        device_id: &str,
        device_name: &str,
        ip_address: &str,
        port: u16,
        request_id: &str,
    ) -> Result<(), Box<dyn Error>> {
        // Check if already paired
        if self.is_paired_device(device_id) {
            self.update_device_last_seen(device_id)?;
            
            // Automatically accept requests from already paired devices
            let event_tx = self.event_tx.clone();
            let request_id = request_id.to_string();
            tokio::spawn(async move {
                if let Err(e) = event_tx.send(DeviceManagerEvent::PairingResponse(request_id, true)).await {
                    error!("Failed to send pairing response: {}", e);
                }
            });
            
            return Ok(());
        }
        
        // Create pairing request
        let request = PairingRequest {
            device_id: device_id.to_string(),
            device_name: device_name.to_string(),
            ip_address: ip_address.to_string(),
            port,
            request_id: request_id.to_string(),
        };
        
        // Notify listeners
        let event_tx = self.event_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = event_tx.send(DeviceManagerEvent::PairingRequest(request)).await {
                error!("Failed to send pairing request event: {}", e);
            }
        });
        
        Ok(())
    }
    
    fn save_devices(&self) -> Result<(), Box<dyn Error>> {
        let devices = self.devices.lock().unwrap();
        let device_list: Vec<PairedDevice> = devices.values().cloned().collect();
        
        let json = to_string_pretty(&device_list)?;
        File::create(&self.storage_path)?.write_all(json.as_bytes())?;
        
        Ok(())
    }
}