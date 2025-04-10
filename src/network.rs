use crate::device_manager::{DeviceManager, DeviceManagerEvent};
use crate::encryption::EncryptionService;
use crate::models::{ClipboardData, PairedDevice};
use futures::stream::StreamExt;
use log::{error, info, warn};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize};
use serde_json::{json, to_string, Value};
use std::collections::HashMap;
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex}; // Use tokio::sync::Mutex
use tokio_tungstenite::{
    accept_async, connect_async,
    tungstenite::protocol::Message,
    WebSocketStream,
};
use uuid::Uuid;
use futures::sink::SinkExt;
use base64::Engine;

const SERVICE_NAME: &str = "_openrelay._tcp.local.";
const DEFAULT_PORT: u16 = 9876;

#[derive(Debug, Serialize, Deserialize)]
pub enum MessageType {
    ClipboardUpdate,
    PairingRequest,
    PairingResponse,
    Auth,
    AuthSuccess,
    AuthFailed,
    SharedKey,
    Error,
}

#[derive(Debug, Serialize, Deserialize)]
struct NetworkMessage {
    #[serde(rename = "type")]
    message_type: String,
    #[serde(flatten)]
    payload: Value,
}

type WebSocketConnection = WebSocketStream<TcpStream>;

pub enum NetworkCommand {
    SendClipboardData(ClipboardData),
    SendPairingRequest(String, u16, oneshot::Sender<bool>),
    HandleDeviceEvent(DeviceManagerEvent),
}

pub struct NetworkService {
    device_manager: Arc<DeviceManager>,
    encryption_service: Arc<EncryptionService>,
    connections: Arc<Mutex<HashMap<String, WebSocketConnection>>>,
    command_tx: mpsc::Sender<NetworkCommand>,
    clipboard_data_tx: mpsc::Sender<ClipboardData>,
    mdns: Option<ServiceDaemon>,
    port: u16,
}

impl Clone for NetworkService {
    fn clone(&self) -> Self {
        Self {
            device_manager: self.device_manager.clone(),
            encryption_service: self.encryption_service.clone(),
            connections: self.connections.clone(),
            command_tx: self.command_tx.clone(),
            clipboard_data_tx: self.clipboard_data_tx.clone(),
            mdns: None, // Don't clone the mDNS service
            port: self.port,
        }
    }
}

impl NetworkService {
    pub fn new(
        device_manager: Arc<DeviceManager>,
        encryption_service: Arc<EncryptionService>,
        clipboard_data_tx: mpsc::Sender<ClipboardData>,
    ) -> Result<(Self, mpsc::Receiver<NetworkCommand>), Box<dyn Error>> {
        let (command_tx, command_rx) = mpsc::channel(100);
        
        Ok((
            Self {
                device_manager,
                encryption_service,
                connections: Arc::new(Mutex::new(HashMap::new())),
                command_tx,
                clipboard_data_tx,
                mdns: None,
                port: DEFAULT_PORT,
            },
            command_rx,
        ))
    }
    
    pub fn command_sender(&self) -> mpsc::Sender<NetworkCommand> {
        self.command_tx.clone()
    }

    pub async fn process_commands(
        device_manager: Arc<DeviceManager>,
        encryption_service: Arc<EncryptionService>,
        clipboard_data_tx: mpsc::Sender<ClipboardData>,
        command_tx: mpsc::Sender<NetworkCommand>,
        connections: Arc<Mutex<HashMap<String, WebSocketConnection>>>,
        mut command_rx: mpsc::Receiver<NetworkCommand>,
    ) {
        while let Some(cmd) = command_rx.recv().await {
            match cmd {
                NetworkCommand::SendClipboardData(data) => {
                    // Create a temporary NetworkService structure just for this operation
                    let temp_service = NetworkService {
                        device_manager: device_manager.clone(),
                        encryption_service: encryption_service.clone(),
                        connections: connections.clone(),
                        command_tx: command_tx.clone(),
                        clipboard_data_tx: clipboard_data_tx.clone(),
                        mdns: None,
                        port: DEFAULT_PORT,
                    };
    
                    if let Err(e) = temp_service.send_clipboard_data(&data).await {
                        error!("Failed to send clipboard data: {}", e);
                    }
                },
                NetworkCommand::SendPairingRequest(ip, port, response_tx) => {
                    // Create a temporary NetworkService 
                    let temp_service = NetworkService {
                        device_manager: device_manager.clone(),
                        encryption_service: encryption_service.clone(),
                        connections: connections.clone(),
                        command_tx: command_tx.clone(),
                        clipboard_data_tx: clipboard_data_tx.clone(),
                        mdns: None,
                        port: DEFAULT_PORT,
                    };
    
                    let result = temp_service.send_pairing_request(&ip, port).await.unwrap_or(false);
                    let _ = response_tx.send(result);
                },
                NetworkCommand::HandleDeviceEvent(event) => {
                    match event {
                        DeviceManagerEvent::PairingResponse(request_id, accepted) => {
                            info!("Handling pairing response: request_id={}, accepted={}", request_id, accepted);
                            // Process the pairing response without locks
                            // Logic for handling pairing responses goes here
                        },
                        _ => warn!("Unhandled device event"),
                    }
                }
            }
        }
    }
    
    pub async fn start(&mut self, rx: mpsc::Receiver<NetworkCommand>) -> Result<(), Box<dyn Error>> {
        // Start WebSocket server
        self.start_server().await?;
        
        // Start mDNS service
        self.register_mdns_service()?;
        
        // Discover other devices
        self.discover_devices().await?;
        
        // Start command processing in a background task
        let device_manager = self.device_manager.clone();
        let encryption_service = self.encryption_service.clone();
        let clipboard_data_tx = self.clipboard_data_tx.clone();
        let command_tx = self.command_tx.clone();
        let connections = self.connections.clone();
        
        tokio::spawn(async move {
            Self::process_commands(
                device_manager,
                encryption_service,
                clipboard_data_tx,
                command_tx,
                connections,
                rx
            ).await;
        });
        
        Ok(())
    }
    
    async fn start_server(&self) -> Result<(), Box<dyn Error>> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        let listener = TcpListener::bind(&addr).await?;
        
        info!("WebSocket server listening on {}", addr);
        
        let device_manager = self.device_manager.clone();
        let encryption_service = self.encryption_service.clone();
        let connections = self.connections.clone();
        let clipboard_data_tx = self.clipboard_data_tx.clone();
        
        tokio::spawn(async move {
            while let Ok((stream, addr)) = listener.accept().await {
                info!("New connection from: {}", addr);
                
                let device_manager = device_manager.clone();
                let encryption_service = encryption_service.clone();
                let connections = connections.clone();
                let clipboard_data_tx = clipboard_data_tx.clone();
                
                tokio::spawn(async move {
                    match accept_async(stream).await {
                        Ok(ws_stream) => {
                            handle_connection(
                                ws_stream,
                                addr,
                                device_manager,
                                encryption_service,
                                connections,
                                clipboard_data_tx,
                            )
                            .await;
                        }
                        Err(e) => {
                            error!("Error during WebSocket handshake: {}", e);
                        }
                    }
                });
            }
        });
        
        Ok(())
    }
    
    fn register_mdns_service(&mut self) -> Result<(), Box<dyn Error>> {
        let mdns = ServiceDaemon::new()?;
        
        // Get hostname but ensure it ends with .local.
        let mut host_name = hostname::get()?
            .to_string_lossy()
            .into_owned();
            
        // Ensure hostname ends with .local.
        if !host_name.ends_with(".local.") {
            host_name = format!("{}.local.", host_name);
        }
            
        let service_info = ServiceInfo::new(
            SERVICE_NAME,
            &format!("openrelay-{}", self.device_manager.get_local_device_id()),
            &host_name,
            "",
            self.port,
            None,
        )?;
        
        mdns.register(service_info)?;
        self.mdns = Some(mdns);
        
        Ok(())
    }
    
    async fn discover_devices(&self) -> Result<(), Box<dyn Error>> {
        let mdns = ServiceDaemon::new()?;
        let receiver = mdns.browse(SERVICE_NAME)?;
        
        let device_manager = self.device_manager.clone();
        let encryption_service = self.encryption_service.clone();
        let connections = self.connections.clone();
        
        tokio::spawn(async move {
            while let Ok(event) = receiver.recv() {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        let host_name = info.get_hostname();
                        let ip_addresses = info.get_addresses();
                        let port = info.get_port();
                        
                        info!("Found service: {} at {:?}:{}", host_name, ip_addresses, port);
                        
                        for ip in ip_addresses {
                            // Check if this is a known device
                            if let Some(device) = device_manager.get_device_by_ip(&ip.to_string()) {
                                // Connect to this device
                                connect_to_device(
                                    device,
                                    device_manager.clone(),
                                    encryption_service.clone(),
                                    connections.clone(),
                                ).await;
                            }
                        }
                    }
                    _ => {}
                }
            }
        });
        
        Ok(())
    }
    
    pub async fn send_clipboard_data(&self, data: &ClipboardData) -> Result<(), Box<dyn Error>> {
        let paired_devices = self.device_manager.get_paired_devices();
        
        for device in paired_devices {
            self.send_clipboard_data_to_device(data, &device).await?;
        }
        
        Ok(())
    }
    
    async fn send_clipboard_data_to_device(
        &self,
        data: &ClipboardData,
        device: &PairedDevice,
    ) -> Result<(), Box<dyn Error>> {
        let mut connections = self.connections.lock().await; // Use await here
        
        // Check if we have an active connection
        if !connections.contains_key(&device.device_id) {
            // Try to connect
            drop(connections); // Release lock before async operation
            connect_to_device(
                device.clone(),
                self.device_manager.clone(),
                self.encryption_service.clone(),
                self.connections.clone(),
            ).await;
            
            connections = self.connections.lock().await; // Use await here
            if !connections.contains_key(&device.device_id) {
                return Ok(()); // Still can't connect
            }
        }
        
        // Get the connection
        let connection = connections.get_mut(&device.device_id).unwrap();
        
        // Create the message
        let message = match (&data.format, &data.text_data, &data.binary_data) {
            (crate::models::ClipboardFormat::Text, Some(text), _) => {
                // Encrypt the data if we have a shared key
                let encrypted_data = if !device.shared_key.is_empty() {
                    self.encryption_service.encrypt_string(text, &device.shared_key)?
                } else {
                    text.clone()
                };
                
                json!({
                    "type": "clipboard_update",
                    "device_id": self.device_manager.get_local_device_id(),
                    "device_name": self.device_manager.get_local_device_name(),
                    "timestamp": data.timestamp,
                    "format": "text/plain",
                    "data": encrypted_data,
                    "encrypted": !device.shared_key.is_empty()
                })
            }
            (crate::models::ClipboardFormat::Image, _, Some(binary)) => {
                // Encrypt the data if we have a shared key
                let encrypted_data = if !device.shared_key.is_empty() {
                    self.encryption_service.encrypt_binary(binary, &device.shared_key)?
                } else {
                    base64::engine::general_purpose::STANDARD.encode(binary)
                };
                
                json!({
                    "type": "clipboard_update",
                    "device_id": self.device_manager.get_local_device_id(),
                    "device_name": self.device_manager.get_local_device_name(),
                    "timestamp": data.timestamp,
                    "format": "image/png",
                    "data": encrypted_data,
                    "encrypted": !device.shared_key.is_empty(),
                    "is_binary": true
                })
            }
            _ => return Ok(()), // Unsupported format
        };
        
        // Send the message
        connection.send(Message::Text(to_string(&message)?.into())).await?;
        
        Ok(())
    }
    
    pub async fn send_pairing_request(&self, ip_address: &str, port: u16) -> Result<bool, Box<dyn Error>> {
        let url = format!("ws://{}:{}/clipboard", ip_address, port);
        
        let (ws_stream, _) = connect_async(url).await?;
        info!("Connected to {}:{}, sending pairing request", ip_address, port);
        
        let (mut write, mut read) = ws_stream.split();
        
        // Generate a request ID
        let request_id = Uuid::new_v4().to_string();
        
        // Create channel for response
        let (response_tx, response_rx) = oneshot::channel();
        
        // Setup response handler
        tokio::spawn(async move {
            let mut result = false;
            
            while let Some(msg) = read.next().await {
                match msg {
                    Ok(Message::Text(text)) => {
                        match serde_json::from_str::<NetworkMessage>(&text) {
                            Ok(msg) if msg.message_type == "pairing_response" => {
                                if let Some(status) = msg.payload.get("status") {
                                    if status == "accepted" {
                                        // Extract device info
                                        if let (Some(device_id), Some(device_name)) = (
                                            msg.payload.get("device_id").and_then(|v| v.as_str()),
                                            msg.payload.get("device_name").and_then(|v| v.as_str()),
                                        ) {
                                            result = true;
                                        }
                                    }
                                }
                                break;
                            }
                            _ => continue,
                        }
                    }
                    Err(e) => {
                        error!("Error in WebSocket connection: {}", e);
                        break;
                    }
                    _ => continue,
                }
            }
            
            let _ = response_tx.send(result);
        });
        
        // Send pairing request
        let message = json!({
            "type": "pairing_request",
            "request_id": request_id,
            "device_id": self.device_manager.get_local_device_id(),
            "device_name": self.device_manager.get_local_device_name()
        });
        
        write.send(Message::Text((to_string(&message)?).into())).await?;
        
        // Wait for response with timeout
        let result = tokio::time::timeout(Duration::from_secs(30), response_rx).await??;
        
        Ok(result)
    }

    pub async fn handle_pairing_response(&self, request_id: &str, accepted: bool) -> Result<(), Box<dyn Error>> {
        // Log the response
        info!("Handling pairing response: request_id={}, accepted={}", request_id, accepted);
        
        // Implement your pairing response logic here
        // For example, if accepted, generate and send a shared key
        
        Ok(())
    }
}

async fn handle_connection(
    ws_stream: WebSocketStream<TcpStream>,
    addr: SocketAddr,
    device_manager: Arc<DeviceManager>,
    encryption_service: Arc<EncryptionService>,
    connections: Arc<Mutex<HashMap<String, WebSocketConnection>>>,
    clipboard_data_tx: mpsc::Sender<ClipboardData>,
) {
    let (mut write, mut read) = ws_stream.split();
    let mut connected_device: Option<PairedDevice> = None;
    
    while let Some(msg) = read.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                match serde_json::from_str::<NetworkMessage>(&text) {
                    Ok(msg) => {
                        match msg.message_type.as_str() {
                            "auth" => {
                                if let (Some(device_id), Some(device_name)) = (
                                    msg.payload.get("device_id").and_then(|v| v.as_str()),
                                    msg.payload.get("device_name").and_then(|v| v.as_str()),
                                ) {
                                    // Check if this is a known device
                                    if let Some(mut device) = device_manager.get_device_by_id(device_id) {
                                        // Update device info
                                        device.device_name = device_name.to_string();
                                        if let IpAddr::V4(ip) = addr.ip() {
                                            device.ip_address = ip.to_string();
                                        }
                                        
                                        connected_device = Some(device.clone());
                                        let _ = device_manager.update_device_last_seen(device_id);
                                        
                                        // Removed insertion of ws_stream because it was moved by .split().
                                        // { 
                                        //     let mut connections = connections.lock().unwrap();
                                        //     // In a real implementation you might store the write half instead.
                                        //     // connections.insert(device.device_id.clone(), ws_stream);
                                        // }
                                        
                                        // Send authentication success
                                        let response = json!({
                                            "type": "auth_success",
                                            "device_id": device_manager.get_local_device_id(),
                                            "device_name": device_manager.get_local_device_name()
                                        });
                                        
                                        let _ = write.send(Message::Text((to_string(&response).unwrap()).into())).await;
                                        info!("Authentication successful for {}", device_name);
                                    } else {
                                        // Authentication failed
                                        let response = json!({
                                            "type": "auth_failed",
                                            "reason": "device_not_paired"
                                        });
                                        
                                        let _ = write.send(Message::Text((to_string(&response).unwrap()).into())).await;
                                        warn!("Authentication failed: device not paired");
                                    }
                                }
                            }
                            "pairing_request" => {
                                if let (Some(device_id), Some(device_name), Some(request_id)) = (
                                    msg.payload.get("device_id").and_then(|v| v.as_str()),
                                    msg.payload.get("device_name").and_then(|v| v.as_str()),
                                    msg.payload.get("request_id").and_then(|v| v.as_str()),
                                ) {
                                    info!("Received pairing request from {} ({})", device_name, device_id);
                                    
                                    // Get IP address
                                    let ip_address = if let IpAddr::V4(ip) = addr.ip() {
                                        ip.to_string()
                                    } else {
                                        "unknown".to_string()
                                    };
                                    
                                    // Handle the pairing request
                                    let _ = device_manager.handle_pairing_request(
                                        device_id,
                                        device_name,
                                        &ip_address,
                                        DEFAULT_PORT,
                                        request_id,
                                    );
                                    
                                    // Result will be sent by the event handler in the main loop
                                }
                            }
                            "clipboard_update" => {
                                if connected_device.is_none() {
                                    // Not authenticated
                                    let response = json!({
                                        "type": "error",
                                        "error": "not_authenticated"
                                    });
                                    
                                    let _ = write.send(Message::Text(to_string(&response).unwrap().into())).await;
                                    continue;
                                }
                                
                                let device = connected_device.as_ref().unwrap();
                                
                                // Parse clipboard data
                                if let (Some(format), Some(data)) = (
                                    msg.payload.get("format").and_then(|v| v.as_str()),
                                    msg.payload.get("data"),
                                ) {
                                    let is_encrypted = msg.payload.get("encrypted")
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false);
                                        
                                    let is_binary = msg.payload.get("is_binary")
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false);
                                    
                                    // Create clipboard data
                                    let clipboard_data = if format == "text/plain" && !is_binary {
                                        let text = if is_encrypted && !device.shared_key.is_empty() {
                                            encryption_service.decrypt_string(
                                                data.as_str().unwrap_or(""),
                                                &device.shared_key,
                                            ).unwrap_or_default()
                                        } else {
                                            data.as_str().unwrap_or("").to_string()
                                        };
                                        
                                        ClipboardData::new_text(text)
                                    } else if format == "image/png" && is_binary {
                                        let binary = if is_encrypted && !device.shared_key.is_empty() {
                                            encryption_service.decrypt_binary(
                                                data.as_str().unwrap_or(""),
                                                &device.shared_key,
                                            ).unwrap_or_default()
                                        } else {
                                            base64::engine::general_purpose::STANDARD
                                                .decode(data.as_str().unwrap_or(""))
                                                .unwrap_or_default()
                                        };
                                        
                                        ClipboardData::new_image(binary)
                                    } else {
                                        continue; // Unsupported format
                                    };
                                    
                                    // Update clipboard
                                    let _ = clipboard_data_tx.send(clipboard_data).await;
                                }
                            }
                            "pairing_response" => {
                                if let (Some(request_id), Some(status)) = (
                                    msg.payload.get("request_id").and_then(|v| v.as_str()),
                                    msg.payload.get("status").and_then(|v| v.as_str()),
                                ) {
                                    info!("Received pairing response: {} -> {}", request_id, status);
                                    
                                    // If accepted and we have a paired device, update it
                                    if status == "accepted" {
                                        if let (Some(remote_device_id), Some(remote_device_name)) = (
                                            msg.payload.get("device_id").and_then(|v| v.as_str()),
                                            msg.payload.get("device_name").and_then(|v| v.as_str()),
                                        ) {
                                            // Create a new device or update an existing one
                                            let device = PairedDevice::new(
                                                remote_device_id.to_string(),
                                                remote_device_name.to_string(),
                                                if let IpAddr::V4(ip) = addr.ip() { ip.to_string() } else { "unknown".to_string() },
                                                DEFAULT_PORT,
                                            );
                                            
                                            // Generate a shared key
                                            let shared_key = encryption_service.generate_shared_key();
                                            
                                            // Update the device
                                            let mut device_with_key = device.clone();
                                            device_with_key.shared_key = shared_key.clone();
                                            let _ = device_manager.add_or_update_device(device_with_key);
                                            
                                            // Send the shared key
                                            let key_message = json!({
                                                "type": "shared_key",
                                                "request_id": request_id,
                                                "shared_key": shared_key
                                            });
                                            
                                            let _ = write.send(Message::Text((to_string(&key_message).unwrap()).into())).await;
                                            info!("Sent shared key for pairing request {}", request_id);
                                        }
                                    }
                                }
                            },
                            "shared_key" => {
                                if let (Some(device), Some(shared_key)) = (
                                    connected_device.as_ref(),
                                    msg.payload.get("shared_key").and_then(|v| v.as_str()),
                                ) {
                                    // Validate key
                                    match base64::engine::general_purpose::STANDARD.decode(shared_key) {
                                        Ok(key_bytes) => {
                                            if key_bytes.len() == 32 {
                                                // Update device with shared key
                                                let mut updated_device = device.clone();
                                                updated_device.shared_key = shared_key.to_string();
                                                let _ = device_manager.add_or_update_device(updated_device);
                                                
                                                info!("Saved shared key for {}", device.device_name);
                                            } else {
                                                warn!("Invalid key size: {} bytes", key_bytes.len());
                                            }
                                        }
                                        Err(e) => {
                                            warn!("Error decoding key: {}", e);
                                        }
                                    }
                                }
                            }
                            _ => {
                                warn!("Unknown message type: {}", msg.message_type);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error parsing message: {}", e);
                    }
                }
            }
            Ok(Message::Close(_)) => {
                info!("Connection closed");
                break;
            }
            Err(e) => {
                error!("Error in WebSocket connection: {}", e);
                break;
            }
            _ => {}
        }
    }
    
    // Clean up connection
    if let Some(device) = connected_device {
        // Use await for the tokio mutex
        let mut connections = connections.lock().await;
        connections.remove(&device.device_id);
    }
}

async fn connect_to_device(
    device: PairedDevice,
    device_manager: Arc<DeviceManager>,
    encryption_service: Arc<EncryptionService>,
    connections: Arc<Mutex<HashMap<String, WebSocketConnection>>>,
) {
    let url = format!("ws://{}:{}/clipboard", device.ip_address, device.port);
    
    match connect_async(url).await {
        Ok((ws_stream, _)) => {
            info!("Connected to {}", device.device_name);
            
            let (mut write, mut read) = ws_stream.split();
            
            // Send authentication message
            let auth_message = json!({
                "type": "auth",
                "device_id": device_manager.get_local_device_id(),
                "device_name": device_manager.get_local_device_name()
            });
            
            if let Err(e) = write.send(Message::Text((to_string(&auth_message).unwrap()).into())).await {
                error!("Error sending auth message: {}", e);
                return;
            }
            
            // Store connection in a more appropriate way - after authenticating
            // Construct a new full WebSocket by reworking the split parts or
            // use a different approach for storing connections
            
            // Spawn task to handle incoming messages
            let device_id = device.device_id.clone();
            let connections_clone = connections.clone();
            
            tokio::spawn(async move {
                while let Some(msg) = read.next().await {
                    match msg {
                        Ok(Message::Close(_)) => {
                            info!("Connection to {} closed", device.device_name);
                            break;
                        }
                        Err(e) => {
                            error!("Error in connection to {}: {}", device.device_name, e);
                            break;
                        }
                        _ => {
                            // Handle other messages if needed
                        }
                    }
                }
                
                // Clean up connection
                let mut connections = connections_clone.lock().await; // Use await
                connections.remove(&device_id);
            });
        }
        Err(e) => {
            error!("Error connecting to {}: {}", device.device_name, e);
        }
    }
}