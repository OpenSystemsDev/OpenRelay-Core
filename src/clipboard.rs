use crate::models::{ClipboardData, ClipboardFormat};
use arboard::Clipboard;
use log::error;
use once_cell::sync::OnceCell;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc::{self, Sender};
use winapi::um::winuser::{AddClipboardFormatListener, RemoveClipboardFormatListener};

// Global sender for clipboard changes
static CLIPBOARD_SENDER: OnceCell<Sender<()>> = OnceCell::new();

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use std::mem;
    use winapi::shared::minwindef::{LPARAM, LRESULT, UINT, WPARAM};
    use winapi::shared::windef::HWND;
    use winapi::um::libloaderapi::GetModuleHandleW;
    use winapi::um::winuser::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
        TranslateMessage, CS_HREDRAW, CS_VREDRAW, MSG, WM_CLIPBOARDUPDATE, WNDCLASSW,
    };

    pub unsafe extern "system" fn window_proc(
        hwnd: HWND,
        msg: UINT,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if msg == WM_CLIPBOARDUPDATE {
            if let Some(sender) = CLIPBOARD_SENDER.get() {
                let _ = sender.blocking_send(());
            }
        }
        unsafe {
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
    }

    pub fn start_clipboard_listener(sender: Sender<()>) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Initialize the sender only once
        if CLIPBOARD_SENDER.set(sender).is_err() {
            return Err("Clipboard listener already initialized".into());
        }

        unsafe {
            // Create a hidden window to receive clipboard messages
            let instance = GetModuleHandleW(std::ptr::null());
            
            let class_name = wide_string("OpenRelayClipboardListener");
            let mut wc: WNDCLASSW = mem::zeroed();
            wc.style = CS_HREDRAW | CS_VREDRAW;
            wc.lpfnWndProc = Some(window_proc);
            wc.hInstance = instance;
            wc.lpszClassName = class_name.as_ptr();
            
            if RegisterClassW(&wc) == 0 {
                return Err("Failed to register window class".into());
            }
            
            let hwnd = CreateWindowExW(
                0,
                class_name.as_ptr(),
                wide_string("Clipboard Listener").as_ptr(),
                0,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                instance,
                std::ptr::null_mut(),
            );
            
            if hwnd.is_null() {
                return Err("Failed to create window".into());
            }
            
            if AddClipboardFormatListener(hwnd) == 0 {
                return Err("Failed to add clipboard format listener".into());
            }
            
            // Message loop
            let hwnd_copy = hwnd as usize;
            thread::spawn(move || {
                let hwnd = hwnd_copy as *mut _;
                let mut msg: MSG = mem::zeroed();
                while GetMessageW(&mut msg, hwnd, 0, 0) > 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                
                RemoveClipboardFormatListener(hwnd);
            });
        }
        
        Ok(())
    }
    
    fn wide_string(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

pub struct ClipboardManager {
    clipboard: Arc<Mutex<Clipboard>>,
    is_updating_clipboard: Arc<Mutex<bool>>,
    clipboard_content_tx: Sender<ClipboardData>,
}

impl ClipboardManager {
    pub fn new() -> Result<(Self, mpsc::Receiver<ClipboardData>), Box<dyn Error>> {
        let clipboard = Arc::new(Mutex::new(Clipboard::new()?));
        let is_updating_clipboard = Arc::new(Mutex::new(false));
        
        // Channel for clipboard content
        let (clipboard_content_tx, clipboard_content_rx) = mpsc::channel(100);
        
        Ok((
            Self {
                clipboard,
                is_updating_clipboard,
                clipboard_content_tx,
            },
            clipboard_content_rx,
        ))
    }
    
    pub fn start_monitoring(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Create channel for clipboard change notifications
        let (tx, mut rx) = mpsc::channel::<()>(100);
        
        // Start clipboard change listener
        #[cfg(target_os = "windows")]
        windows::start_clipboard_listener(tx)?;
        
        let clipboard = self.clipboard.clone();
        let is_updating_clipboard = self.is_updating_clipboard.clone();
        let content_tx = self.clipboard_content_tx.clone();
        
        // Spawn task to handle clipboard changes
        tokio::spawn(async move {
            while let Some(_) = rx.recv().await {
                let is_updating = {
                    let guard = is_updating_clipboard.lock().unwrap();
                    *guard
                };
                
                if is_updating {
                    continue; // Skip if we're the ones updating the clipboard
                }
                
                match Self::get_clipboard_content(&clipboard) {
                    Ok(Some(data)) => {
                        if let Err(e) = content_tx.send(data).await {
                            error!("Failed to send clipboard content: {}", e);
                        }
                    }
                    Ok(None) => {} // No supported content
                    Err(e) => error!("Failed to get clipboard content: {}", e),
                }
            }
        });
        
        Ok(())
    }
    
    pub fn update_clipboard(&self, data: &ClipboardData) -> Result<(), Box<dyn Error>> {
        let mut is_updating = self.is_updating_clipboard.lock().unwrap();
        *is_updating = true;
        
        let mut clipboard = self.clipboard.lock().unwrap();
        
        match data.format {
            ClipboardFormat::Text => {
                if let Some(text) = &data.text_data {
                    clipboard.set_text(text)?;
                }
            }
            ClipboardFormat::Image => {
                if let Some(image_data) = &data.binary_data {
                    // Not implemented yet
                    error!("Image clipboard not implemented yet");
                }
            }
            ClipboardFormat::Files => {
                if let Some(files) = &data.text_data {
                    // For files, store paths as text
                    clipboard.set_text(files)?;
                }
            }
        }
        
        // Reset the flag after a short delay
        let is_updating_clipboard = self.is_updating_clipboard.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut guard = is_updating_clipboard.lock().unwrap();
            *guard = false;
        });
        
        Ok(())
    }
    
    fn get_clipboard_content(clipboard: &Arc<Mutex<Clipboard>>) -> Result<Option<ClipboardData>, Box<dyn Error + Send + Sync>> {
        let mut clipboard = clipboard.lock().unwrap();
        
        // Try to get text
        if let Ok(text) = clipboard.get_text() {
            if !text.is_empty() {
                return Ok(Some(ClipboardData::new_text(text)));
            }
        }
        
        // Try to get image (not implemented)
        
        Ok(None)
    }
}