# OpenRelay-core

OpenRelay-core is the central component that handles all core processes of Openrelay.
This ismplemented in Rust for performance, memory safety, and cross-platform functionality.

## Overview

OpenRelay-core functions as a key management system and secure data storage platform through its C foreign function interface that allows Openrelay to access it.

## Features

- Strong Encryption through AES-256-GCM enables the protection of all sensitive data.
- Keys are randomly generated, rotated every 7 days, and stored securely
- Built to work across platforms and ecosystems, on Windows, macOS, Linux, and Android

## Security
- All clipboard data is encrypted with AES-256-GCM (NIST SP 800-38D)
- Uses FIPS 140-3 certified cryptographic algorithms
- Follows OWASP Cryptographic Storage Cheat Sheet recommendations
- Keys automatically rotate every 7 days (following NIST SP 800-57 guidelines with 7-day cycles) ensuring your keys are always protected

## Building from source

To build OpenRelay-core, run:

```bash
cargo build --release
```

The dll file can be found at:
- Windows: `target/release/openrelay_core.dll`
- macOS: `target/release/libopenrelay_core.dylib`
- Linux: `target/release/libopenrelay_core.so`

## C API

Through its C API interface the library makes available the following functions:

- `encryption_init`: Initialize the encryption service
- `encryption_generate_key`: Generate a new encryption key
- `encryption_encrypt`: Encrypt data with a given key
- `encryption_decrypt`: Decrypt data with a given key
- `encryption_free_buffer`: Free memory allocated by the library
- `encryption_cleanup`: Clean up resources

Key management and rotation:
- `get_current_key_id`: Get the current encryption key ID
- `should_rotate_key`: Check if the current key should be rotated
- `create_rotation_key`: Create a new rotation key
- `get_key_update_package`: Create a key update package
- `import_key_update_package`: Import a key update package

## Implementation Details

OpenRelay-core uses:

- The `aes-gcm` crate for AES-256-GCM encryption
- The `rand` crate for secure random number generation
- A secure key rotation system to maintain security over time
- Proper memory management to avoid leaks

## License

This project is licensed under the AGPL-3.0 License - see the LICENSE file for details.