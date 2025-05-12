# OpenRelay-core

OpenRelay-core is the central component that handles all core processes of Openrelay.
This ismplemented in Rust for performance, memory safety, and cross-platform functionality.

## Overview

OpenRelay-core serves as a key management system and secure data storage platform.
OpenRelay accesses it through a C API.

## Features

- AES-256-GCM protection for all sensitive data
- Secure random key generation using cryptographically secure random number generators
- Fast, memory-safe implementation for cross-platform use
- Built to work across platforms and ecosystems on Windows, macOS, Linux, and Android

## Security
- Data is encrypted with AES-256-GCM (NIST SP 800-38D)
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

The following functions are available using the Foreign Function Interface (FFI):
- `encryption_init`: Initialize the encryption service
- `encryption_generate_key`: Generate a new encryption key
- `encryption_encrypt`: Encrypt data with a given key
- `encryption_decrypt`: Decrypt data with a given key   
- `encryption_free_buffer`: Free memory allocated by the library
- `encryption_cleanup`: Clean up resources

Secure Storage functions:
- `securely_store_device_info`: Securely encrypt and store device information
- `securely_retrieve_device_info`: Retrieve and decrypt device information

## Implementation Details

OpenRelay-core uses:
- The `aes-gcm` crate for AES-256-GCM encryption
- The `rand` crate for secure random number generation
- Proper memory management to avoid leaks

## Devlog

See [DEVLOG.md](/DEVLOG.md)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the AGPL-3.0 License - see the LICENSE file for details.