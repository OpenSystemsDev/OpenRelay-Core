# Development Log - OpenRelay Core

This log tracks the development progress, major changes, decisions, and bug fixes for the OpenRelay-core project.

**Maintainer:** Awe03
**Repository:** https://github.com/OpenSystemsDev/OpenRelay-Core

---

## 2025-05-08

**Time:** 11:14:38 UTC | **Author:** Awe03

### Cleanup of `keychain.rs` since the functionality was moved to the client OpenRelay
*   **Decision:**  Shifted the whether key should be rotated functionality to the client (OpenRelay).  
    Initially, OpenRelay-core was responsible for this, but this created issues with state management of whether keys should be rotated or not, and transmitting them to other clients.  
    For debugging purposes, this was moved to the client, and seeing that it works perfectly well, it will remain there.
*   **Cleanup:**  Removed unnecessary functions from `keychain.rs` and `ffi.rs` that were related to the management of key rotation. This job has now been entrusted to the client.
*   **Cleanup:**  Removed all unused variables and optimized performance