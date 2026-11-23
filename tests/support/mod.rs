//! Loopback stand-ins and generated certificates shared by the integration tests.

#![allow(dead_code, reason = "each test binary uses part of the helpers")]

#[cfg(all(windows, feature = "system"))]
pub mod cng_store;
pub mod pem;
pub mod pki;
pub mod tls_server;
