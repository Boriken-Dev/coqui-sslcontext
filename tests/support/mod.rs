//! Loopback stand-ins and generated certificates shared by the integration tests.

#![allow(dead_code, reason = "each test binary uses part of the helpers")]

#[cfg(windows)]
pub mod cng_store;
pub mod pki;
pub mod tls_server;
