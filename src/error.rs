//! The crate's error type.

use alloc::string::String;
use core::fmt;

/// What can go wrong building a TLS configuration or reading a keystore.
///
/// A message names what failed and never quotes the input: a key, a PIN or a certificate may be
/// a secret.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A TLS configuration, a keystore or a certificate could not be used.
    #[error("tls: {0}")]
    Tls(Reason),
    /// A file operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A short, fixed or derived description of why something failed, free of input text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason(String);

impl Reason {
    pub(crate) fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
