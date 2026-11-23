#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    missing_docs,
    missing_debug_implementations,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::alloc_instead_of_core
)]
#![deny(unsafe_code)]

extern crate alloc;

mod client;
mod error;
mod identity;
mod keylog;
pub mod keystore;
mod load;
mod password;
mod pin;
pub mod policy;
mod secret;
mod select;
mod settings;

pub use client::{ClientCertificates, NonDefault, Tls, TlsBuilder, Trust, client_config};
pub use error::{Error, Reason};
pub use identity::{CertificateInfo, Identity, KeyType};
#[cfg(all(windows, feature = "system"))]
pub use keystore::CngSource;
#[cfg(all(target_os = "macos", feature = "system"))]
pub use keystore::KeychainSource;
#[cfg(feature = "pkcs11")]
pub use keystore::{Pkcs11Source, Pkcs11SourceBuilder};
pub use password::KeyPassword;
pub use pin::{KeystoreKind, Pin, PinAnswer, PinCallback, PinPurpose, PinRequest};
pub use policy::{
    AutoSelectRule, AutoSelectRuleBuilder, NameFilter, browser_policies, rules_from_policy,
};
pub use secret::Secret;
pub use select::{
    CertificateRequest, Chooser, IdentityQuery, IdentityQueryBuilder, IdentitySource, Selector,
    SelectorBuilder,
};
pub use settings::{KeyLogging, Pkcs11Settings, SelectorSettings, TlsSettings, TlsVersion};
