#![cfg(feature = "testing")]
//! Software identities that count signatures, and small public details.

mod support;

use coqui_sslcontext::testing::{SoftwareSigningKey, software_identity};
use coqui_sslcontext::{
    AutoSelectRule, ClientCertificates, KeyPassword, NameFilter, Tls, Trust, VERSION,
};
use support::pem::pem;
use support::pki::Ca;
use support::tls_server::{ClientAuth, TlsServer, https_get};

#[test]
fn a_software_identity_counts_the_signatures_made_for_a_handshake() {
    let server_ca = Ca::new("Server CA");
    let client_ca = Ca::new("Client CA");
    let server = TlsServer::start(
        &server_ca.issue_server("localhost"),
        &[client_ca.der()],
        ClientAuth::Required,
    );
    let leaf = client_ca.issue_client("counted-user");
    let certificates: String = leaf
        .chain
        .iter()
        .map(|der| pem("CERTIFICATE", der.as_ref()))
        .collect();
    let (identity, key) = software_identity(
        certificates.as_bytes(),
        pem("PRIVATE KEY", &leaf.key_pkcs8).as_bytes(),
        &KeyPassword::None,
    )
    .unwrap();
    assert_eq!(key.calls(), 0);
    let tls = Tls::builder()
        .trust(Trust::Roots(vec![server_ca.der()]))
        .client_certificates(ClientCertificates::Identity(identity))
        .build()
        .unwrap();
    https_get(
        tls.client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();
    assert_eq!(key.calls(), 1, "one CertificateVerify signature");
    assert!(format!("{key:?}").contains("calls"));
}

#[test]
fn a_der_key_is_accepted_and_a_bad_one_is_not() {
    let leaf = Ca::new("Der CA").issue_client("der-user");
    assert!(SoftwareSigningKey::new(&leaf.key_pkcs8, &KeyPassword::None).is_ok());
    assert!(SoftwareSigningKey::new(b"\x00\x01", &KeyPassword::None).is_err());
}

#[test]
fn the_version_rules_and_non_defaults_are_readable() {
    assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
    let rule = AutoSelectRule::builder("corp.example")
        .subject(NameFilter::Contains("staff".into()))
        .build();
    assert_eq!(rule.pattern(), "corp.example");
    assert_eq!(rule.subject(), &NameFilter::Contains("staff".into()));
    assert_eq!(rule.issuer(), &NameFilter::Any);
    let builder = Tls::builder().trust(Trust::Disabled);
    assert_eq!(builder.non_defaults()[0].setting, "trust");
    assert!(Tls::builder().non_defaults().is_empty());
}
