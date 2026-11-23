#![cfg(feature = "issue")]
//! The test certificate authority: constraints, leaf contents, key types and reloading.

mod support;

use std::time::{Duration, SystemTime};

use coqui_sslcontext::{
    CertificateAuthority, ClientAuth, ClientCertificates, Error, IssueSettings, KeyPassword,
    KeyType, Tls, Trust,
};
use support::tls_server::{TlsServer, https_get};
use x509_cert::der::Decode;

fn client_for(ca: &CertificateAuthority, identity: Option<coqui_sslcontext::Identity>) -> Tls {
    let builder = Tls::builder().trust(Trust::Roots(vec![ca.certificate_der().clone()]));
    match identity {
        Some(identity) => builder.client_certificates(ClientCertificates::Identity(identity)),
        None => builder.client_certificates(ClientCertificates::None),
    }
    .build()
    .unwrap()
}

fn handshake(
    ca: &CertificateAuthority,
    names: &[&str],
    connect_as: &str,
) -> Result<String, String> {
    let issued = ca.issue(names.iter().copied()).unwrap();
    let server = TlsServer::start_config(issued.server_config(ClientAuth::None).unwrap());
    https_get(
        client_for(ca, None).client_config(connect_as).unwrap(),
        server.addr,
        connect_as,
    )
}

#[test]
fn a_leaf_for_a_name_is_accepted_by_a_client_that_trusts_the_ca() {
    let ca = CertificateAuthority::builder("Test Root").create().unwrap();
    assert_eq!(ca.info().subject(), "CN=Test Root");
    assert!(handshake(&ca, &["localhost"], "localhost").is_ok());
    // A certificate for another name is not accepted for this one.
    assert!(handshake(&ca, &["other.example"], "localhost").is_err());
    // IP addresses are alternative names too.
    assert!(handshake(&ca, &["127.0.0.1", "localhost"], "127.0.0.1").is_ok());
}

#[test]
fn the_leaf_serves_and_authenticates_and_carries_key_identifiers() {
    let ca = CertificateAuthority::builder("Test Root").create().unwrap();
    let issued = ca
        .leaf(["localhost"])
        .common_name("Display Name")
        .issue()
        .unwrap();
    let info = issued.info().unwrap();
    assert_eq!(info.subject(), "CN=Display Name");
    assert_eq!(info.issuer(), "CN=Test Root");
    assert!(info.client_auth(), "clientAuth is among the usages");
    let certificate = x509_cert::Certificate::from_der(issued.certificate_der().as_ref()).unwrap();
    let oids: Vec<String> = certificate
        .tbs_certificate()
        .extensions()
        .unwrap()
        .iter()
        .map(|extension| extension.extn_id.to_string())
        .collect();
    for (oid, name) in [
        ("2.5.29.17", "subject alternative name"),
        ("2.5.29.37", "extended key usage"),
        ("2.5.29.35", "authority key identifier"),
        ("2.5.29.14", "subject key identifier"),
    ] {
        assert!(
            oids.iter().any(|found| found == oid),
            "{name} missing in {oids:?}"
        );
    }

    // Mutual TLS: the same leaf is the client's identity.
    let server = TlsServer::start_config(
        issued
            .server_config(ClientAuth::Required(Trust::Roots(vec![
                ca.certificate_der().clone(),
            ])))
            .unwrap(),
    );
    let reply = https_get(
        client_for(&ca, Some(issued.identity().unwrap()))
            .client_config("localhost")
            .unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();
    assert!(reply.ends_with("client certificate seen"));
    assert!(!format!("{issued:?}").contains("BEGIN"));
}

#[test]
fn name_constraints_limit_what_the_ca_can_vouch_for() {
    for permitted in [
        vec!["corp.example"],
        vec![".corp.example"],
        vec!["*.corp.example"],
        vec!["10.0.0.0/8", "corp.example"],
    ] {
        let ca = CertificateAuthority::builder("Constrained")
            .permitted(permitted.clone())
            .create()
            .unwrap();
        assert!(
            handshake(&ca, &["host.corp.example"], "host.corp.example").is_ok(),
            "{permitted:?}"
        );
        assert!(
            handshake(&ca, &["evil.example"], "evil.example").is_err(),
            "{permitted:?} must not vouch for another domain"
        );
    }
    let networks = CertificateAuthority::builder("Networks")
        .permitted(["10.0.0.0/8"])
        .create()
        .unwrap();
    assert!(handshake(&networks, &["10.1.2.3"], "10.1.2.3").is_ok());
    assert!(handshake(&networks, &["192.0.2.1"], "192.0.2.1").is_err());
}

#[test]
fn names_that_cannot_be_constraints_or_certificates_are_credential_errors() {
    for bad in ["", "a*b.example", "*", "http://corp.example/"] {
        let built = CertificateAuthority::builder("Bad")
            .permitted([bad])
            .create();
        assert!(matches!(built, Err(Error::Credential(_))), "{bad:?}");
    }
    let ca = CertificateAuthority::builder("Root").create().unwrap();
    assert!(matches!(
        ca.issue(Vec::<String>::new()),
        Err(Error::Credential(_))
    ));
}

#[test]
fn key_types_validity_and_backdating_follow_the_settings() {
    let mut settings = IssueSettings::default();
    settings.leaf_validity = Duration::from_secs(2 * 24 * 3600);
    settings.backdate = Duration::from_secs(600);
    let ca = CertificateAuthority::builder("Typed Root")
        .settings(settings)
        .create()
        .unwrap()
        .with_settings({
            let mut settings = IssueSettings::default();
            settings.leaf_validity = Duration::from_secs(2 * 24 * 3600);
            settings.backdate = Duration::from_secs(600);
            settings
        });
    let now = SystemTime::now();
    let info = ca.issue(["localhost"]).unwrap().info().unwrap();
    assert_eq!(info.key_type(), KeyType::EcP256);
    let lifetime = info.not_after().duration_since(now).unwrap();
    assert!(lifetime > Duration::from_secs(2 * 24 * 3600 - 60));
    assert!(lifetime < Duration::from_secs(2 * 24 * 3600 + 60));
    let before = now.duration_since(info.not_before()).unwrap();
    assert!(before > Duration::from_secs(540) && before < Duration::from_secs(660));

    for (key_type, bits) in [
        (KeyType::EcP384, 384),
        (KeyType::Ed25519, 256),
        (KeyType::Rsa, 2048),
    ] {
        let issued = ca.leaf(["localhost"]).key_type(key_type).issue().unwrap();
        let info = issued.info().unwrap();
        assert_eq!(info.key_type(), key_type);
        assert_eq!(info.key_bits(), bits);
        let server = TlsServer::start_config(issued.server_config(ClientAuth::None).unwrap());
        https_get(
            client_for(&ca, None).client_config("localhost").unwrap(),
            server.addr,
            "localhost",
        )
        .unwrap_or_else(|error| panic!("{key_type:?}: {error}"));
    }
    assert!(matches!(
        ca.leaf(["localhost"]).key_type(KeyType::EcP521).issue(),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn a_ca_is_saved_and_loaded_again_with_or_without_a_password() {
    let ca = CertificateAuthority::builder("Saved Root")
        .create()
        .unwrap();
    let key = ca.private_key_pem(&KeyPassword::None).unwrap();
    assert!(key.starts_with("-----BEGIN PRIVATE KEY-----"));
    let again = CertificateAuthority::from_pem(
        ca.certificate_pem().as_bytes(),
        key.as_bytes(),
        &KeyPassword::None,
    )
    .unwrap();
    assert_eq!(again.info().fingerprint(), ca.info().fingerprint());
    // A leaf from the reloaded CA verifies against the original certificate.
    let issued = again.issue(["localhost"]).unwrap();
    let server = TlsServer::start_config(issued.server_config(ClientAuth::None).unwrap());
    https_get(
        client_for(&ca, None).client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();

    assert!(matches!(
        CertificateAuthority::from_pem(b"nothing", key.as_bytes(), &KeyPassword::None),
        Err(Error::Credential(_))
    ));
    let other = CertificateAuthority::builder("Other Root")
        .create()
        .unwrap();
    let mismatched = CertificateAuthority::from_pem(
        other.certificate_pem().as_bytes(),
        key.as_bytes(),
        &KeyPassword::None,
    );
    // rcgen cannot tell a mismatched key from the certificate, but a leaf from it is not trusted.
    if let Ok(mismatched) = mismatched {
        let issued = mismatched.issue(["localhost"]).unwrap();
        let server = TlsServer::start_config(issued.server_config(ClientAuth::None).unwrap());
        assert!(
            https_get(
                client_for(&other, None).client_config("localhost").unwrap(),
                server.addr,
                "localhost"
            )
            .is_err()
        );
    }
}

#[cfg(feature = "encrypted-keys")]
#[test]
fn an_exported_key_is_encrypted_when_a_password_is_given() {
    let ca = CertificateAuthority::builder("Locked Root")
        .create()
        .unwrap();
    let key = ca.private_key_pem(&KeyPassword::from("s3cret")).unwrap();
    assert!(key.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    assert!(
        CertificateAuthority::from_pem(
            ca.certificate_pem().as_bytes(),
            key.as_bytes(),
            &KeyPassword::from("s3cret")
        )
        .is_ok()
    );
    for password in [KeyPassword::None, KeyPassword::from("wrong")] {
        assert!(matches!(
            CertificateAuthority::from_pem(
                ca.certificate_pem().as_bytes(),
                key.as_bytes(),
                &password
            ),
            Err(Error::Credential(_))
        ));
    }
}
