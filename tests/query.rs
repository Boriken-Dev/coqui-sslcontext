//! Finding identities by query, several identities per client, fallbacks, bundles and versions.

mod support;

use std::sync::Arc;

use coqui_sslcontext::{
    CertificateRequest, ClientCertificates, Error, Identity, IdentityQuery, IdentitySource,
    KeyLogging, KeyType, Selector, Tls, TlsVersion, Trust,
};
use rustls::SignatureScheme;
use support::pki::{Ca, Leaf};
use support::tls_server::{ClientAuth, TlsServer, https_get};

fn identity(leaf: &Leaf, label: &str) -> Identity {
    let key = rustls::crypto::ring::sign::any_supported_type(&leaf.key()).unwrap();
    Identity::new(leaf.chain.clone(), key, label).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

#[test]
fn a_query_matches_every_criterion_it_names() {
    let ca = Ca::new("Query CA");
    let alice = identity(&ca.issue_client("alice"), "work card");
    let expired = identity(&ca.issue_expired_client("alice-old"), "old card");
    let sources: Vec<Identity> = vec![alice.clone(), expired.clone()];

    let by = |query: IdentityQuery| sources.find(&query).unwrap();
    assert_eq!(by(IdentityQuery::builder().build()).len(), 1, "valid only");
    assert_eq!(
        by(IdentityQuery::builder().valid_only(false).build()).len(),
        2
    );
    assert_eq!(
        by(IdentityQuery::builder().subject("ALICE").build()).len(),
        1
    );
    assert_eq!(
        by(IdentityQuery::builder().issuer("query ca").build()).len(),
        1
    );
    assert!(by(IdentityQuery::builder().subject("bob").build()).is_empty());
    assert_eq!(
        by(IdentityQuery::builder().label("WORK CARD").build()).len(),
        1
    );
    assert!(by(IdentityQuery::builder().label("work").build()).is_empty());

    let sha1 = hex(alice.info().sha1());
    let colons: Vec<String> = sha1
        .as_bytes()
        .chunks(2)
        .map(|pair| String::from_utf8_lossy(pair).into())
        .collect();
    for thumbprint in [
        sha1.clone(),
        sha1.to_lowercase(),
        colons.join(":"),
        hex(alice.info().sha256()),
    ] {
        let found = by(IdentityQuery::builder().thumbprint(thumbprint).build());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].info().fingerprint(), alice.info().fingerprint());
    }
    assert!(by(IdentityQuery::builder().thumbprint("00").build()).is_empty());
}

#[test]
fn the_best_match_is_the_one_that_expires_last_and_none_is_not_found() {
    let ca = Ca::new("Renewal CA");
    let one = identity(&ca.issue_client("same-name"), "one");
    let sources = vec![one.clone()];
    let query = IdentityQuery::builder().subject("same-name").build();
    assert_eq!(
        sources.find_one(&query).unwrap().info().fingerprint(),
        one.info().fingerprint()
    );
    let missing = IdentityQuery::builder().subject("nobody").build();
    assert!(matches!(
        sources.find_one(&missing),
        Err(Error::NotFound(_))
    ));

    let selector = Selector::builder().source(sources).build();
    assert_eq!(selector.find(&query).len(), 1);
    assert!(selector.find(&missing).is_empty());
}

#[test]
fn several_identities_are_told_apart_by_what_the_server_can_verify() {
    let ca = Ca::new("Two Keys CA");
    let p256 = identity(&ca.issue_client("ec256"), "p256");
    let p384 = identity(&ca.issue_client_p384("ec384"), "p384");
    assert_eq!(p384.info().key_type(), KeyType::EcP384);
    assert_eq!(p384.info().key_bits(), 384);
    let tls = Tls::builder()
        .trust(Trust::Disabled)
        .client_certificates(ClientCertificates::Identities(vec![
            p256.clone(),
            p384.clone(),
        ]))
        .build()
        .unwrap();
    let config = tls.client_config("localhost").unwrap();
    let chosen = |schemes: &[SignatureScheme]| {
        config
            .client_auth_cert_resolver
            .resolve(&[], schemes)
            .map(|key| key.cert[0].as_ref().to_vec())
    };
    assert_eq!(
        chosen(&[SignatureScheme::ECDSA_NISTP384_SHA384]).unwrap(),
        p384.chain()[0].as_ref()
    );
    assert_eq!(
        chosen(&[SignatureScheme::ECDSA_NISTP256_SHA256]).unwrap(),
        p256.chain()[0].as_ref()
    );
    assert!(chosen(&[SignatureScheme::ED25519]).is_none());
}

#[test]
fn a_fallback_identity_is_sent_only_when_the_keystores_have_nothing() {
    let server_ca = Ca::new("Fallback Server CA");
    let client_ca = Ca::new("Fallback Client CA");
    let server = TlsServer::start(
        &server_ca.issue_server("localhost"),
        &[client_ca.der()],
        ClientAuth::Required,
    );
    let fallback = identity(&client_ca.issue_client("fallback-user"), "fallback");
    let tls = Tls::builder()
        .trust(Trust::Roots(vec![server_ca.der()]))
        .client_certificates(ClientCertificates::Selector(Arc::new(
            Selector::builder().build(),
        )))
        .fallback_identity(fallback.clone())
        .build()
        .unwrap();
    let reply = https_get(
        tls.client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    );
    assert_eq!(
        reply.unwrap().rsplit("\r\n\r\n").next().unwrap(),
        "client certificate seen"
    );
    assert_eq!(
        server.presented()[0].as_deref(),
        Some(fallback.chain()[0].as_ref())
    );

    // A selector that has a certificate wins over the fallback.
    let own = identity(&client_ca.issue_client("own-user"), "own");
    let tls = Tls::builder()
        .trust(Trust::Roots(vec![server_ca.der()]))
        .client_certificates(ClientCertificates::Selector(Arc::new(
            Selector::builder()
                .source(own.clone())
                .send_sole_candidate(true)
                .build(),
        )))
        .fallback_identity(fallback)
        .build()
        .unwrap();
    https_get(
        tls.client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();
    assert_eq!(
        server.presented()[1].as_deref(),
        Some(own.chain()[0].as_ref())
    );
}

#[test]
fn a_certificate_request_reports_the_names_key_types_and_pss_rule() {
    let ca = Ca::new("Request CA");
    let der = ca.der();
    let name = {
        use x509_cert::der::{Decode, Encode};
        let certificate = x509_cert::Certificate::from_der(der.as_ref()).unwrap();
        certificate.tbs_certificate().subject().to_der().unwrap()
    };
    let schemes = vec![
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::ECDSA_NISTP256_SHA256,
    ];
    let request = CertificateRequest::new(Some("host.example".into()), vec![name], schemes);
    assert_eq!(request.host(), Some("host.example"));
    assert_eq!(request.authority_names(), vec!["CN=Request CA".to_string()]);
    assert_eq!(request.key_types(), vec![KeyType::Rsa, KeyType::EcP256]);
    assert!(request.rsa_pss_required());
    assert_eq!(request.tls_version(), None);
    let with_pkcs1 = CertificateRequest::new(
        None,
        vec![],
        vec![
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ],
    );
    assert!(!with_pkcs1.rsa_pss_required());
    assert_eq!(
        with_pkcs1
            .with_tls_version(Some(TlsVersion::Tls13))
            .tls_version(),
        Some(TlsVersion::Tls13)
    );
}

#[test]
fn tls13_alone_tells_the_selector_the_version() {
    let ca = Ca::new("Version CA");
    for (minimum, expected) in [
        (TlsVersion::Tls13, Some(TlsVersion::Tls13)),
        (TlsVersion::Tls12, None),
    ] {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_in = Arc::clone(&seen);
        let selector = Selector::builder()
            .source(vec![
                identity(&ca.issue_client("v-one"), "one"),
                identity(&ca.issue_client("v-two"), "two"),
            ])
            .remember(false)
            .chooser(Arc::new(move |request, _| {
                seen_in.lock().unwrap().push(request.tls_version());
                Some(0)
            }))
            .build();
        let tls = Tls::builder()
            .trust(Trust::Disabled)
            .client_certificates(ClientCertificates::Selector(Arc::new(selector)))
            .minimum_version(minimum)
            .build()
            .unwrap();
        let config = tls.client_config("localhost").unwrap();
        let schemes = [SignatureScheme::ECDSA_NISTP256_SHA256];
        assert!(
            config
                .client_auth_cert_resolver
                .resolve(&[], &schemes)
                .is_some()
        );
        assert_eq!(*seen.lock().unwrap(), vec![expected]);
    }
}

#[test]
fn protocol_versions_bound_what_is_negotiated() {
    let ca = Ca::new("Versions CA");
    let server_leaf = ca.issue_server("localhost");
    let both = TlsServer::start(&server_leaf, &[], ClientAuth::Off);
    let only12 = TlsServer::start_with(
        &server_leaf,
        &[],
        ClientAuth::Off,
        &[&rustls::version::TLS12],
    );
    let build = |min, max| {
        Tls::builder()
            .trust(Trust::Roots(vec![ca.der()]))
            .minimum_version(min)
            .maximum_version(max)
            .build()
            .unwrap()
    };
    let get = |tls: &Tls, server: &TlsServer| {
        https_get(
            tls.client_config("localhost").unwrap(),
            server.addr,
            "localhost",
        )
    };

    get(&build(TlsVersion::Tls12, TlsVersion::Tls13), &both).unwrap();
    get(&build(TlsVersion::Tls12, TlsVersion::Tls12), &both).unwrap();
    get(&build(TlsVersion::Tls13, TlsVersion::Tls13), &both).unwrap();
    let negotiated = both.versions.lock().unwrap().clone();
    assert_eq!(
        negotiated,
        vec![
            Some(rustls::ProtocolVersion::TLSv1_3),
            Some(rustls::ProtocolVersion::TLSv1_2),
            Some(rustls::ProtocolVersion::TLSv1_3)
        ]
    );
    assert!(get(&build(TlsVersion::Tls13, TlsVersion::Tls13), &only12).is_err());
    get(&build(TlsVersion::Tls12, TlsVersion::Tls13), &only12).unwrap();

    let inverted = Tls::builder()
        .minimum_version(TlsVersion::Tls13)
        .maximum_version(TlsVersion::Tls12)
        .build();
    assert!(matches!(inverted, Err(Error::Tls(_))));
}

#[test]
fn a_bundle_file_or_directory_or_pem_text_replaces_the_system_trust() {
    let trusted = Ca::new("Bundle CA");
    let other = Ca::new("Other CA");
    let server = TlsServer::start(&trusted.issue_server("localhost"), &[], ClientAuth::Off);
    let pem = |ca: &Ca| {
        let body: String = rustls::pki_types::CertificateDer::from(ca.der().to_vec())
            .as_ref()
            .chunks(48)
            .map(|chunk| base64(chunk) + "\n")
            .collect();
        format!("-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n")
    };
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("ca.pem");
    std::fs::write(&file, pem(&trusted)).unwrap();
    let other_directory = tempfile::tempdir().unwrap();
    std::fs::write(other_directory.path().join("other.pem"), pem(&other)).unwrap();
    let empty = tempfile::tempdir().unwrap();

    let get = |trust: Trust| {
        let tls = Tls::builder().trust(trust).build()?;
        Ok::<_, Error>(https_get(
            tls.client_config("localhost")?,
            server.addr,
            "localhost",
        ))
    };
    assert!(get(Trust::Bundle(file)).unwrap().is_ok());
    assert!(
        get(Trust::Bundle(directory.path().to_path_buf()))
            .unwrap()
            .is_ok()
    );
    assert!(
        get(Trust::roots_from_pem(pem(&trusted).as_bytes()).unwrap())
            .unwrap()
            .is_ok()
    );
    assert!(
        get(Trust::Bundle(other_directory.path().to_path_buf()))
            .unwrap()
            .is_err()
    );
    assert!(matches!(
        get(Trust::Bundle(empty.path().to_path_buf())),
        Err(Error::Tls(_))
    ));
    assert!(matches!(
        get(Trust::Bundle("no-such-bundle.pem".into())),
        Err(Error::Io(_))
    ));
    assert!(matches!(
        Trust::roots_from_pem(b"nothing"),
        Err(Error::Credential(_))
    ));
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::new();
    for chunk in bytes.chunks(3) {
        let block = u32::from(chunk[0]) << 16
            | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..4 {
            text.push(if index <= chunk.len() {
                char::from(ALPHABET[(block >> (18 - 6 * index) & 63) as usize])
            } else {
                '='
            });
        }
    }
    text
}

#[test]
fn session_secrets_are_logged_only_when_asked() {
    let ca = Ca::new("Key Log CA");
    let server = TlsServer::start(&ca.issue_server("localhost"), &[], ClientAuth::Off);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("keys.log");
    let tls = Tls::builder()
        .trust(Trust::Roots(vec![ca.der()]))
        .key_log(KeyLogging::File(path.clone()))
        .build()
        .unwrap();
    assert_eq!(tls.non_defaults().len(), 1);
    https_get(
        tls.client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();
    let log = std::fs::read_to_string(&path).unwrap();
    assert!(
        log.lines()
            .any(|line| line.starts_with("CLIENT_TRAFFIC_SECRET_0 ")),
        "{log}"
    );

    let quiet = Tls::builder()
        .trust(Trust::Roots(vec![ca.der()]))
        .build()
        .unwrap();
    assert!(quiet.non_defaults().is_empty());
    assert_eq!(quiet.settings().key_log, KeyLogging::Off);
}

#[test]
fn the_per_host_configurations_are_bounded() {
    let ca = Ca::new("Cache CA");
    let mut settings = coqui_sslcontext::TlsSettings::default();
    settings.config_cache_capacity = 2;
    let tls = Tls::builder()
        .trust(Trust::Roots(vec![ca.der()]))
        .settings(settings)
        .build()
        .unwrap();
    let first = tls.client_config("a.example").unwrap();
    assert!(Arc::ptr_eq(
        &first,
        &tls.client_config("a.example").unwrap()
    ));
    tls.client_config("b.example").unwrap();
    tls.client_config("c.example").unwrap();
    assert!(!Arc::ptr_eq(
        &first,
        &tls.client_config("a.example").unwrap()
    ));
}
