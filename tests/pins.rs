//! Public key pins: checked in addition to verification, or alone for a self-signed peer.

mod support;

use coqui_sslcontext::{ClientCertificates, Error, Pins, Tls, TlsBuilder, Trust};
use rcgen::{CertificateParams, KeyPair, date_time_ymd};
use sha2::{Digest, Sha256};
use support::pki::{Ca, Leaf};
use support::tls_server::{ClientAuth, TlsServer, https_get};

fn self_signed(names: &[&str], expired: bool) -> Leaf {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(
        names
            .iter()
            .map(|name| (*name).to_string())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    if expired {
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(2021, 1, 1);
    }
    let certificate = params.self_signed(&key).unwrap();
    Leaf {
        chain: vec![certificate.der().clone()],
        key_pkcs8: key.serialize_der(),
    }
}

fn builder() -> TlsBuilder {
    Tls::builder().client_certificates(ClientCertificates::None)
}

fn get(tls: &Tls, server: &TlsServer, host: &str) -> Result<String, String> {
    https_get(tls.client_config(host).unwrap(), server.addr, host)
}

fn base64(bytes: &[u8]) -> String {
    support::pem::pem("X", bytes)
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect()
}

#[test]
fn a_pinned_self_signed_peer_is_accepted_by_its_key_and_name() {
    let leaf = self_signed(&["localhost"], false);
    let server = TlsServer::start(&leaf, &[], ClientAuth::Off);
    let pins = Pins::new().with_certificate(leaf.leaf_der()).unwrap();
    let tls = builder().trust(Trust::Pinned(pins)).build().unwrap();
    assert!(
        get(&tls, &server, "localhost")
            .unwrap()
            .ends_with("no client certificate")
    );
    // The name is still checked.
    assert!(get(&tls, &server, "other.example").is_err());
    // Pinning is stricter than the default and is not a setting to flag.
    assert!(tls.non_defaults().is_empty());
}

#[test]
fn a_self_signed_peer_with_another_key_or_an_expired_certificate_is_refused() {
    let leaf = self_signed(&["localhost"], false);
    let stranger = self_signed(&["localhost"], false);
    let server = TlsServer::start(&stranger, &[], ClientAuth::Off);
    let pins = Pins::new().with_certificate(leaf.leaf_der()).unwrap();
    let tls = builder().trust(Trust::Pinned(pins)).build().unwrap();
    assert!(get(&tls, &server, "localhost").is_err());

    let expired = self_signed(&["localhost"], true);
    let server = TlsServer::start(&expired, &[], ClientAuth::Off);
    let pins = Pins::new().with_certificate(expired.leaf_der()).unwrap();
    let tls = builder().trust(Trust::Pinned(pins)).build().unwrap();
    assert!(get(&tls, &server, "localhost").is_err());

    assert!(matches!(
        builder().trust(Trust::Pinned(Pins::new())).build(),
        Err(Error::Tls(_))
    ));
}

#[test]
fn pins_are_checked_in_addition_to_verification() {
    let ca = Ca::new("Pinned CA");
    let leaf = ca.issue_server("localhost");
    let server = TlsServer::start(&leaf, &[], ClientAuth::Off);
    let tls = |pins: Pins| {
        builder()
            .trust(Trust::Roots(vec![ca.der()]))
            .pins(pins)
            .build()
            .unwrap()
    };

    // The server's own key, or the CA's (which the server sends in its chain), satisfies a pin.
    let own = Pins::new().with_certificate(leaf.leaf_der()).unwrap();
    assert!(get(&tls(own), &server, "localhost").is_ok());
    let issuer = Pins::new().with_certificate(ca.der().as_ref()).unwrap();
    assert!(get(&tls(issuer), &server, "localhost").is_ok());
    // Several pins: one match is enough.
    let several = Pins::new()
        .with_digest([7; 32])
        .with_certificate(leaf.leaf_der())
        .unwrap();
    assert!(get(&tls(several), &server, "localhost").is_ok());

    // Verification still applies: a pinned key that the trust does not vouch for is refused.
    let untrusted = TlsServer::start(&self_signed(&["localhost"], false), &[], ClientAuth::Off);
    let pins = Pins::new().with_digest([7; 32]);
    assert!(
        get(&tls(pins), &server, "localhost").is_err(),
        "no certificate is pinned"
    );
    let other = self_signed(&["localhost"], false);
    let pinned_but_untrusted = Pins::new().with_certificate(other.leaf_der()).unwrap();
    assert!(get(&tls(pinned_but_untrusted), &untrusted, "localhost").is_err());

    assert!(matches!(
        builder()
            .trust(Trust::Roots(vec![ca.der()]))
            .pins(Pins::new())
            .build(),
        Err(Error::Tls(_))
    ));
}

#[test]
fn pins_are_read_from_base64_hex_and_curl_forms_and_written_back() {
    let leaf = self_signed(&["localhost"], false);
    let digest: [u8; 32] = {
        use x509_cert::der::{Decode, Encode};
        let certificate = x509_cert::Certificate::from_der(leaf.leaf_der()).unwrap();
        let spki = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .unwrap();
        Sha256::digest(spki).into()
    };
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    let colons: Vec<String> = digest.iter().map(|byte| format!("{byte:02X}")).collect();
    let b64 = base64(&digest);
    for text in [
        format!("sha256/{b64}"),
        format!("sha256//{b64}"),
        format!("SHA256/{b64}"),
        format!("sha256:{hex}"),
        format!("sha256:{}", colons.join(":")),
        hex.clone(),
    ] {
        let pins = Pins::parse(&text).unwrap_or_else(|error| panic!("{text}: {error}"));
        assert!(pins.matches(leaf.leaf_der()), "{text}");
        assert!(!pins.matches(self_signed(&["localhost"], false).leaf_der()));
    }
    let both = Pins::parse(&format!("sha256/{b64}, {hex};  sha256:{hex}")).unwrap();
    assert_eq!(both.to_entries().len(), 3);
    assert_eq!(Pins::parse(&both.to_entries().join(",")).unwrap(), both);

    for bad in [
        "",
        "   ",
        "sha256/!!!",
        "sha256/AAAA",
        "md5/AAAA",
        "zz",
        "sha256:12",
    ] {
        let error = Pins::parse(bad).unwrap_err();
        assert!(matches!(error, Error::Credential(_)), "{bad}: {error}");
        assert!(!error.to_string().contains("AAAA"));
    }
    assert!(!Pins::new().matches(b"not a certificate"));
    assert!(Pins::new().with_certificate(b"not a certificate").is_err());
}

#[test]
fn a_pinned_certificate_appended_to_the_chain_does_not_satisfy_a_pin() {
    let ca = Ca::new("Chain CA");
    let unrelated = Ca::new("Public Intermediate");
    let mut leaf = ca.issue_server("localhost");
    leaf.chain.push(unrelated.der());
    let server = TlsServer::start(&leaf, &[], ClientAuth::Off);
    let tls = |pins: Pins| {
        builder()
            .trust(Trust::Roots(vec![ca.der()]))
            .pins(pins)
            .build()
            .unwrap()
    };
    let appended = Pins::new()
        .with_certificate(unrelated.der().as_ref())
        .unwrap();
    assert!(get(&tls(appended), &server, "localhost").is_err());
    // The CA that really issued the leaf still satisfies a pin.
    let issuer = Pins::new().with_certificate(ca.der().as_ref()).unwrap();
    assert!(get(&tls(issuer), &server, "localhost").is_ok());
}

#[test]
fn pins_beside_disabled_trust_are_refused() {
    let leaf = self_signed(&["localhost"], false);
    let pins = Pins::new().with_certificate(leaf.leaf_der()).unwrap();
    let built = builder().trust(Trust::Disabled).pins(pins).build();
    assert!(matches!(built, Err(Error::Tls(_))));
}
