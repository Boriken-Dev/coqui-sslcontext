#![cfg(all(feature = "pkcs11", unix))]

//! The PIN model against real PKCS #11 tokens: four SoftHSM tokens (`main`, `always-auth`,
//! `no-pin` and `asked`), created and filled by this test with `softhsm2-util` and `pkcs11-tool`
//! under a temporary configuration that only the child process sees.
//!
//! Run with `COQUI_SSLCONTEXT_TEST_PKCS11=1 cargo test --features pkcs11 --test pkcs11_tokens -- --ignored`.

mod support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use coqui_sslcontext::{
    ClientCertificates, Error, IdentitySource, Pin, PinAnswer, PinPurpose, Pkcs11Source, Secret,
    Selector, Tls, Trust,
};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use support::pki::Ca;
use support::tls_server::{ClientAuth, TlsServer, https_get};

const PIN: &str = "1234";
const SO_PIN: &str = "5678";
const TOKENS: [&str; 4] = ["main", "always-auth", "no-pin", "asked"];

fn module_path() -> PathBuf {
    [
        "/usr/lib64/pkcs11/libsofthsm2.so",
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/pkcs11/libsofthsm2.so",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|path| path.exists())
    .expect("libsofthsm2.so is installed")
}

fn run(program: &str, args: &[&str], config: &Path) -> String {
    let output = Command::new(program)
        .args(args)
        .env("SOFTHSM2_CONF", config)
        .output()
        .unwrap_or_else(|error| panic!("{program} runs: {error}"));
    assert!(
        output.status.success(),
        "{program} {args:?}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// `(label, slot, serial)` of every token `softhsm2-util --show-slots` lists.
fn show_slots(config: &Path) -> Vec<(String, u64, String)> {
    let text = run("softhsm2-util", &["--show-slots"], config);
    let (mut slot, mut serial, mut found) = (0_u64, String::new(), Vec::new());
    for line in text.lines().map(str::trim) {
        if let Some(number) = line.strip_prefix("Slot ")
            && let Ok(number) = number.trim().parse()
        {
            slot = number;
        } else if let Some(value) = line.strip_prefix("Serial number:") {
            serial = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("Label:") {
            found.push((value.trim().to_string(), slot, serial.clone()));
        }
    }
    found
}

fn parent() {
    let directory = tempfile::tempdir().unwrap();
    let dir = directory.path();
    let tokens = dir.join("tokens");
    std::fs::create_dir(&tokens).unwrap();
    let config = dir.join("softhsm2.conf");
    std::fs::write(
        &config,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\n",
            tokens.display()
        ),
    )
    .unwrap();

    let client_ca = Ca::new("Corp Client CA");
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "token-user");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let certificate = client_ca.sign_with(params, &key);
    let path = |name: &str| dir.join(name);
    std::fs::write(path("client.der"), &certificate).unwrap();
    std::fs::write(path("client.key.der"), key.serialize_der()).unwrap();
    std::fs::write(path("client.key.pem"), key.serialize_pem()).unwrap();
    std::fs::write(path("client-ca.der"), client_ca.der()).unwrap();
    // The key that demands the PIN for every signature is RSA: SoftHSM signs with a
    // hash-and-RSA mechanism in several parts, which a login in the middle of the operation needs.
    let output = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
        ])
        .arg(path("rsa.pem"))
        .output()
        .expect("openssl runs");
    assert!(output.status.success(), "openssl genpkey");
    let rsa = KeyPair::from_pem_and_sign_algo(
        &std::fs::read_to_string(path("rsa.pem")).unwrap(),
        &rcgen::PKCS_RSA_SHA256,
    )
    .unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "token-user");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    std::fs::write(path("rsa.cert.der"), client_ca.sign_with(params, &rsa)).unwrap();
    std::fs::write(path("rsa.key.der"), rsa.serialize_der()).unwrap();

    let module = module_path();
    let module = module.to_str().unwrap();
    let pkcs11_tool = |label: &str, extra: &[&str]| {
        let mut args = vec![
            "--module",
            module,
            "--token-label",
            label,
            "--login",
            "--pin",
            PIN,
        ];
        args.extend_from_slice(extra);
        run("pkcs11-tool", &args, &config);
    };
    for label in TOKENS {
        run(
            "softhsm2-util",
            &[
                "--init-token",
                "--free",
                "--label",
                label,
                "--pin",
                PIN,
                "--so-pin",
                SO_PIN,
            ],
            &config,
        );
        if label == "always-auth" {
            pkcs11_tool(
                label,
                &[
                    "--write-object",
                    path("rsa.key.der").to_str().unwrap(),
                    "--type",
                    "privkey",
                    "--label",
                    "client",
                    "--id",
                    "01",
                    "--always-auth",
                ],
            );
        } else {
            run(
                "softhsm2-util",
                &[
                    "--import",
                    path("client.key.pem").to_str().unwrap(),
                    "--token",
                    label,
                    "--label",
                    "client",
                    "--id",
                    "01",
                    "--pin",
                    PIN,
                ],
                &config,
            );
        }
        let certificate = if label == "always-auth" {
            "rsa.cert.der"
        } else {
            "client.der"
        };
        pkcs11_tool(
            label,
            &[
                "--write-object",
                path(certificate).to_str().unwrap(),
                "--type",
                "cert",
                "--label",
                "client",
                "--id",
                "01",
            ],
        );
    }
    let slots: String = show_slots(&config)
        .iter()
        .map(|(label, slot, serial)| format!("{label} {slot} {serial}\n"))
        .collect();
    std::fs::write(path("slots.txt"), slots).unwrap();

    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "four_tokens_follow_the_pin_model",
            "--ignored",
            "--nocapture",
        ])
        .env("SOFTHSM2_CONF", &config)
        .env("COQUI_SSLCONTEXT_TEST_PKCS11_DIR", dir)
        .env("COQUI_SSLCONTEXT_TEST_PKCS11_MODULE", module)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "the scenarios in the child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct World {
    module: String,
    server_ca: Ca,
    server: TlsServer,
    client_der: Vec<u8>,
    slots: BTreeMap<String, (u64, String)>,
}

impl World {
    fn source(&self, token: &str, pin: Pin) -> Pkcs11Source {
        Pkcs11Source::builder(&self.module)
            .pin(pin)
            .token_label(token)
            .build()
    }

    /// Whether a handshake that requires the client certificate succeeds with `source`.
    fn handshake(&self, source: Pkcs11Source) -> Result<(), String> {
        let tls = Tls::builder()
            .trust(Trust::Roots(vec![self.server_ca.der()]))
            .client_certificates(ClientCertificates::Selector(Arc::new(
                Selector::builder().source(source).build(),
            )))
            .build()
            .unwrap();
        let reply = https_get(
            tls.client_config("localhost").unwrap(),
            self.server.addr,
            "localhost",
        )?;
        assert!(reply.ends_with("client certificate seen"), "{reply}");
        Ok(())
    }
}

/// `(token, purpose, keystore_prompt)` of each PIN request a callback heard.
type Heard = Arc<Mutex<Vec<(String, PinPurpose, bool)>>>;

fn recording(pin: &'static str, seen: &Heard) -> Pin {
    let seen = Arc::clone(seen);
    Pin::callback(move |request| {
        seen.lock().unwrap().push((
            request.token().to_string(),
            request.purpose(),
            request.keystore_prompt(),
        ));
        PinAnswer::Secret(Secret::new(pin))
    })
}

fn child() {
    let dir = PathBuf::from(std::env::var("COQUI_SSLCONTEXT_TEST_PKCS11_DIR").unwrap());
    let module = std::env::var("COQUI_SSLCONTEXT_TEST_PKCS11_MODULE").unwrap();
    let slots: BTreeMap<String, (u64, String)> = std::fs::read_to_string(dir.join("slots.txt"))
        .unwrap()
        .lines()
        .map(|line| {
            let mut fields = line.split(' ');
            let label = fields.next().unwrap().to_string();
            let slot = fields.next().unwrap().parse().unwrap();
            (label, (slot, fields.next().unwrap().to_string()))
        })
        .collect();
    let server_ca = Ca::new("Scenario Server CA");
    let client_ca_der =
        rustls::pki_types::CertificateDer::from(std::fs::read(dir.join("client-ca.der")).unwrap());
    let server = TlsServer::start(
        &server_ca.issue_server("localhost"),
        &[client_ca_der],
        ClientAuth::Required,
    );
    let world = World {
        module,
        server_ca,
        server,
        client_der: std::fs::read(dir.join("client.der")).unwrap(),
        slots,
    };

    // The tokens, and the filters that narrow them.
    let all = Pkcs11Source::builder(&world.module).build();
    let mut labels = all.tokens().unwrap();
    labels.sort();
    let mut expected: Vec<String> = TOKENS.iter().map(|label| (*label).to_string()).collect();
    expected.sort();
    assert_eq!(labels, expected);
    let (slot, serial) = world.slots["asked"].clone();
    for source in [
        Pkcs11Source::builder(&world.module).slot(slot).build(),
        Pkcs11Source::builder(&world.module)
            .token_serial(&serial)
            .build(),
        Pkcs11Source::builder(&world.module).token("asked").build(),
        Pkcs11Source::builder(&world.module).token(&serial).build(),
    ] {
        assert_eq!(source.tokens().unwrap(), vec!["asked".to_string()]);
    }

    // main: a PIN given as a value signs; a callback hears about the listing and the signing.
    let identities = world.source("main", Pin::from(PIN)).identities().unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(
        identities[0].chain()[0].as_ref(),
        world.client_der.as_slice()
    );
    assert_eq!(identities[0].label(), "client");
    world
        .handshake(world.source("main", Pin::from(PIN)))
        .unwrap();
    assert_eq!(
        world.server.presented().last().unwrap().as_deref(),
        Some(world.client_der.as_slice())
    );

    // A wrong PIN is an error, and the source never sends a PIN again, not even a good one.
    let wrong = world.source("main", Pin::from("0000"));
    assert!(matches!(wrong.identities(), Err(Error::WrongPin)));
    assert!(matches!(wrong.identities(), Err(Error::WrongPin)));
    // One bad try leaves the token usable: it was tried once, not retried.
    world
        .handshake(world.source("main", Pin::from(PIN)))
        .unwrap();

    // always-auth: the key demands the PIN for every signature.
    let seen = Arc::new(Mutex::new(Vec::new()));
    world
        .handshake(world.source("always-auth", recording(PIN, &seen)))
        .unwrap();
    let purposes: Vec<PinPurpose> = seen.lock().unwrap().iter().map(|entry| entry.1).collect();
    assert!(purposes.contains(&PinPurpose::PerSignature), "{purposes:?}");
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .all(|entry| entry.0 == "always-auth")
    );
    // Without a PIN it cannot sign.
    assert!(
        world
            .handshake(world.source("always-auth", Pin::None))
            .is_err()
    );

    // no-pin: the source has no PIN to give, so the key cannot be used, and nothing is asked.
    assert!(world.handshake(world.source("no-pin", Pin::None)).is_err());
    let declined = Pin::callback(|_| PinAnswer::Decline);
    assert!(world.handshake(world.source("no-pin", declined)).is_err());
    // The keystore's own prompt needs a PIN pad, which SoftHSM does not have.
    assert!(
        world
            .handshake(world.source("no-pin", Pin::Keystore))
            .is_err()
    );

    // Two threads that each find a wrong PIN: the callback is asked once, because the first
    // rejection is recorded before the second thread asks.
    let asked = Arc::new(AtomicUsize::new(0));
    let counted = {
        let asked = Arc::clone(&asked);
        Pin::callback(move |_| {
            asked.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(200));
            PinAnswer::Secret(Secret::new("0000"))
        })
    };
    let shared = Arc::new(world.source("main", counted));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let source = Arc::clone(&shared);
            std::thread::spawn(move || source.identities())
        })
        .collect();
    for thread in threads {
        assert!(matches!(thread.join().unwrap(), Err(Error::WrongPin)));
    }
    assert!(matches!(shared.identities(), Err(Error::WrongPin)));
    assert_eq!(
        asked.load(Ordering::SeqCst),
        1,
        "the callback is not asked again"
    );

    // A login that fails in the middle of a signature leaves nothing active: the next one works.
    let decline = Arc::new(AtomicBool::new(true));
    let flaky = {
        let decline = Arc::clone(&decline);
        Pin::callback(move |request| {
            if request.purpose() == PinPurpose::PerSignature && decline.load(Ordering::SeqCst) {
                PinAnswer::Decline
            } else {
                PinAnswer::Secret(Secret::new(PIN))
            }
        })
    };
    let identity = world
        .source("always-auth", flaky)
        .identities()
        .unwrap()
        .remove(0);
    let tls = Tls::builder()
        .trust(Trust::Roots(vec![world.server_ca.der()]))
        .client_certificates(ClientCertificates::Identity(identity))
        .build()
        .unwrap();
    let get = || {
        https_get(
            tls.client_config("localhost").unwrap(),
            world.server.addr,
            "localhost",
        )
    };
    assert!(get().is_err(), "the per-signature login was declined");
    decline.store(false, Ordering::SeqCst);
    assert!(
        get().is_ok(),
        "the session was not left with an active operation"
    );

    // asked: the callback is told the token, never a PIN, and that there is no PIN pad.
    let seen = Arc::new(Mutex::new(Vec::new()));
    world
        .handshake(world.source("asked", recording(PIN, &seen)))
        .unwrap();
    let entries = seen.lock().unwrap().clone();
    assert!(entries.iter().any(|entry| entry.1 == PinPurpose::List));
    assert!(entries.iter().all(|entry| entry.0 == "asked" && !entry.2));
}

#[test]
#[ignore = "needs softhsm2-util, pkcs11-tool and SoftHSM; run with COQUI_SSLCONTEXT_TEST_PKCS11=1 and --ignored"]
fn four_tokens_follow_the_pin_model() {
    if std::env::var_os("COQUI_SSLCONTEXT_TEST_PKCS11_DIR").is_none() {
        assert!(
            std::env::var_os("COQUI_SSLCONTEXT_TEST_PKCS11").is_some(),
            "set COQUI_SSLCONTEXT_TEST_PKCS11=1 to run this test"
        );
        parent();
    } else {
        child();
    }
}
