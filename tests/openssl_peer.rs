#![cfg(unix)]

//! Mutual TLS against a peer that is not rustls: `openssl s_server -Verify 1`.
//!
//! Run with `COQUI_SSLCONTEXT_TEST_OPENSSL=1 cargo test --test openssl_peer -- --ignored`.

mod support;

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use coqui_sslcontext::{ClientCertificates, Identity, Tls, Trust};
use support::pem::pem;
use support::pki::{Ca, Leaf};
use support::tls_server::https_get;

struct SServer {
    child: Child,
    addr: SocketAddr,
}

impl Drop for SServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(directory: &std::path::Path, server: &Leaf, client_ca: &Ca) -> SServer {
    let path = |name: &str| directory.join(name);
    let chain: String = server
        .chain
        .iter()
        .map(|der| pem("CERTIFICATE", der.as_ref()))
        .collect();
    std::fs::write(path("server.pem"), chain).unwrap();
    std::fs::write(path("server.key"), pem("PRIVATE KEY", &server.key_pkcs8)).unwrap();
    std::fs::write(
        path("clients.pem"),
        pem("CERTIFICATE", client_ca.der().as_ref()),
    )
    .unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let child = Command::new("openssl")
        .args([
            "s_server",
            "-accept",
            &format!("127.0.0.1:{port}"),
            "-www",
            "-verify_return_error",
            "-Verify",
            "1",
        ])
        .arg("-cert")
        .arg(path("server.pem"))
        .arg("-key")
        .arg(path("server.key"))
        .arg("-CAfile")
        .arg(path("clients.pem"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("openssl runs");
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let started = Instant::now();
    while TcpStream::connect(addr).is_err() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "s_server did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    SServer { child, addr }
}

#[test]
#[ignore = "needs the openssl program; run with COQUI_SSLCONTEXT_TEST_OPENSSL=1 and --ignored"]
fn openssl_requires_and_verifies_the_client_certificate_this_crate_sends() {
    assert!(
        std::env::var_os("COQUI_SSLCONTEXT_TEST_OPENSSL").is_some(),
        "set COQUI_SSLCONTEXT_TEST_OPENSSL=1 to run this test"
    );
    let directory = tempfile::tempdir().unwrap();
    let server_ca = Ca::new("OpenSSL Server CA");
    let client_ca = Ca::new("OpenSSL Client CA");
    let server = start(
        directory.path(),
        &server_ca.issue_server("localhost"),
        &client_ca,
    );

    let get = |identity: Option<Identity>| {
        let builder = Tls::builder().trust(Trust::Roots(vec![server_ca.der()]));
        let tls = match identity {
            Some(identity) => builder.client_certificates(ClientCertificates::Identity(identity)),
            None => builder.client_certificates(ClientCertificates::None),
        }
        .build()
        .unwrap();
        https_get(
            tls.client_config("localhost").unwrap(),
            server.addr,
            "localhost",
        )
    };
    let identity = |leaf: &Leaf| Identity::from_der(&leaf.chain, &leaf.key_pkcs8).unwrap();

    let reply = get(Some(identity(&client_ca.issue_client("openssl-user")))).unwrap();
    assert!(reply.starts_with("HTTP/1.0 200 ok"), "{reply}");
    assert!(get(None).is_err(), "no certificate: refused");
    let stranger = Ca::new("Stranger CA");
    assert!(
        get(Some(identity(&stranger.issue_client("stranger")))).is_err(),
        "a certificate of another CA: refused"
    );
}
