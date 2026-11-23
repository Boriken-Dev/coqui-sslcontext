#![cfg(all(windows, feature = "system"))]

mod support;

use std::sync::Arc;

use coqui_sslcontext::{ClientCertificates, CngSource, IdentitySource, Selector, Tls, Trust};
use support::cng_store::{KeyGuard, import};
use support::pki::Ca;
use support::tls_server::{ClientAuth, TlsServer, https_get};

#[test]
#[ignore = "imports a key into an in-memory Windows store; run with COQUI_SSLCONTEXT_TEST_CNG=1 and --ignored"]
fn a_certificate_and_key_held_by_a_windows_store_answer_a_servers_certificate_request() {
    assert!(
        std::env::var_os("COQUI_SSLCONTEXT_TEST_CNG").is_some(),
        "set COQUI_SSLCONTEXT_TEST_CNG=1 to run this test"
    );
    let server_ca = Ca::new("Server CA");
    let client_ca = Ca::new("Corp Client CA");
    let client = client_ca.issue_client("keystore-user");
    let server = TlsServer::start(
        &server_ca.issue_server("localhost"),
        &[client_ca.der()],
        ClientAuth::Required,
    );

    let store = import(&client);
    let _keys = KeyGuard(Arc::clone(&store));
    // A software key signs silently, so no PIN is ever asked for: the policy can be none.
    let source = CngSource::from_store(store, "test store").pin(coqui_sslcontext::Pin::None);
    // The store holds the leaf and its CA; only the leaf has a key.
    assert_eq!(source.identities().unwrap().len(), 1);

    let tls = Tls::builder()
        .trust(Trust::Roots(vec![server_ca.der()]))
        .client_certificates(ClientCertificates::Selector(Arc::new(
            Selector::builder().source(source).build(),
        )))
        .build()
        .unwrap();
    let reply = https_get(
        tls.client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();
    assert!(reply.ends_with("client certificate seen"), "{reply}");
    assert_eq!(server.presented(), [Some(client.leaf_der().to_vec())]);
}

#[test]
fn the_current_users_personal_store_opens_and_lists_without_prompting() {
    let source = CngSource::current_user("MY").expect("the personal store opens");
    // What it holds depends on the machine; listing must not fail or prompt.
    let _ = source.identities().unwrap();
}
