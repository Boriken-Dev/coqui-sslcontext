mod support;

use std::sync::Arc;

use coqui_sslcontext::{
    AutoSelectRule, CertificateChoice, ClientCertificates, Identity, IdentityQuery, NameFilter,
    Selector, Tls, Trust,
};
use support::pki::{Ca, Leaf};
use support::tls_server::{ClientAuth, TlsServer, https_get};

fn identity(leaf: &Leaf, label: &str) -> Identity {
    let key = rustls::crypto::ring::sign::any_supported_type(&leaf.key()).unwrap();
    Identity::new(leaf.chain.clone(), key, label).unwrap()
}

struct World {
    ca: Ca,
    server: Leaf,
}

fn world() -> World {
    let ca = Ca::new("Test Server CA");
    let server = ca.issue_server("localhost");
    World { ca, server }
}

fn tls_with(world: &World, selector: Selector) -> Tls {
    Tls::builder()
        .trust(Trust::Roots(vec![world.ca.der()]))
        .client_certificates(ClientCertificates::Selector(Arc::new(selector)))
        .build()
        .unwrap()
}

#[test]
fn the_certificate_issued_under_a_ca_the_server_names_is_presented() {
    let w = world();
    let corp = Ca::new("Corp Client CA");
    let other = Ca::new("Some Other CA");
    let wanted = corp.issue_client("alice");
    let unwanted = other.issue_client("mallory");
    let server = TlsServer::start(&w.server, &[corp.der()], ClientAuth::Required);
    let selector = Selector::builder()
        .source(identity(&unwanted, "other"))
        .source(identity(&wanted, "corp"))
        .policy(Arc::new(|_| CertificateChoice::First))
        .build();
    let tls = tls_with(&w, selector);
    let reply = https_get(
        tls.client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();
    assert!(reply.ends_with("client certificate seen"), "{reply}");
    assert_eq!(server.presented(), [Some(wanted.leaf_der().to_vec())]);
}

#[test]
fn nothing_is_presented_when_no_certificate_fits_and_a_required_server_refuses_the_handshake() {
    let w = world();
    let corp = Ca::new("Corp Client CA");
    let other = Ca::new("Some Other CA");
    let server = TlsServer::start(&w.server, &[corp.der()], ClientAuth::Required);
    let selector = Selector::builder()
        .source(identity(&other.issue_client("mallory"), "other"))
        .build();
    let tls = tls_with(&w, selector);
    assert!(
        https_get(
            tls.client_config("localhost").unwrap(),
            server.addr,
            "localhost"
        )
        .is_err()
    );
    assert_eq!(server.presented(), []);
}

#[test]
fn an_expired_certificate_and_one_for_the_wrong_purpose_are_not_offered() {
    let w = world();
    let corp = Ca::new("Corp Client CA");
    let server = TlsServer::start(&w.server, &[corp.der()], ClientAuth::Optional);
    let selector = Selector::builder()
        .source(identity(&corp.issue_expired_client("old"), "expired"))
        .source(identity(
            &corp.issue_server_only_client("server-only"),
            "wrong purpose",
        ))
        .build();
    let tls = tls_with(&w, selector);
    let reply = https_get(
        tls.client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();
    assert!(reply.ends_with("no client certificate"), "{reply}");
    assert_eq!(server.presented(), [None]);
}

#[test]
fn several_candidates_send_none_until_a_rule_or_a_chooser_picks() {
    let w = world();
    let corp = Ca::new("Corp Client CA");
    let alice = corp.issue_client("alice");
    let bob = corp.issue_client("bob");
    let server = TlsServer::start(&w.server, &[corp.der()], ClientAuth::Optional);

    let ambiguous = Selector::builder()
        .source(identity(&alice, "alice"))
        .source(identity(&bob, "bob"))
        .build();
    let tls = tls_with(&w, ambiguous);
    https_get(
        tls.client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();

    let by_rule = Selector::builder()
        .source(identity(&alice, "alice"))
        .source(identity(&bob, "bob"))
        .rules([AutoSelectRule::builder("localhost")
            .subject(NameFilter::Attributes(vec![("CN".into(), "bob".into())]))
            .build()])
        .build();
    let tls = tls_with(&w, by_rule);
    https_get(
        tls.client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();

    let by_chooser = Selector::builder()
        .source(identity(&alice, "alice"))
        .source(identity(&bob, "bob"))
        .chooser(Arc::new(|_request, candidates| {
            candidates.iter().position(|c| c.label() == "alice")
        }))
        .build();
    let tls = tls_with(&w, by_chooser);
    https_get(
        tls.client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();

    assert_eq!(
        server.presented(),
        [
            None,
            Some(bob.leaf_der().to_vec()),
            Some(alice.leaf_der().to_vec())
        ]
    );
}

#[test]
fn an_identity_given_outright_is_sent_to_a_server_that_names_no_ca() {
    let w = world();
    let anyone = Ca::new("Anyone");
    let mine = anyone.issue_client("me");
    let server = TlsServer::start(&w.server, &[anyone.der()], ClientAuth::Required);
    let tls = Tls::builder()
        .trust(Trust::Roots(vec![w.ca.der()]))
        .client_certificates(ClientCertificates::Identity(identity(&mine, "given")))
        .build()
        .unwrap();
    let reply = https_get(
        tls.client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();
    assert!(reply.ends_with("client certificate seen"), "{reply}");
}

#[test]
fn the_choice_made_for_a_host_is_remembered_until_forgotten() {
    let w = world();
    let corp = Ca::new("Corp Client CA");
    let alice = corp.issue_client("alice");
    let bob = corp.issue_client("bob");
    let server = TlsServer::start(&w.server, &[corp.der()], ClientAuth::Optional);
    let pick_bob = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&pick_bob);
    let selector = Arc::new(
        Selector::builder()
            .source(identity(&alice, "alice"))
            .source(identity(&bob, "bob"))
            .chooser(Arc::new(move |_request, candidates| {
                let wanted = if flag.load(std::sync::atomic::Ordering::SeqCst) {
                    "bob"
                } else {
                    "alice"
                };
                candidates.iter().position(|c| c.label() == wanted)
            }))
            .build(),
    );
    // A configuration keeps its own TLS session cache, and a resumed session sends no
    // certificate, so each handshake here uses a configuration of its own.
    let tls = || {
        Tls::builder()
            .trust(Trust::Roots(vec![w.ca.der()]))
            .client_certificates(ClientCertificates::Selector(Arc::clone(&selector)))
            .build()
            .unwrap()
    };
    https_get(
        tls().client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();
    pick_bob.store(true, std::sync::atomic::Ordering::SeqCst);
    https_get(
        tls().client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();
    selector.forget(Some("localhost"));
    https_get(
        tls().client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();
    let alice_der = alice.leaf_der().to_vec();
    let bob_der = bob.leaf_der().to_vec();
    assert_eq!(
        server.presented(),
        [Some(alice_der.clone()), Some(alice_der), Some(bob_der)]
    );
}

#[test]
fn the_system_verifier_refuses_a_server_whose_ca_the_system_does_not_trust() {
    let w = world();
    let server = TlsServer::start(&w.server, &[], ClientAuth::Off);
    let tls = Tls::builder()
        .client_certificates(ClientCertificates::None)
        .build()
        .unwrap();
    let error = https_get(
        tls.client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap_err();
    assert!(!error.is_empty());
    assert_eq!(server.presented(), []);
}

#[test]
fn disabling_trust_is_reported_as_a_non_default_setting() {
    let tls = Tls::builder()
        .trust(Trust::Disabled)
        .client_certificates(ClientCertificates::None)
        .build()
        .unwrap();
    let settings = tls.non_defaults();
    assert_eq!(settings.len(), 1);
    assert_eq!(settings[0].setting, "trust");
    let default = Tls::builder()
        .client_certificates(ClientCertificates::None)
        .build()
        .unwrap();
    assert!(default.non_defaults().is_empty());
    let w = world();
    let server = TlsServer::start(&w.server, &[], ClientAuth::Off);
    let reply = https_get(
        tls.client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();
    assert!(reply.ends_with("no client certificate"));
}

#[test]
fn a_sole_fitting_certificate_is_not_sent_unasked() {
    let w = world();
    let corp = Ca::new("Corp Client CA");
    let alice = corp.issue_client("alice");
    let server = TlsServer::start(&w.server, &[corp.der()], ClientAuth::Optional);
    let selector = Selector::builder()
        .source(identity(&alice, "alice"))
        .build();
    let tls = tls_with(&w, selector);
    let reply = https_get(
        tls.client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();
    assert!(reply.ends_with("no client certificate"), "{reply}");
    assert_eq!(server.presented(), [None]);
}

fn presented_by(w: &World, corp: &Ca, selector: Selector) -> Option<Vec<u8>> {
    let server = TlsServer::start(&w.server, &[corp.der()], ClientAuth::Optional);
    let tls = tls_with(w, selector);
    https_get(
        tls.client_config("localhost").unwrap(),
        server.addr,
        "localhost",
    )
    .unwrap();
    server.presented().remove(0)
}

#[test]
fn a_certificate_policy_decides_per_host_and_can_send_none_first_or_a_pinned_identity() {
    let w = world();
    let corp = Ca::new("Corp Client CA");
    let alice = corp.issue_client("alice");
    let bob = corp.issue_client("bob");
    let with = |choice: CertificateChoice| {
        Selector::builder()
            .source(identity(&alice, "alice"))
            .source(identity(&bob, "bob"))
            .rules([AutoSelectRule::builder("localhost").build()])
            .policy(Arc::new(move |_| choice.clone()))
            .build()
    };
    // `None` beats a rule that matches the host.
    assert_eq!(presented_by(&w, &corp, with(CertificateChoice::None)), None);
    let first = presented_by(&w, &corp, with(CertificateChoice::First));
    assert!(first == Some(alice.leaf_der().to_vec()) || first == Some(bob.leaf_der().to_vec()));
    let pin = IdentityQuery::builder().label("bob").build();
    assert_eq!(
        presented_by(&w, &corp, with(CertificateChoice::Pin(pin))),
        Some(bob.leaf_der().to_vec())
    );
    let nobody = IdentityQuery::builder().label("nobody").build();
    assert_eq!(
        presented_by(&w, &corp, with(CertificateChoice::Pin(nobody))),
        None
    );
    // `Default` is the selector's own choice: here the rule matches the host.
    assert!(presented_by(&w, &corp, with(CertificateChoice::Default)).is_some());
}

#[test]
fn a_certificate_policy_is_given_the_server_host() {
    let w = world();
    let corp = Ca::new("Corp Client CA");
    let alice = corp.issue_client("alice");
    let selector = Selector::builder()
        .source(identity(&alice, "alice"))
        .policy(Arc::new(|host| {
            if host == "localhost" {
                CertificateChoice::First
            } else {
                CertificateChoice::None
            }
        }))
        .build();
    assert_eq!(
        presented_by(&w, &corp, selector),
        Some(alice.leaf_der().to_vec())
    );
}

#[test]
fn sending_the_sole_candidate_is_a_listed_weakening() {
    let w = world();
    let corp = Ca::new("Corp Client CA");
    let alice = corp.issue_client("alice");
    let selector = Selector::builder()
        .source(identity(&alice, "alice"))
        .send_sole_candidate(true)
        .build();
    assert_eq!(selector.non_defaults().len(), 1);
    let tls = tls_with(&w, selector);
    let listed = tls.non_defaults();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].setting, "client_certificates");
    assert_eq!(listed[0].value, "sole candidate sent unasked");
    assert!(
        Selector::builder().build().non_defaults().is_empty() && {
            let tls = Tls::builder().build().unwrap();
            tls.non_defaults().is_empty()
        }
    );
    let builder = Tls::builder().send_sole_candidate(true);
    assert_eq!(builder.non_defaults()[0].setting, "client_certificates");
    let sent = presented_by(
        &w,
        &corp,
        Selector::builder()
            .source(identity(&alice, "alice"))
            .send_sole_candidate(true)
            .build(),
    );
    assert_eq!(sent, Some(alice.leaf_der().to_vec()));
}
