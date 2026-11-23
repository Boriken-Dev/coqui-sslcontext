# coqui-sslcontext

[![Version](https://img.shields.io/crates/v/coqui-sslcontext.svg)](https://crates.io/crates/coqui-sslcontext)
[![Rust version](https://img.shields.io/crates/msrv/coqui-sslcontext.svg)](https://crates.io/crates/coqui-sslcontext)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-sslcontext/blob/main/LICENSE)
[![Docs](https://img.shields.io/docsrs/coqui-sslcontext)](https://docs.rs/coqui-sslcontext)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-sslcontext/test.yaml)](https://github.com/Boriken-Dev/coqui-sslcontext/actions/workflows/test.yaml)

**rustls configurations that follow the system.** rustls configurations that follow the system: the OS trust store, client certificates held in OS keystores, server configurations, pins and a test CA.

## Features

- Under construction.

## Installation

```sh
cargo add --git https://github.com/Boriken-Dev/coqui-sslcontext coqui-sslcontext
```

| Feature | Adds | Default |
| --- | --- | --- |

## Quick start

Under construction.

## API overview

See [AGENTS.md](https://github.com/Boriken-Dev/coqui-sslcontext/blob/main/AGENTS.md).

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

### Releasing

No release is cut yet; the crate is consumed by git revision.

## License

MIT OR Apache-2.0, at your option. See [LICENSE](https://github.com/Boriken-Dev/coqui-sslcontext/blob/main/LICENSE).
