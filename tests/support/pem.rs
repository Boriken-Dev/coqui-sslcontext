//! PEM text for DER bytes, so a test can write a file the library reads.

use std::fmt::Write;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(bytes: &[u8]) -> String {
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

/// `der` as a PEM block labelled `label`, lines of 64 characters.
pub fn pem(label: &str, der: &[u8]) -> String {
    let mut body = String::new();
    for line in base64(der).as_bytes().chunks(64) {
        writeln!(body, "{}", std::str::from_utf8(line).unwrap()).unwrap();
    }
    format!("-----BEGIN {label}-----\n{body}-----END {label}-----\n")
}
