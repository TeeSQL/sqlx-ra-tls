//! End-to-end test for [`sqlx_ra_tls::extract_tdx_quote`].
//!
//! Builds self-signed certificates with synthetic TDX-quote extensions
//! matching each of the two OIDs dstack uses today, then asserts the
//! extraction round-trips the quote bytes back to the caller.

use parity_scale_codec::Encode;
use rcgen::{CertificateParams, CustomExtension, KeyPair};
use sqlx_ra_tls::{extract_tdx_quote, OID_ATTESTATION, OID_TDX_QUOTE};

fn oid_to_u64s(s: &str) -> Vec<u64> {
    s.split('.').map(|p| p.parse::<u64>().unwrap()).collect()
}

fn wrap_octet_string(content: &[u8]) -> Vec<u8> {
    // DER OCTET STRING (tag 0x04). We only need to support content sizes
    // representative of real TDX quotes (<= 64 KiB) so the multi-byte
    // length form covers the range.
    let mut out = Vec::with_capacity(content.len() + 5);
    out.push(0x04);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    } else {
        panic!("payload too large for test helper");
    }
    out.extend_from_slice(content);
    out
}

fn generate_cert(extensions: Vec<CustomExtension>) -> Vec<u8> {
    let key_pair = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["ra-tls-test.invalid".to_string()]).unwrap();
    params.custom_extensions = extensions;
    let cert = params.self_signed(&key_pair).unwrap();
    cert.der().to_vec()
}

#[test]
fn extracts_legacy_oid_quote() {
    let quote = b"LEGACY-TDX-QUOTE-PAYLOAD";
    let ext =
        CustomExtension::from_oid_content(&oid_to_u64s(OID_TDX_QUOTE), wrap_octet_string(quote));
    let der = generate_cert(vec![ext]);

    let extracted = extract_tdx_quote(&der).expect("legacy quote should parse");
    assert_eq!(extracted, quote);
}

#[test]
fn extracts_current_oid_scale_envelope() {
    // Matches the full SCALE-encoded `VersionedAttestation::V0` layout
    // used by real dstack sidecars — variant tag, inner AttestationQuote
    // tag, Vec<u8> quote, empty event log, empty runtime events,
    // 64-byte report_data, empty config string, unit report.
    let quote = b"MODERN-TDX-QUOTE-FROM-DSTACK-SIDECAR".to_vec();

    let mut envelope = Vec::new();
    envelope.push(0x00u8); // VersionedAttestation::V0
    envelope.push(0x00u8); // AttestationQuote::DstackTdx
    envelope.extend(quote.encode()); // Vec<u8> quote
    envelope.extend(Vec::<u8>::new().encode()); // TdxQuote.event_log
    envelope.extend(Vec::<u8>::new().encode()); // Attestation.runtime_events
    envelope.extend(vec![0u8; 64]); // Attestation.report_data
    envelope.extend("".encode()); // Attestation.config

    let ext = CustomExtension::from_oid_content(
        &oid_to_u64s(OID_ATTESTATION),
        wrap_octet_string(&envelope),
    );
    let der = generate_cert(vec![ext]);

    let extracted = extract_tdx_quote(&der).expect("versioned quote should parse");
    assert_eq!(extracted, quote);
}

#[test]
fn returns_none_when_no_attestation_extension_present() {
    let der = generate_cert(vec![]);
    assert!(extract_tdx_quote(&der).is_none());
}

#[test]
fn returns_none_for_malformed_cert() {
    assert!(extract_tdx_quote(b"not a certificate").is_none());
}

#[test]
fn legacy_oid_preferred_over_current_when_both_present() {
    let legacy = b"LEGACY-QUOTE".to_vec();
    let modern = b"MODERN-QUOTE".to_vec();

    let mut envelope = Vec::new();
    envelope.push(0x00u8);
    envelope.push(0x00u8);
    envelope.extend(modern.encode());
    envelope.extend(Vec::<u8>::new().encode());
    envelope.extend(Vec::<u8>::new().encode());
    envelope.extend(vec![0u8; 64]);
    envelope.extend("".encode());

    let ext_legacy =
        CustomExtension::from_oid_content(&oid_to_u64s(OID_TDX_QUOTE), wrap_octet_string(&legacy));
    let ext_modern = CustomExtension::from_oid_content(
        &oid_to_u64s(OID_ATTESTATION),
        wrap_octet_string(&envelope),
    );

    let der = generate_cert(vec![ext_legacy, ext_modern]);
    let extracted = extract_tdx_quote(&der).expect("at least one quote should parse");

    // Order of preference mirrors the Python/TypeScript SDKs, which try
    // the legacy OID first. If we change the Rust ordering we should
    // update the peer SDKs too.
    assert_eq!(extracted, legacy);
}
