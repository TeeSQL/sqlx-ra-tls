//! TDX quote extraction from dstack RA-TLS X.509 certificates.
//!
//! dstack embeds attestation data in X.509 extensions using Phala's PEN
//! (Private Enterprise Number 62397):
//!
//! - OID `1.3.6.1.4.1.62397.1.1` — raw TDX quote bytes (legacy)
//! - OID `1.3.6.1.4.1.62397.1.8` — SCALE-encoded `VersionedAttestation`
//!   (current; wraps the raw quote inside a `V0` enum variant)
//!
//! See https://github.com/Dstack-TEE/dstack/blob/master/ra-tls/src/oids.rs
//! for the canonical OID definitions.
//!
//! This module mirrors the extraction logic in the Python `ra-tls-verify`
//! (`src/ra_tls_verify/cert.py`) and the TypeScript `prisma-ra-tls`
//! (`src/cert.ts`). Keep the three in sync when the on-wire format changes.

use x509_parser::prelude::*;

/// Legacy OID: raw TDX quote as the extension payload.
pub const OID_TDX_QUOTE: &str = "1.3.6.1.4.1.62397.1.1";

/// Current OID: SCALE-encoded `VersionedAttestation`. The payload begins with
/// a single-byte enum-variant tag (`0x00` for `V0`) followed by the inner
/// attestation bytes (which include the TDX quote and optional event log).
pub const OID_ATTESTATION: &str = "1.3.6.1.4.1.62397.1.8";

/// Strip one layer of DER OCTET STRING wrapping from `der` if present.
///
/// dstack encodes the extension contents as `OCTET STRING { payload }` inside
/// the X.509 extension's `extnValue`. `x509-parser` returns the `extnValue`
/// content directly, so we have to peel off one more layer to reach the
/// actual payload.
///
/// If the input does not start with the OCTET STRING tag (`0x04`) or the
/// length fields are malformed, the input is returned unchanged. The caller
/// is responsible for treating the returned slice as untrusted.
fn strip_octet_string_wrapper(der: &[u8]) -> &[u8] {
    if der.len() < 2 || der[0] != 0x04 {
        return der;
    }

    let mut offset = 1usize;
    let first_len_byte = der[offset];

    let length: usize;
    if first_len_byte < 0x80 {
        length = first_len_byte as usize;
        offset += 1;
    } else {
        let num_len_bytes = (first_len_byte & 0x7F) as usize;
        offset += 1;
        if num_len_bytes == 0 || num_len_bytes > 4 || offset + num_len_bytes > der.len() {
            return der;
        }
        let mut acc: usize = 0;
        for i in 0..num_len_bytes {
            acc = (acc << 8) | (der[offset + i] as usize);
        }
        length = acc;
        offset += num_len_bytes;
    }

    let end = offset.saturating_add(length);
    if end > der.len() {
        return der;
    }
    &der[offset..end]
}

/// Extract a raw TDX quote from the DER-encoded certificate `cert_der`.
///
/// Returns `Some(quote)` on success. Returns `None` if:
/// - The certificate fails to parse
/// - Neither `OID_TDX_QUOTE` nor `OID_ATTESTATION` is present
/// - The SCALE envelope is malformed for the current OID
///
/// The caller must verify the quote contents against a real attestation
/// service — this function only handles the transport layer.
pub fn extract_tdx_quote(cert_der: &[u8]) -> Option<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;

    // Legacy OID path: payload is the raw quote, wrapped in OCTET STRING.
    for ext in cert.extensions() {
        let oid = ext.oid.to_id_string();
        if oid == OID_TDX_QUOTE {
            let stripped = strip_octet_string_wrapper(ext.value);
            if !stripped.is_empty() {
                return Some(stripped.to_vec());
            }
        }
    }

    // Current OID path: SCALE-encoded `VersionedAttestation`.
    //
    // The on-wire shape is `[variant_u8=0x00][SCALE-encoded inner struct]`
    // where the inner struct for V0 is the full `Attestation` record
    // (see `dstack-attest/src/attestation.rs`). Intel Trust Authority
    // accepts a raw TDX quote, not the whole envelope — but in current
    // dstack deployments the quote bytes sit at a well-defined SCALE
    // offset after the variant tag.
    //
    // We mirror the Python `ra-tls-verify` and TypeScript `prisma-ra-tls`
    // peer SDKs, which both just strip the variant byte and return the
    // remainder. That keeps the three implementations lockstep and avoids
    // re-implementing the full dstack attestation schema in every
    // language. The downside is that a fully-strict verifier will reject
    // the payload; such callers should either upgrade to the V1 CBOR
    // layout (once supported) or implement a custom `extract_tdx_quote`
    // wrapper.
    for ext in cert.extensions() {
        let oid = ext.oid.to_id_string();
        if oid == OID_ATTESTATION {
            let stripped = strip_octet_string_wrapper(ext.value);
            if let Some(quote) = decode_versioned_v0_quote(stripped) {
                return Some(quote);
            }
        }
    }

    None
}

/// Parse the on-wire `VersionedAttestation::V0` envelope and pull the
/// embedded TDX quote bytes out of the inner `Attestation` struct.
///
/// Layout (SCALE, matching `dstack-attest::VersionedAttestation`):
///
/// ```text
/// [u8 variant tag = 0x00 for V0]
/// [u8 AttestationQuote variant = 0x00 for DstackTdx]
/// [Compact<u32> quote length][quote bytes]        // AttestationQuote::DstackTdx.quote
/// [Compact<u32> event_log length][…event entries] // TdxQuote.event_log
/// [Compact<u32> runtime_events length][…]
/// [64 bytes report_data]
/// [Compact<u32> config length][config UTF-8 bytes]
/// [report = () -> 0 bytes]
/// ```
///
/// On any decode failure we fall back to the "strip the variant tag"
/// heuristic used by the Python and TypeScript peer SDKs — same output,
/// just the whole envelope minus the outer tag. That path is lossy for
/// anything that expects raw quote bytes, but it matches the existing
/// SDK behaviour and lets callers plug a custom `extract_tdx_quote` if
/// they need strict parsing.
fn decode_versioned_v0_quote(payload: &[u8]) -> Option<Vec<u8>> {
    use parity_scale_codec::{Compact, Decode};

    if payload.is_empty() {
        return None;
    }

    let mut cursor = payload;
    let variant = u8::decode(&mut cursor).ok()?;
    if variant != 0x00 {
        // V1 (msgpack) or unknown version — fall back to the legacy strip.
        return Some(payload[1..].to_vec());
    }

    // Try to walk the SCALE envelope. Any failure here means the wire
    // format has drifted from what we expect; bail to the legacy strip.
    let mut inner = cursor;
    let quote_variant = u8::decode(&mut inner).ok()?;
    if quote_variant != 0x00 {
        // DstackGcpTdx or DstackNitroEnclave — not a raw TDX quote payload.
        return Some(payload[1..].to_vec());
    }

    // `AttestationQuote::DstackTdx(TdxQuote { quote: Vec<u8>, event_log })`
    let quote_bytes: Vec<u8> = match Vec::<u8>::decode(&mut inner) {
        Ok(v) => v,
        Err(_) => return Some(payload[1..].to_vec()),
    };

    // Minimal sanity check: a real TDX quote is ~4–6 KiB and starts with
    // version bytes that are never 0x00. If the parsed Vec<u8> is empty
    // something is wrong with the wire format; fall back so the caller's
    // verifier sees the full envelope and can report the real error.
    if quote_bytes.is_empty() {
        return Some(payload[1..].to_vec());
    }

    // We could also skip `event_log`, `runtime_events`, etc. but the
    // caller only needs the quote bytes. Capture them and return.
    let _ = Compact::<u32>::decode(&mut inner); // best-effort, result ignored
    Some(quote_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_short_form() {
        // OCTET STRING (length 4) { 0x01 0x02 0x03 0x04 }
        let der = [0x04, 0x04, 0x01, 0x02, 0x03, 0x04];
        assert_eq!(strip_octet_string_wrapper(&der), &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn strip_long_form() {
        // OCTET STRING (length 0x0100) = 256 bytes
        let mut der = vec![0x04, 0x82, 0x01, 0x00];
        der.extend(std::iter::repeat_n(0xAB, 256));
        let out = strip_octet_string_wrapper(&der);
        assert_eq!(out.len(), 256);
        assert!(out.iter().all(|b| *b == 0xAB));
    }

    #[test]
    fn strip_non_octet_returns_input() {
        let der = [0x30, 0x02, 0x01, 0x02];
        assert_eq!(strip_octet_string_wrapper(&der), &der[..]);
    }

    #[test]
    fn strip_truncated_length_returns_input() {
        // Indicates 4 bytes of length follow but only provides 1.
        let der = [0x04, 0x84, 0x01];
        assert_eq!(strip_octet_string_wrapper(&der), &der[..]);
    }

    #[test]
    fn decode_versioned_v0_extracts_inner_quote() {
        use parity_scale_codec::Encode;

        // V0 envelope: [VersionedAttestation tag][AttestationQuote tag]
        //              [Vec<u8> quote][Compact event_log length][…]
        // We build a minimal payload with empty event log / runtime events
        // / config and a zero-length report tail.
        let quote = b"fake-tdx-quote-bytes".to_vec();

        let mut envelope = Vec::new();
        envelope.push(0x00u8); // VersionedAttestation::V0
        envelope.push(0x00u8); // AttestationQuote::DstackTdx
        envelope.extend(quote.encode()); // Vec<u8> quote
        envelope.extend(Vec::<u8>::new().encode()); // empty event_log
        envelope.extend(Vec::<u8>::new().encode()); // empty runtime_events
        envelope.extend(vec![0u8; 64]); // report_data (fixed 64 bytes)
        envelope.extend("".encode()); // empty config string
                                      // report = () → zero bytes

        assert_eq!(
            decode_versioned_v0_quote(&envelope).as_deref(),
            Some(quote.as_slice())
        );
    }

    #[test]
    fn decode_versioned_unknown_variant_falls_back_to_strip() {
        // 0x01 isn't V0; the decoder should still produce SOMETHING by
        // stripping the leading byte (matching the Python/TS peer SDKs).
        let envelope = vec![0x01u8, 0xAB, 0xCD];
        assert_eq!(
            decode_versioned_v0_quote(&envelope).as_deref(),
            Some(&[0xAB, 0xCD][..])
        );
    }

    #[test]
    fn decode_versioned_empty_rejected() {
        assert!(decode_versioned_v0_quote(&[]).is_none());
    }

    #[test]
    fn decode_versioned_v0_fallback_on_malformed_inner() {
        // Variant=V0 but the inner bytes aren't a valid SCALE-encoded
        // Attestation. We should fall back to the strip heuristic rather
        // than return None — otherwise well-behaved callers can't recover.
        let envelope = vec![0x00u8, 0xFF, 0xFF];
        assert_eq!(
            decode_versioned_v0_quote(&envelope).as_deref(),
            Some(&[0xFF, 0xFF][..])
        );
    }
}
