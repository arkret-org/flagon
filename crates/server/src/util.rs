//! Small crate-wide helpers shared by otherwise unrelated modules.

/// Lowercase hex encoding of a byte string used by audit-chain diagnostics.
pub(crate) fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// HMAC-SHA256 tag encoded with the Arkret base64url-without-padding wire
/// convention used by every outbound teabay webhook.
pub(crate) fn webhook_hmac_signature(secret: &[u8], body: &[u8]) -> anyhow::Result<String> {
    use hmac::{Hmac, Mac};

    let mut mac = <Hmac<sha2::Sha256> as hmac::KeyInit>::new_from_slice(secret)?;
    mac.update(body);
    Ok(arkret_sdk::canonical::base64url_encode(
        mac.finalize().into_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_signature_uses_canonical_base64url_encoding() {
        let signature =
            webhook_hmac_signature(b"key", b"The quick brown fox jumps over the lazy dog").unwrap();
        assert_eq!(signature, "97yD9DBThCSxMpjmqm-xQ-9NWaFJRhdZl0edvC0aPNg");
    }
}
