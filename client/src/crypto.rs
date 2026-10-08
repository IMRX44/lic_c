/// Client-side cryptography:
/// - Decrypt session key using HWID-derived wrapping key (AES-256-GCM)
/// - Verify Ed25519 token signature (server public key pinned at build time)

use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use zeroize::Zeroize;

/// The server's Ed25519 public key, pinned at compile time.
/// Replace this with your actual server public key (32 bytes as hex).
/// Generate with: `python3 -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; k=Ed25519PrivateKey.generate(); print(k.public_key().public_bytes_raw().hex())"`
pub const PINNED_SERVER_PUBLIC_KEY_HEX: &str =
    env!("SERVER_PUBLIC_KEY_HEX"); // set via RUSTFLAGS or build.rs

/// Decrypt the session key received from the server.
/// encrypted_hex: nonce(12 bytes) + ciphertext(32+16 bytes) — all hex-encoded
pub fn decrypt_session_key(
    encrypted_hex: &str,
    wrapping_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let data = hex::decode(encrypted_hex).map_err(|e| e.to_string())?;
    if data.len() < 12 + 16 {
        return Err("Encrypted key too short".to_string());
    }
    let nonce = Nonce::from_slice(&data[..12]);
    let key = Key::<Aes256Gcm>::from_slice(wrapping_key);
    let cipher = Aes256Gcm::new(key);
    cipher.decrypt(nonce, &data[12..]).map_err(|_| "Decryption failed (wrong HWID or license?)".to_string())
}

/// Verify an Ed25519 session token from the server.
/// token format: hex(payload) "." hex(signature)
pub fn verify_session_token(token: &str) -> Result<SessionClaims, String> {
    let parts: Vec<&str> = token.splitn(2, '.').collect();
    if parts.len() != 2 {
        return Err("Invalid token format".to_string());
    }

    let payload = hex::decode(parts[0]).map_err(|e| e.to_string())?;
    let sig_bytes = hex::decode(parts[1]).map_err(|e| e.to_string())?;

    if payload.len() < 144 {
        return Err("Token payload too short".to_string());
    }

    // Verify against pinned public key
    let pub_key_bytes = hex::decode(PINNED_SERVER_PUBLIC_KEY_HEX)
        .map_err(|_| "Invalid pinned public key")?;
    let verifying_key = VerifyingKey::from_bytes(
        &pub_key_bytes.try_into().map_err(|_| "Public key must be 32 bytes")?
    ).map_err(|e| e.to_string())?;

    let signature = Signature::from_slice(&sig_bytes).map_err(|e| e.to_string())?;
    verifying_key.verify(&payload, &signature).map_err(|_| "Signature verification failed")?;

    // Decode fields (must match server's build_session_token)
    let license_id = String::from_utf8_lossy(&payload[0..36]).trim().to_string();
    let hwid_hash   = String::from_utf8_lossy(&payload[36..100]).trim().to_string();
    let product_slug= String::from_utf8_lossy(&payload[100..132]).trim().to_string();
    let expires_at  = u64::from_be_bytes(payload[132..140].try_into().unwrap());
    let sequence    = u32::from_be_bytes(payload[140..144].try_into().unwrap());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if now > expires_at {
        return Err("Session token expired".to_string());
    }

    Ok(SessionClaims { license_id, hwid_hash, product_slug, expires_at, sequence })
}

#[derive(Debug, Clone)]
pub struct SessionClaims {
    pub license_id: String,
    pub hwid_hash: String,
    pub product_slug: String,
    pub expires_at: u64,
    pub sequence: u32,
}

/// Zeroize session key from memory when dropped.
pub struct SessionKey(pub Vec<u8>);

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
