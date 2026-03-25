//! Stateless session token authentication for the dashboard.
//! Tokens are HMAC-SHA256 signed and contain username + expiry.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Create a session token: base64(username:expiry_unix:hmac_hex)
pub fn create_session_token(username: &str, secret: &str, ttl_hours: u64) -> String {
    use base64::Engine;
    let expiry = chrono::Utc::now().timestamp() + (ttl_hours as i64 * 3600);
    let payload = format!("{username}:{expiry}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(payload.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    base64::engine::general_purpose::STANDARD.encode(format!("{payload}:{signature}"))
}

/// Verify a session token. Returns the username if valid and not expired.
pub fn verify_session_token(token: &str, secret: &str) -> Option<String> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token)
        .ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let parts: Vec<&str> = decoded_str.splitn(3, ':').collect();
    if parts.len() != 3 {
        return None;
    }
    let (username, expiry_str, provided_sig) = (parts[0], parts[1], parts[2]);

    let expiry: i64 = expiry_str.parse().ok()?;
    if chrono::Utc::now().timestamp() > expiry {
        return None;
    }

    let payload = format!("{username}:{expiry_str}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(payload.as_bytes());
    let expected_sig = hex::encode(mac.finalize().into_bytes());

    use subtle::ConstantTimeEq;
    if provided_sig.len() != expected_sig.len() {
        return None;
    }
    if provided_sig
        .as_bytes()
        .ct_eq(expected_sig.as_bytes())
        .into()
    {
        Some(username.to_string())
    } else {
        None
    }
}

/// Hash a password with Argon2id (salted, memory-hard).
pub fn hash_password(password: &str) -> String {
    use argon2::password_hash::{rand_core::OsRng, SaltString};
    use argon2::{Argon2, PasswordHasher};
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("Argon2 hash")
        .to_string()
}

/// Compare two secrets in constant time using fixed-width digests.
///
/// Both inputs are hashed to SHA-256 (fixed 32 bytes) before comparison,
/// eliminating length oracles that leak information about the expected secret.
pub fn fixed_width_eq(a: &str, b: &str) -> bool {
    use sha2::Digest;
    use subtle::ConstantTimeEq;
    let hash_a = Sha256::digest(a.as_bytes());
    let hash_b = Sha256::digest(b.as_bytes());
    hash_a.ct_eq(&hash_b).into()
}

/// Verify a password against a stored hash.
///
/// Supports both Argon2id (preferred) and legacy SHA-256 hex hashes
/// for backward compatibility during migration.
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    if stored_hash.starts_with("$argon2") {
        use argon2::{Argon2, PasswordHash, PasswordVerifier};
        let Ok(parsed) = PasswordHash::new(stored_hash) else {
            return false;
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    } else {
        // Legacy SHA-256 fallback
        use sha2::Digest;
        let computed = hex::encode(Sha256::digest(password.as_bytes()));
        fixed_width_eq(&computed, stored_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_password() {
        let hash = hash_password("secret123");
        assert!(verify_password("secret123", &hash));
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn test_create_and_verify_token() {
        let token = create_session_token("admin", "my-secret", 1);
        let user = verify_session_token(&token, "my-secret");
        assert_eq!(user, Some("admin".to_string()));
    }

    #[test]
    fn test_token_wrong_secret() {
        let token = create_session_token("admin", "my-secret", 1);
        let user = verify_session_token(&token, "wrong-secret");
        assert_eq!(user, None);
    }

    #[test]
    fn test_token_invalid_base64() {
        let user = verify_session_token("not-valid-base64!!!", "secret");
        assert_eq!(user, None);
    }

    #[test]
    fn test_password_hash_length_mismatch() {
        assert!(!verify_password("x", "short"));
    }

    #[test]
    fn test_b4_password_hash_is_salted() {
        // B4: Unsalted SHA-256 means the same password always produces the same hash.
        // A proper password hash (Argon2, bcrypt, etc.) uses a random salt,
        // so hashing the same password twice must produce different outputs.
        let hash1 = hash_password("my-password");
        let hash2 = hash_password("my-password");
        assert_ne!(
            hash1, hash2,
            "B4: password hash must be salted — same input must produce different hashes"
        );
    }

    #[test]
    fn test_b4_password_hash_not_plain_sha256() {
        // B4: SHA-256 produces a 64-char hex string. A proper password hash
        // includes algorithm metadata (e.g. "$argon2id$...") and is longer.
        let hash = hash_password("test");
        assert!(
            hash.len() > 64,
            "B4: password hash should not be plain SHA-256 (64 hex chars), got length {}",
            hash.len()
        );
    }

    #[test]
    fn test_b10_fixed_width_eq_correct() {
        // B10: Comparing secrets must use fixed-width digests to eliminate length oracles.
        // A `fixed_width_eq` function should hash both inputs to SHA-256 (fixed 32 bytes)
        // before constant-time comparison, so input length never leaks.
        assert!(fixed_width_eq("secret", "secret"));
        assert!(!fixed_width_eq("secret", "wrong"));
        assert!(!fixed_width_eq("secret", "secre")); // different length, no short-circuit
        assert!(!fixed_width_eq("secret", "secrets")); // different length, no short-circuit
        assert!(!fixed_width_eq("", "x"));
    }
}
