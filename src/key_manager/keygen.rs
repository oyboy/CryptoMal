use std::io;
use pbkdf2::{pbkdf2_hmac};
use sha2::{Sha256};
const ITERATIONS: u32 = 10_000;
pub const KEY_LEN: usize = 16;
pub fn generate_key(password: &[u8], salt: &[u8], iterations: Option<u32>, key_len: Option<usize>) -> io::Result<Vec<u8>> {
    let kl = key_len.unwrap_or_else(|| KEY_LEN);
    let mut key = vec![0u8; kl];
    let iter = iterations.unwrap_or_else(|| ITERATIONS);
    pbkdf2_hmac::<Sha256>(password, salt, iter, &mut key);
    Ok(key)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_default_key_generation() {
        let password = b"password";
        let salt = b"unique_salt";
        let key = generate_key(password, salt, None, None).unwrap();
        assert_eq!(key.len(), KEY_LEN);
    }
    #[test]
    fn test_custom_key_length() {
        let password = b"password";
        let salt = b"unique_salt";
        let key = generate_key(password, salt, None, Some(48)).unwrap();
        assert_eq!(key.len(), 48);
    }
    #[test]
    fn test_custom_iterations() {
        let password = b"password";
        let salt = b"unique_salt";
        let key1 = generate_key(password, salt, Some(1_000), Some(32)).unwrap();
        let key2 = generate_key(password, salt, Some(200_000), Some(32)).unwrap();
        assert_ne!(key1, key2, "keys with different iteration counts must differ");
    }
    #[test]
    fn test_deterministic_output() {
        let password = b"password";
        let salt = b"unique_salt";
        let key1 = generate_key(password, salt, Some(100_000), Some(32)).unwrap();
        let key2 = generate_key(password, salt, Some(100_000), Some(32)).unwrap();
        assert_eq!(key1, key2, "same inputs must give the same result");
    }
    #[test]
    fn test_different_passwords_produce_different_keys() {
        let salt = b"unique_salt";
        let key1 = generate_key(b"password1", salt, None, Some(32)).unwrap();
        let key2 = generate_key(b"password2", salt, None, Some(32)).unwrap();
        assert_ne!(key1, key2, "different passwords must produce different keys");
    }
    #[test]
    fn test_different_salts_produce_different_keys() {
        let password = b"password";
        let key1 = generate_key(password, b"salt1", None, Some(32)).unwrap();
        let key2 = generate_key(password, b"salt2", None, Some(32)).unwrap();
        assert_ne!(key1, key2, "different salts must produce different keys");
    }
}