use sha2::Sha256;
use hmac::{Hmac, KeyInit, Mac};
use std::io::{Error, ErrorKind};
const VERIFIER_SIZE: usize = 32;
type HmacSha256 = Hmac<Sha256>;

pub fn create_verifier(key: &[u8], salt: &[u8; VERIFIER_SIZE]) -> Result<[u8; VERIFIER_SIZE], Error> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| Error::new(ErrorKind::Other, "Invalid key length"))?;
    mac.update(salt);
    let result = mac.finalize().into_bytes();
    let mut verifier = [0u8; VERIFIER_SIZE];
    verifier.copy_from_slice(&result[..VERIFIER_SIZE]);
    Ok(verifier)
}
pub fn verify_key(candidate_key: &[u8], stored_verifier: &[u8; VERIFIER_SIZE], salt: &[u8; VERIFIER_SIZE]) -> Result<bool, Error> {
    let expected = create_verifier(candidate_key, salt)?;
    Ok(expected == *stored_verifier)
}