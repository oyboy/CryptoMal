use std::io::{Error, ErrorKind};
use cryptocore::mac::hmac::Hmac;
const VERIFIER_SIZE: usize = 32;

pub fn create_verifier(key: &[u8], salt: &[u8; VERIFIER_SIZE]) -> Result<[u8; VERIFIER_SIZE], Error> {
    let mut hmac = Hmac::new(key, "sha256")
        .map_err(|e| Error::new(ErrorKind::Other, e))?;

    hmac.update(salt);

    let hex_output = hmac.finalize();
    let bytes = hex::decode(&hex_output)
        .map_err(|_| Error::new(ErrorKind::Other, "Failed to decode HMAC hex output"))?;

    if bytes.len() < VERIFIER_SIZE {
        return Err(Error::new(
            ErrorKind::Other,
            "HMAC output too short for verifier",
        ));
    }

    let mut verifier = [0u8; VERIFIER_SIZE];
    verifier.copy_from_slice(&bytes[..VERIFIER_SIZE]);
    Ok(verifier)
}

pub fn verify_key(
    candidate_key: &[u8],
    stored_verifier: &[u8; VERIFIER_SIZE],
    salt: &[u8; VERIFIER_SIZE],
) -> Result<bool, Error> {
    let expected = create_verifier(candidate_key, salt)?;
    Ok(expected == *stored_verifier)
}