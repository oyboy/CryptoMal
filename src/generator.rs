use rand::rngs::OsRng;
use rand::TryRngCore;

const SALT_SIZE: usize = 32;
const IV_SIZE: usize = 16;
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.try_fill_bytes(&mut salt).expect("Error salt generation");
    salt
}
pub fn generate_iv() -> [u8; IV_SIZE] {
    let mut iv = [0u8; IV_SIZE];
    OsRng.try_fill_bytes(&mut iv).expect("Error iv generation");
    iv
}