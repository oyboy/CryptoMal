use rand::Rng;
const SALT_SIZE: usize = 32;
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    rand::rng().fill(&mut salt);
    salt
}