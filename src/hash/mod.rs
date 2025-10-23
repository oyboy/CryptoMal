pub trait Hasher {
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> String;
}
mod sha256;
mod sha3;

pub use sha256::Sha256;
pub use sha3::Sha3;