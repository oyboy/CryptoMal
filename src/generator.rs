use rand::rngs::OsRng;
use rand::TryRngCore;
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.try_fill_bytes(&mut bytes).expect("Error random generation");
    bytes
}
#[cfg(test)]
mod tests {
    use crate::generator::generate_random_bytes;
    use std::collections::HashSet;

    const COUNT: usize = 1000;
    #[test]
    fn statistical_test() {
        let mut generated_byte_sequences = HashSet::new();
        for _i in 0..COUNT {
            generated_byte_sequences.insert(generate_random_bytes(16));
        }
        assert_eq!(generated_byte_sequences.len(), COUNT);
    }
}