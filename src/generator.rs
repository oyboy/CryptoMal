use rand::rngs::OsRng;
use rand::TryRngCore;
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.try_fill_bytes(&mut bytes).expect("Error random generation");
    bytes
}
#[cfg(test)]
mod tests {
    use super::generate_random_bytes;
    use std::collections::HashSet;
    use std::fs::File;
    use std::io::Write;

    const COUNT: usize = 1000;
    const KEY_LEN: usize = 16;
    const NIST_FILE_SIZE: usize = 10_000_000;  // 10 MB

    #[test]
    fn statistical_test() { 
        let mut generated_byte_sequences = HashSet::new();
        for _i in 0..COUNT {
            let key = generate_random_bytes(KEY_LEN);
            generated_byte_sequences.insert(key);
        }
        assert_eq!(generated_byte_sequences.len(), COUNT, "Duplicates found! CSPRNG flaw.");
    }

    #[test]
    fn hamming_weight_test() {
        let mut total_bits_set = 0;
        let total_bits = COUNT * KEY_LEN * 8; 
        for _i in 0..COUNT {
            let key = generate_random_bytes(KEY_LEN);
            for &byte in &key {
                total_bits_set += byte.count_ones() as usize;
            }
        }
        let avg_percentage = (total_bits_set as f64 / total_bits as f64) * 100.0;
        assert!((45.0..=55.0).contains(&avg_percentage), "Avg Hamming weight not ~50%: {:.2}%", avg_percentage);
    }

    #[test]
    fn generate_nist_data() {
        let mut file = File::create("nist_test_data.bin").expect("Failed to create NIST file");
        let mut written = 0;
        while written < NIST_FILE_SIZE {
            let chunk_size = std::cmp::min(4096, NIST_FILE_SIZE - written);
            let chunk = generate_random_bytes(chunk_size);
            file.write_all(&chunk).expect("Failed to write chunk");
            written += chunk_size;
        }
        println!("Generated {} bytes for NIST testing in 'nist_test_data.bin'", written);
    }
}