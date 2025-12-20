use std::io::{Write, Read};
use cryptocore::cryptor::{encrypt_file, decrypt_file, CipherMode};
use cryptocore::generator;
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;
    use crate::generator;

    const TEST_KEY_BYTES: &[u8] = b"1234567890ABCDEF";
    const IV_SIZE: usize = 16;
    const MODES: &[CipherMode] = &[
        CipherMode::ECB,
        CipherMode::CBC,
        CipherMode::CTR,
        CipherMode::OFB,
    ];

    fn roundtrip(mode: CipherMode, data: &[u8]) {
        let mut input = NamedTempFile::new().unwrap();
        input.write_all(data).unwrap();
        input.flush().unwrap();

        let encrypted = NamedTempFile::new().unwrap();
        let decrypted = NamedTempFile::new().unwrap();

        let iv = if matches!(mode, CipherMode::ECB) {
            vec![0u8; IV_SIZE]
        } else {
            generator::generate_random_bytes(IV_SIZE)
        };

        encrypt_file(
            input.path().to_str().unwrap(),
            encrypted.path().to_str().unwrap(),
            None,  // password
            Some(TEST_KEY_BYTES),
            mode,
            iv.clone(),
        ).unwrap();

        decrypt_file(
            encrypted.path().to_str().unwrap(),
            decrypted.path().to_str().unwrap(),
            None,  // password
            Some(TEST_KEY_BYTES),
            mode,
            iv,
        ).unwrap();

        let mut buf = Vec::new();
        fs::File::open(decrypted.path()).unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(buf, data, "mismatch for mode {mode:?}");
    }

    #[test]
    fn test_all_modes_roundtrip() {
        let samples: Vec<Vec<u8>> = vec![
            b"short".to_vec(),
            b"exactly16bytes!".to_vec(),
            b"longer test string that spans multiple blocks and checks PKCS7 padding".to_vec(),
            vec![0u8; 10_000],
        ];

        for &mode in MODES {
            for sample in &samples {
                roundtrip(mode, sample);
            }
        }
    }
}