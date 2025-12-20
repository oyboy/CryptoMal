#[cfg(test)]
mod gcm_integration {
    use cryptocore::gcm::Gcm;
    use rand::{Rng, rng};

    const KEY_HEX: &str = "00112233445566778899aabbccddeeff";
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;

    fn get_key() -> Vec<u8> {
        hex::decode(KEY_HEX).unwrap()
    }

    fn simulate_cli_encrypt(input_data: &[u8], aad: &[u8]) -> Vec<u8> {
        let key = get_key();
        let mut nonce = [0u8; NONCE_LEN];
        rng().fill(&mut nonce);

        let gcm = Gcm::new(&key);
        let (ciphertext, tag) = gcm.encrypt(&nonce, input_data, aad);

        let mut output = Vec::new();
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        output.extend_from_slice(&tag);
        output
    }


    fn simulate_cli_decrypt(file_content: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        if file_content.len() < NONCE_LEN + TAG_LEN {
            return None;
        }

        let key = get_key();
        let nonce = &file_content[0..NONCE_LEN];
        let tag_start = file_content.len() - TAG_LEN;
        let ciphertext = &file_content[NONCE_LEN..tag_start];
        let tag = &file_content[tag_start..];

        let gcm = Gcm::new(&key);
        gcm.decrypt(nonce, ciphertext, aad, tag)
    }

    #[test]
    fn test_gcm_file_io_roundtrip() {
        let samples: Vec<&[u8]> = vec![
            b"Short message",
            b"Exactly 16 bytes block",
            b"Long message spanning multiple blocks with GCM counter mode...",
            &[0u8; 5000], // Large zero buffer
        ];
        let aad_samples: Vec<&[u8]> = vec![b"", b"meta-data", b"headers"];

        for sample in samples {
            for aad in &aad_samples {
                // 1. Encrypt (Write to "file")
                let encrypted_file_bytes = simulate_cli_encrypt(sample, aad);

                // 2. Decrypt (Read from "file")
                let decrypted = simulate_cli_decrypt(&encrypted_file_bytes, aad);

                assert_eq!(decrypted.unwrap(), sample.to_vec(), "Roundtrip failed for len {}", sample.len());
            }
        }
    }

    #[test]
    fn test_gcm_aad_mismatch_failure() {
        let plaintext = b"Secret Financial Data";
        let aad_correct = b"Transaction: ID-123";
        let aad_wrong = b"Transaction: ID-999";

        let encrypted_file = simulate_cli_encrypt(plaintext, aad_correct);

        let result = simulate_cli_decrypt(&encrypted_file, aad_wrong);

        assert!(result.is_none(), "Decryption should fail when AAD mismatches");
    }

    #[test]
    fn test_gcm_file_tampering() {
        let plaintext = b"Critical System File";
        let aad = b"system";

        let mut encrypted_file = simulate_cli_encrypt(plaintext, aad);

        let mut tampered_nonce = encrypted_file.clone();
        tampered_nonce[0] ^= 0xFF;
        assert!(simulate_cli_decrypt(&tampered_nonce, aad).is_none(), "Should fail on nonce tamper");

        let mut tampered_cipher = encrypted_file.clone();
        let mid = encrypted_file.len() / 2;
        tampered_cipher[mid] ^= 0xAA;
        assert!(simulate_cli_decrypt(&tampered_cipher, aad).is_none(), "Should fail on ciphertext tamper");

        let mut tampered_tag = encrypted_file.clone();
        let last = tampered_tag.len() - 1;
        tampered_tag[last] ^= 0x01;
        assert!(simulate_cli_decrypt(&tampered_tag, aad).is_none(), "Should fail on tag tamper");
    }
    #[test]
    fn test_nonce_randomness() {
        let input = b"Data";
        let aad = b"";

        let file1 = simulate_cli_encrypt(input, aad);
        let file2 = simulate_cli_encrypt(input, aad);

        let nonce1 = &file1[0..12];
        let nonce2 = &file2[0..12];

        assert_ne!(nonce1, nonce2, "Nonces must be random and unique for each encryption");

        assert_ne!(file1, file2);
    }
    #[test]
    fn test_gcm_empty_aad_compatibility() {
        let plaintext = b"No metadata attached";
        let aad_empty = b"";

        let encrypted = simulate_cli_encrypt(plaintext, aad_empty);
        let decrypted = simulate_cli_decrypt(&encrypted, aad_empty);

        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[test]
    fn test_nist_zeros() {
        let key = vec![0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = vec![0u8; 16];
        let aad = vec![0u8; 0];

        let gcm = Gcm::new(&key);
        let (cipher, tag) = gcm.encrypt(&nonce, &plaintext, &aad);
        
        let decrypted = gcm.decrypt(&nonce, &cipher, &aad, &tag);
        assert_eq!(decrypted.unwrap(), plaintext);
    }
}