#[cfg(test)]
mod tests {
    use cryptocore::cryptor::{encrypt_file, CipherMode};
    use cryptocore::gcm::Gcm;
    use std::fs::File;
    use std::io::{Write, Read};
    use tempfile::NamedTempFile;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn test_aes_ecb_nist_sp800_38a() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let plaintext = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a");
        let expected_cipher = hex_to_bytes("3ad77bb40d7a3660a89ecaf32466ef97");

        let mut input = NamedTempFile::new().unwrap();
        input.write_all(&plaintext).unwrap();
        input.flush().unwrap();

        let encrypted = NamedTempFile::new().unwrap();
        let iv = vec![0u8; 16];

        encrypt_file(
            input.path().to_str().unwrap(),
            encrypted.path().to_str().unwrap(),
            None,
            Some(&key),
            CipherMode::ECB,
            iv,
        ).unwrap();

        let mut out = Vec::new();
        File::open(encrypted.path()).unwrap().read_to_end(&mut out).unwrap();

        assert!(out.len() >= 32);
        let ct_start = out.len() - 32;
        let ct_end = ct_start + 16;
        let ct = &out[ct_start..ct_end];

        assert_eq!(ct, &expected_cipher[..]);
    }

    #[test]
    fn test_gcm_nist_vector() {
        let key = hex::decode("00000000000000000000000000000000").unwrap();
        let iv  = hex::decode("000000000000000000000000").unwrap();
        let pt  = hex::decode("00000000000000000000000000000000").unwrap();
        let aad = Vec::<u8>::new();

        let expected_ct  = hex::decode("0388dace60b6a392f328c2b971b2fe78").unwrap();
        let expected_tag = hex::decode("ab6e47d42cec13bdf53a67b21257bddf").unwrap();

        let gcm = Gcm::new(&key);
        let (ct, tag) = gcm.encrypt(&iv, &pt, &aad);

        assert_eq!(ct, expected_ct);
        assert_eq!(tag.to_vec(), expected_tag);

        let dec = gcm.decrypt(&iv, &ct, &aad, &tag).unwrap();
        assert_eq!(dec, pt);
    }
}