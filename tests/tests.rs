#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Write, Read};
    use tempfile::NamedTempFile;
    use CryptoMal::cryptor::{encrypt_file, decrypt_file};
    #[test]
    fn test_encrypt_decrypt_file() {
        let mut input = NamedTempFile::new().expect("Failed to create temp input file");
        let test_data = b"Hello, AES128 encryption test!";
        input.write_all(test_data).expect("Failed to write to temp file");
        input.flush().unwrap();

        let key = "mysecretkey12345"; 

        let enc_file = NamedTempFile::new().expect("Failed to create temp encrypted file");
        let enc_path = enc_file.path().to_str().unwrap();

        encrypt_file(input.path().to_str().unwrap(), enc_path, key).expect("Encryption failed");

        let dec_file = NamedTempFile::new().expect("Failed to create temp decrypted file");
        let dec_path = dec_file.path().to_str().unwrap();

        decrypt_file(enc_path, dec_path, key).expect("Decryption failed");

        let mut decrypted = Vec::new();
        let mut dec_reader = File::open(dec_path).expect("Failed to open decrypted file");
        dec_reader.read_to_end(&mut decrypted).expect("Failed to read decrypted file");

        assert_eq!(decrypted, test_data, "Decrypted data does not match original");
    }

    #[test]
    fn test_encrypt_decrypt_empty_file() {
        let input = NamedTempFile::new().expect("Failed to create temp input file");

        let key = "mysecretkey12345";

        let enc_file = NamedTempFile::new().expect("Failed to create temp encrypted file");
        let dec_file = NamedTempFile::new().expect("Failed to create temp decrypted file");

        encrypt_file(input.path().to_str().unwrap(), enc_file.path().to_str().unwrap(), key)
            .expect("Encryption failed");

        decrypt_file(enc_file.path().to_str().unwrap(), dec_file.path().to_str().unwrap(), key)
            .expect("Decryption failed");

        let mut decrypted = Vec::new();
        File::open(dec_file.path())
            .unwrap()
            .read_to_end(&mut decrypted)
            .unwrap();

        assert!(decrypted.is_empty(), "Decrypted empty file should be empty");
    }

    #[test]
    fn test_encrypt_decrypt_non_multiple_block_size() {
        let mut input = NamedTempFile::new().unwrap();
        let test_data = b"123456789";
        input.write_all(test_data).unwrap();
        input.flush().unwrap();

        let key = "mysecretkey12345";

        let enc_file = NamedTempFile::new().unwrap();
        let dec_file = NamedTempFile::new().unwrap();

        encrypt_file(input.path().to_str().unwrap(), enc_file.path().to_str().unwrap(), key).unwrap();
        decrypt_file(enc_file.path().to_str().unwrap(), dec_file.path().to_str().unwrap(), key).unwrap();

        let mut decrypted = Vec::new();
        File::open(dec_file.path()).unwrap().read_to_end(&mut decrypted).unwrap();

        assert_eq!(decrypted, test_data, "Decrypted non-block-size file mismatch");
    }
}
