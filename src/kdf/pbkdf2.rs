use crate::mac::hmac::Hmac;

const HMAC_SHA256_OUTPUT_SIZE: usize = 32;

pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, dklen: usize) -> Result<Vec<u8>, String> {
    if dklen == 0 {
        return Err("Derived key length must be greater than 0".to_string());
    }
    if iterations == 0 {
        return Err("Iteration count must be greater than 0".to_string());
    }

    let blocks_needed = (dklen + HMAC_SHA256_OUTPUT_SIZE - 1) / HMAC_SHA256_OUTPUT_SIZE;
    let mut derived_key = Vec::with_capacity(dklen);

    for i in 1..=blocks_needed {
        let mut salt_with_index = salt.to_vec();
        salt_with_index.extend_from_slice(&(i as u32).to_be_bytes());

        let mut hmac = Hmac::new(password, "sha256")?;
        hmac.update(&salt_with_index);
        let u1_hex = hmac.finalize();
        let u1_bytes = hex::decode(u1_hex).map_err(|_| "Hex decode failed")?;

        let mut block = u1_bytes.clone();
        let mut u_prev = u1_bytes;

        for _ in 2..=iterations {
            let mut hmac_iter = Hmac::new(password, "sha256")?;
            hmac_iter.update(&u_prev);

            let u_curr_hex = hmac_iter.finalize();
            let u_curr_bytes = hex::decode(u_curr_hex).map_err(|_| "Hex decode failed")?;

            for (b, u) in block.iter_mut().zip(u_curr_bytes.iter()) {
                *b ^= u;
            }
            u_prev = u_curr_bytes;
        }

        derived_key.extend_from_slice(&block);
    }

    Ok(derived_key[..dklen].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), String>;

    #[test]
    fn test_pbkdf2_basic_properties() -> TestResult {
        let password: &[u8] = b"password";
        let salt: &[u8] = b"salt";
        let iterations = 1;
        let dklen = 32;

        let result = pbkdf2_hmac_sha256(password, salt, iterations, dklen)?;
        assert_eq!(result.len(), dklen);

        let result2 = pbkdf2_hmac_sha256(password, salt, iterations, dklen)?;
        assert_eq!(result, result2);

        let diff_password_result =
            pbkdf2_hmac_sha256(b"different".as_ref(), salt, iterations, dklen)?;
        assert_ne!(result, diff_password_result);

        let diff_salt_result =
            pbkdf2_hmac_sha256(password, b"different".as_ref(), iterations, dklen)?;
        assert_ne!(result, diff_salt_result);

        let diff_iter_result =
            pbkdf2_hmac_sha256(password, salt, iterations + 1, dklen)?;
        assert_ne!(result, diff_iter_result);

        Ok(())
    }

    #[test]
    fn test_pbkdf2_length_variations() -> TestResult {
        let password: &[u8] = b"password";
        let salt: &[u8] = b"salt";
        let iterations = 1000;

        for dklen in [1, 16, 32, 48, 64, 100] {
            let result = pbkdf2_hmac_sha256(password, salt, iterations, dklen)?;
            assert_eq!(result.len(), dklen);
        }

        Ok(())
    }

    #[test]
    fn test_pbkdf2_empty_inputs() -> TestResult {
        let result1 = pbkdf2_hmac_sha256(b"".as_ref(), b"salt", 1, 32)?;
        assert_eq!(result1.len(), 32);

        let result2 = pbkdf2_hmac_sha256(b"password", b"".as_ref(), 1, 32)?;
        assert_eq!(result2.len(), 32);

        let result3 = pbkdf2_hmac_sha256(b"".as_ref(), b"".as_ref(), 1, 32)?;
        assert_eq!(result3.len(), 32);

        Ok(())
    }

    #[test]
    fn test_pbkdf2_large_iterations() -> TestResult {
        let password: &[u8] = b"password";
        let salt: &[u8] = b"salt";

        let small_iter = pbkdf2_hmac_sha256(password, salt, 1000, 32)?;
        let large_iter = pbkdf2_hmac_sha256(password, salt, 10000, 32)?;

        assert_ne!(small_iter, large_iter);

        Ok(())
    }

    #[test]
    fn test_pbkdf2_consistency() -> TestResult {
        let test_cases: Vec<(&[u8], &[u8], u32, usize)> = vec![
            (b"pass".as_ref(), b"salt".as_ref(), 1, 32),
            (b"longer password".as_ref(), b"longer salt value".as_ref(), 100, 64),
            (b"p".as_ref(), b"s".as_ref(), 1000, 16),
        ];

        for (password, salt, iterations, dklen) in test_cases {
            let result1 = pbkdf2_hmac_sha256(password, salt, iterations, dklen)?;
            let result2 = pbkdf2_hmac_sha256(password, salt, iterations, dklen)?;

            assert_eq!(result1, result2);
            assert_eq!(result1.len(), dklen);
        }

        Ok(())
    }

    #[test]
    fn test_pbkdf2_openssl_compatibility_check() -> TestResult {
        let password: &[u8] = b"test123";
        let salt: &[u8] = b"mysalt";
        let iterations = 10000;
        let dklen = 32;

        let result = pbkdf2_hmac_sha256(password, salt, iterations, dklen)?;
        println!("Для проверки совместимости с OpenSSL выполните:");
        println!("echo -n 'test123' | openssl kdf -keylen {} \\", dklen);
        println!("  -kdfopt pass:test123 \\");
        println!("  -kdfopt salt:{} \\", hex::encode(salt));
        println!("  -kdfopt iter:{} \\", iterations);
        println!("  PBKDF2");
        println!();
        println!("Ваш результат: {}", hex::encode(&result));
        println!("Результат должен совпадать с выводом OpenSSL");

        assert_eq!(result.len(), dklen);

        Ok(())
    }
    #[test]
    fn test_rfc_6070_vector_1() {
        let dk = pbkdf2_hmac_sha256(
            b"password",
            b"salt",
            1,
            20,
        ).expect("pbkdf2 failed");
        assert_eq!(
            hex::encode(&dk),
            "120fb6cffcf8b32c43e7225256c4f837a86548c9"
        );
    }

    #[test]
    fn test_rfc_6070_vector_2() {
        let dk = pbkdf2_hmac_sha256(
            b"password",
            b"salt",
            2,
            20,
        ).expect("pbkdf2 failed");
        assert_eq!(
            hex::encode(&dk),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8e"
        );
    }
}