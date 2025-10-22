use std::path::Path;
use crate::generator;

const IV_SIZE: usize = 16;
const KEY_LEN: usize = 16;

#[derive(Debug)]
pub struct Params<'a> {
    pub algorithm: Option<&'a str>,
    pub password: Option<&'a str>,
    pub key: Option<Vec<u8>>,
    pub in_file: Option<&'a str>,
    pub out_file: Option<&'a str>,
    pub iv: Option<Vec<u8>>,
    pub mode: Option<&'a str>,
}

#[derive(Debug)]
pub struct ValidatedParams {
    pub algorithm: String,
    pub key_bytes: Option<Vec<u8>>,
    pub password: Option<String>,
    pub in_file: String,
    pub out_file: String,
    pub iv: Vec<u8>,
    pub mode: String,
}

impl<'a> Params<'a> {
    pub fn finalize(self) -> Result<ValidatedParams, String> {
        let algorithm = self.algorithm.unwrap_or("AES").to_string();
        let mode_str = self.mode.unwrap_or("ECB").to_string();

        let (key_bytes_opt, password_opt) = if let Some(k) = self.key {
            (Some(k), None)
        } else if let Some(pass) = self.password {
            (None, Some(pass.to_string()))
        } else {
            let key = generator::generate_random_bytes(KEY_LEN);
            println!("Generated random key: {}", hex::encode(&key));
            (Some(key), None)
        };

        let in_file = self.in_file.ok_or("Input file not provided")?.to_string();
        if !Path::new(&in_file).exists() {
            return Err(format!("Input file '{}' does not exist", in_file));
        }

        let out_file = match self.out_file {
            Some(path) => path.to_string(),
            None => {
                let postfix = match mode_str.as_str() {
                    "DEC" => ".dec",
                    _ => ".enc",
                };
                format!("{}{}", in_file, postfix)
            }
        };

        if in_file == out_file {
            return Err("Input and output files must be different".to_string());
        }

        let iv = match self.iv {
            Some(v) => {
                if v.len() != IV_SIZE {
                    return Err(format!("IV must be {} bytes", IV_SIZE));
                }
                v
            }
            None => generator::generate_random_bytes(IV_SIZE),
        };
        
        Ok(ValidatedParams {
            algorithm,
            key_bytes: key_bytes_opt,
            password: password_opt,
            in_file,
            out_file,
            iv,
            mode: mode_str,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_finalize_encrypt_password() {
        let mut input_file = NamedTempFile::new().unwrap();
        input_file.write_all(b"data").unwrap();
        let input_path = input_file.path().to_str().unwrap();

        let params = Params {
            algorithm: Some("AES"),
            password: Some("pass1234"),
            key: None,
            in_file: Some(input_path),
            out_file: None,
            iv: None,
            mode: Some("CBC"),
        };

        let v = params.finalize().expect("should finalize OK");
        assert_eq!(v.algorithm, "AES");
        assert_eq!(v.mode, "CBC");
        assert!(v.key_bytes.is_none());
        assert!(v.password.is_some());
        assert_eq!(v.password.as_ref().unwrap(), "pass1234");
        assert_eq!(v.iv.len(), 16);
    }

    #[test]
    fn test_finalize_decrypt_password() {
        let mut input_file = NamedTempFile::new().unwrap();
        input_file.write_all(b"data").unwrap();
        let input_path = input_file.path().to_str().unwrap();

        let params = Params {
            algorithm: None,
            password: Some("pass1234"),
            key: None,
            in_file: Some(input_path),
            out_file: None,
            iv: None,
            mode: Some("CBC"),
        };

        let v = params.finalize().unwrap();
        assert!(v.key_bytes.is_none());
        assert!(v.password.is_some());
        assert_eq!(v.password.as_ref().unwrap(), "pass1234");
    }

    #[test]
    fn test_finalize_with_key() {
        let mut input_file = NamedTempFile::new().unwrap();
        input_file.write_all(b"data").unwrap();
        let input_path = input_file.path().to_str().unwrap();

        let key = vec![1u8; 16];
        let params = Params {
            algorithm: Some("AES"),
            password: None,
            key: Some(key.clone()),
            in_file: Some(input_path),
            out_file: None,
            iv: None,
            mode: Some("ECB"),
        };

        let v = params.finalize().unwrap();
        assert_eq!(v.key_bytes, Some(key));
        assert!(v.password.is_none());
        assert_eq!(v.mode, "ECB");
    }

    #[test]
    fn test_finalize_with_random_key_generated() {
        let mut input_file = NamedTempFile::new().unwrap();
        input_file.write_all(b"data").unwrap();
        let input_path = input_file.path().to_str().unwrap();

        let params = Params {
            algorithm: Some("AES"),
            password: None,
            key: None,
            in_file: Some(input_path),
            out_file: None,
            iv: None,
            mode: None,
        };

        let v = params.finalize().unwrap();
        assert!(v.key_bytes.is_some());
        assert_eq!(v.key_bytes.as_ref().unwrap().len(), 16);
        assert!(v.password.is_none());
    }

    #[test]
    fn test_fails_on_nonexistent_file() {
        let params = Params {
            algorithm: Some("AES"),
            password: Some("1234"),
            key: None,
            in_file: Some("no_such_file.txt"),
            out_file: None,
            iv: None,
            mode: Some("CBC"),
        };

        assert!(params.finalize().is_err());
    }

    #[test]
    fn test_fails_on_invalid_iv_length() {
        let mut input_file = NamedTempFile::new().unwrap();
        input_file.write_all(b"data").unwrap();
        let input_path = input_file.path().to_str().unwrap();

        let params = Params {
            algorithm: Some("AES"),
            password: Some("1234"),
            key: None,
            in_file: Some(input_path),
            out_file: None,
            iv: Some(vec![1, 2, 3]),
            mode: Some("ECB"),
        };

        assert!(params.finalize().is_err());
    }
}