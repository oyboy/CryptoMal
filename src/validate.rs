use std::path::Path;

pub fn validate_params(algorithm: Option<&str>, mode: Option<&str>, key: Option<&str>, in_file: Option<&str>) -> Result<(), String> {
    if let Some(alg) = algorithm {
        if alg != "AES" {
            return Err(format!("Unsupported algorithm: {}", alg));
        }
    }
    if let Some(m) = mode {
        if m != "ECB" && m != "CBC" {
            return Err(format!("Unsupported mode: {}", m));
        }
    }
    if let Some(k) = key {
        if k.len() < 32 {
            return Err("Key must be at least 32 bytes".to_string());
        }
    }
    if let Some(file) = in_file {
        if !Path::new(file).exists() {
            return Err(format!("Input file {} does not exist", file));
        }
    }
    Ok(())
}
pub fn create_output_file_if_not_provided(mode: &str, in_file: &str) -> Result<(), String> {
    match mode {
        "ENC" => {
            let postfix = String::from(".enc");
            let out = String::from(in_file) + &postfix;
            println!("Creating output file {}", out);
            Ok(())
        }
        "DEC" => {
            let postfix = String::from(".dec");
            let out = String::from(in_file) + &postfix;
            println!("Creating output file {}", out);
            Ok(())
        }
        _ => Err(format!("Unsupported mode: {}", mode)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_params() {
        let key: &str = "12345678123456781234567812345678";
        assert!(validate_params(Some("AES"), Some("ECB"), Some(key), Some("Cargo.toml")).is_ok());
        assert!(validate_params(Some("DES"), Some("ECB"), Some(key), Some("Cargo.toml")).is_err());
        assert!(validate_params(Some("AES"), Some("OFB"), Some(key), Some("Cargo.toml")).is_err());
        assert!(validate_params(Some("AES"), Some("ECB"), Some("123"), Some("Cargo.toml")).is_err());
        assert!(validate_params(Some("AES"), Some("ECB"), Some(key), Some("nonexistent.txt")).is_err());
        assert!(validate_params(None, None, Some(key), Some("Cargo.toml")).is_ok());
    }
}