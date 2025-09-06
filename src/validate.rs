use std::path::Path;
use std::fs::File;
pub fn validate_params(algorithm: Option<&str>, key: Option<&str>, in_file: Option<&str>, out_file: Option<&str>) -> Result<(), String> {
    if let Some(alg) = algorithm {
        if alg != "AES" {
            return Err(format!("Unsupported algorithm: {}", alg));
        }
    }
    if let Some(k) = key {
        if k.len() < 16 {
            return Err("Key must be at least 16 bytes".to_string());
        }
    }
    if let Some(file) = in_file {
        if !Path::new(file).exists() {
            return Err(format!("Input file {} does not exist", file));
        }
    }
    if Some(out_file) == Some(in_file) {
        return Err("Files should have different names".to_string());
    }
    Ok(())
}
pub fn create_output_file_if_not_provided(mode: &str, in_file: &str, out_file: Option<&str>) -> Result<String, String> {
    if let Some(out) = out_file {
        File::create(out).map_err(|e| format!("Unable to create output file '{}': {}", out, e))?;
        return Ok(out.to_string());
    }
    let postfix = match mode {
        "ENC" => ".enc",
        "DEC" => ".dec",
        _ => return Err(format!("Unsupported mode: {}", mode)),
    };

    let out = format!("{}{}", in_file, postfix);
    println!("Creating output file {}", out);

    File::create(&out)
        .map_err(|e| format!("Unable to create output file '{}': {}", out, e))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_params() {
        let key: &str = "1234567890ABCDEF";
        assert!(validate_params(Some("AES"), Some(key), Some("Cargo.toml"), Some("Cargo2.toml")).is_ok());
        assert!(validate_params(Some("DES"), Some(key), Some("Cargo.toml"), Some("Cargo2.toml")).is_err());
        assert!(validate_params(Some("AES"), Some("123"), Some("Cargo.toml"), Some("Cargo2.toml")).is_err());
        assert!(validate_params(Some("AES"), Some(key), Some("nonexistent.txt"), Some("Cargo2.toml")).is_err());
        assert!(validate_params(Some("AES"), Some(key), Some("same.name"), Some("same.name")).is_err());
        assert!(validate_params(None, Some(key), Some("Cargo.toml"), Some("Cargo2.toml")).is_ok());
    }
}