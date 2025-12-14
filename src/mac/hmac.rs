use crate::hash::{Hasher, Sha256, Sha3};

pub struct Hmac {
    inner_hasher: Box<dyn Hasher>,
    outer_hasher: Box<dyn Hasher>,
    algorithm: String,
}

impl Hmac {
    pub fn new(key: &[u8], algorithm: &str) -> Result<Self, String> {
        let block_size = match algorithm {
            "sha256" => 64,
            "sha3-256" => 136,
            _ => return Err("Unsupported algorithm for HMAC".to_string()),
        };

        let mut hasher_for_key: Box<dyn Hasher> = match algorithm {
            "sha256" => Box::new(Sha256::new()),
            "sha3-256" => Box::new(Sha3::new()),
            _ => return Err("Unsupported algorithm".to_string()),
        };

        let processed_key = if key.len() > block_size {
            hasher_for_key.update(key);
            let digest_hex = hasher_for_key.finalize();
            hex::decode(digest_hex.to_string()).map_err(|_| "Failed to decode hash")?
        } else {
            key.to_vec()
        };

        let mut padded_key = processed_key;
        if padded_key.len() < block_size {
            padded_key.resize(block_size, 0);
        }

        let ipad: Vec<u8> = padded_key.iter().map(|b| b ^ 0x36).collect();
        let opad: Vec<u8> = padded_key.iter().map(|b| b ^ 0x5c).collect();

        let mut inner_hasher: Box<dyn Hasher> = match algorithm {
            "sha256" => Box::new(Sha256::new()),
            "sha3-256" => Box::new(Sha3::new()),
            _ => unreachable!(),
        };

        let mut outer_hasher: Box<dyn Hasher> = match algorithm {
            "sha256" => Box::new(Sha256::new()),
            "sha3-256" => Box::new(Sha3::new()),
            _ => unreachable!(),
        };

        inner_hasher.update(&ipad);
        outer_hasher.update(&opad);

        Ok(Hmac {
            inner_hasher,
            outer_hasher,
            algorithm: algorithm.to_string(),
        })
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner_hasher.update(data);
    }

    pub fn finalize(mut self) -> String {
        let inner_result_hex = self.inner_hasher.finalize();

        let inner_bytes = hex::decode(inner_result_hex.to_string())
            .expect("Failed to decode inner hash output");

        self.outer_hasher.update(&inner_bytes);

        self.outer_hasher.finalize().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex_to_bytes(s: &str) -> Vec<u8> {
        hex::decode(s).expect("Invalid hex in test")
    }

    #[test]
    fn test_rfc4231_case_1() {
        let key = vec![0x0bu8; 20];
        let data = b"Hi There";
        let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

        let mut hmac = Hmac::new(&key, "sha256").unwrap();
        hmac.update(data);
        assert_eq!(hmac.finalize(), expected);
    }

    #[test]
    fn test_rfc4231_case_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

        let mut hmac = Hmac::new(key, "sha256").unwrap();
        hmac.update(data);
        assert_eq!(hmac.finalize(), expected);
    }

    #[test]
    fn test_rfc4231_case_3() {
        let key = vec![0xaa; 20];
        let data = vec![0xdd; 50];
        let expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";

        let mut hmac = Hmac::new(&key, "sha256").unwrap();
        hmac.update(&data);
        assert_eq!(hmac.finalize(), expected);
    }

    #[test]
    fn test_rfc4231_case_6() {
        let key = vec![0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";

        let mut hmac = Hmac::new(&key, "sha256").unwrap();
        hmac.update(data);
        assert_eq!(hmac.finalize(), expected);
    }
}