use aes::Aes128;
use cipher::{BlockEncrypt, KeyInit};
use cipher::generic_array::GenericArray;

pub struct Gcm {
    cipher: Aes128,
    h: u128,
}

impl Gcm {
    pub fn new(key: &[u8]) -> Self {
        if key.len() != 16 {
            panic!("Aes128 requires a 16-byte key, got {}", key.len());
        }
        let key_block = GenericArray::from_slice(key);

        let cipher = Aes128::new(key_block);

        let mut zero_block = GenericArray::from([0u8; 16]);
        cipher.encrypt_block(&mut zero_block);

        let h = u128::from_be_bytes(zero_block.into());

        Gcm { cipher, h }
    }

    fn gf_mult(&self, x: u128, y: u128) -> u128 {
        let mut z: u128 = 0;
        let mut v = y;
        let mut x_temp = x;

        for _ in 0..128 {
            if (x_temp >> 127) & 1 == 1 {
                z ^= v;
            }
            x_temp <<= 1;

            let mask = if (v & 1) == 1 {
                0xE1000000_00000000_00000000_00000000
            } else {
                0
            };
            v = (v >> 1) ^ mask;
        }
        z
    }

    fn ghash(&self, aad: &[u8], ciphertext: &[u8]) -> u128 {
        let mut y = 0u128;

        for chunk in aad.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            let b_val = u128::from_be_bytes(block);

            y ^= b_val;
            y = self.gf_mult(y, self.h);
        }

        for chunk in ciphertext.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            let b_val = u128::from_be_bytes(block);

            y ^= b_val;
            y = self.gf_mult(y, self.h);
        }

        let aad_len_bits = (aad.len() as u128) * 8;
        let c_len_bits = (ciphertext.len() as u128) * 8;

        let len_block_bytes = {
            let mut bytes = [0u8; 16];
            bytes[0..8].copy_from_slice(&(aad_len_bits as u64).to_be_bytes());
            bytes[8..16].copy_from_slice(&(c_len_bits as u64).to_be_bytes());
            bytes
        };
        let len_val = u128::from_be_bytes(len_block_bytes);

        y ^= len_val;
        y = self.gf_mult(y, self.h);

        y
    }

    fn get_j0(nonce: &[u8]) -> [u8; 16] {
        let mut block = [0u8; 16];
        if nonce.len() != 12 {
            panic!("GCM implementation currently only supports 12-byte nonce");
        }
        block[..12].copy_from_slice(nonce);
        block[15] = 1; // Counter starts at 1
        block
    }

    fn inc_counter(counter: &mut [u8; 16]) {
        let mut val = u32::from_be_bytes(counter[12..16].try_into().unwrap());
        val = val.wrapping_add(1);
        counter[12..16].copy_from_slice(&val.to_be_bytes());
    }

    fn encrypt_counter_block(&self, counter: &[u8; 16]) -> [u8; 16] {
        let mut block = GenericArray::from(*counter);
        self.cipher.encrypt_block(&mut block);
        block.into()
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let mut j0 = Self::get_j0(nonce);

        let mut counter_block = j0;
        Self::inc_counter(&mut counter_block);

        let mut ciphertext = Vec::with_capacity(plaintext.len());

        for chunk in plaintext.chunks(16) {
            let keystream = self.encrypt_counter_block(&counter_block);
            Self::inc_counter(&mut counter_block);

            for i in 0..chunk.len() {
                ciphertext.push(chunk[i] ^ keystream[i]);
            }
        }
        
        let s = self.ghash(aad, &ciphertext);

        let encrypted_j0_arr = self.encrypt_counter_block(&j0);
        let encrypted_j0_val = u128::from_be_bytes(encrypted_j0_arr);

        let t_val = s ^ encrypted_j0_val;

        (ciphertext, t_val.to_be_bytes())
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8], tag: &[u8]) -> Option<Vec<u8>> {
        let j0 = Self::get_j0(nonce);

        let s = self.ghash(aad, ciphertext);
        let encrypted_j0_arr = self.encrypt_counter_block(&j0);
        let encrypted_j0_val = u128::from_be_bytes(encrypted_j0_arr);

        let computed_t_val = s ^ encrypted_j0_val;
        let computed_tag = computed_t_val.to_be_bytes();

        if computed_tag != tag {
            return None;
        }

        let mut counter_block = j0;
        Self::inc_counter(&mut counter_block);

        let mut plaintext = Vec::with_capacity(ciphertext.len());

        for chunk in ciphertext.chunks(16) {
            let keystream = self.encrypt_counter_block(&counter_block);
            Self::inc_counter(&mut counter_block);

            for i in 0..chunk.len() {
                plaintext.push(chunk[i] ^ keystream[i]);
            }
        }
        Some(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_key() -> Vec<u8> {
        hex::decode("00000000000000000000000000000000").unwrap()
    }

    #[test]
    fn test_round_trip() {
        let key = get_key();
        let gcm = Gcm::new(&key);
        let nonce = [0u8; 12];
        let plaintext = b"Hello GCM World";
        let aad = b"Metadata";

        let (ciphertext, tag) = gcm.encrypt(&nonce, plaintext, aad);
        let decrypted = gcm.decrypt(&nonce, &ciphertext, aad, &tag);

        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[test]
    fn test_empty_aad() {
        let key = get_key();
        let gcm = Gcm::new(&key);
        let nonce = [0x11u8; 12];
        let plaintext = b"Payload with empty AAD";
        let aad = b"";

        let (ciphertext, tag) = gcm.encrypt(&nonce, plaintext, aad);
        let decrypted = gcm.decrypt(&nonce, &ciphertext, aad, &tag);

        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = get_key();
        let gcm = Gcm::new(&key);
        let nonce = [0x22u8; 12];
        let plaintext = b"";
        let aad = b"Just AAD";

        let (ciphertext, tag) = gcm.encrypt(&nonce, plaintext, aad);
        assert_eq!(ciphertext.len(), 0);

        let decrypted = gcm.decrypt(&nonce, &ciphertext, aad, &tag);
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[test]
    fn test_aad_tamper() {
        let key = get_key();
        let gcm = Gcm::new(&key);
        let nonce = [0u8; 12];
        let plaintext = b"Secret";
        let aad_correct = b"correct";
        let aad_wrong = b"wrong";

        let (ciphertext, tag) = gcm.encrypt(&nonce, plaintext, aad_correct);

        let result = gcm.decrypt(&nonce, &ciphertext, aad_wrong, &tag);
        assert!(result.is_none(), "Decryption must fail with wrong AAD");
    }

    #[test]
    fn test_ciphertext_tamper() {
        let key = get_key();
        let gcm = Gcm::new(&key);
        let nonce = [0u8; 12];
        let plaintext = b"Dont touch me";
        let aad = b"";

        let (mut ciphertext, tag) = gcm.encrypt(&nonce, plaintext, aad);

        if let Some(last) = ciphertext.last_mut() {
            *last ^= 0x01;
        }

        let result = gcm.decrypt(&nonce, &ciphertext, aad, &tag);
        assert!(result.is_none(), "Decryption must fail with tampered ciphertext");
    }

    #[test]
    fn test_tag_tamper() {
        let key = get_key();
        let gcm = Gcm::new(&key);
        let nonce = [0u8; 12];
        let plaintext = b"Touch the tag";
        let aad = b"";

        let (ciphertext, mut tag) = gcm.encrypt(&nonce, plaintext, aad);

        tag[0] ^= 0xFF;

        let result = gcm.decrypt(&nonce, &ciphertext, aad, &tag);
        assert!(result.is_none(), "Decryption must fail with tampered tag");
    }

    #[test]
    #[should_panic(expected = "only supports 12-byte nonce")]
    fn test_invalid_nonce_len() {
        let key = get_key();
        let gcm = Gcm::new(&key);
        let bad_nonce = [0u8; 13]; 
        let aad = b"";

        gcm.encrypt(&bad_nonce, b"data", aad);
    }
}