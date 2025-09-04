use aes::Aes128;
use aes::cipher::KeyInit;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Error, ErrorKind, Read, Write};
use crate::key_manager::{verifier, generator};
const BLOCK_SIZE: usize = 16;
const SALT_SIZE: usize = 32;
const VERIFIER_SIZE: usize = 32;
pub fn encrypt_file(input_file: &str, output_file: &str, key: &str) -> io::Result<()> {
    let mut reader = BufReader::new(File::open(input_file)?);
    let mut writer = BufWriter::new(File::create(output_file)?);

    let mut buffer = [0u8; BLOCK_SIZE];
    let mut leftover = Vec::new();

    let key_bytes = key.as_bytes();
    let salt = generator::generate_salt();
    let hmac = verifier::create_verifier(key_bytes, &salt).expect("Error generating verifier");
    writer.write_all(&salt)?;
    writer.write_all(&hmac)?;
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        if bytes_read < BLOCK_SIZE {
            leftover.extend_from_slice(&buffer[..bytes_read]);
            break;
        } else {
            let block: [u8; BLOCK_SIZE] = buffer;
            let enc_block = encrypt_block(&block, key_bytes);
            writer.write_all(&enc_block)?;
        }
    }
    if leftover.len() > 0 {
        let padded = pad_pkcs7(leftover);
        let enc = encrypt_block(&padded, key_bytes);
        writer.write_all(&enc)?;
    } else {
        let padded = pad_pkcs7(vec![]);
        let encrypted = encrypt_block(&padded, key.as_bytes());
        writer.write_all(&encrypted)?;
    }
    writer.flush()?;
    Ok(())
}
pub fn decrypt_file(in_file: &str, out_file: &str, key: &str) -> io::Result<()> {
    let key_bytes = key.as_bytes();
    let cipher = Aes128::new_from_slice(&key_bytes);

    let mut reader = BufReader::new(File::open(in_file)?);

    let metadata = std::fs::metadata(in_file)?;
    if metadata.len() < (SALT_SIZE + VERIFIER_SIZE) as u64 {
        return Err(Error::new(ErrorKind::InvalidData, "Файл слишком маленький: нет места для соли и HMAC"));
    }
    let mut salt = [0u8; SALT_SIZE];
    let mut stored_hmac = [0u8; VERIFIER_SIZE];
    reader.read_exact(&mut salt)?;
    reader.read_exact(&mut stored_hmac)?;

    if !verifier::verify_key(key_bytes, &stored_hmac, &salt).map_err(|e| {
        Error::new(ErrorKind::InvalidData, format!("Ошибка проверки ключа: {}", e))
    })? {
        return Err(Error::new(ErrorKind::InvalidData, "Неверный ключ!"));
    }

    let mut writer = BufWriter::new(File::create(out_file)?);

    let mut buffer = [0u8; BLOCK_SIZE];
    let mut prev_block: Option<[u8; BLOCK_SIZE]> = None;    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {break;}
        if bytes_read < BLOCK_SIZE {
            return Err(Error::new(ErrorKind::InvalidData, "Файл повреждён: неполный блок"));
        }

        let block = buffer;
        let dec_block = decrypt_block(&block, key.as_bytes());

        if let Some(prev) = prev_block.take() {
            writer.write_all(&prev)?;
        }
        prev_block = Some(dec_block);
    }
    if let Some(last) = prev_block {
        let unpadded = unpad_pkcs7(&last)?;
        writer.write_all(&unpadded)?;
    }
    writer.flush()?;
    Ok(())
}
fn encrypt_block(block: &[u8; BLOCK_SIZE], key: &[u8]) -> [u8; BLOCK_SIZE] {
    let mut result = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        result[i] = block[i] ^ key[i % key.len()];
    }
    result
}
fn decrypt_block(block: &[u8; BLOCK_SIZE], key: &[u8]) -> [u8; BLOCK_SIZE] {
    let mut result = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        result[i] = block[i] ^ key[i % key.len()];
    }
    result
}
fn pad_pkcs7(mut block: Vec<u8>) -> [u8; BLOCK_SIZE] {
    let padding_size = BLOCK_SIZE - (block.len() % BLOCK_SIZE);
    block.extend(std::iter::repeat(padding_size as u8).take(padding_size));

    let mut arr = [0u8; BLOCK_SIZE];
    arr.copy_from_slice(&block[..BLOCK_SIZE]);
    arr
}
fn unpad_pkcs7(block: &[u8; BLOCK_SIZE]) -> io::Result<Vec<u8>> {
    let pad_size = block[BLOCK_SIZE - 1] as usize;
    if pad_size == 0 || pad_size > BLOCK_SIZE {
        return Err(Error::new(ErrorKind::InvalidData, "некорректный PKCS#7"));
    }
    if !block[BLOCK_SIZE - pad_size..].iter().all(|&b| b as usize == pad_size) {
        return Err(Error::new(ErrorKind::InvalidData, "битый PKCS#7"));
    }
    Ok(block[..BLOCK_SIZE - pad_size].to_vec())
}