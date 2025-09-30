use aes::Aes128;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit, generic_array::GenericArray};
use cipher::{StreamCipher, KeyIvInit};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Error, ErrorKind, Read, Write};
use crate::key_manager::{verifier, keygen};
use crate::generator;

const BLOCK_SIZE: usize = 16;
const SALT_SIZE: usize = 32;
const VERIFIER_SIZE: usize = 32;
const IV_SIZE: usize = 16;

type Aes128Ctr = ctr::Ctr128BE<Aes128>;
type Aes128Ofb = ofb::Ofb<Aes128>;

#[derive(Clone, Copy, Debug)]
pub enum CipherMode { ECB, CBC, CTR, OFB }

pub fn encrypt_file(input_file: &str, output_file: &str, password: &str, mode: CipherMode) -> io::Result<()> {
    let mut reader = BufReader::new(File::open(input_file)?);
    let mut writer = BufWriter::new(File::create(output_file)?);

    let salt: [u8; SALT_SIZE] = generator::generate_random_bytes(SALT_SIZE).try_into().expect("salt must be 32 bytes");
    let key_bytes = keygen::generate_key(password.as_bytes(), &salt, None, None)?;
    let hmac = verifier::create_verifier(&key_bytes, &salt)
        .map_err(|e| Error::new(ErrorKind::Other, format!("verifier: {e}")))?;
    writer.write_all(&salt)?;
    writer.write_all(&hmac)?;

    match mode {
        CipherMode::ECB => encrypt_ecb(&mut reader, &mut writer, &key_bytes),
        CipherMode::CBC => {
            let iv: [u8; IV_SIZE] = generator::generate_random_bytes(IV_SIZE).try_into().expect("Failed to convert bytes vector in IV");
            writer.write_all(&iv)?;
            encrypt_cbc(&mut reader, &mut writer, &key_bytes, &iv)
        }
        CipherMode::CTR => {
            let iv = generator::generate_random_bytes(IV_SIZE);
            writer.write_all(&iv)?;
            encrypt_stream(&mut reader, &mut writer, Aes128Ctr::new_from_slices(&key_bytes, &iv).unwrap())
        }
        CipherMode::OFB => {
            let iv = generator::generate_random_bytes(IV_SIZE);
            writer.write_all(&iv)?;
            encrypt_stream(&mut reader, &mut writer, Aes128Ofb::new_from_slices(&key_bytes, &iv).unwrap())
        }
    }?;

    writer.flush()?;
    Ok(())
}

pub fn decrypt_file(in_file: &str, out_file: &str, password: &str, mode: CipherMode) -> io::Result<()> {
    let meta = std::fs::metadata(in_file)?;
    if meta.len() < (SALT_SIZE + VERIFIER_SIZE) as u64 {
        return Err(Error::new(ErrorKind::InvalidData, "слишком мало данных для salt+hmac"));
    }

    let mut reader = BufReader::new(File::open(in_file)?);
    let mut writer = BufWriter::new(File::create(out_file)?);

    let mut salt = [0u8; SALT_SIZE];
    let mut stored_hmac = [0u8; VERIFIER_SIZE];
    reader.read_exact(&mut salt)?;
    reader.read_exact(&mut stored_hmac)?;
    
    let key_bytes = keygen::generate_key(password.as_bytes(), &salt, None, None)?;
    let ok = verifier::verify_key(&key_bytes, &stored_hmac, &salt)
        .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Ошибка проверки ключа: {e}")))?;
    if !ok {
        return Err(Error::new(ErrorKind::InvalidData, "Неверный ключ"));
    }

    match mode {
        CipherMode::ECB => decrypt_ecb(&mut reader, &mut writer, &key_bytes),
        CipherMode::CBC => {
            let mut iv = [0u8; BLOCK_SIZE];
            reader.read_exact(&mut iv)?;
            decrypt_cbc(&mut reader, &mut writer, &key_bytes, &iv)
        }
        CipherMode::CTR => {
            let mut iv = [0u8; BLOCK_SIZE];
            reader.read_exact(&mut iv)?;
            decrypt_stream(&mut reader, &mut writer, Aes128Ctr::new_from_slices(&key_bytes, &iv).unwrap())
        }
        CipherMode::OFB => {
            let mut iv = [0u8; BLOCK_SIZE];
            reader.read_exact(&mut iv)?;
            decrypt_stream(&mut reader, &mut writer, Aes128Ofb::new_from_slices(&key_bytes, &iv).unwrap())
        }
    }?;

    writer.flush()?;
    Ok(())
}


fn encrypt_ecb<R: Read, W: Write>(reader: &mut R, writer: &mut W, key: &[u8]) -> io::Result<()> {
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut buf = [0u8; BLOCK_SIZE];
    let mut leftover = Vec::new();

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }
        if n < BLOCK_SIZE {
            leftover.extend_from_slice(&buf[..n]);
            break;
        }
        let enc = aes_encrypt_block(&cipher, &buf);
        writer.write_all(&enc)?;
    }

    let padded = pad_pkcs7(leftover);
    let enc = aes_encrypt_block(&cipher, &padded);
    writer.write_all(&enc)?;
    Ok(())
}

fn decrypt_ecb<R: Read, W: Write>(reader: &mut R, writer: &mut W, key: &[u8]) -> io::Result<()> {
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut buf = [0u8; BLOCK_SIZE];
    let mut prev: Option<[u8; BLOCK_SIZE]> = None;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }
        if n < BLOCK_SIZE {
            return Err(Error::new(ErrorKind::InvalidData, "неполный блок в ECB"));
        }
        let dec = aes_decrypt_block(&cipher, &buf);

        if let Some(p) = prev.take() { writer.write_all(&p)?; }
        prev = Some(dec);
    }

    if let Some(last) = prev {
        let unpadded = unpad_pkcs7(&last)?;
        writer.write_all(&unpadded)?;
    }
    Ok(())
}


fn encrypt_cbc<R: Read, W: Write>(reader: &mut R, writer: &mut W, key: &[u8], iv: &[u8; BLOCK_SIZE]) -> io::Result<()> {
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut buf = [0u8; BLOCK_SIZE];
    let mut leftover = Vec::new();
    let mut prev = *iv;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }
        if n < BLOCK_SIZE {
            leftover.extend_from_slice(&buf[..n]);
            break;
        }
        let x = xor16(&buf, &prev);
        let enc = aes_encrypt_block(&cipher, &x);
        writer.write_all(&enc)?;
        prev = enc;
    }

    let padded = pad_pkcs7(leftover);
    let x = xor16(&padded, &prev);
    let enc = aes_encrypt_block(&cipher, &x);
    writer.write_all(&enc)?;
    Ok(())
}

fn decrypt_cbc<R: Read, W: Write>(reader: &mut R, writer: &mut W, key: &[u8], iv: &[u8; BLOCK_SIZE]) -> io::Result<()> {
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut buf = [0u8; BLOCK_SIZE];
    let mut prev_ct = *iv;
    let mut prev_plain: Option<[u8; BLOCK_SIZE]> = None;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }
        if n < BLOCK_SIZE { return Err(Error::new(ErrorKind::InvalidData, "неполный блок в CBC")); }

        let dec = aes_decrypt_block(&cipher, &buf);
        let plain = xor16(&dec, &prev_ct);

        if let Some(p) = prev_plain.take() { writer.write_all(&p)?; }
        prev_plain = Some(plain);
        prev_ct = buf;
    }

    if let Some(last) = prev_plain {
        let unpadded = unpad_pkcs7(&last)?;
        writer.write_all(&unpadded)?;
    }
    Ok(())
}

fn encrypt_stream<R: Read, W: Write, C: StreamCipher>(reader: &mut R, writer: &mut W, mut cipher: C) -> io::Result<()> {
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }
        let mut chunk = &mut buf[..n];
        cipher.apply_keystream(&mut chunk);
        writer.write_all(&chunk)?;
    }
    Ok(())
}
fn decrypt_stream<R: Read, W: Write, C: StreamCipher>(reader: &mut R, writer: &mut W, cipher: C) -> io::Result<()> {
    encrypt_stream(reader, writer, cipher)
}


fn aes_encrypt_block(cipher: &Aes128, input: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut block = GenericArray::clone_from_slice(input);
    cipher.encrypt_block(&mut block);
    block.into()
}
fn aes_decrypt_block(cipher: &Aes128, input: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut block = GenericArray::clone_from_slice(input);
    cipher.decrypt_block(&mut block);
    block.into()
}

fn xor16(a: &[u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut out = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE { out[i] = a[i] ^ b[i]; }
    out
}

fn pad_pkcs7(mut tail: Vec<u8>) -> [u8; BLOCK_SIZE] {
    let pad = BLOCK_SIZE - (tail.len() % BLOCK_SIZE);
    tail.extend(std::iter::repeat(pad as u8).take(pad));
    let mut arr = [0u8; BLOCK_SIZE];
    arr.copy_from_slice(&tail[..BLOCK_SIZE]);
    arr
}
fn unpad_pkcs7(block: &[u8; BLOCK_SIZE]) -> io::Result<Vec<u8>> {
    let pad = block[BLOCK_SIZE - 1] as usize;
    if pad == 0 || pad > BLOCK_SIZE { return Err(Error::new(ErrorKind::InvalidData, "некорректный PKCS#7")); }
    if !block[BLOCK_SIZE - pad..].iter().all(|&b| b as usize == pad) {
        return Err(Error::new(ErrorKind::InvalidData, "битый PKCS#7"));
    }
    Ok(block[..BLOCK_SIZE - pad].to_vec())
}
