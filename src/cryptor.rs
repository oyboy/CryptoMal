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
const BUFFER_SIZE: usize = 1_048_576;

type Aes128Ctr = ctr::Ctr128BE<Aes128>;
type Aes128Ofb = ofb::Ofb<Aes128>;

#[derive(Clone, Copy, Debug)]
pub enum CipherMode { ECB, CBC, CTR, OFB }

fn derive_effective_key(password: Option<&str>, key_bytes: Option<&[u8]>, salt: &[u8], ) -> io::Result<Vec<u8>> {
    if let Some(pw) = password {
        keygen::generate_key(pw.as_bytes(), salt, None, None)
            .map_err(|e| Error::new(ErrorKind::Other, format!("Keygen failed: {e}")))
    } else if let Some(kb) = key_bytes {
        Ok(kb.to_vec())
    } else {
        Err(Error::new(ErrorKind::InvalidInput, "Key or password required"))
    }
}

pub fn encrypt_file(input_file: &str, output_file: &str, password: Option<&str>, key_bytes: Option<&[u8]>, mode: CipherMode, iv: Vec<u8>) -> io::Result<()> {
    let mut reader = BufReader::new(File::open(input_file)?);
    let mut writer = BufWriter::new(File::create(output_file)?);

    let salt: [u8; SALT_SIZE] = generator::generate_random_bytes(SALT_SIZE).try_into().expect("salt must be 32 bytes");

    let key_bytes = derive_effective_key(password, key_bytes, &salt)?;

    let hmac = verifier::create_verifier(&key_bytes, &salt)
        .map_err(|e| Error::new(ErrorKind::Other, format!("verifier: {e}")))?;
    writer.write_all(&salt)?;
    writer.write_all(&hmac)?;

    match mode {
        CipherMode::ECB => encrypt_ecb(&mut reader, &mut writer, &key_bytes),
        CipherMode::CBC => {
            writer.write_all(&iv)?;
            encrypt_cbc(&mut reader, &mut writer, &key_bytes, &iv.try_into().unwrap())
        }
        CipherMode::CTR => {
            writer.write_all(&iv)?;
            encrypt_stream(&mut reader, &mut writer, Aes128Ctr::new_from_slices(&key_bytes, &iv).unwrap())
        }
        CipherMode::OFB => {
            writer.write_all(&iv)?;
            encrypt_stream(&mut reader, &mut writer, Aes128Ofb::new_from_slices(&key_bytes, &iv).unwrap())
        }
    }?;

    writer.flush()?;
    Ok(())
}

pub fn decrypt_file(in_file: &str, out_file: &str, password: Option<&str>, key_bytes: Option<&[u8]>, mode: CipherMode, mut iv: Vec<u8>) -> io::Result<()> {
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

    let key_bytes = derive_effective_key(password, key_bytes, &salt)?;

    let ok = verifier::verify_key(&key_bytes, &stored_hmac, &salt)
        .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Ошибка проверки ключа: {e}")))?;
    if !ok {
        return Err(Error::new(ErrorKind::InvalidData, "Неверный ключ"));
    }

    match mode {
        CipherMode::ECB => decrypt_ecb(&mut reader, &mut writer, &key_bytes),
        CipherMode::CBC => {
            reader.read_exact(&mut iv)?;
            decrypt_cbc(&mut reader, &mut writer, &key_bytes, &iv.try_into().unwrap())
        }
        CipherMode::CTR => {
            reader.read_exact(&mut iv)?;
            decrypt_stream(&mut reader, &mut writer, Aes128Ctr::new_from_slices(&key_bytes, &iv).unwrap())
        }
        CipherMode::OFB => {
            reader.read_exact(&mut iv)?;
            decrypt_stream(&mut reader, &mut writer, Aes128Ofb::new_from_slices(&key_bytes, &iv).unwrap())
        }
    }?;

    writer.flush()?;
    Ok(())
}

fn process_ecb_blocks<W: Write>(chunks: &mut std::slice::ChunksExact<'_, u8>, cipher: &Aes128, writer: &mut W) -> io::Result<()> {
    for chunk in chunks.by_ref() {
        let block_arr: [u8; BLOCK_SIZE] = chunk.try_into().unwrap();
        let enc = aes_encrypt_block(cipher, &block_arr);
        writer.write_all(&enc)?;
    }
    Ok(())
}

fn process_cbc_blocks<W: Write>(chunks: &mut std::slice::ChunksExact<'_, u8>, cipher: &Aes128, writer: &mut W, prev: &mut [u8; BLOCK_SIZE]) -> io::Result<()> {
    for chunk in chunks.by_ref() {
        let block_arr: [u8; BLOCK_SIZE] = chunk.try_into().unwrap();
        let x = xor16(&block_arr, prev);
        let enc = aes_encrypt_block(cipher, &x);
        writer.write_all(&enc)?;
        *prev = enc;
    }
    Ok(())
}

fn process_decrypt_ecb_blocks<W: Write>(chunks: std::slice::ChunksExact<'_, u8>, cipher: &Aes128, writer: &mut W, last_plain: &mut Option<[u8; BLOCK_SIZE]>) -> io::Result<()> {
    for chunk in chunks {
        let ct: [u8; BLOCK_SIZE] = chunk.try_into().unwrap();
        let plain = aes_decrypt_block(cipher, &ct);
        if let Some(p) = last_plain.take() {
            writer.write_all(&p)?;
        }
        *last_plain = Some(plain);
    }
    Ok(())
}

fn process_decrypt_cbc_blocks<W: Write>(chunks: std::slice::ChunksExact<'_, u8>, cipher: &Aes128, writer: &mut W, last_plain: &mut Option<[u8; BLOCK_SIZE]>, prev_ct: &mut [u8; BLOCK_SIZE]) -> io::Result<()> {
    for chunk in chunks {
        let ct: [u8; BLOCK_SIZE] = chunk.try_into().unwrap();
        let dec = aes_decrypt_block(cipher, &ct);
        let plain = xor16(&dec, prev_ct);
        if let Some(p) = last_plain.take() {
            writer.write_all(&p)?;
        }
        *last_plain = Some(plain);
        *prev_ct = ct;
    }
    Ok(())
}

fn encrypt_ecb<R: Read, W: Write>(reader: &mut R, writer: &mut W, key: &[u8]) -> io::Result<()> {
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut remainder = Vec::new();
    let mut buffer = vec![0u8; BUFFER_SIZE];

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        remainder.extend_from_slice(&buffer[..n]);
        let mut chunks = remainder.chunks_exact(BLOCK_SIZE);
        process_ecb_blocks(&mut chunks, &cipher, writer)?;
        remainder = chunks.remainder().to_vec();
    }

    // Pad and encrypt the remainder (always pad, even if empty)
    let pad_len = BLOCK_SIZE - (remainder.len() % BLOCK_SIZE);
    remainder.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    let mut chunks = remainder.chunks_exact(BLOCK_SIZE);
    process_ecb_blocks(&mut chunks, &cipher, writer)?;
    Ok(())
}

fn decrypt_ecb<R: Read, W: Write>(reader: &mut R, writer: &mut W, key: &[u8]) -> io::Result<()> {
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut last_plain: Option<[u8; BLOCK_SIZE]> = None;
    let mut buffer = vec![0u8; BUFFER_SIZE];

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        if n % BLOCK_SIZE != 0 {
            return Err(Error::new(ErrorKind::InvalidData, "Input not multiple of block size"));
        }
        process_decrypt_ecb_blocks(buffer[..n].chunks_exact(BLOCK_SIZE), &cipher, writer, &mut last_plain)?;
    }

    if let Some(last) = last_plain {
        let unpadded = unpad_pkcs7(&last)?;
        writer.write_all(&unpadded)?;
    }
    Ok(())
}

fn encrypt_cbc<R: Read, W: Write>(reader: &mut R, writer: &mut W, key: &[u8], iv: &[u8; BLOCK_SIZE]) -> io::Result<()> {
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut prev = *iv;
    let mut remainder = Vec::new();
    let mut buffer = vec![0u8; BUFFER_SIZE];

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        remainder.extend_from_slice(&buffer[..n]);
        let mut chunks = remainder.chunks_exact(BLOCK_SIZE);
        process_cbc_blocks(&mut chunks, &cipher, writer, &mut prev)?;
        remainder = chunks.remainder().to_vec();
    }

    // Pad and encrypt the remainder (always pad, even if empty)
    let pad_len = BLOCK_SIZE - (remainder.len() % BLOCK_SIZE);
    remainder.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    let mut chunks = remainder.chunks_exact(BLOCK_SIZE);
    process_cbc_blocks(&mut chunks, &cipher, writer, &mut prev)?;
    Ok(())
}

fn decrypt_cbc<R: Read, W: Write>(reader: &mut R, writer: &mut W, key: &[u8], iv: &[u8; BLOCK_SIZE]) -> io::Result<()> {
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut prev_ct = *iv;
    let mut last_plain: Option<[u8; BLOCK_SIZE]> = None;
    let mut buffer = vec![0u8; BUFFER_SIZE];

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        if n % BLOCK_SIZE != 0 {
            return Err(Error::new(ErrorKind::InvalidData, "Input not multiple of block size"));
        }
        process_decrypt_cbc_blocks(buffer[..n].chunks_exact(BLOCK_SIZE), &cipher, writer, &mut last_plain, &mut prev_ct)?;
    }

    if let Some(last) = last_plain {
        let unpadded = unpad_pkcs7(&last)?;
        writer.write_all(&unpadded)?;
    }
    Ok(())
}

fn encrypt_stream<R: Read, W: Write, C: StreamCipher>(reader: &mut R, writer: &mut W, mut cipher: C) -> io::Result<()> {
    let mut buf = vec![0u8; BUFFER_SIZE];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }
        cipher.apply_keystream(&mut buf[..n]);
        writer.write_all(&buf[..n])?;
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

fn unpad_pkcs7(block: &[u8; BLOCK_SIZE]) -> io::Result<Vec<u8>> {
    let pad = block[BLOCK_SIZE - 1] as usize;
    if pad == 0 || pad > BLOCK_SIZE { return Err(Error::new(ErrorKind::InvalidData, "некорректный PKCS#7")); }
    if !block[BLOCK_SIZE - pad..].iter().all(|&b| b as usize == pad) {
        return Err(Error::new(ErrorKind::InvalidData, "битый PKCS#7"));
    }
    Ok(block[..BLOCK_SIZE - pad].to_vec())
}