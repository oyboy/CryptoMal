use std::fs::{File};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;
use std::hash::{DefaultHasher, Hasher};
use tempfile::TempDir;
use CryptoMal::cryptor::{encrypt_file, decrypt_file, CipherMode};
use CryptoMal::generator;

const TEST_KEY: &[u8] = b"1234567890ABCDEF";
const CHUNK_SIZE: usize = 1_048_576;
const FILE_SIZE_MB: usize = 1024; 

fn create_large_file(path: &Path, size_mb: usize) -> std::io::Result<()> {
    println!("  Creating file with random data at: {}", path.display());
    let mut file = File::create(path)?;
    let total_bytes = size_mb * 1_048_576;
    let mut written = 0;

    let mut rng = rand::rng();
    let mut random_chunk = vec![0u8; CHUNK_SIZE];

    while written < total_bytes {
        let chunk_size = std::cmp::min(CHUNK_SIZE, total_bytes - written);

        use rand::Rng;
        rng.fill(&mut random_chunk[..chunk_size]);

        file.write_all(&random_chunk[..chunk_size])?;
        written += chunk_size;

        if written % (100 * 1_048_576) == 0 && written > 0 {
            println!("    Created {} MB...", written / 1_048_576);
        }
    }
    println!("  File created with random data: {} bytes in temp dir", total_bytes);
    Ok(())
}

fn compute_checksum(path: &Path) -> std::io::Result<u64> {
    println!("  Computing checksum for: {}", path.display());
    let mut file = File::open(path)?;
    let mut hasher = DefaultHasher::new();

    let mut buffer = Vec::with_capacity(CHUNK_SIZE);
    buffer.resize(CHUNK_SIZE, 0u8); 

    let mut total_read = 0;
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 { break; }
        hasher.write(&buffer[..bytes_read]);
        total_read += bytes_read;
        if total_read % (100 * 1_048_576) == 0 && total_read > 0 {
            println!("    Hashed {} MB...", total_read / 1_048_576);
        }
    }
    let checksum = hasher.finish();
    println!("  Checksum computed: 0x{:x}", checksum);
    Ok(checksum)
}

#[test]
fn load_test_large_file_roundtrip() {
    println!("=== Starting high-load integration test for {} MB file ===", FILE_SIZE_MB);
    println!("(System: 12 GB RAM, SSD — expected times: creation <1s, encrypt/decrypt 10-30s each)");

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    println!("  Temp dir created: {}", temp_dir.path().display());

    let input_path = temp_dir.path().join("input_large.bin");
    let encrypted_path = temp_dir.path().join("encrypted_large.bin");
    let decrypted_path = temp_dir.path().join("decrypted_large.bin");

    let create_start = Instant::now();
    create_large_file(&input_path, FILE_SIZE_MB).expect("Failed to create large file");
    let create_duration = create_start.elapsed();
    let create_mbps = (FILE_SIZE_MB as f64 / create_duration.as_secs_f64()) as usize;
    println!("File creation complete: {:?} ({} MB/s)", create_duration, create_mbps);

    let original_checksum = compute_checksum(&input_path).expect("Failed to compute original checksum");

    println!("Starting encryption (CBC mode)...");
    let encrypt_start = Instant::now();
    let iv = generator::generate_random_bytes(16);
    encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        None, 
        Some(TEST_KEY),
        CipherMode::CBC,
        iv.clone(),
    ).expect("Encryption failed");
    let encrypt_duration = encrypt_start.elapsed();

    let encrypt_mbps = (FILE_SIZE_MB as f64 / encrypt_duration.as_secs_f64()) as usize;
    println!("Encryption complete: {:?} ({} MB/s)", encrypt_duration, encrypt_mbps);

    println!("Starting decryption (CBC mode)...");
    let decrypt_start = Instant::now();
    decrypt_file(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        None,
        Some(TEST_KEY),
        CipherMode::CBC,
        iv,
    ).expect("Decryption failed");
    let decrypt_duration = decrypt_start.elapsed();
    let decrypt_mbps = (FILE_SIZE_MB as f64 / decrypt_duration.as_secs_f64()) as usize;
    println!("Decryption complete: {:?} ({} MB/s)", decrypt_duration, decrypt_mbps);

    let decrypted_checksum = compute_checksum(&decrypted_path).expect("Failed to compute decrypted checksum");
    assert_eq!(original_checksum, decrypted_checksum, "Checksum mismatch! Roundtrip failed.");

    println!("=== High-load test PASSED: Full roundtrip verified for {} MB ===", FILE_SIZE_MB);
    let total_duration = create_duration + encrypt_duration + decrypt_duration;
    println!("  - Total time: {:?}", total_duration);
    println!("  - Files auto-deleted from temp dir.");
}