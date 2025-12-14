mod validate;
mod cryptor;
mod key_manager;
mod hash;
mod process_hollowing;
mod herpaderping;
mod gcm;

mod mac;
pub mod generator;
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::Path;
use clap::{Parser, Subcommand};
use cryptor::CipherMode;
use hash::{Hasher, Sha256, Sha3};
use mac::{hmac::Hmac};
use crate::gcm::Gcm;
use rand::{Rng, rng};

#[derive(Parser)]
pub struct Args {
    #[arg(short, long)]
    verbose: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Encrypt {
        #[arg(short, long, default_value = "AES")]
        algorithm: String,
        #[arg(short, long, default_value = "ECB")]
        mode: String,
        #[arg(short, long)]
        key: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        iv: Option<String>,
        #[arg(long)]
        aad: Option<String>,
        in_file: String,
        out_file: Option<String>,
    },
    Decrypt {
        #[arg(short, long)]
        key: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(short, long, default_value = "ECB")]
        mode: String,
        #[arg(long)]
        iv: Option<String>,
        #[arg(long)]
        aad: Option<String>,
        in_file: String,
        out_file: Option<String>,
    },
    Derive {
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        salt: String,
        #[arg(short, long, default_value_t = 100_000)]
        iterations: u32,
        #[arg(short, long, default_value_t = 16)]
        length: usize,
    },
    Dgst {
        #[arg(short, long)]
        algorithm: String,
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: Option<String>,
        #[arg(long)]
        hmac: bool,
        #[arg(short, long, required_if_eq("hmac", "true"))]
        key: Option<String>,
        #[arg(long)]
        verify: Option<String>,
    },
    Herpaderp {
        #[arg(short, long)]
        payload: Option<String>,
        #[arg(short, long)]
        decoy: Option<String>,
        #[arg(short, long)]
        replace: Option<String>,
    }
}

trait Command {
    fn execute(&self, verbose: bool) -> Result<(), String>;
}

impl Command for Commands {
    fn execute(&self, verbose: bool) -> Result<(), String> {
        let log = |msg: &str| {
            if verbose {
                println!("Log: {}", msg);
            }
        };
        match self {
            Commands::Encrypt { algorithm, mode, key, password, iv, aad, in_file, out_file } => {
                if mode.to_uppercase() == "GCM" {
                    if algorithm.to_uppercase() != "AES" {
                        return Err("GCM mode is currently only supported for AES".to_string());
                    }

                    let key_hex = key.as_ref().ok_or("Key is required for GCM mode")?;
                    let key_bytes = hex::decode(key_hex).map_err(|_| "Invalid key hex")?;
                    if key_bytes.len() != 16 {
                        return Err("AES-128-GCM requires a 16-byte key".to_string());
                    }

                    let aad_bytes = if let Some(aad_str) = aad {
                        hex::decode(aad_str).map_err(|_| "Invalid AAD hex string")?
                    } else {
                        Vec::new()
                    };

                    let mut file = File::open(in_file).map_err(|e| format!("Failed to open input: {}", e))?;
                    let mut plaintext = Vec::new();
                    file.read_to_end(&mut plaintext).map_err(|e| e.to_string())?;

                    let mut nonce = [0u8; 12];
                    rng().fill(&mut nonce);
                    log(&format!("Generated Nonce: {}", hex::encode(nonce)));

                    let gcm = Gcm::new(&key_bytes);
                    let (ciphertext, tag) = gcm.encrypt(&nonce, &plaintext, &aad_bytes);

                    let mut output_data = Vec::with_capacity(12 + ciphertext.len() + 16);
                    output_data.extend_from_slice(&nonce);
                    output_data.extend_from_slice(&ciphertext);
                    output_data.extend_from_slice(&tag);

                    if let Some(out_path) = out_file {
                        let mut out = File::create(out_path).map_err(|e| e.to_string())?;
                        out.write_all(&output_data).map_err(|e| e.to_string())?;
                    } else {
                        std::io::stdout().write_all(&output_data).map_err(|e| e.to_string())?;
                    }

                    return Ok(());
                }

                let iv_bytes = iv.as_ref().map(|hex| hex::decode(hex).expect("Invalid IV hex"));
                let key_bytes = key.as_ref().map(|hex| hex::decode(hex).expect("Invalid key hex"));

                let params = validate::Params {
                    algorithm: Some(algorithm),
                    password: password.as_deref(),
                    key: key_bytes,
                    in_file: Some(in_file),
                    out_file: out_file.as_deref(),
                    iv: iv_bytes,
                    mode: Some(mode),
                };
                let v = params.finalize()?;

                let cipher_mode = mode_from_str(&v.mode)?;
                cryptor::encrypt_file(&v.in_file, &v.out_file, v.password.as_deref(), v.key_bytes.as_deref(), cipher_mode, v.iv)
                    .expect("Encryption failed");
                Ok(())
            }

            Commands::Decrypt { key, password, mode, iv, aad, in_file, out_file } => {
                if mode.to_uppercase() == "GCM" {
                    let key_hex = key.as_ref().ok_or("Key is required for GCM mode")?;
                    let key_bytes = hex::decode(key_hex).map_err(|_| "Invalid key hex")?;
                    if key_bytes.len() != 16 {
                        return Err("AES-128-GCM requires a 16-byte key".to_string());
                    }

                    let aad_bytes = if let Some(aad_str) = aad {
                        hex::decode(aad_str).map_err(|_| "Invalid AAD hex string")?
                    } else {
                        Vec::new()
                    };

                    let mut file = File::open(in_file).map_err(|e| format!("Failed to open input: {}", e))?;
                    let mut input_data = Vec::new();
                    file.read_to_end(&mut input_data).map_err(|e| e.to_string())?;

                    if input_data.len() < 28 {
                        return Err("Input file too short for GCM".to_string());
                    }

                    let nonce = &input_data[0..12];
                    let tag_start = input_data.len() - 16;
                    let ciphertext = &input_data[12..tag_start];
                    let tag = &input_data[tag_start..];

                    let gcm = Gcm::new(&key_bytes);

                    match gcm.decrypt(nonce, ciphertext, &aad_bytes, tag) {
                        Some(plaintext) => {
                            if let Some(out_path) = out_file {
                                let mut out = File::create(out_path).map_err(|e| e.to_string())?;
                                out.write_all(&plaintext).map_err(|e| e.to_string())?;
                                println!("[SUCCESS] Decryption completed successfully");
                            } else {
                                std::io::stdout().write_all(&plaintext).map_err(|e| e.to_string())?;
                            }
                        }
                        None => {
                            eprintln!("[ERROR] Authentication failed: AAD mismatch or ciphertext tampered");
                            if let Some(out_path) = out_file {
                                if Path::new(out_path).exists() {
                                    let _ = fs::remove_file(out_path);
                                }
                            }
                            std::process::exit(1);
                        }
                    }
                    return Ok(());
                }

                let iv_bytes = iv.as_ref().map(|hex| hex::decode(hex).expect("Invalid IV hex string"));
                let key_bytes = key.as_ref().map(|hex| hex::decode(hex).expect("Invalid key hex"));

                let params = validate::Params {
                    algorithm: None,
                    password: password.as_deref(),
                    key: key_bytes,
                    in_file: Some(in_file),
                    out_file: out_file.as_deref(),
                    iv: iv_bytes,
                    mode: Some(mode),
                };
                let v = params.finalize()?;

                let cipher_mode = mode_from_str(mode)?;
                cryptor::decrypt_file(&v.in_file, &v.out_file, v.password.as_deref(), v.key_bytes.as_deref(), cipher_mode, v.iv)
                    .expect("Decryption failed");
                Ok(())
            }

            Commands::Derive { password, salt, iterations, length } => {
                log("running derive command...");
                let key_bytes = key_manager::keygen::generate_key(
                    password.as_bytes(),
                    salt.as_bytes(),
                    Some(*iterations),
                    Some(*length),
                ).map_err(|e| e.to_string())?;

                println!("Generated key: {}", hex::encode(key_bytes));
                Ok(())
            }

            Commands::Dgst { algorithm, input, output, hmac, key, verify } => {
                let file = File::open(input).map_err(|e| e.to_string())?;
                let mut reader = BufReader::new(file);
                let mut buf = [0u8; 8192];

                let result_hex = if *hmac {
                    let key_hex = key.as_ref().ok_or("Key is required for HMAC mode")?;
                    let key_bytes = hex::decode(key_hex).map_err(|_| "Invalid key hex string")?;

                    let mut hmac_instance = Hmac::new(&key_bytes, algorithm)
                        .map_err(|e| e)?;

                    loop {
                        let n = reader.read(&mut buf).map_err(|e| e.to_string())?;
                        if n == 0 { break; }
                        hmac_instance.update(&buf[..n]);
                    }
                    hmac_instance.finalize()
                } else {
                    let mut hasher: Box<dyn Hasher> = match algorithm.as_str() {
                        "sha256" => Box::new(Sha256::new()),
                        "sha3-256" => Box::new(Sha3::new()),
                        _ => return Err("Unsupported algorithm".to_string()),
                    };

                    loop {
                        let n = reader.read(&mut buf).map_err(|e| e.to_string())?;
                        if n == 0 { break; }
                        hasher.update(&buf[..n]);
                    }
                    hasher.finalize().to_string()
                };

                if let Some(verify_file_path) = verify {
                    let verify_file = File::open(verify_file_path).map_err(|e| format!("Failed to open verify file: {}", e))?;
                    let mut verify_reader = BufReader::new(verify_file);
                    let mut expected_content = String::new();
                    verify_reader.read_to_string(&mut expected_content).map_err(|e| e.to_string())?;

                    let expected_hash = expected_content
                        .split_whitespace()
                        .next()
                        .ok_or("Invalid verification file format")?;

                    if result_hex.eq_ignore_ascii_case(expected_hash) {
                        println!("[OK] HMAC verification successful");
                    } else {
                        eprintln!("[ERROR] HMAC verification failed");
                        std::process::exit(1);
                    }
                } else {
                    let out_str = format!("{} {}\n", result_hex, input);

                    if let Some(o) = output {
                        let mut out_file = File::create(o).map_err(|e| e.to_string())?;
                        out_file.write_all(out_str.as_bytes()).map_err(|e| e.to_string())?;
                    } else {
                        print!("{}", out_str);
                    }
                }
                Ok(())
            }
            Commands::Herpaderp {payload, decoy, replace} => {
                herpaderping::job::create_process(payload, decoy, replace).unwrap();
                Ok(())
            }
        }
    }
}

fn mode_from_str(mode: &str) -> Result<CipherMode, String> {
    match mode.to_uppercase().as_str() {
        "ECB" => Ok(CipherMode::ECB),
        "CBC" => Ok(CipherMode::CBC),
        "CTR" => Ok(CipherMode::CTR),
        "OFB" => Ok(CipherMode::OFB),
        _ => {
            Err(format!("Unsupported mode: {}", mode))?;
            std::process::exit(1);
        },
    }
}

fn main() {
    let args = Args::parse();
    if let Err(res) = args.command.execute(args.verbose) {
        eprintln!("Error {}", res);
        std::process::exit(1);
    }
}