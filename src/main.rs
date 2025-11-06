mod validate;
mod cryptor;
mod key_manager;
mod hash;
mod process_hollowing;
mod herpaderping;
pub mod generator;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use clap::{Parser, Subcommand};
use cryptor::CipherMode;
use hash::{Hasher, Sha256, Sha3};

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
            Commands::Encrypt { algorithm, mode, key, password, iv, in_file, out_file } => {
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

            Commands::Decrypt { key, password, mode, iv, in_file, out_file } => {
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
            
            Commands::Dgst {algorithm, input, output} => {
                let file = File::open(input).map_err(|e| e.to_string())?;
                
                let mut reader = BufReader::new(file);
                let mut hasher: Box<dyn Hasher> = match algorithm.as_str() {
                    "sha256" => Box::new(Sha256::new()),
                    "sha3-256" => Box::new(Sha3::new()),
                    _ => return Err("Unsupported algorithm".to_string()),
                };
                
                let mut buf = [0u8; 8192];
                loop {
                    let n = reader.read(&mut buf).map_err(|e| e.to_string())?;
                    if n == 0 { break;}
                    hasher.update(&buf[..n]);
                }
                
                let hash = hasher.finalize();
                let out_str = format!("{}\n", hash);
                
                if let Some(o) = output {
                    let mut out_file = File::create(o).map_err(|e| e.to_string())?;
                    out_file.write_all(out_str.as_bytes()).map_err(|e| e.to_string())?;
                } else {
                    println!("{}", out_str);
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
    //process_hollowing::job::create_hidden_process().unwrap();
    let args = Args::parse();
    if let Err(res) = args.command.execute(args.verbose) {
        eprintln!("Error {}", res);
        std::process::exit(1);
    }
}