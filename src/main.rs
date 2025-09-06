mod validate;
mod cryptor;
mod key_manager;
pub mod generator;

use clap::{Parser, Subcommand};
use cryptor::CipherMode;
#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    verbose: bool,
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Encrypt {
        #[arg(short, long, default_value = "AES")]
        algorithm: String,
        #[arg(short, long, default_value = "ECB")]
        mode: String,
        #[arg(short, long)]
        key: String,
        in_file: String,
        out_file: Option<String>,
    },
    Decrypt {
        #[arg(short, long)]
        key: String,
        #[arg(short, long, default_value = "ECB")]
        mode: String,
        in_file: String,
        out_file: Option<String>,
    },
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
            Commands::Encrypt { algorithm, mode, key, in_file, out_file } => {
                log("running encrypt command...");
                validate::validate_params(Some(algorithm), Some(key), Some(in_file), out_file.as_deref())?;
                let cipher_mode = mode_from_str(mode)?;
                let out = validate::create_output_file_if_not_provided("ENC", in_file, out_file.as_deref())?;
                cryptor::encrypt_file(in_file, &out, key, cipher_mode).expect("Encryption failed");
                Ok(())
            }
            Commands::Decrypt {key, mode, in_file, out_file } => {
                log("running decrypt command...");
                validate::validate_params(None, Some(key), Some(in_file), out_file.as_deref())?;
                let cipher_mode = mode_from_str(mode)?;
                let out = validate::create_output_file_if_not_provided("DEC", in_file, out_file.as_deref())?;
                cryptor::decrypt_file(in_file, &out, key, cipher_mode).expect("Decryption failed");
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