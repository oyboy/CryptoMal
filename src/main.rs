mod validate;
mod cryptor;
use clap::{Parser, Subcommand};

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
                validate::validate_params(Some(algorithm), Some(mode), Some(key), Some(in_file), out_file.as_deref())?;
                let out = validate::create_output_file_if_not_provided("ENC", in_file, out_file.as_deref())?;
                cryptor::encrypt_file(in_file, &out, key).expect("Encryption failed");
                Ok(())
            }
            Commands::Decrypt {key, in_file, out_file } => {
                log("running decrypt command...");
                validate::validate_params(None, None, Some(key), Some(in_file), out_file.as_deref())?;
                let out = validate::create_output_file_if_not_provided("DEC", in_file, out_file.as_deref())?;
                cryptor::decrypt_file(in_file, &out, key).expect("Decryption failed");
                Ok(())
            }
        }
    }
}

fn main() {
    let args = Args::parse();
    if let Err(res) = args.command.execute(args.verbose) {
        eprintln!("Error {}", res);
        std::process::exit(1);
    }
}