use clap::{Parser, Subcommand};
use lowmc_rs::LowMC;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "lowmc")]
#[command(about = "LowMC block cipher CLI tool")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new LowMC key and save it to ~/.lowmc/
    GenerateKey {
        /// Name for the key file (without extension)
        #[arg(short, long, default_value = "default")]
        name: String,

        /// Overwrite existing key file
        #[arg(short, long)]
        force: bool,
    },

    /// Encrypt data using a saved key
    Encrypt {
        /// Name of the key to use
        #[arg(short, long, default_value = "default")]
        key: String,

        /// Input file (use - for stdin)
        #[arg(short, long, default_value = "-")]
        input: String,

        /// Output file (use - for stdout)
        #[arg(short, long, default_value = "-")]
        output: String,

        /// Format: hex, base64, or raw
        #[arg(short, long, default_value = "hex")]
        format: String,
    },

    /// Decrypt data using a saved key
    Decrypt {
        /// Name of the key to use
        #[arg(short, long, default_value = "default")]
        key: String,

        /// Input file (use - for stdin)
        #[arg(short, long, default_value = "-")]
        input: String,

        /// Output file (use - for stdout)
        #[arg(short, long, default_value = "-")]
        output: String,

        /// Format: hex, base64, or raw
        #[arg(short, long, default_value = "hex")]
        format: String,
    },

    /// List all saved keys
    ListKeys,

    /// Show information about a key
    KeyInfo {
        /// Name of the key
        #[arg(short, long, default_value = "default")]
        name: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKey { name, force } => {
            generate_key(&name, force);
        }
        Commands::Encrypt {
            key,
            input,
            output,
            format,
        } => {
            encrypt_data(&key, &input, &output, &format);
        }
        Commands::Decrypt {
            key,
            input,
            output,
            format,
        } => {
            decrypt_data(&key, &input, &output, &format);
        }
        Commands::ListKeys => {
            list_keys();
        }
        Commands::KeyInfo { name } => {
            key_info(&name);
        }
    }
}

fn get_lowmc_dir() -> PathBuf {
    let mut home = dirs::home_dir().expect("Could not find home directory");
    home.push(".lowmc");
    home
}

fn ensure_lowmc_dir() -> io::Result<()> {
    let dir = get_lowmc_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }
    Ok(())
}

fn get_key_path(name: &str) -> PathBuf {
    let mut path = get_lowmc_dir();
    path.push(format!("{}.key", name));
    path
}

fn generate_key(name: &str, force: bool) {
    let key_path = get_key_path(name);

    if key_path.exists() && !force {
        eprintln!("Key '{}' already exists. Use --force to overwrite.", name);
        std::process::exit(1);
    }

    match ensure_lowmc_dir() {
        Ok(()) => {
            let key = LowMC::generate_random_key();
            let key_hex = format!("{:032x}", key);

            match fs::write(&key_path, &key_hex) {
                Ok(()) => {
                    println!("Generated new key '{}': {}", name, key_hex);
                    println!("Key saved to: {}", key_path.display());
                }
                Err(e) => {
                    eprintln!("Failed to save key: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to create .lowmc directory: {}", e);
            std::process::exit(1);
        }
    }
}

fn load_key(name: &str) -> u128 {
    let key_path = get_key_path(name);

    if !key_path.exists() {
        eprintln!(
            "Key '{}' not found. Generate it first with 'lowmc generate-key --name {}'",
            name, name
        );
        std::process::exit(1);
    }

    match fs::read_to_string(&key_path) {
        Ok(key_hex) => {
            let key_hex = key_hex.trim();
            if key_hex.len() != 32 {
                eprintln!("Invalid key format in {}", key_path.display());
                std::process::exit(1);
            }

            match u128::from_str_radix(key_hex, 16) {
                Ok(key) => key,
                Err(_) => {
                    eprintln!("Invalid key format in {}", key_path.display());
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to read key file: {}", e);
            std::process::exit(1);
        }
    }
}

fn read_input(input: &str) -> Vec<u8> {
    if input == "-" {
        let mut data = Vec::new();
        io::stdin()
            .read_to_end(&mut data)
            .expect("Failed to read from stdin");
        data
    } else {
        fs::read(input).expect(&format!("Failed to read file: {}", input))
    }
}

fn write_output(output: &str, data: &[u8]) {
    if output == "-" {
        io::stdout()
            .write_all(data)
            .expect("Failed to write to stdout");
    } else {
        fs::write(output, data).expect(&format!("Failed to write file: {}", output));
    }
}

fn encrypt_data(key_name: &str, input: &str, output: &str, format: &str) {
    let key = load_key(key_name);
    let cipher = LowMC::new(key);

    let input_data = read_input(input);

    // Pad input to 16-byte boundary (128 bits)
    let mut padded_data = input_data.clone();
    let padding_len = 16 - (input_data.len() % 16);
    if padding_len < 16 {
        padded_data.extend_from_slice(&vec![padding_len as u8; padding_len]);
    } else {
        padded_data.extend_from_slice(&vec![16u8; 16]);
    }

    let mut encrypted_data = Vec::new();

    // Encrypt each 16-byte block, output 32 bytes per block (low+high)
    for chunk in padded_data.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let block_u128 = u128::from_le_bytes(block);

        let (low, high) = cipher.encrypt(block_u128);
        encrypted_data.extend_from_slice(&low.to_le_bytes());
        encrypted_data.extend_from_slice(&high.to_le_bytes());
    }

    // Format output
    let formatted_data = match format.to_lowercase().as_str() {
        "hex" => {
            let hex_string = encrypted_data
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            hex_string.into_bytes()
        }
        "base64" => {
            // Simple base64 implementation - in production use a proper crate
            let mut base64 = Vec::new();
            for chunk in encrypted_data.chunks(3) {
                let mut bytes = [0u8; 3];
                bytes[..chunk.len()].copy_from_slice(chunk);

                let b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                let mut val = (bytes[0] as u32) << 16 | (bytes[1] as u32) << 8 | bytes[2] as u32;

                for _ in 0..4 {
                    let idx = (val >> 18) & 0x3F;
                    base64.push(b64_chars.as_bytes()[idx as usize]);
                    val <<= 6;
                }
            }
            base64
        }
        "raw" => encrypted_data,
        _ => {
            eprintln!("Unsupported format: {}. Use hex, base64, or raw", format);
            std::process::exit(1);
        }
    };

    write_output(output, &formatted_data);
}

fn decrypt_data(key_name: &str, input: &str, output: &str, format: &str) {
    let key = load_key(key_name);
    let cipher = LowMC::new(key);

    let input_data = read_input(input);

    // Parse input format
    let encrypted_data = match format.to_lowercase().as_str() {
        "hex" => {
            let hex_string = String::from_utf8(input_data).expect("Invalid UTF-8 in hex input");
            let mut data = Vec::new();
            for chunk in hex_string.as_bytes().chunks(2) {
                if chunk.len() == 2 {
                    let byte = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16)
                        .expect("Invalid hex");
                    data.push(byte);
                }
            }
            data
        }
        "base64" => {
            // Simple base64 decoding - in production use a proper crate
            let mut data = Vec::new();
            let b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

            for chunk in input_data.chunks(4) {
                let mut val = 0u32;
                for &byte in chunk {
                    if let Some(idx) = b64_chars.find(byte as char) {
                        val = (val << 6) | (idx as u32);
                    }
                }

                data.push((val >> 16) as u8);
                if chunk.len() > 1 {
                    data.push((val >> 8) as u8);
                }
                if chunk.len() > 2 {
                    data.push(val as u8);
                }
            }
            data
        }
        "raw" => input_data,
        _ => {
            eprintln!("Unsupported format: {}. Use hex, base64, or raw", format);
            std::process::exit(1);
        }
    };

    if encrypted_data.len() % 32 != 0 {
        eprintln!("Ciphertext length must be a multiple of 32 bytes (256 bits per block)");
        std::process::exit(1);
    }

    let mut decrypted_data = Vec::new();

    // Decrypt each 32-byte block
    for chunk in encrypted_data.chunks(32) {
        let mut low_bytes = [0u8; 16];
        let mut high_bytes = [0u8; 16];
        low_bytes.copy_from_slice(&chunk[..16]);
        high_bytes.copy_from_slice(&chunk[16..]);
        let low = u128::from_le_bytes(low_bytes);
        let high = u128::from_le_bytes(high_bytes);
        let decrypted = cipher.decrypt(low, high);
        decrypted_data.extend_from_slice(&decrypted.to_le_bytes());
    }

    // Remove padding
    if let Some(&padding_len) = decrypted_data.last() {
        if padding_len <= 16 && padding_len > 0 {
            let len = decrypted_data.len();
            if len >= padding_len as usize {
                decrypted_data.truncate(len - padding_len as usize);
            }
        }
    }

    write_output(output, &decrypted_data);
}

fn list_keys() {
    match ensure_lowmc_dir() {
        Ok(()) => {
            let dir = get_lowmc_dir();
            match fs::read_dir(dir) {
                Ok(entries) => {
                    let mut keys = Vec::new();
                    for entry in entries {
                        if let Ok(entry) = entry {
                            if let Some(ext) = entry.path().extension() {
                                if ext == "key" {
                                    if let Some(name) = entry.path().file_stem() {
                                        keys.push(name.to_string_lossy().to_string());
                                    }
                                }
                            }
                        }
                    }

                    if keys.is_empty() {
                        println!("No keys found. Generate one with 'lowmc generate-key'");
                    } else {
                        println!("Available keys:");
                        for key in keys {
                            println!("  {}", key);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read .lowmc directory: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to access .lowmc directory: {}", e);
            std::process::exit(1);
        }
    }
}

fn key_info(name: &str) {
    let key_path = get_key_path(name);

    if !key_path.exists() {
        eprintln!("Key '{}' not found", name);
        std::process::exit(1);
    }

    match fs::metadata(&key_path) {
        Ok(metadata) => {
            println!("Key: {}", name);
            println!("Path: {}", key_path.display());
            println!("Size: {} bytes", metadata.len());

            if let Ok(created) = metadata.created() {
                println!("Created: {:?}", created);
            }

            // Show first few characters of the key
            if let Ok(key_content) = fs::read_to_string(&key_path) {
                let key_hex = key_content.trim();
                if key_hex.len() >= 8 {
                    println!("Key (first 8 chars): {}...", &key_hex[..8]);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to get key info: {}", e);
            std::process::exit(1);
        }
    }
}
