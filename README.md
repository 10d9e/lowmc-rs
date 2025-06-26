# lowmc-rs

## LowMC Command-Line Interface (CLI)

### Build & Install

```sh
# Build the CLI binary
cargo build --release --bin lowmc

# Optionally, install to your $HOME/.cargo/bin
cargo install --path . --bin lowmc
```

### Usage

#### Generate a new key

```sh
lowmc generate-key --name mykey
```
- Keys are saved in `~/.lowmc/` as `<name>.key`.

#### Encrypt a file

```sh
lowmc encrypt --key mykey --input plaintext.txt --output ciphertext.txt --format hex
```
- Supported formats: `hex`, `base64`, `raw`.

#### Decrypt a file

```sh
lowmc decrypt --key mykey --input ciphertext.txt --output decrypted.txt --format hex
```

#### List all keys

```sh
lowmc list-keys
```

#### Show key info

```sh
lowmc key-info --name mykey
```

#### Help

```sh
lowmc --help
```

## Overview

LowMC is a family of block ciphers designed to minimize the number of AND gates in the circuit representation, making it suitable for applications in multi-party computation, fully homomorphic encryption, and zero-knowledge proofs.

This implementation provides:
- **Block size**: 256 bits
- **Key size**: 80 bits  
- **Rounds**: 12
- **S-boxes per round**: 49 (3-bit S-boxes)
- **Identity bits per round**: 109

## Features

- ✅ Complete LowMC implementation following the specification
- ✅ All core cryptographic components (S-box layer, linear layer, key schedule)
- ✅ Matrix inversion and rank checking for full-rank matrices

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
lowmc-rs = "0.1.0"
```

### Basic Usage

```rust
use lowmc_rs::LowMC;

fn main() {
    // Create cipher with 80-bit key
    let cipher = LowMC::new(0x123456789ABCDEFu128);
    
    // Encrypt a message (uses lower 128 bits of u128)
    let plaintext = 0xDEADBEEFu128;
    let ciphertext = cipher.encrypt(plaintext);
    let recovered = cipher.decrypt(ciphertext);
    
    println!("Plaintext:  {:#x}", plaintext);
    println!("Ciphertext: {:#x}", ciphertext);
    println!("Recovered:  {:#x}", recovered);
    assert_eq!(plaintext, recovered);
}
```

### Key Management

```rust
use lowmc_rs::LowMC;

let mut cipher = LowMC::new(0x12345u128);

// Change key
cipher.set_key(0x54321u128);
```

## Examples

Run the included example:

```bash
cargo run --example simple --release
```

## Testing

Run the comprehensive test suite:

```bash
# Tests must be run in release mode with single thread due to global LFSR state
cargo test --release -- --test-threads=1
```

The test suite includes:
- S-box and inverse S-box verification
- Substitution layer round-trip tests
- Matrix inversion correctness
- Full-rank matrix generation
- Single-round encryption/decryption
- Complete cipher functionality tests

## Library Structure

- `src/lib.rs` - Main library implementation
- `src/main.rs` - Simple binary demo
- `examples/simple.rs` - Comprehensive usage example
- Unit tests included in library

## Implementation Notes

- Uses custom `BitVec` implementation for efficient bit manipulation
- Matrix operations use Gaussian elimination over GF(2)
- All matrices are verified to have full rank before use

## Performance

The implementation is optimized for correctness and clarity. For production use in performance-critical applications, consider:
- Using fixed precomputed matrices instead of random generation
- Batch processing multiple blocks
- Platform-specific optimizations

## License

Licensed under either of:
- Apache License, Version 2.0
- MIT License

at your option.

## References

- [LowMC: Cryptanalysis of LowMC](https://eprint.iacr.org/2015/016.pdf)
- [LowMC specification](https://github.com/LowMC/lowmc)

## Status

This implementation successfully passes all cryptographic component tests. The core algorithm structure is mathematically sound and follows the LowMC specification exactly.