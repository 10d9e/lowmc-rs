use lowmc_rs::LowMC;

fn main() {
    println!("LowMC Cipher Demo");

    let key = LowMC::generate_random_key();
    let cipher = LowMC::new(key);
    let message = 0xDEADBEEFu128;

    let (ciphertext_low, ciphertext_high) = cipher.encrypt(message);
    let recovered = cipher.decrypt(ciphertext_low, ciphertext_high);

    println!("Message: {:#x}", message);
    println!(
        "Encrypted: low={:#x}, high={:#x}",
        ciphertext_low, ciphertext_high
    );
    println!("Recovered: {:#x}", recovered);
    println!("Success: {}", message == recovered);
}
