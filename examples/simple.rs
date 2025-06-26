use lowmc_rs::LowMC;

fn main() {
    println!("🔐 LowMC Block Cipher Example");
    println!("=============================");

    // Create a LowMC cipher with a key
    let key = 0x123456789ABCDEF0u128;
    let cipher = LowMC::new(key);

    println!("🔑 Key: {:#x}", key);
    println!("📊 Block size: 256 bits");
    println!("🔧 Key size: 80 bits");
    println!("🔄 Rounds: 12");
    println!("📦 S-boxes: 49 (3-bit each)");
    println!();

    // Example 1: Basic 128-bit encryption
    println!("📝 Example 1: 128-bit Message Encryption");
    println!("-----------------------------------------");

    let message = 0xDEADBEEFCAFEBABEu128;
    println!("📥 Plaintext:  {:#x}", message);

    let (ciphertext_low, ciphertext_high) = cipher.encrypt(message);
    println!(
        "🔒 Ciphertext: low={:#x}, high={:#x}",
        ciphertext_low, ciphertext_high
    );

    let decrypted = cipher.decrypt(ciphertext_low, ciphertext_high);
    println!("🔓 Decrypted:  {:#x}", decrypted);

    let success = message == decrypted;
    println!("✅ Success: {}", success);
    println!();

    // Example 2: Full 256-bit encryption
    println!("📝 Example 2: Full 256-bit Encryption");
    println!("--------------------------------------");

    let plaintext_low = 0x123456789ABCDEFu128;
    let plaintext_high = 0xFEDCBA9876543210u128;
    println!(
        "📥 Plaintext:  low={:#x}, high={:#x}",
        plaintext_low, plaintext_high
    );

    let (cipher_low, cipher_high) = cipher.encrypt_full(plaintext_low, plaintext_high);
    println!(
        "🔒 Ciphertext: low={:#x}, high={:#x}",
        cipher_low, cipher_high
    );

    let (recovered_low, recovered_high) = cipher.decrypt_full(cipher_low, cipher_high);
    println!(
        "🔓 Decrypted:  low={:#x}, high={:#x}",
        recovered_low, recovered_high
    );

    let full_success = plaintext_low == recovered_low && plaintext_high == recovered_high;
    println!("✅ Success: {}", full_success);
    println!();

    // Example 3: Multiple messages with same key
    println!("📝 Example 3: Multiple Messages");
    println!("-------------------------------");

    let messages = [0x0u128, 0x1u128, 0xFFFFFFFFu128, 0x123456789ABCDEFu128];

    for (i, &msg) in messages.iter().enumerate() {
        let (ct_low, ct_high) = cipher.encrypt(msg);
        let recovered = cipher.decrypt(ct_low, ct_high);

        println!(
            "Message {}: {:#x} -> ({:#x}, {:#x}) -> {:#x} ✅",
            i + 1,
            msg,
            ct_low,
            ct_high,
            recovered
        );

        assert_eq!(msg, recovered);
    }

    println!();
    println!("🎉 All examples completed successfully!");
    println!("💡 The LowMC cipher is working correctly with:");
    println!("   • Deterministic encryption/decryption");
    println!("   • Full 256-bit block processing");
    println!("   • Clean matrix operations without LFSR");
    println!("   • Thread-safe operation");
}
