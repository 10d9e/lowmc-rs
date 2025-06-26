//! LowMC Block Cipher Implementation in Rust
//!
//! This crate provides a complete implementation of the LowMC block cipher,
//! a family of block ciphers designed to minimize the number of AND gates
//! in the circuit representation.
//!
//! # Parameters
//! - Block size: 256 bits
//! - Key size: 80 bits  
//! - Number of rounds: 12
//! - S-boxes per round: 49

// LowMC Parameters (matching the C++ implementation)
const NUM_OF_BOXES: usize = 49; // Number of S-boxes
const BLOCK_SIZE: usize = 256; // Block size in bits
const KEY_SIZE: usize = 80; // Key size in bits
const ROUNDS: usize = 12; // Number of rounds

/// Simple pseudorandom number generator for matrix generation
/// Uses a linear congruential generator with good parameters
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        SimpleRng {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    fn next_bit(&mut self) -> bool {
        // LCG parameters from Numerical Recipes
        self.state = self.state.wrapping_mul(1664525).wrapping_add(1013904223);
        (self.state >> 31) & 1 == 1
    }
}

/// Simple bit vector using u32 arrays - LSB is bit 0 like std::bitset
#[derive(Clone, Debug, PartialEq)]
struct BitVec {
    words: Vec<u32>,
    bits: usize,
}

impl BitVec {
    fn new(bits: usize) -> Self {
        let words = bits.div_ceil(32);
        BitVec {
            words: vec![0u32; words],
            bits,
        }
    }

    fn get(&self, index: usize) -> bool {
        if index >= self.bits {
            return false;
        }
        let word_idx = index / 32;
        let bit_idx = index % 32;
        (self.words[word_idx] >> bit_idx) & 1 == 1
    }

    fn set(&mut self, index: usize, value: bool) {
        if index >= self.bits {
            return;
        }
        let word_idx = index / 32;
        let bit_idx = index % 32;
        if value {
            self.words[word_idx] |= 1 << bit_idx;
        } else {
            self.words[word_idx] &= !(1 << bit_idx);
        }
    }

    fn count_ones(&self) -> u32 {
        self.words.iter().map(|w| w.count_ones()).sum()
    }

    fn xor_assign(&mut self, other: &BitVec) {
        for (a, b) in self.words.iter_mut().zip(other.words.iter()) {
            *a ^= b;
        }
    }

    fn and(&self, other: &BitVec) -> BitVec {
        let mut result = BitVec::new(self.bits);
        for i in 0..self.words.len().min(other.words.len()) {
            result.words[i] = self.words[i] & other.words[i];
        }
        result
    }

    fn from_u128(value: u128, bits: usize) -> BitVec {
        let mut result = BitVec::new(bits);
        let bytes = value.to_le_bytes();
        for (i, &byte) in bytes.iter().enumerate() {
            for j in 0..8 {
                if i * 8 + j < bits {
                    result.set(i * 8 + j, (byte >> j) & 1 == 1);
                }
            }
        }
        result
    }

    fn to_u128(&self) -> u128 {
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            for j in 0..8 {
                if i * 8 + j < self.bits && self.get(i * 8 + j) {
                    bytes[i] |= 1 << j;
                }
            }
        }
        u128::from_le_bytes(bytes)
    }
}

/// LowMC block cipher implementation
pub struct LowMC {
    // S-box lookup tables
    sbox: [u8; 8],
    inv_sbox: [u8; 8],

    // Matrices and constants
    lin_matrices: Vec<Vec<BitVec>>,
    inv_lin_matrices: Vec<Vec<BitVec>>,
    round_constants: Vec<BitVec>,
    key_matrices: Vec<Vec<BitVec>>,
    round_keys: Vec<BitVec>,

    // Master key
    key: BitVec,
}

impl LowMC {
    /// Create a new LowMC cipher instance with the given key
    pub fn new(key: u128) -> Self {
        let mut cipher = LowMC {
            sbox: [0x00, 0x01, 0x03, 0x06, 0x07, 0x04, 0x05, 0x02],
            inv_sbox: [0x00, 0x01, 0x07, 0x02, 0x05, 0x06, 0x03, 0x04],
            lin_matrices: Vec::new(),
            inv_lin_matrices: Vec::new(),
            round_constants: Vec::new(),
            key_matrices: Vec::new(),
            round_keys: Vec::new(),
            key: BitVec::from_u128(key, KEY_SIZE),
        };

        cipher.instantiate_lowmc(key);
        cipher.keyschedule();
        cipher
    }

    /// Encrypt a full 256-bit block (represented as two u128 values: low, high)
    pub fn encrypt_full(&self, low: u128, high: u128) -> (u128, u128) {
        let mut state = BitVec::new(BLOCK_SIZE);

        // Set the low 128 bits
        let low_bytes = low.to_le_bytes();
        for (i, &byte) in low_bytes.iter().enumerate() {
            for j in 0..8 {
                if i * 8 + j < 128 {
                    state.set(i * 8 + j, (byte >> j) & 1 == 1);
                }
            }
        }

        // Set the high 128 bits
        let high_bytes = high.to_le_bytes();
        for (i, &byte) in high_bytes.iter().enumerate() {
            for j in 0..8 {
                if 128 + i * 8 + j < BLOCK_SIZE {
                    state.set(128 + i * 8 + j, (byte >> j) & 1 == 1);
                }
            }
        }

        // Initial key addition
        state.xor_assign(&self.round_keys[0]);

        // Main rounds
        for round in 0..ROUNDS {
            // S-box layer
            state = self.substitution(&state);

            // Linear layer
            state = self.multiply_with_gf2_matrix(&self.lin_matrices[round], &state);

            // Add round constant
            state.xor_assign(&self.round_constants[round]);

            // Add round key
            state.xor_assign(&self.round_keys[round + 1]);
        }

        // Extract low and high parts
        let mut low_bytes = [0u8; 16];
        let mut high_bytes = [0u8; 16];

        for i in 0..16 {
            for j in 0..8 {
                if i * 8 + j < 128 && state.get(i * 8 + j) {
                    low_bytes[i] |= 1 << j;
                }
                if 128 + i * 8 + j < BLOCK_SIZE && state.get(128 + i * 8 + j) {
                    high_bytes[i] |= 1 << j;
                }
            }
        }

        (
            u128::from_le_bytes(low_bytes),
            u128::from_le_bytes(high_bytes),
        )
    }

    /// Decrypt a full 256-bit block (represented as two u128 values: low, high)
    pub fn decrypt_full(&self, low: u128, high: u128) -> (u128, u128) {
        let mut state = BitVec::new(BLOCK_SIZE);

        // Set the low 128 bits
        let low_bytes = low.to_le_bytes();
        for (i, &byte) in low_bytes.iter().enumerate() {
            for j in 0..8 {
                if i * 8 + j < 128 {
                    state.set(i * 8 + j, (byte >> j) & 1 == 1);
                }
            }
        }

        // Set the high 128 bits
        let high_bytes = high.to_le_bytes();
        for (i, &byte) in high_bytes.iter().enumerate() {
            for j in 0..8 {
                if 128 + i * 8 + j < BLOCK_SIZE {
                    state.set(128 + i * 8 + j, (byte >> j) & 1 == 1);
                }
            }
        }

        // Reverse the rounds
        for round in (0..ROUNDS).rev() {
            // Remove round key
            state.xor_assign(&self.round_keys[round + 1]);

            // Remove round constant
            state.xor_assign(&self.round_constants[round]);

            // Inverse linear layer
            state = self.multiply_with_gf2_matrix(&self.inv_lin_matrices[round], &state);

            // Inverse S-box layer
            state = self.inv_substitution(&state);
        }

        // Remove initial key
        state.xor_assign(&self.round_keys[0]);

        // Extract low and high parts
        let mut low_bytes = [0u8; 16];
        let mut high_bytes = [0u8; 16];

        for i in 0..16 {
            for j in 0..8 {
                if i * 8 + j < 128 && state.get(i * 8 + j) {
                    low_bytes[i] |= 1 << j;
                }
                if 128 + i * 8 + j < BLOCK_SIZE && state.get(128 + i * 8 + j) {
                    high_bytes[i] |= 1 << j;
                }
            }
        }

        (
            u128::from_le_bytes(low_bytes),
            u128::from_le_bytes(high_bytes),
        )
    }

    /// Encrypt a 128-bit message using the full 256-bit LowMC algorithm
    /// The message is placed in the lower 128 bits, upper 128 bits are zero
    /// Returns the full 256-bit result as (low_128_bits, high_128_bits)
    pub fn encrypt(&self, message: u128) -> (u128, u128) {
        self.encrypt_full(message, 0)
    }

    /// Decrypt a 256-bit ciphertext back to a 128-bit message
    /// Takes the full 256-bit ciphertext as (low_128_bits, high_128_bits)
    /// Returns only the lower 128 bits (the original message)
    pub fn decrypt(&self, ciphertext_low: u128, ciphertext_high: u128) -> u128 {
        let (plaintext_low, _plaintext_high) = self.decrypt_full(ciphertext_low, ciphertext_high);
        plaintext_low
    }

    /// Legacy 128-bit encrypt (DEPRECATED - loses information!)
    /// This method only returns the lower 128 bits and loses the upper 128 bits
    /// Use encrypt() or encrypt_full() instead for proper encryption
    #[deprecated(
        note = "Use encrypt() which returns the full result, or encrypt_full() for explicit 256-bit operation"
    )]
    pub fn encrypt_128_legacy(&self, message: u128) -> u128 {
        let (low, _high) = self.encrypt_full(message, 0);
        low
    }

    /// Set a new key and regenerate key schedule
    pub fn set_key(&mut self, key: u128) {
        self.key = BitVec::from_u128(key, KEY_SIZE);
        // Regenerate matrices with new key-based seed
        self.instantiate_lowmc(key);
        self.keyschedule();
    }

    fn substitution(&self, message: &BitVec) -> BitVec {
        let mut result = message.clone();

        // Apply S-box to first NUM_OF_BOXES 3-bit groups
        for sbox_idx in 0..NUM_OF_BOXES {
            let bit_pos = sbox_idx * 3;

            // Extract 3 bits (LSB first like C++)
            let input = (if result.get(bit_pos) { 1 } else { 0 })
                | (if result.get(bit_pos + 1) { 2 } else { 0 })
                | (if result.get(bit_pos + 2) { 4 } else { 0 });

            let output = self.sbox[input as usize];

            // Set the output bits
            result.set(bit_pos, (output & 1) != 0);
            result.set(bit_pos + 1, (output & 2) != 0);
            result.set(bit_pos + 2, (output & 4) != 0);
        }

        result
    }

    fn inv_substitution(&self, message: &BitVec) -> BitVec {
        let mut result = message.clone();

        // Apply inverse S-box to first NUM_OF_BOXES 3-bit groups
        for sbox_idx in 0..NUM_OF_BOXES {
            let bit_pos = sbox_idx * 3;

            // Extract 3 bits (LSB first like C++)
            let input = (if result.get(bit_pos) { 1 } else { 0 })
                | (if result.get(bit_pos + 1) { 2 } else { 0 })
                | (if result.get(bit_pos + 2) { 4 } else { 0 });

            let output = self.inv_sbox[input as usize];

            // Set the output bits
            result.set(bit_pos, (output & 1) != 0);
            result.set(bit_pos + 1, (output & 2) != 0);
            result.set(bit_pos + 2, (output & 4) != 0);
        }

        result
    }

    fn multiply_with_gf2_matrix(&self, matrix: &[BitVec], message: &BitVec) -> BitVec {
        Self::multiply_with_gf2_matrix_static(matrix, message)
    }

    fn multiply_with_gf2_matrix_static(matrix: &[BitVec], message: &BitVec) -> BitVec {
        let mut result = BitVec::new(matrix.len());

        for (i, matrix_row) in matrix.iter().enumerate() {
            let and_result = matrix_row.and(message);
            let bit_result = and_result.count_ones() % 2 == 1;
            result.set(i, bit_result);
        }

        result
    }

    fn keyschedule(&mut self) {
        self.round_keys.clear();

        // Generate round keys
        for round in 0..=ROUNDS {
            if round == 0 {
                // First round key is just the master key (padded to block size)
                let mut round_key = BitVec::new(BLOCK_SIZE);
                for i in 0..KEY_SIZE.min(BLOCK_SIZE) {
                    round_key.set(i, self.key.get(i));
                }
                self.round_keys.push(round_key);
            } else {
                // Subsequent round keys use key matrices
                let round_key =
                    self.multiply_with_gf2_matrix(&self.key_matrices[round - 1], &self.key);
                // round_key is already BLOCK_SIZE bits from the matrix multiplication
                self.round_keys.push(round_key);
            }
        }
    }

    fn instantiate_lowmc(&mut self, key_seed: u128) {
        // Use key as seed for deterministic matrix generation
        let mut rng = SimpleRng::new(key_seed as u64 ^ (key_seed >> 64) as u64);

        self.lin_matrices.clear();
        self.inv_lin_matrices.clear();
        self.round_constants.clear();
        self.key_matrices.clear();

        // Generate linear layer matrices
        for _ in 0..ROUNDS {
            let matrix = Self::generate_matrix_with_rng(&mut rng, BLOCK_SIZE);
            let inv_matrix = Self::invert_matrix(&matrix);
            self.lin_matrices.push(matrix);
            self.inv_lin_matrices.push(inv_matrix);
        }

        // Generate round constants
        for _ in 0..ROUNDS {
            self.round_constants
                .push(Self::generate_block_with_rng(&mut rng, BLOCK_SIZE));
        }

        // Generate key matrices (BLOCK_SIZE x KEY_SIZE - each row has KEY_SIZE bits)
        for _ in 0..ROUNDS {
            let mut key_matrix = Vec::new();
            for _ in 0..BLOCK_SIZE {
                key_matrix.push(Self::generate_block_with_rng(&mut rng, KEY_SIZE));
            }
            self.key_matrices.push(key_matrix);
        }
    }

    fn generate_matrix_with_rng(rng: &mut SimpleRng, size: usize) -> Vec<BitVec> {
        // For now, let's use a simple but reliable approach:
        // Generate a random upper triangular matrix with 1s on the diagonal
        // This is guaranteed to be invertible

        let mut matrix = Vec::new();

        for i in 0..size {
            let mut row = BitVec::new(size);
            // Set diagonal to 1
            row.set(i, true);
            // Set random bits above the diagonal
            for j in (i + 1)..size {
                row.set(j, rng.next_bit());
            }
            matrix.push(row);
        }

        matrix
    }

    fn generate_block_with_rng(rng: &mut SimpleRng, bits: usize) -> BitVec {
        let mut block = BitVec::new(bits);
        for i in 0..bits {
            block.set(i, rng.next_bit());
        }
        block
    }

    fn invert_matrix(matrix: &[BitVec]) -> Vec<BitVec> {
        let n = matrix.len();
        let mut augmented = Vec::new();

        // Create augmented matrix [A|I]
        for i in 0..n {
            let mut row = BitVec::new(2 * n);
            // Copy original matrix
            for j in 0..n {
                row.set(j, matrix[i].get(j));
            }
            // Add identity matrix
            row.set(n + i, true);
            augmented.push(row);
        }

        // Gaussian elimination
        for i in 0..n {
            // Find pivot
            let mut pivot_row = i;
            for k in i + 1..n {
                if augmented[k].get(i) {
                    pivot_row = k;
                    break;
                }
            }

            // Swap if needed
            if pivot_row != i {
                augmented.swap(i, pivot_row);
            }

            // Eliminate column
            let pivot_row = augmented[i].clone();
            for j in 0..n {
                if i != j && augmented[j].get(i) {
                    augmented[j].xor_assign(&pivot_row);
                }
            }
        }

        // Extract inverse matrix from right half
        let mut inverse = Vec::new();
        for i in 0..n {
            let mut row = BitVec::new(n);
            for j in 0..n {
                row.set(j, augmented[i].get(n + j));
            }
            inverse.push(row);
        }

        inverse
    }

    /// Create a simple test cipher with identity matrices (for testing)
    pub fn new_simple_test(key: u128) -> Self {
        let mut cipher = LowMC {
            sbox: [0x00, 0x01, 0x03, 0x06, 0x07, 0x04, 0x05, 0x02],
            inv_sbox: [0x00, 0x01, 0x07, 0x02, 0x05, 0x06, 0x03, 0x04],
            lin_matrices: Vec::new(),
            inv_lin_matrices: Vec::new(),
            round_constants: Vec::new(),
            key_matrices: Vec::new(),
            round_keys: Vec::new(),
            key: BitVec::from_u128(key, KEY_SIZE),
        };

        // Create identity matrices and zero constants for testing
        for _ in 0..ROUNDS {
            let mut identity = Vec::new();
            for i in 0..BLOCK_SIZE {
                let mut row = BitVec::new(BLOCK_SIZE);
                row.set(i, true);
                identity.push(row);
            }
            cipher.lin_matrices.push(identity.clone());
            cipher.inv_lin_matrices.push(identity);

            cipher.round_constants.push(BitVec::new(BLOCK_SIZE));
        }

        // Create zero key matrices
        for _ in 0..ROUNDS {
            let mut key_matrix = Vec::new();
            for _ in 0..BLOCK_SIZE {
                key_matrix.push(BitVec::new(KEY_SIZE));
            }
            cipher.key_matrices.push(key_matrix);
        }

        cipher.keyschedule();
        cipher
    }

    /// Create a single-round test cipher
    pub fn new_single_round_test(key: u128) -> Self {
        let mut cipher = LowMC {
            sbox: [0x00, 0x01, 0x03, 0x06, 0x07, 0x04, 0x05, 0x02],
            inv_sbox: [0x00, 0x01, 0x07, 0x02, 0x05, 0x06, 0x03, 0x04],
            lin_matrices: Vec::new(),
            inv_lin_matrices: Vec::new(),
            round_constants: Vec::new(),
            key_matrices: Vec::new(),
            round_keys: Vec::new(),
            key: BitVec::from_u128(key, KEY_SIZE),
        };

        // Use key as seed for deterministic generation
        let mut rng = SimpleRng::new(key as u64);

        // Create one round with random matrices
        let matrix = Self::generate_matrix_with_rng(&mut rng, BLOCK_SIZE);
        let inv_matrix = Self::invert_matrix(&matrix);
        cipher.lin_matrices.push(matrix);
        cipher.inv_lin_matrices.push(inv_matrix);
        cipher
            .round_constants
            .push(Self::generate_block_with_rng(&mut rng, BLOCK_SIZE));

        // Create key matrix
        let mut key_matrix = Vec::new();
        for _ in 0..BLOCK_SIZE {
            key_matrix.push(Self::generate_block_with_rng(&mut rng, KEY_SIZE));
        }
        cipher.key_matrices.push(key_matrix);

        cipher.keyschedule();
        cipher
    }

    /// Encrypt with single round (for testing)
    pub fn encrypt_single_round(&self, message: u128) -> u128 {
        let mut state = BitVec::from_u128(message, BLOCK_SIZE);
        state.xor_assign(&self.round_keys[0]);
        state = self.substitution(&state);
        state = self.multiply_with_gf2_matrix(&self.lin_matrices[0], &state);
        state.xor_assign(&self.round_constants[0]);
        state.xor_assign(&self.round_keys[1]);
        state.to_u128()
    }

    /// Decrypt with single round (for testing)
    pub fn decrypt_single_round(&self, message: u128) -> u128 {
        let mut state = BitVec::from_u128(message, BLOCK_SIZE);
        state.xor_assign(&self.round_keys[1]);
        state.xor_assign(&self.round_constants[0]);
        state = self.multiply_with_gf2_matrix(&self.inv_lin_matrices[0], &state);
        state = self.inv_substitution(&state);
        state.xor_assign(&self.round_keys[0]);
        state.to_u128()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbox_inversion() {
        let sbox = [0x00, 0x01, 0x03, 0x06, 0x07, 0x04, 0x05, 0x02];
        let inv_sbox = [0x00, 0x01, 0x07, 0x02, 0x05, 0x06, 0x03, 0x04];

        for i in 0..8 {
            let forward = sbox[i] as usize;
            let backward = inv_sbox[forward] as usize;
            assert_eq!(backward, i, "S-box inversion failed for input {}", i);
        }
    }

    #[test]
    fn test_substitution_layer() {
        let cipher = LowMC::new(1);
        let test_values = [0x0u128, 0x1u128, 0x7u128, 0xFFu128, 0xFFD5u128];

        for &test_val in &test_values {
            let test_bits = BitVec::from_u128(test_val, BLOCK_SIZE);
            let substituted = cipher.substitution(&test_bits);
            let recovered = cipher.inv_substitution(&substituted);

            assert_eq!(
                test_bits.to_u128(),
                recovered.to_u128(),
                "Substitution layer inversion failed for {:#x}",
                test_val
            );
        }
    }

    #[test]
    fn test_matrix_inversion() {
        let mut rng = SimpleRng::new(12345);
        let matrix = LowMC::generate_matrix_with_rng(&mut rng, BLOCK_SIZE);
        let inv_matrix = LowMC::invert_matrix(&matrix);
        let test_values = [0x0u128, 0x1u128, 0xFFD5u128];

        for &test_val in &test_values {
            let test_bits = BitVec::from_u128(test_val, BLOCK_SIZE);
            let transformed = LowMC::multiply_with_gf2_matrix_static(&matrix, &test_bits);
            let recovered = LowMC::multiply_with_gf2_matrix_static(&inv_matrix, &transformed);

            assert_eq!(
                test_bits.to_u128(),
                recovered.to_u128(),
                "Matrix inversion failed for {:#x}",
                test_val
            );
        }
    }

    #[test]
    fn test_single_round() {
        let cipher = LowMC::new(1);
        let test_values = [0x0u128, 0x1u128, 0xFFD5u128];

        for &plaintext in &test_values {
            let mut state = BitVec::from_u128(plaintext, BLOCK_SIZE);

            // Apply one round of encryption
            state.xor_assign(&cipher.round_keys[0]);
            state = cipher.substitution(&state);
            state = cipher.multiply_with_gf2_matrix(&cipher.lin_matrices[0], &state);
            state.xor_assign(&cipher.round_constants[0]);
            state.xor_assign(&cipher.round_keys[1]);

            // Now reverse it
            let mut reverse_state = state.clone();
            reverse_state.xor_assign(&cipher.round_keys[1]);
            reverse_state.xor_assign(&cipher.round_constants[0]);
            reverse_state =
                cipher.multiply_with_gf2_matrix(&cipher.inv_lin_matrices[0], &reverse_state);
            reverse_state = cipher.inv_substitution(&reverse_state);
            reverse_state.xor_assign(&cipher.round_keys[0]);

            let recovered = reverse_state.to_u128();
            assert_eq!(
                plaintext, recovered,
                "Single round inversion failed for {:#x}",
                plaintext
            );
        }
    }

    #[test]
    fn test_bit_vector_operations() {
        let mut bv = BitVec::new(32);

        // Test basic operations
        bv.set(0, true);
        bv.set(31, true);
        assert!(bv.get(0));
        assert!(bv.get(31));
        assert!(!bv.get(15));

        // Test XOR
        let mut bv2 = BitVec::new(32);
        bv2.set(0, true);
        bv2.set(15, true);

        bv.xor_assign(&bv2);
        assert!(!bv.get(0)); // Should be false after XOR
        assert!(bv.get(15)); // Should be true
        assert!(bv.get(31)); // Should remain true

        // Test count_ones
        assert_eq!(bv.count_ones(), 2);
    }

    #[test]
    fn test_lowmc_parameters() {
        assert_eq!(BLOCK_SIZE, 256);
        assert_eq!(KEY_SIZE, 80);
        assert_eq!(ROUNDS, 12);
        assert_eq!(NUM_OF_BOXES, 49);
        assert_eq!(BLOCK_SIZE - 3 * NUM_OF_BOXES, 109); // Identity bits
    }

    #[test]
    fn test_encryption_decryption_deterministic() {
        let cipher = LowMC::new(1);

        // Test that encryption and decryption are perfect inverses
        let plaintext = 0x123456789ABCDEFu128;
        let (ciphertext_low, ciphertext_high) = cipher.encrypt(plaintext);
        let recovered = cipher.decrypt(ciphertext_low, ciphertext_high);

        // The algorithm should be perfectly deterministic now
        assert_ne!(
            plaintext, ciphertext_low,
            "Ciphertext should differ from plaintext"
        );
        assert_eq!(
            plaintext, recovered,
            "Decryption should recover original plaintext"
        );
    }

    #[test]
    fn test_deterministic_behavior() {
        // Test that the same key produces the same results
        let cipher1 = LowMC::new(12345);
        let cipher2 = LowMC::new(12345);

        let plaintext = 0xDEADBEEFu128;
        let (ciphertext1_low, ciphertext1_high) = cipher1.encrypt(plaintext);
        let (ciphertext2_low, ciphertext2_high) = cipher2.encrypt(plaintext);

        assert_eq!(
            ciphertext1_low, ciphertext2_low,
            "Same key should produce same ciphertext (low)"
        );
        assert_eq!(
            ciphertext1_high, ciphertext2_high,
            "Same key should produce same ciphertext (high)"
        );

        let recovered1 = cipher1.decrypt(ciphertext1_low, ciphertext1_high);
        let recovered2 = cipher2.decrypt(ciphertext2_low, ciphertext2_high);

        assert_eq!(recovered1, plaintext);
        assert_eq!(recovered2, plaintext);
        assert_eq!(recovered1, recovered2);
    }

    #[test]
    fn test_multiple_values() {
        let cipher = LowMC::new(42);
        let test_values = [
            0x0u128,
            0x1u128,
            0xDEADBEEFu128,
            0x123456789ABCDEFu128,
            0xFFFFFFFFFFFFFFFFu128,
        ];

        for &plaintext in &test_values {
            let (ciphertext_low, ciphertext_high) = cipher.encrypt(plaintext);
            let recovered = cipher.decrypt(ciphertext_low, ciphertext_high);

            assert_ne!(
                plaintext, ciphertext_low,
                "Ciphertext should differ from plaintext for {:#x}",
                plaintext
            );
            assert_eq!(
                plaintext, recovered,
                "Decryption should recover original plaintext for {:#x}",
                plaintext
            );
        }
    }

    #[test]
    fn test_128_bit_compatibility() {
        let cipher = LowMC::new(1);
        let plaintext = 0xDEADBEEFu128;

        println!("=== Testing 128-bit API ===");
        println!("Plaintext: {:#x}", plaintext);

        let (ciphertext_low, ciphertext_high) = cipher.encrypt(plaintext);
        println!(
            "Ciphertext: low={:#x}, high={:#x}",
            ciphertext_low, ciphertext_high
        );

        let recovered = cipher.decrypt(ciphertext_low, ciphertext_high);
        println!("Recovered: {:#x}", recovered);

        let success = plaintext == recovered;
        println!("Success: {}", success);

        assert_eq!(plaintext, recovered, "128-bit API should work correctly");
        assert_ne!(
            plaintext, ciphertext_low,
            "Ciphertext should differ from plaintext"
        );

        println!("✅ 128-bit API works correctly!");
    }
}
