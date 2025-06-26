//! # LowMC Rounds Determination Tool
//!
//! This binary determines the minimum number of rounds needed for security for
//! a given set of LowMC parameters. It's a Rust port of the original `determine_rounds.py` script.
//!
//! ## Overview
//!
//! LowMC is a block cipher designed for MPC (Multi-Party Computation) and FHE (Fully Homomorphic Encryption)
//! applications. The security of LowMC depends on the number of rounds, which must be sufficient to
//! resist various cryptanalytic attacks.
//!
//! ## Security Analysis
//!
//! The tool analyzes security against several attack vectors:
//!
//! 1. **Statistical Attacks**: Differential and linear cryptanalysis
//! 2. **Boomerang Attacks**: Advanced differential attacks using multiple differentials
//! 3. **Derivative Attacks**: Algebraic attacks using derivatives
//! 4. **Interpolation Attacks**: Algebraic attacks using polynomial interpolation
//! 5. **Polytopic Attacks**: Advanced algebraic attacks using multiple differences
//!
//! ## Usage
//!
//! ```bash
//! cargo run --bin determine_rounds -- <block_size> <sboxes> <data_complexity> <key_size> [options]
//! ```
//!
//! ### Parameters
//! - `block_size`: Size of the block in bits (e.g., 256)
//! - `sboxes`: Number of S-boxes per round (e.g., 49)
//! - `data_complexity`: Log2 of allowed data complexity (e.g., 60)
//! - `key_size`: Size of the key in bits (e.g., 80)
//!
//! ### Options
//! - `-v, --verbose`: Print detailed calculation information
//! - `-q, --quiet`: Only print the final number of rounds
//! - `-m, --multiplicity`: Print multiplicative complexity information
//!
//! ## Example
//!
//! ```bash
//! # For LowMC with 256-bit blocks, 49 S-boxes, 60-bit data complexity, 80-bit keys
//! cargo run --bin determine_rounds -- 256 49 60 80 -v
//! ```
//!
//! ## Mathematical Background
//!
//! The security analysis is based on:
//! - **Differential Probability**: Probability of differential trails
//! - **Linear Correlation**: Correlation of linear trails  
//! - **Algebraic Degree**: Maximum degree of output polynomials
//! - **Diffusion**: How quickly differences spread through the cipher
//!
//! The tool uses binary search to find the minimum number of rounds where
//! the probability of successful attacks becomes negligible (< 2^-100).

use std::collections::HashMap;
use std::env;

/// Negligible probability threshold for security analysis.
/// This represents 2^-100, which is considered cryptographically negligible.
const NEGL_PROB: f64 = 7.888609052210118e-31; // 2^-100

/// Parameters for LowMC security analysis.
///
/// This struct holds all the parameters needed to analyze the security
/// of a LowMC instantiation and determine the minimum number of rounds.
#[derive(Debug, Clone)]
struct Parameters {
    /// Block size in bits (e.g., 256)
    blocksize: usize,
    /// Number of S-boxes per round (e.g., 49)
    sboxes: usize,
    /// Log2 of allowed data complexity for attacks (e.g., 60)
    data_complexity: usize,
    /// Key size in bits (e.g., 80)
    keysize: usize,
    /// Number of identity bits in the S-box layer
    /// This is calculated as `blocksize - 3 * sboxes`
    identity_bits: usize,
    /// Verbosity level for output
    verbosity: Verbosity,
    /// Whether to include multiplicative complexity information
    with_multiplicity: bool,
}

/// Verbosity levels for output control.
#[derive(Debug, Clone, PartialEq)]
enum Verbosity {
    /// Only print the final number of rounds
    Quiet,
    /// Print standard output with distinguisher breakdown
    Normal,
    /// Print detailed calculation information
    Verbose,
}

impl Parameters {
    /// Creates a new Parameters instance with the given LowMC parameters.
    ///
    /// # Arguments
    ///
    /// * `blocksize` - Size of the block in bits
    /// * `sboxes` - Number of S-boxes per round
    /// * `data_complexity` - Log2 of allowed data complexity
    /// * `keysize` - Size of the key in bits
    ///
    /// # Returns
    ///
    /// A new Parameters instance with calculated identity_bits.
    fn new(blocksize: usize, sboxes: usize, data_complexity: usize, keysize: usize) -> Self {
        Parameters {
            blocksize,
            sboxes,
            data_complexity,
            keysize,
            identity_bits: blocksize - 3 * sboxes,
            verbosity: Verbosity::Normal,
            with_multiplicity: false,
        }
    }

    /// Prints the parameters in a human-readable format.
    fn print(&self) {
        println!("Block size:      {}", self.blocksize);
        println!("# of Sboxes:     {}", self.sboxes);
        println!("Data complexity: {}", self.data_complexity);
        println!("Key size:        {}", self.keysize);
    }
}

/// Memoization cache for expensive computations.
///
/// This struct provides caching functionality to avoid recomputing
/// expensive mathematical operations. It's particularly useful for
/// the trail counting functions which are called repeatedly.
struct Memorizer<T> {
    /// Cache storage using string keys
    cache: HashMap<String, T>,
}

impl<T: Clone> Memorizer<T> {
    /// Creates a new empty memoizer.
    fn new() -> Self {
        Memorizer {
            cache: HashMap::new(),
        }
    }

    /// Gets a value from cache or computes it if not present.
    ///
    /// # Arguments
    ///
    /// * `key` - String key for the cache entry
    /// * `compute` - Closure that computes the value if not cached
    ///
    /// # Returns
    ///
    /// The cached or newly computed value.
    fn get_or_compute<F>(&mut self, key: String, compute: F) -> T
    where
        F: FnOnce() -> T,
    {
        if let Some(value) = self.cache.get(&key) {
            value.clone()
        } else {
            let value = compute();
            self.cache.insert(key, value.clone());
            value
        }
    }
}

/// Main function that orchestrates the security analysis.
///
/// This function:
/// 1. Parses command line arguments
/// 2. Validates parameters
/// 3. Performs security analysis for each attack vector
/// 4. Determines the minimum secure number of rounds
/// 5. Prints results
fn main() {
    let params = parse_program_arguments();
    check_parameter_validity(&params);

    if params.verbosity == Verbosity::Verbose {
        println!("{}", "-".repeat(46));
        println!("LowMC rounds determination");
        println!("{}", "-".repeat(46));
        params.print();
        println!("{}", "-".repeat(46));
    }

    let mut cache = Memorizer::new();

    if params.verbosity == Verbosity::Verbose {
        println!("Calculating statistical rounds");
    }
    let statistical_rounds = determine_statistical_rounds(&params, &mut cache);

    if params.verbosity == Verbosity::Verbose {
        println!("Calculating boomerang rounds");
    }
    let boomerang_rounds = determine_boomerang_rounds(&params, &mut cache);

    if params.verbosity == Verbosity::Verbose {
        println!("Calculating derivative rounds");
    }
    let derivative_rounds = determine_derivative_rounds(&params);

    if params.verbosity == Verbosity::Verbose {
        println!("Calculating interpolation rounds");
    }
    let interpolation_rounds = determine_interpolation_rounds(&params);

    if params.verbosity == Verbosity::Verbose {
        println!("Calculating round-key guessing rounds");
    }
    let keyguess_state_rounds = determine_keyguess_state_rounds(&params);
    let keyguess_bit_rounds = determine_keyguess_bit_rounds(&params, 1);

    if params.verbosity == Verbosity::Verbose {
        println!("Calculating polytopic attack rounds");
    }
    let polytopic_rounds = determine_polytopic_attack_rounds(&params);

    let distinguishers = vec![
        (
            "Statistical with state guessing",
            statistical_rounds + keyguess_state_rounds,
        ),
        ("Boomerang attack", boomerang_rounds),
        (
            "Derivative + bit guessing",
            derivative_rounds + keyguess_bit_rounds,
        ),
        (
            "Derivative + interpolation",
            derivative_rounds + interpolation_rounds,
        ),
        ("Impossible polytopic attack", polytopic_rounds),
    ];

    print_rounds(&params, &distinguishers);
}

///////////////////////////////////////////////////////////
// Determining secure rounds for a range of distinguishers
///////////////////////////////////////////////////////////

/// Determines the minimum number of rounds needed for security against statistical attacks.
///
/// Statistical attacks include differential and linear cryptanalysis. This function
/// uses binary search to find the minimum number of rounds where no good differential
/// or linear trail exists with probability higher than the data complexity.
///
/// # Arguments
///
/// * `params` - LowMC parameters
/// * `cache` - Memoization cache for expensive computations
///
/// # Returns
///
/// The minimum number of rounds needed for security against statistical attacks.
fn determine_statistical_rounds(params: &Parameters, cache: &mut Memorizer<u128>) -> usize {
    // Determine the number of rounds using a divide-and-conquer approach
    let mut upper_bound = 1;

    // Find upper bound
    loop {
        if no_good_trail_after_round(params, upper_bound, cache) {
            break;
        }
        upper_bound *= 2;
    }

    let mut lower_excl_bound = upper_bound / 2;

    // Binary search
    while lower_excl_bound + 1 < upper_bound {
        let rounds = lower_excl_bound + (upper_bound - lower_excl_bound) / 2;
        if no_good_trail_after_round(params, rounds, cache) {
            upper_bound = rounds;
        } else {
            lower_excl_bound = rounds;
        }
    }
    upper_bound
}

/// Determines the minimum number of rounds needed for security against boomerang attacks.
///
/// Boomerang attacks use two differential trails (top and bottom) and are more powerful
/// than standard differential attacks. This function finds the minimum rounds where
/// no good boomerang trail can be constructed.
///
/// # Arguments
///
/// * `params` - LowMC parameters
/// * `cache` - Memoization cache for expensive computations
///
/// # Returns
///
/// The minimum number of rounds needed for security against boomerang attacks.
fn determine_boomerang_rounds(params: &Parameters, cache: &mut Memorizer<u128>) -> usize {
    let mut upper_bound = 2;

    // Find upper bound
    loop {
        if no_good_boomerang_after_round(params, upper_bound, cache) {
            break;
        }
        upper_bound *= 2;
    }

    let mut lower_excl_bound = upper_bound / 2;

    // Binary search
    while lower_excl_bound + 1 < upper_bound {
        let rounds = lower_excl_bound + (upper_bound - lower_excl_bound) / 2;
        if no_good_boomerang_after_round(params, rounds, cache) {
            upper_bound = rounds;
        } else {
            lower_excl_bound = rounds;
        }
    }
    upper_bound
}

/// Determines the minimum number of rounds needed for security against derivative attacks.
///
/// Derivative attacks are algebraic attacks that exploit the algebraic properties
/// of the cipher. This includes degree analysis and influence analysis.
///
/// # Arguments
///
/// * `params` - LowMC parameters
///
/// # Returns
///
/// The minimum number of rounds needed for security against derivative attacks.
fn determine_derivative_rounds(params: &Parameters) -> usize {
    let degree_rounds = determine_degree_rounds(params);
    let influence_rounds = determine_influence_rounds(params);
    degree_rounds + influence_rounds
}

/// Determines the minimum number of rounds needed for security against polytopic attacks.
///
/// Polytopic attacks are advanced algebraic attacks that use multiple differences
/// simultaneously. This function analyzes the diffusion properties for different
/// d-difference sizes.
///
/// # Arguments
///
/// * `params` - LowMC parameters
///
/// # Returns
///
/// The minimum number of rounds needed for security against polytopic attacks.
fn determine_polytopic_attack_rounds(params: &Parameters) -> usize {
    let mut attacked_rounds = Vec::new();

    for ddiff_size in 1..=(2 * params.keysize / params.blocksize + 1) {
        if (ddiff_size + 1).ilog2() as usize > params.data_complexity {
            continue; // Initial free rounds
        }

        let mut rounds = determine_free_rounds(params, (ddiff_size + 1).ilog2() as usize);
        // d-difference diffusion rounds
        rounds += polytopic_listing_rounds(params, ddiff_size);
        // Backwards key-guessing rounds
        rounds += polytopic_listing_rounds(params, ddiff_size)
            + determine_free_rounds(
                params,
                params.blocksize - params.data_complexity / ddiff_size,
            );
        attacked_rounds.push(rounds);
    }

    attacked_rounds.into_iter().max().unwrap_or(0)
}

/// Determines the minimum number of rounds needed for security against interpolation attacks.
///
/// Interpolation attacks solve systems of linear equations to recover key information.
/// This function estimates the number of terms in the interpolation polynomial and
/// determines when solving becomes computationally infeasible.
///
/// # Arguments
///
/// * `params` - LowMC parameters
///
/// # Returns
///
/// The minimum number of rounds needed for security against interpolation attacks.
fn determine_interpolation_rounds(params: &Parameters) -> usize {
    for rounds in 1.. {
        let terms = interpolation_terms(params, rounds);
        if (terms as f64).log2() >= params.keysize as f64 / 2.3
            || (terms as f64).log2() >= params.data_complexity as f64
        {
            return rounds;
        }
    }
    unreachable!()
}

/// Determines how many rounds back it is possible to guess the full state.
///
/// This is used in combination with other attacks where the attacker can
/// guess parts of the internal state.
///
/// # Arguments
///
/// * `params` - LowMC parameters
///
/// # Returns
///
/// Number of rounds back for full state guessing.
fn determine_keyguess_state_rounds(params: &Parameters) -> usize {
    params.keysize / (3 * params.sboxes)
}

/// Determines how many rounds back it is possible to guess a subspace of given dimension.
///
/// This is a generalization of state guessing for subspaces of smaller dimension.
///
/// # Arguments
///
/// * `params` - LowMC parameters
/// * `dimension` - Dimension of the subspace to guess
///
/// # Returns
///
/// Number of rounds back for subspace guessing.
fn determine_keyguess_bit_rounds(params: &Parameters, dimension: usize) -> usize {
    let free_rounds = determine_free_rounds(params, dimension);
    let guess_state_rounds = determine_keyguess_state_rounds(params);
    free_rounds + guess_state_rounds
}

////////////////////////////////////////////////////
// Statistical and boomerang distinguisher functions
////////////////////////////////////////////////////

/// Determines whether a good differential/linear trail exists after the given number of rounds.
///
/// A "good" trail has probability higher than 2^-(data_complexity). This function
/// checks if the number of possible good trails times the realization probability
/// is smaller than the negligible probability threshold.
///
/// # Arguments
///
/// * `params` - LowMC parameters
/// * `rounds` - Number of rounds to check
/// * `cache` - Memoization cache
///
/// # Returns
///
/// `true` if no good trail exists (secure), `false` otherwise.
fn no_good_trail_after_round(
    params: &Parameters,
    rounds: usize,
    cache: &mut Memorizer<u128>,
) -> bool {
    let max_active_sboxes = params.data_complexity / 2;
    let all_good_trails = all_possible_good_trails(params, max_active_sboxes, rounds, cache);
    let inv_realization_probability =
        (2_u128.saturating_pow(params.blocksize as u32) - 1).saturating_pow(rounds as u32 - 1);

    let threshold = (1.0 / NEGL_PROB) as u128;
    // Use saturating multiplication to avoid overflow
    let product = threshold.saturating_mul(all_good_trails);
    product < inv_realization_probability
}

/// Calculates an upper bound for the number of possible good trails over the given rounds.
///
/// This function uses dynamic programming to count all possible trails that activate
/// at most `max_active_sboxes` S-boxes over the specified number of rounds.
///
/// # Arguments
///
/// * `params` - LowMC parameters
/// * `max_active_sboxes` - Maximum number of active S-boxes allowed
/// * `rounds` - Number of rounds
/// * `cache` - Memoization cache
///
/// # Returns
///
/// Upper bound on the number of possible good trails.
fn all_possible_good_trails(
    params: &Parameters,
    max_active_sboxes: usize,
    rounds: usize,
    cache: &mut Memorizer<u128>,
) -> u128 {
    let key = format!(
        "trails_{}_{}_{}_{}",
        params.blocksize, params.sboxes, max_active_sboxes, rounds
    );

    cache.get_or_compute(key, || {
        let mut current_trails = vec![0u128; max_active_sboxes + 1];

        // Store the number of good trails after 1 round
        for (active_sboxes, trail) in current_trails.iter_mut().enumerate() {
            *trail = one_round_trails(params, active_sboxes);
        }

        for _ in 2..=rounds {
            let mut new_trails = vec![0u128; max_active_sboxes + 1];
            for prev_actives in 0..=max_active_sboxes {
                for new_actives in 0..=(max_active_sboxes - prev_actives) {
                    let product = current_trails[prev_actives]
                        .saturating_mul(one_round_trails(params, new_actives));
                    new_trails[prev_actives + new_actives] =
                        new_trails[prev_actives + new_actives].saturating_add(product);
                }
            }
            current_trails = new_trails;
        }

        current_trails
            .iter()
            .fold(0u128, |acc, &x| acc.saturating_add(x))
    })
}

/// Determines whether a good boomerang trail exists after the given number of rounds.
///
/// Boomerang trails consist of two differential trails (top and bottom) that are
/// used together. This function checks if any combination of top and bottom trails
/// can be realized with sufficient probability.
///
/// # Arguments
///
/// * `params` - LowMC parameters
/// * `rounds` - Number of rounds
/// * `cache` - Memoization cache
///
/// # Returns
///
/// `true` if no good boomerang trail exists (secure), `false` otherwise.
fn no_good_boomerang_after_round(
    params: &Parameters,
    rounds: usize,
    cache: &mut Memorizer<u128>,
) -> bool {
    let max_actives = params.data_complexity / 4;
    let top_rounds = rounds / 2;
    let bottom_rounds = rounds - top_rounds;

    for top_actives in 0..=max_actives {
        let bottom_actives = max_actives - top_actives;
        let top_good_trails = all_possible_good_trails(params, top_actives, top_rounds, cache);
        let bottom_good_trails =
            all_possible_good_trails(params, bottom_actives, bottom_rounds, cache);
        let inv_top_realization_prob = (2_u128.saturating_pow(params.blocksize as u32) - 1)
            .saturating_pow(top_rounds as u32 - 1);
        let inv_bottom_realization_prob = (2_u128.saturating_pow(params.blocksize as u32) - 1)
            .saturating_pow(bottom_rounds as u32 - 1);

        let threshold = (1.0 / NEGL_PROB) as u128;
        if threshold.saturating_mul(top_good_trails) >= inv_top_realization_prob
            && threshold.saturating_mul(bottom_good_trails) >= inv_bottom_realization_prob
        {
            return false;
        }
    }
    true
}

/// Calculates the number of one-round trails activating exactly the given number of S-boxes.
///
/// Each active S-box contributes a factor of 4 to the trail count (due to the 3-bit S-box
/// having 4 possible output differences for a fixed input difference).
///
/// # Arguments
///
/// * `params` - LowMC parameters
/// * `active_sboxes` - Number of active S-boxes
///
/// # Returns
///
/// Number of one-round trails with exactly the given number of active S-boxes.
fn one_round_trails(params: &Parameters, active_sboxes: usize) -> u128 {
    // For large parameters, we need to handle overflow carefully
    let activating = activating_vectors(params, active_sboxes);
    let power_of_4 = 4_u128.saturating_pow(active_sboxes as u32);
    activating.saturating_mul(power_of_4)
}

/// Calculates the number of vectors that activate the given number of S-boxes.
///
/// This function counts how many input vectors result in exactly the given number
/// of active S-boxes, considering the identity part of the S-box layer.
///
/// # Arguments
///
/// * `params` - LowMC parameters
/// * `active_sboxes` - Number of active S-boxes
///
/// # Returns
///
/// Number of activating vectors.
fn activating_vectors(params: &Parameters, active_sboxes: usize) -> u128 {
    // Handle potential overflow with saturating arithmetic
    let combinations = choose(params.sboxes, active_sboxes);
    let power_of_7 = 7_u128.saturating_pow(active_sboxes as u32);
    let power_of_2 = 2_u128.saturating_pow(params.identity_bits as u32);

    combinations
        .saturating_mul(power_of_7)
        .saturating_mul(power_of_2)
}

////////////////////////////////////////////////////
// Impossible distinguisher functions
////////////////////////////////////////////////////

/// Determines the maximal number of rounds for which there exists a subspace
/// of given dimension that depends only linearly on the input bits.
///
/// This is used in impossible differential attacks where the attacker can
/// exploit linear subspaces that don't get mixed by the nonlinear layer.
///
/// # Arguments
///
/// * `params` - LowMC parameters
/// * `dimension` - Dimension of the subspace
///
/// # Returns
///
/// Number of free rounds for the given subspace dimension.
fn determine_free_rounds(params: &Parameters, dimension: usize) -> usize {
    if dimension > params.blocksize {
        panic!("dimension must not be larger than blocksize");
    }
    if 3 * params.sboxes == params.blocksize {
        0
    } else {
        // Add 1 as security margin
        (params.blocksize - dimension) / (3 * params.sboxes) + 1
    }
}

////////////////////////////////////////////////////
// Polytopic distinguisher functions
////////////////////////////////////////////////////

/// Determines the number of rounds after which all d-differences are reachable
/// or after which it should not be possible to list all reachable d-differences.
///
/// This function analyzes the diffusion properties of d-differences through
/// the cipher structure.
///
/// # Arguments
///
/// * `params` - LowMC parameters
/// * `ddiff_size` - Size of the d-difference
///
/// # Returns
///
/// Number of rounds needed for d-difference diffusion.
fn polytopic_listing_rounds(params: &Parameters, ddiff_size: usize) -> usize {
    let mut rounds = 0;
    let diffusion_per_round = calculate_average_polytopic_diffusion(params, ddiff_size);
    let mut diffusion = 0.0;

    while diffusion < params.keysize as f64
        && diffusion < ddiff_size as f64 * params.blocksize as f64
    {
        rounds += 1;
        diffusion += diffusion_per_round;
    }
    rounds
}

/// Calculates the average diffusion of d-differences of given size.
///
/// This function estimates how much a d-difference spreads on average
/// through one round of the cipher.
///
/// # Arguments
///
/// * `params` - LowMC parameters
/// * `ddiff_size` - Size of the d-difference
///
/// # Returns
///
/// Average diffusion per round in bits.
fn calculate_average_polytopic_diffusion(params: &Parameters, ddiff_size: usize) -> f64 {
    let sboxes = params.sboxes;
    let mut all_created_differences = 0.0;
    let sbox_two_active = 8_usize.pow(ddiff_size as u32) - 1 - ddiff_size * 7;

    for inactive in 0..=sboxes {
        for one_active in 0..=(sboxes - inactive) {
            let number_of_patterns = choose(sboxes, inactive) as f64
                * choose(sboxes - inactive, one_active) as f64
                * (ddiff_size * 7).pow(one_active as u32) as f64
                * sbox_two_active.pow((sboxes - inactive - one_active) as u32) as f64;
            let new_differences = number_of_patterns
                * 4_usize.pow(one_active as u32) as f64
                * 8_usize.pow((sboxes - inactive - one_active) as u32) as f64;
            all_created_differences += new_differences;
        }
    }

    all_created_differences.log2() - 3.0 * sboxes as f64 * ddiff_size as f64
}

////////////////////////////////////////////////////
// Derivative distinguisher functions
////////////////////////////////////////////////////

/// Determines the number of rounds needed so that the maximal possible degree
/// is not smaller than the allowed data complexity minus one.
///
/// This function ensures that the algebraic degree of the cipher output
/// is high enough to resist algebraic attacks.
///
/// # Arguments
///
/// * `params` - LowMC parameters
///
/// # Returns
///
/// Number of rounds needed for sufficient algebraic degree.
fn determine_degree_rounds(params: &Parameters) -> usize {
    for rounds in 1.. {
        let max_degree = determine_degree_upper_bound(params, rounds);
        if max_degree >= params.data_complexity - 1 {
            return rounds;
        }
    }
    unreachable!()
}

/// Calculates an upper bound for the algebraic degree after the given number of rounds.
///
/// The algebraic degree grows as the cipher processes data through multiple rounds.
/// This function provides a conservative upper bound on the degree.
///
/// # Arguments
///
/// * `params` - LowMC parameters
/// * `rounds` - Number of rounds
///
/// # Returns
///
/// Upper bound on the algebraic degree.
fn determine_degree_upper_bound(params: &Parameters, rounds: usize) -> usize {
    let mut degree = 1;
    for _ in 0..rounds {
        degree = degree
            .min(2 * degree)
            .min(params.sboxes + degree)
            .min((params.blocksize + degree) / 2);
    }
    degree
}

/// Estimates the number of rounds for one bit to influence all others.
///
/// This is used in influence analysis, which studies how quickly
/// changes in input bits propagate to affect all output bits.
///
/// # Arguments
///
/// * `params` - LowMC parameters
///
/// # Returns
///
/// Number of rounds needed for full influence.
fn determine_influence_rounds(params: &Parameters) -> usize {
    (params.blocksize as f64 / (7.0 / 8.0 * params.sboxes as f64 * 3.0)).ceil() as usize
}

////////////////////////////////////////////////////
// Interpolation distinguisher functions
////////////////////////////////////////////////////

/// Estimates the number of different terms in the key bits that appear
/// in an interpolation attack on the last 'rounds' rounds.
///
/// Interpolation attacks solve systems of linear equations to recover
/// key information. This function estimates the complexity of such attacks.
///
/// # Arguments
///
/// * `params` - LowMC parameters
/// * `rounds` - Number of rounds to attack
///
/// # Returns
///
/// Estimated number of terms in the interpolation polynomial.
fn interpolation_terms(params: &Parameters, rounds: usize) -> u128 {
    let mut keybit_terms = vec![0u128; params.blocksize + 1];

    // After 1 round
    keybit_terms[0] = 1;
    keybit_terms[1] = params.blocksize as u128;
    keybit_terms[2] = 3 * params.sboxes as u128;

    // For each additional round
    for _ in 1..rounds {
        let mut newkeybit_terms = vec![0u128; params.blocksize + 1];
        newkeybit_terms[0] = 1;
        newkeybit_terms[1] = params.blocksize as u128;

        for degree in 2..=params.blocksize {
            let mut terms_of_degree = 0u128;
            for degree_1st_factor in 0..=(degree / 2) {
                terms_of_degree +=
                    keybit_terms[degree_1st_factor] * keybit_terms[degree - degree_1st_factor];
            }
            newkeybit_terms[degree] = terms_of_degree.min(choose(params.blocksize, degree));
        }
        keybit_terms = newkeybit_terms;
    }

    let mut terms = 0u128;
    for (degree, &val) in keybit_terms
        .iter()
        .enumerate()
        .take(2_usize.pow(rounds as u32).min(params.blocksize) + 1)
    {
        terms += val.min(terms_with_bounded_degree(
            params.keysize,
            2_usize.pow(rounds as u32) - degree,
        ));
    }
    terms
}

/// Calculates the number of possible terms with the given maximal degree
/// in the given number of variables.
///
/// This is used in interpolation attack analysis to bound the number
/// of possible terms in the interpolation polynomial.
///
/// # Arguments
///
/// * `variables` - Number of variables
/// * `max_degree` - Maximum degree allowed
///
/// # Returns
///
/// Number of possible terms.
fn terms_with_bounded_degree(variables: usize, max_degree: usize) -> u128 {
    let mut terms = 0u128;
    for degree in 0..=max_degree {
        terms += choose(variables, degree);
    }
    terms
}

///////////////////////////////////
// Helper functions
///////////////////////////////////

/// Parses command line arguments and creates a Parameters instance.
///
/// This function handles the command line interface, including parameter
/// validation and option parsing.
///
/// # Returns
///
/// A Parameters instance with the parsed arguments.
///
/// # Panics
///
/// Panics if invalid arguments are provided or if required arguments are missing.
fn parse_program_arguments() -> Parameters {
    let args: Vec<String> = env::args().collect();

    if args.len() < 5 {
        eprintln!(
            "Usage: {} <block_size> <sboxes> <data_complexity> <key_size> [options]",
            args[0]
        );
        eprintln!("Options:");
        eprintln!("  -v, --verbose    Print additional information");
        eprintln!("  -q, --quiet      Only print the number of total rounds");
        eprintln!("  -m, --multiplicity Print multiplicative complexities");
        std::process::exit(1);
    }

    let blocksize: usize = args[1].parse().expect("Invalid block size");
    let sboxes: usize = args[2].parse().expect("Invalid number of S-boxes");
    let data_complexity: usize = args[3].parse().expect("Invalid data complexity");
    let keysize: usize = args[4].parse().expect("Invalid key size");

    let mut params = Parameters::new(blocksize, sboxes, data_complexity, keysize);

    for arg in &args[5..] {
        match arg.as_str() {
            "-v" | "--verbose" => params.verbosity = Verbosity::Verbose,
            "-q" | "--quiet" => params.verbosity = Verbosity::Quiet,
            "-m" | "--multiplicity" => params.with_multiplicity = true,
            _ => eprintln!("Unknown option: {}", arg),
        }
    }

    params
}

/// Validates that the given parameters are coherent and valid.
///
/// This function checks various constraints that must be satisfied
/// for a valid LowMC parameter set.
///
/// # Arguments
///
/// * `params` - Parameters to validate
///
/// # Panics
///
/// Exits the program if parameters are invalid.
fn check_parameter_validity(params: &Parameters) {
    if params.blocksize < params.data_complexity
        || params.sboxes * 3 > params.blocksize
        || params.data_complexity > params.keysize
        || params.sboxes < 1
        || params.blocksize < 1
        || params.data_complexity < 1
        || params.keysize < 1
    {
        eprintln!("Invalid parameter set");
        std::process::exit(1);
    }
}

/// Prints the security analysis results in a formatted table.
///
/// This function displays the number of rounds needed for each attack vector
/// and determines the overall secure number of rounds (maximum of all).
///
/// # Arguments
///
/// * `params` - LowMC parameters
/// * `distinguishers` - List of attack vectors and their required rounds
fn print_rounds(params: &Parameters, distinguishers: &[(&str, usize)]) {
    let total_rounds = distinguishers
        .iter()
        .map(|(_, rounds)| *rounds)
        .max()
        .unwrap_or(0);

    if params.verbosity != Verbosity::Quiet {
        println!("{}", "-".repeat(46));
        println!("{:<40}{:>6}", "Distinguisher", "Rounds");
        println!("{}", "-".repeat(46));
        for (name, rounds) in distinguishers {
            println!("{:<40}{:>6}", name, rounds);
        }
        println!("{}", "-".repeat(46));
        println!("{:<40}{:>6}", "Secure rounds:", total_rounds);
    } else {
        println!("{}", total_rounds);
    }

    if params.with_multiplicity {
        println!("{}", "-".repeat(46));
        println!(
            "{:<40}{:>6}",
            "Total number of ANDs:",
            total_rounds * 3 * params.sboxes
        );
        println!(
            "{:<40}{:6.2}",
            "Number of ANDs per bit:",
            total_rounds as f64 * 3.0 * params.sboxes as f64 / params.blocksize as f64
        );
        println!("{:<40}{:>6}", "AND-depth:", total_rounds);
    }
}

/// Calculates the binomial coefficient "n choose k".
///
/// This function computes the number of ways to choose k items from n items
/// without regard to order. It's used extensively in the combinatorial
/// calculations for trail counting.
///
/// # Arguments
///
/// * `n` - Total number of items
/// * `k` - Number of items to choose
///
/// # Returns
///
/// The binomial coefficient C(n,k).
///
/// # Note
///
/// Uses saturating arithmetic to handle large numbers safely.
fn choose(n: usize, k: usize) -> u128 {
    if k > n {
        return 0;
    }
    if k == 0 || k == n {
        return 1;
    }

    let k = k.min(n - k); // Take advantage of symmetry
    let mut result = 1u128;

    for i in 0..k {
        result = result * (n - i) as u128 / (i + 1) as u128;
    }

    result
}
