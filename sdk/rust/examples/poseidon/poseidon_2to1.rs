//! Poseidon 2-to-1 Hash Example
//!
//! Demonstrates the Poseidon hash function (width t=3, two inputs, one output),
//! compatible with Solana's `sol_poseidon`. Uses the reference vector and produces the
//! identical digest.
//!
//! Arguments:
//!     [1..2]: <str> Input numbers
//!     [3]:    <str> Reference hash

/*
    Built-in test vector (matches the "light-poseidon" README):
    in0 = 0x0101010101010101010101010101010101010101010101010101010101010101
    in1 = 0x0202020202020202020202020202020202020202020202020202020202020202
    out = 0x0d54e1938f8a8c1c7deb5e0355f26319207b84fe9ca2ce1b26e735c829821990
*/

use ligetron::bn254fr::Bn254Fr;
use ligetron::get_args;
use ligetron::poseidon::PoseidonContext3;

fn main() {
    let args = get_args();

    // t = 3, so the hash takes exactly t-1 = 2 inputs; state[0] stays the
    // (zero) domain tag and is the lane read out.
    let inputs: Vec<Bn254Fr> = (1..=2)
        .map(|i| Bn254Fr::from_c_str(args.get_as_c_str(i)))
        .collect();
    let reference = Bn254Fr::from_c_str(args.get_as_c_str(3));

    let mut ctx = PoseidonContext3::new();
    for input in &inputs {
        ctx.update(input);
    }
    let result = ctx.finalize();

    result.print_hex();

    Bn254Fr::assert_equal(&result, &reference);
}
