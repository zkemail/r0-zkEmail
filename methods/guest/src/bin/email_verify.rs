#![no_main]

use risc0_zkvm::guest::env;
use zkemail_core::{abi_encode_email_verifier_output, EmailVerifierOutput, Email, verify_email };

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: Vec<u8> = env::read_frame();
    let input: Email = borsh::from_slice::<Email>(&input).unwrap();
    let output: EmailVerifierOutput = verify_email(&input);
    let output = abi_encode_email_verifier_output(&output);
    env::commit(&output);
}
