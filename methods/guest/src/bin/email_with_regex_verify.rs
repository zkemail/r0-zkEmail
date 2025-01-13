#![no_main]

use risc0_zkvm::guest::env;
use zkemail_core::{ EmailWithRegex, EmailWithRegexVerifierOutput, verify_email_with_regex };

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: Vec<u8> = env::read_frame();
    let input: EmailWithRegex = borsh::from_slice::<EmailWithRegex>(&input).unwrap();
    let output: EmailWithRegexVerifierOutput = verify_email_with_regex(&input);
    env::commit(&output);
}
