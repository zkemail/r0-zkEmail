#![no_main]

use risc0_zkvm::guest::env;
use zkemail_core::{
    abi_encode_email_with_regex_verifier_output,
    EmailWithRegex,
    EmailWithRegexVerifierOutput,
    verify_email_with_regex,
};

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: Vec<u8> = env::read_frame();
    let input: EmailWithRegex = borsh::from_slice::<EmailWithRegex>(&input).unwrap();
    let output: EmailWithRegexVerifierOutput = verify_email_with_regex(&input);
    let output = abi_encode_email_with_regex_verifier_output(&output);
    env::commit_slice(&output);
}
