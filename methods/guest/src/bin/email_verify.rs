#![no_main]

use cfdkim::{ verify_email_with_key, DkimPublicKey };
use mailparse::parse_mail;
use risc0_zkvm::guest::env;
use sha2::{ Digest, Sha256 };
use slog::{ o, Discard, Logger };
use zkemail_core::{ EmailVerifierOutput, Email };

fn hash_bytes(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn verify_dkim(input: &Email, logger: &Logger) -> bool {
    let parsed_email = parse_mail(&input.raw_email).unwrap();
    let public_key = DkimPublicKey::try_from_bytes(
        &input.public_key.key,
        &input.public_key.key_type
    ).unwrap();

    let result = verify_email_with_key(
        logger,
        &input.from_domain,
        &parsed_email,
        public_key
    ).unwrap();

    result.with_detail().starts_with("pass")
}

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: Vec<u8> = env::read_frame();
    let input: Email = borsh::from_slice::<Email>(&input).unwrap();
    let logger = Logger::root(Discard, o!());

    let verified = verify_dkim(&input, &logger);

    let output = EmailVerifierOutput {
        from_domain_hash: hash_bytes(input.from_domain.as_bytes()),
        public_key_hash: hash_bytes(&input.public_key.key),
        verified,
    };

    env::commit(&output);
}
