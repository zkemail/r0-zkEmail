use cfdkim::{verify_email_with_key, DkimPublicKey};
use mailparse::parse_mail;
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use slog::{o, Discard, Logger};

#[derive(Debug, Serialize, Deserialize)]
struct Email {
    from_domain: String,
    raw_email: Vec<u8>,
    public_key_type: String,
    public_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DKIMOutput {
    from_domain_hash: Vec<u8>,
    public_key_hash: Vec<u8>,
    verified: bool,
}

fn main() {
    let input: Vec<u8> = env::read_frame();
    let input: Email = postcard::from_bytes(&input).unwrap();

    let logger = Logger::root(Discard, o!());

    let parsed_email = parse_mail(&input.raw_email).unwrap();

    let public_key =
        DkimPublicKey::try_from_bytes(&input.public_key, &input.public_key_type).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(input.from_domain.as_bytes());
    let from_domain_hash = hasher.finalize().to_vec();

    let mut hasher = Sha256::new();
    hasher.update(&input.public_key);
    let public_key_hash = hasher.finalize().to_vec();

    let result =
        verify_email_with_key(&logger, &input.from_domain, &parsed_email, public_key).unwrap();

    let verified = match result {
        result if result.with_detail().starts_with("pass") => true,
        _ => false,
    };

    let output = DKIMOutput {
        from_domain_hash,
        public_key_hash,
        verified,
    };

    env::commit(&output);
}
