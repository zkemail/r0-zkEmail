use cfdkim::{ verify_email_with_key, DkimPublicKey };
use mailparse::parse_mail;
use risc0_zkvm::guest::env;
use sha2::{ Digest, Sha256 };
use slog::{ o, Discard, Logger };
use zkemail_core::{ EmailVerifierOutput, Email, EmailWithRegex, EmailWithRegexVerifierOutput };
use regex_automata::{ dfa::{ dense, regex::Regex }, Match };

fn main() {
    let input: Vec<u8> = env::read_frame();
    let input: EmailWithRegex = postcard::from_bytes(&input).unwrap();

    let logger = Logger::root(Discard, o!());

    let parsed_email = parse_mail(&input.email.raw_email).unwrap();

    let public_key = DkimPublicKey::try_from_bytes(
        &input.email.public_key.key,
        &input.email.public_key.key_type
    ).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(input.email.from_domain.as_bytes());
    let from_domain_hash = hasher.finalize().to_vec();

    let mut hasher = Sha256::new();
    hasher.update(&input.email.public_key.key);
    let public_key_hash = hasher.finalize().to_vec();

    let result = verify_email_with_key(
        &logger,
        &input.email.from_domain,
        &parsed_email,
        public_key
    ).unwrap();

    let verified = match result {
        result if result.with_detail().starts_with("pass") => true,
        _ => false,
    };

    let mut regex_verified = vec![false; input.regex_info.parts.len()];
    let mut regex_matches = vec![vec![]; input.regex_info.parts.len()];

    let email_body = if parsed_email.subparts.is_empty() {
        parsed_email.get_body().unwrap()
    } else {
        let mut body = None;
        for part in parsed_email.subparts.iter() {
            if part.ctype.mimetype == "text/html" {
                body = Some(part.get_body().unwrap());
                break;
            }
        }
        body.unwrap_or_else(|| parsed_email.subparts[0].get_body().unwrap())
    };

    for (i, part) in input.regex_info.parts.iter().enumerate() {
        let (_is_public, dfa) = part;
        let fwd: dense::DFA<&[u32]> = dense::DFA
            ::from_bytes(&dfa.fwd)
            .expect("Failed to convert bytes to DFA").0;
        let rev: dense::DFA<&[u32]> = dense::DFA
            ::from_bytes(&dfa.bwd)
            .expect("Failed to convert bytes to DFA").0;
        let re = Regex::builder().build_from_dfas(fwd, rev);

        let matches: Vec<Match> = re.find_iter(&email_body).collect();

        if matches.len() > 0 {
            regex_verified[i] = true;
            regex_matches[i] = matches
                .iter()
                .map(|m| m.start())
                .collect();
        }
    }

    env::commit(
        &(EmailWithRegexVerifierOutput {
            email: EmailVerifierOutput {
                from_domain_hash,
                public_key_hash,
                verified,
            },
            regex_verified,
            regex_matches,
        })
    );
}
