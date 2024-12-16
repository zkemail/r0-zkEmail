#![no_main]

use cfdkim::{ verify_email_with_key, DkimPublicKey };
use mailparse::{ parse_mail, ParsedMail };
use risc0_zkvm::guest::env;
use sha2::{ Digest, Sha256 };
use slog::{ o, Discard, Logger };
use zkemail_core::{ EmailVerifierOutput, EmailWithRegex, EmailWithRegexVerifierOutput, DFA };
use regex_automata::{ dfa::{ dense, regex::Regex }, Match };

fn hash_bytes(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn extract_email_body(parsed_email: &ParsedMail) -> String {
    if parsed_email.subparts.is_empty() {
        return parsed_email.get_body().unwrap();
    }

    let body = parsed_email.subparts
        .iter()
        .find(|part| part.ctype.mimetype == "text/html")
        .map(|part| part.get_body())
        .unwrap_or_else(|| parsed_email.subparts[0].get_body());

    body.unwrap()
}

fn process_regex_parts(parts: &[(bool, DFA)], email_body: &str) -> (bool, Vec<String>) {
    let mut regex_verified = false;
    let mut regex_matches = Vec::with_capacity(
        parts
            .iter()
            .filter(|(is_public, _)| *is_public)
            .count()
    );

    for part in parts {
        let (is_public, dfa) = part;
        let fwd = dense::DFA::from_bytes(&dfa.fwd).unwrap().0;
        let rev = dense::DFA::from_bytes(&dfa.bwd).unwrap().0;

        let re = Regex::builder().build_from_dfas(fwd, rev);
        let matches: Vec<Match> = re.find_iter(email_body).collect();

        if !matches.is_empty() {
            regex_verified = true;
            if *is_public {
                let substring = email_body[matches[0].start()..matches[0].end()].to_string();
                regex_matches.push(substring);
            }
        }
    }

    (regex_verified, regex_matches)
}

fn verify_dkim(input: &EmailWithRegex, logger: &Logger) -> bool {
    let parsed_email = parse_mail(&input.email.raw_email).unwrap();

    let public_key = DkimPublicKey::try_from_bytes(
        &input.email.public_key.key,
        &input.email.public_key.key_type
    ).unwrap();

    let result = verify_email_with_key(
        logger,
        &input.email.from_domain,
        &parsed_email,
        public_key
    ).unwrap();

    result.with_detail().starts_with("pass")
}

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: Vec<u8> = env::read_frame();
    let input: EmailWithRegex = postcard::from_bytes(&input).unwrap();

    let logger = Logger::root(Discard, o!());
    let parsed_email = parse_mail(&input.email.raw_email).unwrap();

    let verified = verify_dkim(&input, &logger);
    let email_body = extract_email_body(&parsed_email);
    let (regex_verified, regex_matches) = process_regex_parts(&input.regex_info.parts, &email_body);

    let output = EmailWithRegexVerifierOutput {
        email: EmailVerifierOutput {
            from_domain_hash: hash_bytes(input.email.from_domain.as_bytes()),
            public_key_hash: hash_bytes(&input.email.public_key.key),
            verified,
        },
        regex_verified,
        regex_matches,
    };

    env::commit(&output);
}
