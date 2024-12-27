#![no_main]

use cfdkim::{ verify_email_with_key, DkimPublicKey };
use mailparse::{ parse_mail, ParsedMail };
use risc0_zkvm::guest::env;
use sha2::{ Digest, Sha256 };
use slog::{ o, Discard, Logger };
use zkemail_core::{
    EmailVerifierOutput,
    EmailWithRegex,
    EmailWithRegexVerifierOutput,
    CompiledRegex,
};
use regex_automata::dfa::{ dense, regex::Regex };

fn hash_bytes(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn extract_email_body(parsed_email: &ParsedMail) -> Vec<u8> {
    parsed_email.subparts
        .iter()
        .find(|part| part.ctype.mimetype == "text/html")
        .map_or_else(
            ||
                parsed_email.subparts
                    .get(0)
                    .map_or(parsed_email.get_body_raw().unwrap(), |part|
                        part.get_body_raw().unwrap()
                    ),
            |part| part.get_body_raw().unwrap()
        )
}

fn process_regex_parts(compiled_regexes: &[CompiledRegex], input: &[u8]) -> (bool, Vec<String>) {
    let capture_count = compiled_regexes
        .iter()
        .filter(|r| r.capture_str.is_some())
        .count();
    let mut regex_matches = Vec::with_capacity(capture_count);

    for part in compiled_regexes {
        let fwd = dense::DFA::from_bytes(&part.verify_re.fwd).unwrap().0;
        let rev = dense::DFA::from_bytes(&part.verify_re.bwd).unwrap().0;
        let re = Regex::builder().build_from_dfas(fwd, rev);

        let matches: Vec<_> = re.find_iter(input).collect();
        if matches.len() != 1 {
            return (false, regex_matches);
        }

        if let Some(capture_str) = &part.capture_str {
            let matched_str = std::str::from_utf8(&input[matches[0].range()]).unwrap();
            if !matched_str.contains(capture_str) || matched_str.matches(capture_str).count() != 1 {
                return (false, regex_matches);
            }
            regex_matches.push(capture_str.to_string());
        }
    }

    (true, regex_matches)
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
    let input: EmailWithRegex = borsh::from_slice::<EmailWithRegex>(&input).unwrap();

    let logger = Logger::root(Discard, o!());
    let parsed_email = parse_mail(&input.email.raw_email).unwrap();

    let verified = verify_dkim(&input, &logger);

    let header_bytes = parsed_email.get_headers().get_raw_bytes();
    let email_body = extract_email_body(&parsed_email);

    let (header_regex_verified, header_regex_matches) = process_regex_parts(
        &input.regex_info.header_parts,
        header_bytes
    );
    let (body_regex_verified, body_regex_matches) = process_regex_parts(
        &input.regex_info.body_parts,
        &email_body
    );

    let output = EmailWithRegexVerifierOutput {
        email: EmailVerifierOutput {
            from_domain_hash: hash_bytes(input.email.from_domain.as_bytes()),
            public_key_hash: hash_bytes(&input.email.public_key.key),
            verified,
        },
        header_regex_verified,
        body_regex_verified,
        header_regex_matches,
        body_regex_matches,
    };

    env::commit(&output);
}
