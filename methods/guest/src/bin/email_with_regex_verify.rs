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
    if parsed_email.subparts.is_empty() {
        return parsed_email.get_body_raw().unwrap();
    }

    let body = parsed_email.subparts
        .iter()
        .find(|part| part.ctype.mimetype == "text/html")
        .map(|part| part.get_body_raw())
        .unwrap_or_else(|| parsed_email.subparts[0].get_body_raw());

    body.unwrap()
}

fn process_regex_parts(compiled_regexes: &[CompiledRegex], input: &[u8]) -> (bool, Vec<String>) {
    let mut regex_verified = true;
    let mut regex_matches = Vec::new();

    for regex in compiled_regexes {
        let verify_fwd = dense::DFA::from_bytes(&regex.verify_re.fwd).unwrap().0;
        let verify_rev = dense::DFA::from_bytes(&regex.verify_re.bwd).unwrap().0;
        let verify_re = Regex::builder().build_from_dfas(verify_fwd, verify_rev);

        if let Some(full_match) = verify_re.find(input) {
            regex_verified &= true;

            // Only search within the range of the full match
            if let Some(capture_re) = &regex.capture_re {
                let capture_fwd = dense::DFA::from_bytes(&capture_re.fwd).unwrap().0;
                let capture_rev = dense::DFA::from_bytes(&capture_re.bwd).unwrap().0;
                let capture_re = Regex::builder().build_from_dfas(capture_fwd, capture_rev);

                let capture_input = &input[full_match.range()];
                let last_match = capture_re.find_iter(capture_input).last();
                if let Some(m) = last_match {
                    let substring = std::str
                        ::from_utf8(&capture_input[m.range()])
                        .unwrap()
                        .to_owned();
                    regex_matches.push(substring);
                }
            }
        } else {
            regex_verified = false;
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
