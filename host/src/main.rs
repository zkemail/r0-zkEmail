use anyhow::{anyhow, Result};
use cfdkim::{
    dns::from_tokio_resolver, public_key::retrieve_public_key, validate_header,
    verify_email_with_resolver,
};
use log::{debug, error, info, warn};
use mailparse::MailHeaderMap;
use methods::{DKIM_VERIFY_ELF, DKIM_VERIFY_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, Prover};
use serde::{Deserialize, Serialize};
use slog::{o, Discard, Logger};
use std::{env, fs::File, io::Read, path::PathBuf};
use trust_dns_resolver::TokioAsyncResolver;

// TODO remove duplication
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

async fn verify_email(from_domain: &str, email_path: &PathBuf) -> Result<()> {
    let logger = Logger::root(Discard, o!());
    let raw_email = read_email_file(email_path)?;
    let email = mailparse::parse_mail(raw_email.as_bytes())
        .map_err(|e| anyhow!("Failed to parse email: {}", e))?;

    debug!("Looking for DKIM signatures...");
    let dkim_headers = email.headers.get_all_headers("DKIM-Signature");
    if dkim_headers.is_empty() {
        warn!("No DKIM signatures found in email!");
        return Err(anyhow!("No DKIM signatures found"));
    }

    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .map_err(|e| anyhow!("Failed to initialize DNS resolver: {}", e))?;
    let resolver = from_tokio_resolver(resolver);

    let prover = default_prover();

    let mut extracted_public_key = None;
    let mut key_type = None;

    for header in dkim_headers.iter() {
        let header_value = String::from_utf8_lossy(header.get_value_raw());

        let dkim_header = match validate_header(&header_value) {
            Ok(h) => h,
            Err(e) => {
                debug!("Invalid DKIM header: {}", e);
                continue;
            }
        };

        if dkim_header.get_required_tag("d").to_lowercase() != from_domain.to_lowercase() {
            continue;
        }

        let algo = dkim_header.get_required_tag("a");
        let current_key_type = if algo.starts_with("rsa-") {
            "rsa"
        } else if algo.starts_with("ed25519-") {
            "ed25519"
        } else {
            debug!("Unsupported algorithm: {}", algo);
            continue;
        };

        let selector = dkim_header.get_required_tag("s");
        match retrieve_public_key(&logger, resolver.clone(), from_domain.to_string(), selector)
            .await
        {
            Ok(pk) => {
                extracted_public_key = Some(pk.to_vec());
                key_type = Some(current_key_type.to_string());
                break;
            }
            Err(e) => {
                debug!("Failed to retrieve public key: {}", e);
                continue;
            }
        }
    }

    let result = verify_email_with_resolver(&logger, from_domain, &email, resolver)
        .await
        .map_err(|e| anyhow!("Failed to verify email: {}", e))?;

    match result {
        result if result.with_detail().starts_with("pass") => {
            info!("DKIM verification passed: {}", result.with_detail());

            let email_proof = Email {
                from_domain: from_domain.to_string(),
                raw_email: raw_email.as_bytes().to_vec(),
                public_key_type: key_type.ok_or_else(|| anyhow!("No key type found"))?,
                public_key: extracted_public_key
                    .ok_or_else(|| anyhow!("No public key extracted"))?,
            };

            generate_and_verify_proof(prover.as_ref(), email_proof)?;
            Ok(())
        }
        result => {
            error!("DKIM verification failed: {}", result.with_detail());
            Err(anyhow!(
                "DKIM verification failed: {}",
                result.with_detail()
            ))
        }
    }
}

fn read_email_file(path: &PathBuf) -> Result<String> {
    let mut file = File::open(path).map_err(|e| anyhow!("Failed to open email file: {}", e))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| anyhow!("Failed to read email contents: {}", e))?;
    Ok(contents)
}

fn generate_and_verify_proof(prover: &dyn Prover, email: Email) -> Result<()> {
    debug!("Starting ZK proof generation");

    let input = postcard::to_allocvec(&email).unwrap();
    let env = ExecutorEnv::builder()
        .write_frame(&input)
        .build()
        .map_err(|e| anyhow!("Failed to build environment: {}", e))?;

    let prove_info = prover
        .prove(env, DKIM_VERIFY_ELF)
        .map_err(|e| anyhow!("Failed to generate proof: {}", e))?;

    let receipt = prove_info.receipt;
    let output: DKIMOutput = receipt.journal.decode()?;
    println!("{:?}", output);

    receipt
        .verify(DKIM_VERIFY_ID)
        .map_err(|e| anyhow!("Failed to verify proof: {}", e))?;

    info!("ZK proof generated and verified successfully");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err(anyhow!("Usage: {} <from_domain> <email_path>", args[0]));
    }

    let from_domain = &args[1];
    let email_path = PathBuf::from(&args[2]);

    verify_email(from_domain, &email_path).await?;
    println!("Email verification and proof generation completed successfully");

    Ok(())
}
