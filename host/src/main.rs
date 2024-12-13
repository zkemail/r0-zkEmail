pub mod utils;

use anyhow::{anyhow, Ok, Result};
use log::{debug, info};
use methods::{
    EMAIL_VERIFY_ELF, EMAIL_VERIFY_ID, EMAIL_WITH_REGEX_VERIFY_ELF, EMAIL_WITH_REGEX_VERIFY_ID,
};
use risc0_zkvm::{default_prover, ExecutorEnv, Prover};
use std::{env, path::PathBuf};
use utils::{generate_email_inputs, generate_email_with_regex_inputs};
use zkemail_core::{Email, EmailVerifierOutput, EmailWithRegex, EmailWithRegexVerifierOutput};

fn generate_and_verify_email_proof(prover: &dyn Prover, email: Email) -> Result<()> {
    debug!("Starting ZK proof generation");

    let input = postcard::to_allocvec(&email).unwrap();
    let env = ExecutorEnv::builder()
        .write_frame(&input)
        .build()
        .map_err(|e| anyhow!("Failed to build environment: {}", e))?;

    let prove_info = prover
        .prove(env, EMAIL_VERIFY_ELF)
        .map_err(|e| anyhow!("Failed to generate proof: {}", e))?;

    let receipt = prove_info.receipt;
    let output: EmailVerifierOutput = receipt.journal.decode()?;
    println!("{:?}", output);

    receipt
        .verify(EMAIL_VERIFY_ID)
        .map_err(|e| anyhow!("Failed to verify proof: {}", e))?;

    info!("ZK proof generated and verified successfully");
    Ok(())
}

fn generate_and_verify_email_with_regex_proof(
    prover: &dyn Prover,
    email_with_regex: EmailWithRegex,
) -> Result<()> {
    let input = postcard::to_allocvec(&email_with_regex).unwrap();
    let env = ExecutorEnv::builder()
        .write_frame(&input)
        .build()
        .map_err(|e| anyhow!("Failed to build environment: {}", e))?;

    let prove_info = prover
        .prove(env, EMAIL_WITH_REGEX_VERIFY_ELF)
        .map_err(|e| anyhow!("Failed to generate proof: {}", e))?;

    let receipt = prove_info.receipt;
    let output: EmailWithRegexVerifierOutput = receipt.journal.decode()?;
    println!("{:?}", output);

    receipt
        .verify(EMAIL_WITH_REGEX_VERIFY_ID)
        .map_err(|e| anyhow!("Failed to verify proof: {}", e))?;

    info!("ZK proof generated and verified successfully");
    Ok(())
}

async fn verify_email(from_domain: &str, email_path: &PathBuf) -> Result<()> {
    let prover = default_prover();
    let email_inputs = generate_email_inputs(from_domain, email_path).await?;
    generate_and_verify_email_proof(prover.as_ref(), email_inputs)?;
    Ok(())
}

async fn verify_email_with_regex(
    from_domain: &str,
    email_path: &PathBuf,
    config_path: &PathBuf,
) -> Result<()> {
    let prover = default_prover();
    let email_with_regex =
        generate_email_with_regex_inputs(from_domain, email_path, config_path).await?;
    generate_and_verify_email_with_regex_proof(prover.as_ref(), email_with_regex)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        return Err(anyhow!(
            "Usage: {} <from_domain> <email_path> [regex_config_path]",
            args[0]
        ));
    }

    let from_domain = &args[1];
    let email_path = PathBuf::from(&args[2]);

    // Optional regex config
    let config_path = if args.len() > 3 {
        Some(PathBuf::from(&args[3]))
    } else {
        None
    };

    match config_path {
        Some(config) => {
            info!(
                "Starting email verification with regex config from {:?}",
                config
            );
            verify_email_with_regex(from_domain, &email_path, &config).await?;
        }
        None => {
            info!("Starting basic email verification without regex config");
            verify_email(from_domain, &email_path).await?;
        }
    }

    println!("Email verification and proof generation completed successfully");
    Ok(())
}
