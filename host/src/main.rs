use anyhow::{anyhow, Ok, Result};
use log::{debug, info};
use methods::{
    EMAIL_VERIFY_ELF, EMAIL_VERIFY_ID, EMAIL_WITH_REGEX_VERIFY_ELF, EMAIL_WITH_REGEX_VERIFY_ID,
};
use risc0_zkvm::{default_prover, ExecutorEnv, Prover};
use serde::{de::DeserializeOwned, Serialize};
use std::{env, fmt::Debug, path::PathBuf};
use zkemail_core::{
    generate_email_inputs, generate_email_with_regex_inputs, Email, EmailVerifierOutput,
    EmailWithRegex, EmailWithRegexVerifierOutput,
};

enum VerificationType {
    Signature,
    SignatureWithRegex(PathBuf),
}

fn generate_and_verify_proof<T, U>(
    prover: &dyn Prover,
    input_data: T,
    elf: &[u8],
    verify_id: &[u32; 8],
) -> Result<U>
where
    T: Serialize,
    U: DeserializeOwned + Debug,
{
    debug!("Starting ZK proof generation");

    let input = postcard::to_allocvec(&input_data).unwrap();
    std::fs::write("input_original.bin", &input)?;
    let env = ExecutorEnv::builder()
        .write_frame(&input)
        .build()
        .map_err(|e| anyhow!("Failed to build environment: {}", e))?;

    let prove_info = prover
        .prove(env, elf)
        .map_err(|e| anyhow!("Failed to generate proof: {}", e))?;

    let receipt = prove_info.receipt;
    let output: U = receipt.journal.decode()?;
    println!("{:?}", output);

    receipt
        .verify(*verify_id)
        .map_err(|e| anyhow!("Failed to verify proof: {}", e))?;

    info!("ZK proof generated and verified successfully");
    Ok(output)
}

async fn verify_email(
    from_domain: &str,
    email_path: &PathBuf,
    verification_type: VerificationType,
) -> Result<()> {
    let prover = default_prover();

    match verification_type {
        VerificationType::Signature => {
            let email_inputs = generate_email_inputs(from_domain, email_path).await?;
            generate_and_verify_proof::<Email, EmailVerifierOutput>(
                prover.as_ref(),
                email_inputs,
                EMAIL_VERIFY_ELF,
                &EMAIL_VERIFY_ID,
            )?;
        }
        VerificationType::SignatureWithRegex(config_path) => {
            let email_with_regex_inputs =
                generate_email_with_regex_inputs(from_domain, email_path, &config_path).await?;
            generate_and_verify_proof::<EmailWithRegex, EmailWithRegexVerifierOutput>(
                prover.as_ref(),
                email_with_regex_inputs,
                EMAIL_WITH_REGEX_VERIFY_ELF,
                &EMAIL_WITH_REGEX_VERIFY_ID,
            )?;
        }
    }
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
            verify_email(
                from_domain,
                &email_path,
                VerificationType::SignatureWithRegex(config),
            )
            .await?;
        }
        None => {
            info!("Starting Signature email verification without regex config");
            verify_email(from_domain, &email_path, VerificationType::Signature).await?;
        }
    }

    println!("Email verification and proof generation completed successfully");
    Ok(())
}
