use alloy::{
    primitives::{utils::parse_ether, Address},
    signers::local::PrivateKeySigner,
};
use anyhow::{bail, ensure, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use boundless_market::{
    client::ClientBuilder,
    contracts::{Input, Offer, Predicate, ProofRequest, Requirements},
    input::InputBuilder,
    storage::StorageProviderConfig,
};
use clap::Parser;
use methods::{
    EMAIL_VERIFY_ELF, EMAIL_VERIFY_ID, EMAIL_WITH_REGEX_VERIFY_ELF, EMAIL_WITH_REGEX_VERIFY_ID,
};
use risc0_zkvm::{default_executor, sha::Digestible, ExecutorEnv};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    time::Duration,
};
use url::Url;
use zkemail_core::{Email, EmailWithRegex};
use zkemail_helpers::{generate_email_inputs, generate_email_with_regex_inputs};

/// Timeout for the transaction to be confirmed.
pub const TX_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub enum EmailInput {
    Basic(Email),
    WithRegex(EmailWithRegex),
}

/// Arguments of the publisher CLI.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// URL of the Ethereum RPC endpoint.
    #[clap(short, long, env = "RPC_URL")]
    rpc_url: Url,
    /// Private key used to interact with the EvenNumber contract.
    #[clap(short, long, env = "WALLET_PRIVATE_KEY")]
    wallet_private_key: PrivateKeySigner,
    /// Submit the request offchain via the provided order stream service url.
    #[clap(short, long, requires = "order_stream_url")]
    offchain: bool,
    /// Offchain order stream service URL to submit offchain requests to.
    #[clap(long, env = "ORDER_STREAM_URL")]
    order_stream_url: Option<Url>,
    /// Storage provider to use
    #[clap(flatten)]
    storage_config: Option<StorageProviderConfig>,
    /// Address of the RiscZeroSetVerifier contract.
    #[clap(short, long, env = "SET_VERIFIER_ADDRESS")]
    set_verifier_address: Address,
    /// Address of the BoundlessfMarket contract.
    #[clap(short, long, env = "BOUNDLESS_MARKET_ADDRESS")]
    boundless_market_address: Address,
    /// Email domain
    #[clap(short, long)]
    email_domain: String,
    /// Email path
    #[clap(short, long)]
    email_path: PathBuf,
    /// Regex config path
    #[clap(short, long)]
    regex_config_path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    match dotenvy::dotenv() {
        Ok(path) => tracing::debug!("Loaded environment variables from {:?}", path),
        Err(e) if e.not_found() => tracing::debug!("No .env file found"),
        Err(e) => bail!("failed to load .env file: {}", e),
    }
    let args = Args::parse();

    // Create a Boundless client from the provided parameters.
    let boundless_client = ClientBuilder::default()
        .with_rpc_url(args.rpc_url)
        .with_boundless_market_address(args.boundless_market_address)
        .with_set_verifier_address(args.set_verifier_address)
        .with_order_stream_url(args.offchain.then_some(args.order_stream_url).flatten())
        .with_storage_provider_config(args.storage_config)
        .with_private_key(args.wallet_private_key)
        .build()
        .await?;

    // Upload the ELF to the storage provider so that it can be fetched by the market.
    ensure!(
        boundless_client.storage_provider.is_some(),
        "a storage provider is required to upload the zkVM guest ELF"
    );

    let (id, image) = match args.regex_config_path {
        Some(_) => (EMAIL_WITH_REGEX_VERIFY_ID, EMAIL_WITH_REGEX_VERIFY_ELF),
        None => (EMAIL_VERIFY_ID, EMAIL_VERIFY_ELF),
    };

    let image_url = boundless_client.upload_image(image).await?;
    tracing::info!("Uploaded image to {}", image_url);

    // Encode the input and upload it to the storage provider.
    let input = match args.regex_config_path {
        Some(config) => {
            let email_with_regex_inputs =
                generate_email_with_regex_inputs(&args.email_domain, &args.email_path, &config)
                    .await?;
            borsh::to_vec(&email_with_regex_inputs)?
        }
        None => {
            let email_inputs = generate_email_inputs(&args.email_domain, &args.email_path).await?;
            borsh::to_vec(&email_inputs)?
        }
    };
    let input = InputBuilder::new().write_frame(&input).build();

    // If the input exceeds 2 kB, upload the input and provide its URL instead, as a rule of thumb.
    let request_input = if input.len() > 2 << 10 {
        let input_url = boundless_client.upload_input(&input).await?;
        tracing::info!("Uploaded input to {}", input_url);
        Input::url(input_url)
    } else {
        tracing::info!("Sending input inline with request");
        Input::inline(input.clone())
    };

    // Dry run the ELF with the input to get the journal and cycle count.
    // This can be useful to estimate the cost of the proving request.
    // It can also be useful to ensure the guest can be executed correctly and we do not send into
    // the market unprovable proving requests. If you have a different mechanism to get the expected
    // journal and set a price, you can skip this step.
    let env = ExecutorEnv::builder().write_slice(&input).build()?;
    let session_info = default_executor().execute(env, image)?;
    let mcycles_count = session_info
        .segments
        .iter()
        .map(|segment| 1 << segment.po2)
        .sum::<u64>()
        .div_ceil(1_000_000);
    let journal = session_info.journal;

    // Create a proof request with the image, input, requirements and offer.
    // The ELF (i.e. image) is specified by the image URL.
    // The input can be specified by an URL, as in this example, or can be posted on chain by using
    // the `with_inline` method with the input bytes.
    // The requirements are the image ID and the digest of the journal. In this way, the market can
    // verify that the proof is correct by checking both the committed image id and digest of the
    // journal. The offer specifies the price range and the timeout for the request.
    // Additionally, the offer can also specify:
    // - the bidding start time: the block number when the bidding starts;
    // - the ramp up period: the number of blocks before the price start increasing until reaches
    //   the maxPrice, starting from the the bidding start;
    // - the lockin price: the price at which the request can be locked in by a prover, if the
    //   request is not fulfilled before the timeout, the prover can be slashed.
    let request = ProofRequest::default()
        .with_image_url(&image_url)
        .with_input(request_input)
        .with_requirements(Requirements::new(
            id,
            Predicate::digest_match(journal.digest()),
        ))
        .with_offer(
            Offer::default()
                // The market uses a reverse Dutch auction mechanism to match requests with provers.
                // Each request has a price range that a prover can bid on. One way to set the price
                // is to choose a desired (min and max) price per million cycles and multiply it
                // by the number of cycles. Alternatively, you can use the `with_min_price` and
                // `with_max_price` methods to set the price directly.
                .with_min_price_per_mcycle(parse_ether("0.001")?, mcycles_count)
                // NOTE: If your offer is not being accepted, try increasing the max price.
                .with_max_price_per_mcycle(parse_ether("0.002")?, mcycles_count)
                // The timeout is the maximum number of blocks the request can stay
                // unfulfilled in the market before it expires. If a prover locks in
                // the request and does not fulfill it before the timeout, the prover can be
                // slashed.
                .with_timeout(1000),
        );

    // Send the request and wait for it to be completed.
    let (request_id, expires_at) = boundless_client.submit_request(&request).await?;
    tracing::info!("Request 0x{request_id:x} submitted");
    let start_time = std::time::Instant::now();

    // Wait for the request to be fulfilled by the market, returning the journal and seal.
    tracing::info!("Waiting for 0x{request_id:x} to be fulfilled");
    let (journal, seal) = boundless_client
        .wait_for_request_fulfillment(request_id, Duration::from_secs(5), expires_at)
        .await?;

    // Calculate and log elapsed time
    let proof_time = start_time.elapsed();
    tracing::info!("Request 0x{request_id:x} fulfilled in {:.2?}", proof_time);

    // Create build directory if it doesn't exist
    fs::create_dir_all("app/build")?;

    // Save data in a format ready for smart contract consumption
    let contract_data = Path::new("app/build/contract_data.json");
    let contract_data_json = serde_json::json!({
    "journal": format!("0x{}", hex::encode(&journal)),
    "seal": format!("0x{}", hex::encode(&seal)),
    "requestId": format!("0x{:x}", request_id),
    });

    let mut file = File::create(contract_data)?;
    serde_json::to_writer_pretty(&mut file, &contract_data_json)?;

    // Log the data
    tracing::info!("Contract data saved to app/build/contract_data.json");
    tracing::info!("Request ID: 0x{:x}", request_id);

    Ok(())
}
