# RISC Zero zkEmail

This repository contains a RISC Zero project to verify DKIM signatures and regex for email content. With r0-zkEmail, email authenticity can be verified through zero-knowledge proofs, removing the need for direct access to email content. Instead, you can generate cryptographic proofs that confirm the signature’s validity while keeping sensitive data private.

## Installation

Clone the repository and navigate into it.

```
git clone https://github.com/zkemail/r0-zkEmail.git

cd r0-zkEmail
```

## Usage

To run the program, you need to download an email. In Google Mail, navigate to an email and use the hamburger menu to download the `.eml` file associated with the email. You then need to run our host, which will accept the domain and path to the email in order to verify the DKIM header.

You can also run the program with a regex config file. This file is a JSON file that contains the regex patterns for the email content. The regex config file is optional, and if it is not provided, the program will run without regex verification. The regex config file can be defined as a JSON file with the following format:

```
{
    "header_parts": [
        {
            "Match": {
                "pattern": "Subject: .*Order Confirmation.*"
            }
        },
        {
            "Capture": {
                "prefix": "Order #",
                "capture": "[0-9]{6}",
                "suffix": " confirmed"
            }
        }
    ],
    "body_parts": [
        {
            "Match": {
                "pattern": "Thank you for your purchase"
            }
        },
        {
            "Capture": {
                "prefix": "Total: $",
                "capture": "[0-9]+\\.[0-9]{2}",
                "suffix": " USD"
            }
        }
    ]
}
```

You can define regex patterns for the header and body of the email. The header regex patterns are applied to the email header, and the body regex patterns are applied to the email body.

We have two types of regex patterns: `Match` and `Capture`.

-   The `Match` pattern is used to verify that a specific pattern exists in the email.
-   The `Capture` pattern is used to extract specific text from the email.
    -   `prefix`: Text that must come before the capture (ensures context)
    -   `capture`: The regex pattern for the text you want to extract
    -   `suffix`: Text that must come after the capture (ensures context)

### Running the Program

The CLI command to run the program is as follows:

```
RISC0_DEV_MODE=1 RUST_LOG=info cargo run --release -- <FROM_DOMAIN> <EMAIL_PATH> <REGEX_CONFIG_PATH>
```

#### Parameters

-   `<FROM_DOMAIN>`: The domain the email comes from. For example, an email from Google Mail account will be `gmail.com`
-   `<EMAIL_PATH>`: The path to the email `.eml` file.
-   `<REGEX_CONFIG_PATH>`: The path to the regex config `.json` file (optional).

### Example

To try out the program, you can run the following command which will execute the program but not generate a proof:

```
RISC0_DEV_MODE=1 RUST_LOG=info cargo run --release -- gmail.com host/test-emails/gmail.eml host/test-regexes/test.json
```

### Generating a Proof

You can generate a proof on [Boundless](https://docs.beboundless.xyz/build/build-a-program) (RiscZero's Prover Network).

#### Steps

1. Create a `.env` file by copying the `.env.example` file and filling in the values.

```
cp .env.example .env
```

2. Run the following command to generate a proof:

```
RUST_BACKTRACE=1 RUST_LOG=info RISC0_DEV_MODE=1 cargo run --release --bin app -- \
  --email-domain <FROM_DOMAIN> \
  --email-path <EMAIL_PATH> \
  --regex-config-path <REGEX_CONFIG_PATH> \ ## Optional
  --storage-provider pinata \ ## Optional
  --pinata-jwt "$PINATA_JWT" \ ## Optional
```

## Disclaimer

Use it at your own risk. This repository is experimental and unaudited. Do not use in production.

## License

This project is licensed under the Apache2 license. See [LICENSE](https://github.com/zkemail/r0-zkEmail/blob/main/LICENSE).
