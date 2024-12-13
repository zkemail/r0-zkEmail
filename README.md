# RISC Zero zkEmail

This repository contains a RISC Zero project to verify DKIM signatures and regex for email content. With r0-zkEmail, email authenticity can be verified through zero-knowledge proofs, removing the need for direct access to email content. Instead, zk-DKIM generates cryptographic proofs that confirm the signature’s validity while keeping sensitive data private.

## Installation

Clone the repository and navigate into it.

```
git clone https://github.com/zkemail/r0-zkEmail.git

cd r0-zkEmail
```

## Usage

To run the program, we need to download an email. In Google Mail, navigate to an email and use the hamburger menu to download the `.eml` file associated with the email. We then need to run our host, which will accept the domain and path to the email in order to verify the DKIM header.

You can also run the program with a regex config file. This file is a JSON file that contains the regex patterns for the email content. The regex config file is optional, and if it is not provided, the program will run without regex verification. The regex config file can be defined as a JSON file with the following format:

```
{
    "parts": [
        {
            "is_public": true,
            "regex": ".*"
        }
    ]
}
```

-   The `is_public` field is a boolean that indicates whether the matched substring will be revealed.
-   The `regex` field is a string that contains the regex pattern.

The CLI command is as follows:

```
RISC0_DEV_MODE=1 RUST_LOG=info cargo run --release -- <FROM_DOMAIN> <EMAIL_PATH> [REGEX_CONFIG_PATH]
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

## Disclaimer

Use it at your own risk. This repository is experimental and unaudited. Do not use in production.

## License

This project is licensed under the Apache2 license. See [LICENSE](https://github.com/zkemail/r0-zkEmail/blob/main/LICENSE).
