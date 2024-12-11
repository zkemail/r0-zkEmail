use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKey {
    pub key: Vec<u8>,
    pub key_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Email {
    pub from_domain: String,
    pub raw_email: Vec<u8>,
    pub public_key: PublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DKIMOutput {
    pub from_domain_hash: Vec<u8>,
    pub public_key_hash: Vec<u8>,
    pub verified: bool,
}
