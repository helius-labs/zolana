use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct ProoflessOutput {
    pub owner: [u8; 32],
    pub blinding: [u8; 31],
    pub asset: [u8; 32],
    pub amount: u64,
    pub data_hash: Option<[u8; 32]>,
    pub utxo_data: Option<Vec<u8>>,
    pub zone_program_id: Option<[u8; 32]>,
    pub zone_data_hash: Option<[u8; 32]>,
    pub zone_data: Option<Vec<u8>>,
    /// Optional free-form memo, emitted in the clear. Not committed into any
    /// hash, so it is informational only.
    pub memo: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub enum OutputData {
    Plaintext(Vec<u8>),
    Encrypted(Vec<u8>),
    VerifiablyEncrypted(Vec<u8>),
}

impl OutputData {
    pub const PLAINTEXT_TAG: u8 = 0;
    pub const ENCRYPTED_TAG: u8 = 1;
    pub const VERIFIABLY_ENCRYPTED_TAG: u8 = 2;
}

pub fn encode_output_data(data: ProoflessOutput) -> Vec<u8> {
    let mut blob = vec![0u8];
    data.serialize(&mut blob)
        .expect("shielded-pool output data serialization is infallible");
    borsh::to_vec(&OutputData::Plaintext(blob))
        .expect("shielded-pool output data serialization is infallible")
}

pub fn encode_verifiably_encrypted(blob: Vec<u8>) -> Vec<u8> {
    borsh::to_vec(&OutputData::VerifiablyEncrypted(blob))
        .expect("shielded-pool output data serialization is infallible")
}
