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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proofless_output_memo_round_trips() {
        let output = ProoflessOutput {
            owner: [1u8; 32],
            blinding: [2u8; 31],
            asset: [3u8; 32],
            amount: 99,
            data_hash: None,
            utxo_data: None,
            zone_program_id: None,
            zone_data_hash: None,
            zone_data: None,
            memo: Some(b"hello".to_vec()),
        };
        let bytes = borsh::to_vec(&output).unwrap();
        let parsed = ProoflessOutput::try_from_slice(&bytes).unwrap();
        assert_eq!(parsed, output);
        assert_eq!(parsed.memo.as_deref(), Some(b"hello".as_slice()));
    }
}
