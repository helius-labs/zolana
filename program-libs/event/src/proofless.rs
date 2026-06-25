use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct ProoflessOutput {
    pub owner: [u8; 32],
    pub blinding: [u8; 31],
    pub asset: [u8; 32],
    pub amount: u64,
    pub program_data_hash: Option<[u8; 32]>,
    pub program_data: Option<Vec<u8>>,
    pub zone_program_id: Option<[u8; 32]>,
    pub policy_data_hash: Option<[u8; 32]>,
    pub zone_data: Option<Vec<u8>>,
}

/// Outer tag on each output's `data`. The bytes are always `[scheme_byte] ++
/// body`; the tag only says how `body` is protected:
/// - `Encrypted`: AEAD-style ciphertext (GCM / CTR), authenticated by tag or by
///   the recomputed output commitment.
/// - `VerifiablyEncrypted`: Poseidon-KDF + CTR ciphertext whose integrity comes
///   from the proof (the merge rail), not an inline tag.
/// - `Plaintext`: not encrypted (proofless, plaintext transfer).
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
    let mut blob = vec![0u8]; // proofless scheme byte
    data.serialize(&mut blob)
        .expect("shielded-pool output data serialization is infallible");
    borsh::to_vec(&OutputData::Plaintext(blob))
        .expect("shielded-pool output data serialization is infallible")
}

pub fn encode_verifiably_encrypted(blob: Vec<u8>) -> Vec<u8> {
    borsh::to_vec(&OutputData::VerifiablyEncrypted(blob))
        .expect("shielded-pool output data serialization is infallible")
}
