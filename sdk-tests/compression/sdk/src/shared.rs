use solana_address::Address;
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::NullifierKey;
use zolana_transaction::ExternalData;

pub fn zero_nullifier_key() -> NullifierKey {
    NullifierKey::from_secret([0u8; 31])
}

pub fn external_data(output_hash: [u8; 32], pda: &Address, payload: Vec<u8>) -> ExternalData {
    ExternalData::new(
        [0u8; 33],
        [0u8; 16],
        vec![TransactOutput {
            utxo_hash: output_hash,
            owner_tag: OwnerTag::Inline(pda.to_bytes()),
            data: Some(payload),
        }],
        vec![pda.to_bytes()],
        Vec::new(),
    )
}
