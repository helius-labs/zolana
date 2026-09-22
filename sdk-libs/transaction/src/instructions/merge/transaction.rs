use solana_address::Address;
use zolana_event::MessageData;
use zolana_keypair::{constants::SALT_LEN, PublicKey};

use crate::{error::TransactionError, utxo::SppProofInputUtxo, SppProofOutputUtxo};

pub struct MergeProofInputs {
    pub input_utxos: Vec<SppProofInputUtxo>,
    pub output_utxo: SppProofOutputUtxo,
    pub expiry_unix_ts: u64,
    pub signing_pubkey: PublicKey,
    pub output_tree_id: u16,
    pub ring_program_id: Option<Address>,
    pub tx_viewing_pk: [u8; 33],
    pub salt: [u8; SALT_LEN],
    pub output_data: MessageData,
}

impl MergeProofInputs {
    pub fn output_hash(&self) -> Result<[u8; 32], TransactionError> {
        self.output_utxo.hash(self.output_tree_id)
    }
}
