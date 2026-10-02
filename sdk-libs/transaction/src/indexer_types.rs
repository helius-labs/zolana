use borsh::BorshDeserialize;
use solana_address::Address;
use zolana_event::{EncryptedRingDepositOutput, MessageData, OutputDataEncoding, ProoflessOutput};
use zolana_keypair::P256Pubkey;

use crate::{
    error::TransactionError,
    serialization::{proofless::Proofless, scheme::EncryptedScheme, UtxoSerialization},
};

/// A ring program's reading of its framing around a ring deposit ciphertext:
/// the recipient's ciphertext inside it, `None` when the ciphertext carries no
/// framing, or an error when the framing does not parse.
pub type DepositPayload = for<'a> fn(&'a [u8]) -> Result<Option<&'a [u8]>, TransactionError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldedTransaction {
    pub slot: u64,
    pub tx_signature: solana_signature::Signature,
    /// Position of this event within the transaction. Required when a caller
    /// verifies which program invocation emitted it.
    pub event_index: Option<u16>,
    pub tx_viewing_pk: Option<P256Pubkey>,
    pub salt: Option<[u8; 16]>,
    pub output_slots: Vec<OutputSlot>,
    pub messages: Vec<MessageData>,
    pub nullifiers: Vec<[u8; 32]>,
    pub proofless: bool,
    /// Emitted by `merge_transact` or `merge_ring`, as the indexer reads it
    /// from the source instruction.
    pub merge: bool,
    pub ring_config: Option<solana_address::Address>,
    pub ring_program_id: Option<solana_address::Address>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputContext {
    pub hash: [u8; 32],
    /// Raw id of the tree the commitment was appended to. `hash` folds it in,
    /// so it is checked by recomputation rather than trusted, and the tree
    /// account is `pda::tree(tree_id)` wherever one is needed.
    pub tree_id: u16,
    pub leaf_index: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputSlot {
    pub view_tag: [u8; 32],
    pub output_context: OutputContext,
    pub payload: Vec<u8>,
}

impl OutputSlot {
    pub fn output_data(&self) -> Option<OutputDataEncoding> {
        OutputDataEncoding::try_from_slice(&self.payload).ok()
    }

    /// The UTXO a proofless deposit publishes in the clear: owner hash, asset,
    /// amount and the derived blinding. `None` for encrypted output kinds, so
    /// this is how a depositor whose recipient holds no viewing key (a program
    /// PDA) reads the deposited UTXO back from an indexer.
    pub fn proofless_output(&self) -> Option<ProoflessOutput> {
        let OutputDataEncoding::Plaintext(blob) = self.output_data()? else {
            return None;
        };
        let (&scheme, body) = blob.split_first()?;
        if EncryptedScheme::from_byte(scheme).ok()? != EncryptedScheme::Proofless {
            return None;
        }
        Proofless::deserialize(body).ok()
    }

    /// Replaces the framing `ring_program_id` puts around its ring deposit
    /// ciphertexts with the recipient's ciphertext inside it, which is what
    /// [`decrypt`](crate::decrypt) opens. Other outputs, deposits of other
    /// rings and unframed ciphertexts are left as published; framing that does
    /// not parse is an error rather than a deposit that silently never opens.
    pub fn unwrap_ring_deposit(
        &mut self,
        ring_program_id: &Address,
        deposit_payload: DepositPayload,
    ) -> Result<(), TransactionError> {
        let Some(OutputDataEncoding::Encrypted(blob)) = self.output_data() else {
            return Ok(());
        };
        let Some((&scheme, body)) = blob.split_first() else {
            return Ok(());
        };
        if scheme != EncryptedScheme::RingDeposit.as_byte() {
            return Ok(());
        }
        let Ok(mut output) = EncryptedRingDepositOutput::try_from_slice(body) else {
            return Ok(());
        };
        if output.ring_program_id != *ring_program_id.as_array() {
            return Ok(());
        }
        let Some(ciphertext) = deposit_payload(&output.encrypted.ciphertext)? else {
            return Ok(());
        };
        output.encrypted.ciphertext = ciphertext.to_vec();
        let serialize = |error: std::io::Error| TransactionError::Serialize(error.to_string());
        let body = borsh::to_vec(&output).map_err(serialize)?;
        self.payload = borsh::to_vec(&OutputDataEncoding::Encrypted(
            [&[scheme][..], &body].concat(),
        ))
        .map_err(serialize)?;
        Ok(())
    }
}
