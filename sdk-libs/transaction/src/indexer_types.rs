use borsh::BorshDeserialize;
use zolana_event::{EncryptedRingDepositOutput, MessageData, OutputDataEncoding, ProoflessOutput};
use zolana_keypair::P256Pubkey;

use crate::{
    error::TransactionError,
    serialization::{proofless::Proofless, scheme::EncryptedScheme, UtxoSerialization},
};

/// Returns the recipient's ciphertext from inside a ring program's framing of
/// a ring deposit ciphertext.
pub type DepositPayload = for<'a> fn(&'a [u8]) -> Result<&'a [u8], TransactionError>;

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
    pub ring_config: Option<solana_address::Address>,
    pub ring_program_id: Option<solana_address::Address>,
}

impl ShieldedTransaction {
    /// A merge publishes no ciphertext and no transaction viewing key, and is
    /// not a deposit. Other transactions can share that shape;
    /// [`rebuild_merge`](crate::rebuild_merge) tells them apart by the
    /// commitment.
    pub fn may_be_merge(&self) -> bool {
        !self.proofless && self.tx_viewing_pk.is_none() && self.salt.is_none()
    }
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

    /// Replaces a ring program's framing of a ring deposit ciphertext with the
    /// recipient's ciphertext inside it, which is what
    /// [`decrypt`](crate::decrypt) opens. Every other output, and a deposit
    /// whose framing does not parse, is left as published.
    pub fn unwrap_ring_deposit(&mut self, deposit_payload: DepositPayload) {
        let Some(OutputDataEncoding::Encrypted(blob)) = self.output_data() else {
            return;
        };
        let Some((&scheme, body)) = blob.split_first() else {
            return;
        };
        if scheme != EncryptedScheme::RingDeposit.as_byte() {
            return;
        }
        let Ok(mut output) = EncryptedRingDepositOutput::try_from_slice(body) else {
            return;
        };
        let Ok(ciphertext) = deposit_payload(&output.encrypted.ciphertext) else {
            return;
        };
        if ciphertext.len() == output.encrypted.ciphertext.len() {
            return;
        }
        output.encrypted.ciphertext = ciphertext.to_vec();
        let Ok(body) = borsh::to_vec(&output) else {
            return;
        };
        if let Ok(payload) = borsh::to_vec(&OutputDataEncoding::Encrypted(
            [&[scheme][..], &body].concat(),
        )) {
            self.payload = payload;
        }
    }
}
