//! The client-side transaction: the spent input UTXO hashes, the new output
//! UTXO hashes, and the transaction-level [`ExternalData`]. [`EncryptedTransaction::hash`]
//! produces the `private_tx_hash` shared as a public input by the SPP and zone proofs.

pub mod builder;
pub mod external_data;
pub mod signed_transaction;
pub mod types;

pub use builder::{
    ConfidentialSlot, EncodeOutputSlot, EncodedSlot, PrebuiltSlot, PreparedRecipient,
    PreparedTransaction, RecipientSlot, SenderSlot, Shape, SlotCx, Transaction, WithdrawalTarget,
    SENDER_SLOT_COUNT,
};
pub use external_data::ExternalData;
pub use signed_transaction::{signed_to_field, PublicAmounts, SignedTransaction};
pub use types::{
    no_address_hashes, private_tx_hash, EncryptedTransaction, InputUtxo, OutputContext, OutputSlot,
    OutputUtxo, ShieldedTransaction,
};
