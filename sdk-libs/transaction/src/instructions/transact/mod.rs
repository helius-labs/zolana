//! Client-side transact assembly in two layers. The low level is
//! [`SppProofInputs`] (the assembled transaction sent to the prover), written
//! as a struct literal after encoding explicit output slots with the [`slots`]
//! encoders; it serves custom UTXOs (zone/swap flows). The high level is [`Transfer`], a
//! padded transfer (fixed [`Shape::IN2_OUT3`] shape, derived change
//! outputs, dummy slots) not intended for custom UTXOs.
//! [`EncryptedTransaction::hash`] produces the `private_tx_hash` shared as a
//! public input by the SPP and zone proofs.

pub mod external_data;
pub mod shape;
pub mod slots;
pub mod spp_proof_inputs;
pub mod transfer;
pub mod types;

pub use external_data::ExternalData;
pub use shape::{Shape, SPP_SUPPORTED_SHAPES};
pub use slots::{encrypt_transaction_data, EncodedTransactionData};
pub use spp_proof_inputs::{
    first_nullifier, get_transaction_viewing_key, inputs_require_p256, signed_to_field,
    PublicAmounts, SppProofInputs,
};
pub use transfer::{
    canonical_shape, resolve_shape, PreparedRecipient, PreparedTransfer, Recipient, Transfer,
    Withdrawal, WithdrawalTarget, SENDER_SLOT_COUNT,
};
pub use types::{
    no_address_hashes, private_tx_hash, EncryptedTransaction, InputUtxo, OutputContext, OutputSlot,
    OutputUtxo, ShieldedTransaction,
};
