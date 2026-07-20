//! Client-side transact assembly in two layers. The low level is
//! [`SppProofInputs`] (the assembled transaction sent to the prover), written
//! as a struct literal after encoding explicit output slots with the [`slots`]
//! encoders; it serves custom UTXOs (zone/swap flows). The high level is [`ConfidentialTransfer`], a
//! padded transfer (smallest fitting [`Shape`], derived change outputs, dummy
//! slots) not intended for custom UTXOs.
//! [`EncryptedTransaction::hash`] produces the `private_tx_hash` shared as a
//! public input by the SPP and zone proofs.

pub mod external_data;
pub mod shape;
pub mod slots;
pub mod spp_proof_inputs;
pub mod transfer;
pub mod types;

pub use external_data::ExternalData;
pub use shape::{canonical_shape, resolve_shape, Shape, SPP_SUPPORTED_SHAPES};
pub use slots::{encode_confidential_slots, encrypt_transaction_data, EncryptedTransactionData};
pub use spp_proof_inputs::{
    first_nullifier, get_transaction_viewing_key, inputs_require_p256, signed_to_proof_input,
    PublicAmounts, SppProofInputs,
};
pub use transfer::{
    ConfidentialTransfer, PreparedTransfer, Recipient, Withdrawal, WithdrawalTarget,
    SENDER_SLOT_COUNT,
};
pub use types::{
    EncryptedTransaction, InputUtxo, OutputContext, OutputSlot, PrivateTxHash, ShieldedTransaction,
    SppProofOutputUtxo,
};
