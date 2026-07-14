//! Client-side transact assembly in two layers. The low level is
//! [`SppProofInputs`] (the assembled transaction sent to the prover) built from
//! explicit output slots via [`SlotTransact`] and the [`slots`] encoders; it
//! serves custom UTXOs (zone/swap flows). The high level is [`Transfer`], a
//! padded transfer (fixed [`transfer::SUPPORTED_SHAPES`] shape, derived change
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
pub use slots::{ConfidentialSlot, EncodeOutputSlot, EncodedSlot, PrebuiltSlot, SlotCx};
pub use spp_proof_inputs::{
    first_nullifier, inputs_require_p256, signed_to_field, PublicAmounts, SlotTransact,
    SppProofInputs,
};
pub use transfer::{
    canonical_shape, resolve_shape, PreparedRecipient, PreparedTransfer, Recipient, Transfer,
    Withdrawal, WithdrawalTarget, SENDER_SLOT_COUNT, SUPPORTED_SHAPES,
};
pub use types::{
    no_address_hashes, private_tx_hash, EncryptedTransaction, InputUtxo, OutputContext, OutputSlot,
    OutputUtxo, ShieldedTransaction,
};
