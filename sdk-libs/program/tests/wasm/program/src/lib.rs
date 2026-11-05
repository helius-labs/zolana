//! The wasm module the browser tests load: the timelock escrow circuits
//! (`sdk-tests/timelock-escrow`) and a state with a custom payload codec.

use borsh::{BorshDeserialize, BorshSerialize};
use spr_program::{circuit::UtxoState, EncryptionCodec};

#[cfg(feature = "wasm")]
pub use timelock_escrow_program::circuits::{
    escrow_authority, Escrow, EscrowCircuit, EscrowPrivateInputs, EscrowPublicInputs, EscrowTerms,
    EscrowTermsCircuit, Withdraw, WithdrawCircuit, WithdrawPrivateInputs, WithdrawPublicInputs,
    ESCROW_TOKEN_INPUTS,
};

/// Exercises a custom payload through the generated wasm state binding.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState)]
#[utxo_state(custom_codec)]
pub struct CompactCounter {
    pub count: u64,
    pub doubled: u64,
}

impl EncryptionCodec for CompactCounter {
    fn serialize_for_encryption(&self) -> std::io::Result<Vec<u8>> {
        borsh::to_vec(&self.count)
    }

    fn deserialize_after_decryption(bytes: &[u8]) -> std::io::Result<Self> {
        let count = u64::try_from_slice(bytes)?;
        let doubled = count.checked_mul(2).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "doubled count overflows")
        })?;
        Ok(Self { count, doubled })
    }
}
