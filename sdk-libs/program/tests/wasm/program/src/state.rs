use borsh::{BorshDeserialize, BorshSerialize};
use spr_program::{input, circuit::UtxoState, EncryptionCodec, UtxoOwner};

#[input]
#[derive(Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState)]
#[cfg_attr(all(feature = "wasm", not(xark), not(xark_client)), derive(serde::Serialize, serde::Deserialize, tsify::Tsify), serde(rename_all = "camelCase", deny_unknown_fields), tsify(large_number_types_as_bigints))]
pub struct EscrowTerms {
    pub creator: UtxoOwner,
    pub unlock: u64,
}

/// Exercises a custom payload through the generated wasm state binding.
#[input]
#[derive(Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState)]
#[utxo_state(custom_codec)]
#[cfg_attr(all(feature = "wasm", not(xark), not(xark_client)), derive(serde::Serialize, serde::Deserialize, tsify::Tsify), serde(rename_all = "camelCase", deny_unknown_fields), tsify(large_number_types_as_bigints))]
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
