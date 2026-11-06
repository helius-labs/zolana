use borsh::{BorshDeserialize, BorshSerialize};
use spr_program::{circuit::UtxoState, input, EncryptionCodec, Field, UtxoOwner};

#[input]
#[derive(Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState)]
pub struct EscrowTerms {
    pub creator: UtxoOwner,
    pub unlock: u64,
}

/// Exercises a custom payload through the generated wasm state binding.
#[input]
#[derive(Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState)]
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

/// Exercises the JS encodings of the field types without serde impls of
/// their own: a `Field` and a byte array longer than 32.
#[input]
#[derive(UtxoState)]
#[utxo_state(custom_codec)]
pub struct EncodedFields {
    pub commitment: Field,
    pub signature: [u8; 64],
}

// `Field` has no byte form in the circuit build, which never encrypts state.
#[cfg(not(xark))]
impl EncryptionCodec for EncodedFields {
    fn serialize_for_encryption(&self) -> std::io::Result<Vec<u8>> {
        borsh::to_vec(&(spr_program::to_bytes(&self.commitment), self.signature))
    }

    fn deserialize_after_decryption(bytes: &[u8]) -> std::io::Result<Self> {
        let (commitment, signature) = <([u8; 32], [u8; 64])>::try_from_slice(bytes)?;
        let commitment = spr_program::from_bytes(&commitment).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "noncanonical commitment")
        })?;
        Ok(Self {
            commitment,
            signature,
        })
    }
}

#[cfg(xark)]
impl EncryptionCodec for EncodedFields {
    fn serialize_for_encryption(&self) -> std::io::Result<Vec<u8>> {
        Err(std::io::Error::other(
            "the circuit build does not encrypt state",
        ))
    }

    fn deserialize_after_decryption(_: &[u8]) -> std::io::Result<Self> {
        Err(std::io::Error::other(
            "the circuit build does not decrypt state",
        ))
    }
}
