use std::collections::HashSet;

use solana_address::Address;
use solana_signature::Signature;
use spr_keypair::{
    constants::BLINDING_LEN, hash::owner_hash, NullifierKey, PublicKey, ShieldedAddress,
    ViewingKey, X25519Pubkey,
};
use spr_transaction::{
    decrypt, utxo::Utxo, AssetRegistry, DecryptionResult, LocalShieldedKeys, ShieldedTransaction,
    SppProofOutputUtxo, WalletUtxo,
};

use super::{DataUtxo, EncryptionCodec};
use crate::{hasher::DataHasher, ClientError, ClientErrorKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramOwner {
    pda: Address,
}

impl ProgramOwner {
    pub fn new(pda: Address) -> Self {
        Self { pda }
    }

    pub fn find(seeds: &[&[u8]], program_id: &Address) -> Self {
        Self::new(Address::find_program_address(seeds, program_id).0)
    }

    pub fn pda(&self) -> &Address {
        &self.pda
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_pda(&self.pda)
    }

    pub fn nullifier_key() -> NullifierKey {
        NullifierKey::from_secret([0u8; BLINDING_LEN])
    }

    pub fn nullifier_pubkey() -> Result<[u8; 32], ClientError> {
        Ok(Self::nullifier_key()
            .pubkey()
            .map_err(ClientErrorKind::InvalidOwner)?)
    }

    pub fn confidential_view_tag(&self) -> [u8; 32] {
        self.pda.to_bytes()
    }

    pub fn owner_hash(&self) -> Result<[u8; 32], ClientError> {
        Ok(owner_hash(&self.public_key(), &Self::nullifier_pubkey()?)
            .map_err(ClientErrorKind::InvalidOwner)?)
    }

    pub fn address(&self, viewing_pubkey: X25519Pubkey) -> Result<ShieldedAddress, ClientError> {
        Ok(ShieldedAddress::for_pda(
            &self.pda,
            Self::nullifier_pubkey()?,
            viewing_pubkey,
        ))
    }

    pub fn decrypt_data_utxos<T: EncryptionCodec + DataHasher>(
        &self,
        viewing_key: &ViewingKey,
        transactions: &[ShieldedTransaction],
        assets: &AssetRegistry,
    ) -> Result<Vec<DataUtxo<T>>, ClientError> {
        let keys = LocalShieldedKeys::new(
            self.address(viewing_key.pubkey())?,
            vec![viewing_key.clone()],
            Self::nullifier_key(),
        )
        .map_err(ClientErrorKind::Transaction)?;
        let DecryptionResult {
            utxos,
            spent_nullifiers,
            ..
        } = decrypt(&keys, transactions, assets).map_err(ClientErrorKind::Transaction)?;
        Ok(decode_data_utxos(utxos.into_iter().filter(|utxo| {
            !spent_nullifiers.contains(&utxo.nullifier)
        })))
    }

    pub fn input(
        &self,
        output: &SppProofOutputUtxo,
        tree_id: u16,
        leaf_index: u64,
    ) -> Result<WalletUtxo, ClientError> {
        let key = Self::nullifier_key();
        let nullifier_pubkey = Self::nullifier_pubkey()?;
        let utxo = Utxo {
            owner: self.public_key(),
            asset: output.asset,
            amount: output.amount,
            blinding: output.blinding,
            ring_program_id: output.ring_program_id,
            data: output.data.clone(),
        };
        let utxo_hash = utxo
            .hash(
                &nullifier_pubkey,
                &output.data_hash.unwrap_or_default(),
                &output.ring_data_hash.unwrap_or_default(),
                tree_id,
            )
            .map_err(ClientErrorKind::InvalidUtxo)?;
        if utxo_hash != output.hash(tree_id).map_err(ClientErrorKind::InvalidUtxo)? {
            return Err(ClientErrorKind::NotProgramOutput.into());
        }
        Ok(WalletUtxo {
            nullifier: utxo
                .nullifier(&utxo_hash, &key)
                .map_err(ClientErrorKind::InvalidUtxo)?,
            utxo,
            nullifier_pubkey,
            utxo_hash,
            data_hash: output.data_hash,
            ring_data_hash: output.ring_data_hash,
            tree_id,
            leaf_index,
            latest_tree_id: None,
            slot: 0,
            tx_signature: Signature::default(),
            slot_index: 0,
            tx_viewing_key: None,
        })
    }
}

/// The UTXOs whose data decodes as a `T` its hash commits to. Anyone can
/// send the PDA an output, and a PDA can hold more than one state type, so
/// an output that is not a `T` is skipped rather than failing the others.
fn decode_data_utxos<T: EncryptionCodec + DataHasher>(
    utxos: impl IntoIterator<Item = WalletUtxo>,
) -> Vec<DataUtxo<T>> {
    let mut claimed = HashSet::new();
    let mut result = Vec::new();
    for utxo in utxos {
        let Ok(data) = DataUtxo::<T>::try_from(utxo) else {
            continue;
        };
        if claimed.insert(data.utxo.utxo_hash) {
            result.push(data);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::{Hasher, HasherError, Poseidon};

    #[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
    struct State {
        value: u64,
    }

    impl EncryptionCodec for State {
        fn serialize_for_encryption(&self) -> std::io::Result<Vec<u8>> {
            borsh::to_vec(self)
        }

        fn deserialize_after_decryption(bytes: &[u8]) -> std::io::Result<Self> {
            <Self as borsh::BorshDeserialize>::try_from_slice(bytes)
        }
    }

    impl DataHasher for State {
        fn hash(&self) -> Result<[u8; 32], HasherError> {
            Poseidon::hashv(&[&spr_hasher::primitives::right_align(
                &self.value.to_be_bytes(),
            )])
        }
    }

    #[test]
    fn outputs_that_are_not_the_state_are_skipped() {
        let owner = ProgramOwner::new(Address::new_from_array([9; 32]));
        let recipient = owner
            .address(ViewingKey::from_bytes(&[7; 32]).pubkey())
            .unwrap();
        let output = |data: Vec<u8>, data_hash: [u8; 32], leaf_index: u64| {
            let output =
                spr_transaction::SppProofOutputUtxo::new(spr_transaction::Mint::SOL, 0, recipient)
                    .unwrap()
                    .with_utxo_data(data, data_hash);
            owner.input(&output, 0, leaf_index).unwrap()
        };
        let state = State { value: 42 };
        let state_hash = crate::hasher::data_hash(&state.hash().unwrap()).unwrap();
        let utxos = [
            // Anyone can send the PDA an output whose data is not a `State`.
            output(vec![1], [5; 32], 0),
            output(borsh::to_vec(&state).unwrap(), state_hash, 1),
            // Data that decodes as a `State` its hash does not commit to, as
            // another state type held by the same PDA can.
            output(borsh::to_vec(&State { value: 7 }).unwrap(), [5; 32], 2),
        ];
        let decoded = decode_data_utxos::<State>(utxos);
        let [only] = decoded.as_slice() else {
            panic!("one state UTXO, got {}", decoded.len());
        };
        assert_eq!(only.data.value, 42);
        assert_eq!(only.utxo.leaf_index, 1);
    }

    #[test]
    fn outputs_without_state_are_skipped() {
        assert!(decode_data_utxos::<State>([WalletUtxo::dummy(0).unwrap()]).is_empty());
    }
}
