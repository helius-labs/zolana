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
        decode_data_utxos(
            utxos
                .into_iter()
                .filter(|utxo| !spent_nullifiers.contains(&utxo.nullifier)),
        )
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
            ring_program_id: None,
            data: output.data.clone(),
        };
        let utxo_hash = utxo
            .hash(
                &nullifier_pubkey,
                &output.data_hash.unwrap_or_default(),
                &[0u8; 32],
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
            ring_data_hash: None,
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

fn decode_data_utxos<T: EncryptionCodec + DataHasher>(
    utxos: impl IntoIterator<Item = WalletUtxo>,
) -> Result<Vec<DataUtxo<T>>, ClientError> {
    let mut claimed = HashSet::new();
    let mut result = Vec::new();
    for utxo in utxos {
        if utxo.utxo.data.utxo_data().is_none() {
            continue;
        }
        let data = DataUtxo::<T>::try_from(utxo)?;
        if claimed.insert(data.utxo.utxo_hash) {
            result.push(data);
        }
    }
    Ok(result)
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
    fn malformed_state_is_reported_instead_of_disappearing() {
        let mut utxo = WalletUtxo::dummy(0).unwrap();
        utxo.utxo.data =
            spr_transaction::Data::new(vec![spr_transaction::DataRecord::UtxoData(vec![1])]);
        let error = decode_data_utxos::<State>([utxo])
            .err()
            .expect("malformed state");
        assert_eq!(error.name(), "ClientError.UtxoDataEncoding");
    }

    #[test]
    fn outputs_without_state_are_skipped() {
        assert!(decode_data_utxos::<State>([WalletUtxo::dummy(0).unwrap()])
            .unwrap()
            .is_empty());
    }
}
