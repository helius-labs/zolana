//! Builds the SPP `ring_deposit` instruction data (tag-prefixed, wincode
//! serialized) the ring forwards via CPI.

use pinocchio::error::ProgramError;
use zolana_interface::instruction::{
    instruction_data::deposit::{
        DepositAssetKind, EncryptedRingDepositData, RingDepositEntry, RingDepositIxData,
    },
    tag::RING_DEPOSIT,
};
use zolana_squads_interface::error::SquadsRingError;

use super::proof::poseidon2;

pub struct SppRingDepositParams {
    pub view_tag: [u8; 32],
    /// `Poseidon(owner, nullifier_pubkey)` of the recipient viewing key account.
    pub owner_hash: [u8; 32],
    pub blinding: [u8; 32],
    pub amount: u64,
    pub asset: DepositAssetKind,
}

/// A squads deposit is fully public: the single entry commits
/// `owner_utxo_hash = Poseidon(owner_hash, blinding)` and publishes the
/// blinding unencrypted as its deposit record, so the recipient rebuilds the
/// UTXO from the event alone. It carries no ring data.
pub fn build_spp_ring_deposit_data(params: SppRingDepositParams) -> Result<Vec<u8>, ProgramError> {
    let owner_utxo_hash = poseidon2(
        &params.owner_hash,
        &params.blinding,
        SquadsRingError::ProofHashingFailed,
    )?;
    let ix_data = RingDepositIxData {
        assets: vec![params.asset],
        deposits: vec![RingDepositEntry {
            asset_index: 0,
            view_tag: params.view_tag,
            owner_utxo_hash,
            amount: params.amount,
            ring_data_hash: [0u8; 32],
            encrypted: EncryptedRingDepositData {
                tx_viewing_pk: [0u8; 33],
                salt: [0u8; 16],
                ciphertext: params.blinding.to_vec(),
            },
        }],
    };

    let mut instruction_data = vec![RING_DEPOSIT];
    instruction_data.extend_from_slice(
        &ix_data
            .serialize()
            .map_err(|_| SquadsRingError::InvalidInstructionData)?,
    );
    Ok(instruction_data)
}

#[cfg(test)]
mod tests {
    use zolana_hasher::{Hasher, Poseidon};

    use super::*;

    #[test]
    fn deposit_entry_commits_owner_and_publishes_blinding() {
        let mut blinding = [0u8; 32];
        blinding[31] = 3;
        let owner_hash = [2u8; 32];
        let instruction_data = build_spp_ring_deposit_data(SppRingDepositParams {
            view_tag: [1u8; 32],
            owner_hash,
            blinding,
            amount: 1_000_000,
            asset: DepositAssetKind::Sol,
        })
        .expect("build");

        assert_eq!(instruction_data.first().copied(), Some(RING_DEPOSIT));
        let parsed =
            RingDepositIxData::deserialize(instruction_data.get(1..).expect("tag-stripped bytes"))
                .expect("SPP must accept the constructed bytes");
        let expected_owner_utxo_hash =
            Poseidon::hashv(&[owner_hash.as_slice(), blinding.as_slice()]).expect("poseidon");
        assert_eq!(
            parsed,
            RingDepositIxData {
                assets: vec![DepositAssetKind::Sol],
                deposits: vec![RingDepositEntry {
                    asset_index: 0,
                    view_tag: [1u8; 32],
                    owner_utxo_hash: expected_owner_utxo_hash,
                    amount: 1_000_000,
                    ring_data_hash: [0u8; 32],
                    encrypted: EncryptedRingDepositData {
                        tx_viewing_pk: [0u8; 33],
                        salt: [0u8; 16],
                        ciphertext: blinding.to_vec(),
                    },
                }],
            }
        );
    }
}
