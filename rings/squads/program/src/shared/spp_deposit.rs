//! Builds the SPP `ring_deposit` instruction data (tag-prefixed, wincode
//! serialized) the zone forwards via CPI for a proofless deposit.
//!
//! The zone's own deposit carries no zone or application data, so `data_hash`
//! and `ring_data_hash` are empty and the created UTXO's `ring_hash` binds only
//! the zone program id SPP reads from the signing `RingConfig`.

use zolana_interface::instruction::{
    tag::RING_DEPOSIT, DepositAssetKind, EncryptedRingDepositData, RingDepositEntry,
    RingDepositIxData,
};
use zolana_squads_interface::error::SquadsZoneError;

/// Inputs for SPP's `ring_deposit` instruction data. `owner_utxo_hash` nests
/// the viewing-key-derived owner with the zone's blinding, which binds the
/// deposit to a recipient SPP itself never sees.
pub struct SppZoneDepositParams {
    pub view_tag: [u8; 32],
    pub owner_utxo_hash: [u8; 32],
    pub asset: DepositAssetKind,
    pub amount: u64,
    pub encrypted: EncryptedRingDepositData,
}

pub fn build_spp_zone_deposit_data(
    params: SppZoneDepositParams,
) -> Result<Vec<u8>, SquadsZoneError> {
    let ix_data = RingDepositIxData {
        assets: vec![params.asset],
        deposits: vec![RingDepositEntry {
            asset_index: 0,
            view_tag: params.view_tag,
            owner_utxo_hash: params.owner_utxo_hash,
            amount: params.amount,
            data_hash: None,
            ring_data_hash: [0u8; 32],
            encrypted: params.encrypted,
        }],
    };

    let mut instruction_data = vec![RING_DEPOSIT];
    instruction_data.extend_from_slice(
        &ix_data
            .serialize()
            .map_err(|_| SquadsZoneError::Serialization)?,
    );
    Ok(instruction_data)
}

#[cfg(test)]
mod tests {
    use zolana_interface::instruction::{tag, RingDepositIxData};

    use super::*;

    fn envelope() -> EncryptedRingDepositData {
        EncryptedRingDepositData {
            tx_viewing_pk: [4u8; 33],
            salt: [5u8; 16],
            ciphertext: vec![6u8; 8],
        }
    }

    #[test]
    fn builds_expected_spp_ix_data() {
        let instruction_data = build_spp_zone_deposit_data(SppZoneDepositParams {
            view_tag: [1u8; 32],
            owner_utxo_hash: [2u8; 32],
            asset: DepositAssetKind::Sol,
            amount: 1_000_000,
            encrypted: envelope(),
        })
        .expect("build");

        assert_eq!(instruction_data.first().copied(), Some(tag::RING_DEPOSIT));
        let parsed =
            RingDepositIxData::deserialize(instruction_data.get(1..).expect("tag-stripped bytes"))
                .expect("SPP must accept the constructed bytes");

        assert_eq!(parsed.assets, vec![DepositAssetKind::Sol]);
        let entry = parsed.deposits.first().expect("one entry");
        assert_eq!(entry.asset_index, 0);
        assert_eq!(entry.view_tag, [1u8; 32]);
        assert_eq!(entry.owner_utxo_hash, [2u8; 32]);
        assert_eq!(entry.amount, 1_000_000);
        assert_eq!(entry.data_hash, None);
        assert_eq!(entry.ring_data_hash, [0u8; 32]);
        assert_eq!(entry.encrypted, envelope());
    }
}
