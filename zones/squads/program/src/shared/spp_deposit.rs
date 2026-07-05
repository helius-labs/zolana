//! Builds the SPP `zone_deposit` instruction data (tag-prefixed, wincode
//! serialized) the zone forwards via CPI for a proofless deposit.
//!
//! The zone's own deposit carries no zone or application data, so
//! `zone_data`/`utxo_data` are empty; the recipient `owner` is derived on-chain
//! from the recipient viewing key account and the asset is inferred by SPP from
//! the forwarded settlement accounts.

use zolana_interface::instruction::{tag::ZONE_DEPOSIT, ZoneDepositIxData};
use zolana_squads_interface::error::SquadsZoneError;

/// Inputs for SPP's `zone_deposit` instruction data. `owner` is the recipient
/// viewing key account's owner; `view_tag`/`blinding` come from the zone's own
/// `DepositIxData`; `amount` becomes SPP's positive `public_amount`.
pub struct SppZoneDepositParams {
    pub view_tag: [u8; 32],
    pub owner: [u8; 32],
    pub blinding: [u8; 31],
    pub amount: u64,
}

/// Build the tag-prefixed, wincode-serialized SPP `zone_deposit` instruction
/// data. `zone_data`/`utxo_data` are empty (the zone deposit carries no extra
/// data), so the created UTXO's `zone_hash` binds only the zone program id SPP
/// reads from the signing `ZoneConfig`.
pub fn build_spp_zone_deposit_data(
    params: SppZoneDepositParams,
) -> Result<Vec<u8>, SquadsZoneError> {
    let ix_data = ZoneDepositIxData {
        view_tag: params.view_tag,
        owner: params.owner,
        blinding: params.blinding,
        public_amount: Some(params.amount),
        zone_data_hash: [0u8; 32],
        zone_data: Vec::new(),
        utxo_data: None,
        memo: None,
    };

    let mut instruction_data = vec![ZONE_DEPOSIT];
    instruction_data.extend_from_slice(
        &ix_data
            .serialize()
            .expect("SPP ZoneDepositIxData serialization is infallible"),
    );
    Ok(instruction_data)
}

#[cfg(test)]
mod tests {
    use zolana_interface::instruction::{tag, ZoneDepositIxData};

    use super::*;

    #[test]
    fn builds_expected_spp_ix_data() {
        let instruction_data = build_spp_zone_deposit_data(SppZoneDepositParams {
            view_tag: [1u8; 32],
            owner: [2u8; 32],
            blinding: [3u8; 31],
            amount: 1_000_000,
        })
        .expect("build");

        assert_eq!(instruction_data.first().copied(), Some(tag::ZONE_DEPOSIT));
        let parsed =
            ZoneDepositIxData::deserialize(instruction_data.get(1..).expect("tag-stripped bytes"))
                .expect("SPP must accept the constructed bytes");

        assert_eq!(parsed.view_tag, [1u8; 32]);
        assert_eq!(parsed.owner, [2u8; 32]);
        assert_eq!(parsed.blinding, [3u8; 31]);
        assert_eq!(parsed.public_amount, Some(1_000_000));
        assert_eq!(parsed.zone_data_hash, [0u8; 32]);
        assert!(parsed.zone_data.is_empty());
        assert_eq!(parsed.utxo_data, None);
    }
}
