//! Builds the SPP `merge_zone` instruction data (tag-prefixed, wincode
//! serialized) the zone forwards via CPI.

use zolana_interface::instruction::{
    instruction_data::merge_transact::{MERGE_ENCRYPTED_UTXO_TYPE_PREFIX, MERGE_INPUT_COUNT},
    tag::ZONE_MERGE_TRANSACT,
    MergeTransactIxData as SppMergeTransactIxData, MergeZoneIxData,
};
use zolana_squads_interface::{
    error::SquadsZoneError, instruction::instruction_data::transact::InputContext,
    types::ProofBytes,
};

/// Inputs needed to build SPP's `merge_zone` instruction data. `encrypted_utxo`
/// must already be in SPP's serialized format (borsh
/// `OutputData::VerifiablyEncrypted`, `MERGE_ENCRYPTED_UTXO_TYPE_PREFIX` first
/// byte) -- the zone forwards it verbatim, the same as `spp_proof`; it never
/// repackages it.
pub struct SppZoneMergeParams<'a> {
    pub expiry_unix_ts: u64,
    pub merge_view_tag: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub output_utxo_hash: [u8; 32],
    pub spp_proof: &'a ProofBytes,
    pub input_contexts: &'a [InputContext],
    pub encrypted_utxo: &'a [u8],
}

/// Build the tag-prefixed, wincode-serialized SPP `merge_zone` instruction
/// data. `eddsa_owner` is always `false`: the zone's merge users are always
/// P256-owned. (SPP's `merge_zone` path never reads the flag -- it binds the
/// owner via `MergeOwnerBinding::Zone` -- so this is convention, not a gate.)
pub fn build_spp_zone_merge_data(
    params: SppZoneMergeParams<'_>,
) -> Result<Vec<u8>, SquadsZoneError> {
    if params.input_contexts.len() != MERGE_INPUT_COUNT {
        return Err(SquadsZoneError::InvalidInstructionData);
    }
    if params.encrypted_utxo.first() != Some(&MERGE_ENCRYPTED_UTXO_TYPE_PREFIX) {
        return Err(SquadsZoneError::InvalidInstructionData);
    }

    let mut nullifiers = Vec::with_capacity(MERGE_INPUT_COUNT);
    let mut utxo_tree_root_index = Vec::with_capacity(MERGE_INPUT_COUNT);
    let mut nullifier_tree_root_index = Vec::with_capacity(MERGE_INPUT_COUNT);
    for ctx in params.input_contexts {
        nullifiers.push(ctx.nullifier);
        utxo_tree_root_index.push(ctx.utxo_root_index);
        nullifier_tree_root_index.push(ctx.nullifier_root_index);
    }

    let merge = SppMergeTransactIxData {
        expiry_unix_ts: params.expiry_unix_ts,
        proof: *params.spp_proof,
        output_utxo_hash: params.output_utxo_hash,
        nullifiers,
        utxo_tree_root_index,
        nullifier_tree_root_index,
        private_tx_hash: params.private_tx_hash,
        encrypted_utxo: params.encrypted_utxo.to_vec(),
        eddsa_owner: false,
    };
    let ix_data = MergeZoneIxData {
        merge_view_tag: params.merge_view_tag,
        merge,
    };

    let mut instruction_data = vec![ZONE_MERGE_TRANSACT];
    instruction_data.extend_from_slice(
        &ix_data
            .serialize()
            .expect("SPP MergeZoneIxData serialization is infallible"),
    );
    Ok(instruction_data)
}

#[cfg(test)]
mod tests {
    use zolana_interface::instruction::{tag, MergeZoneIxData as SppMergeZoneIxData};

    use super::*;

    fn sample_input_contexts() -> Vec<InputContext> {
        (0..MERGE_INPUT_COUNT as u8)
            .map(|i| InputContext {
                nullifier: [i; 32],
                tree_index: 0,
                utxo_root_index: u16::from(i),
                nullifier_root_index: u16::from(i) + 100,
            })
            .collect()
    }

    fn sample_encrypted_utxo() -> Vec<u8> {
        let mut bytes = vec![MERGE_ENCRYPTED_UTXO_TYPE_PREFIX];
        bytes.extend(std::iter::repeat_n(7u8, 109));
        bytes
    }

    #[test]
    fn builds_expected_spp_ix_data() {
        let proof_bytes: ProofBytes = [3u8; 192];
        let input_contexts = sample_input_contexts();
        let encrypted_utxo = sample_encrypted_utxo();

        let instruction_data = build_spp_zone_merge_data(SppZoneMergeParams {
            expiry_unix_ts: 1_700_000_000,
            merge_view_tag: [5u8; 32],
            private_tx_hash: [6u8; 32],
            output_utxo_hash: [7u8; 32],
            spp_proof: &proof_bytes,
            input_contexts: &input_contexts,
            encrypted_utxo: &encrypted_utxo,
        })
        .expect("build");

        assert_eq!(
            instruction_data.first().copied(),
            Some(tag::ZONE_MERGE_TRANSACT)
        );
        let parsed =
            SppMergeZoneIxData::deserialize(instruction_data.get(1..).expect("tag-stripped bytes"))
                .expect("SPP must accept the constructed bytes");

        assert_eq!(parsed.merge_view_tag, [5u8; 32]);
        assert_eq!(parsed.merge.expiry_unix_ts, 1_700_000_000);
        assert_eq!(parsed.merge.proof, proof_bytes);
        assert_eq!(parsed.merge.output_utxo_hash, [7u8; 32]);
        assert_eq!(parsed.merge.private_tx_hash, [6u8; 32]);
        assert_eq!(parsed.merge.encrypted_utxo, encrypted_utxo);
        assert!(!parsed.merge.eddsa_owner);
        assert_eq!(parsed.merge.nullifiers.len(), MERGE_INPUT_COUNT);
        assert_eq!(parsed.merge.nullifiers.first(), Some(&[0u8; 32]));
        assert_eq!(
            parsed.merge.utxo_tree_root_index,
            vec![0, 1, 2, 3, 4, 5, 6, 7]
        );
        assert_eq!(
            parsed.merge.nullifier_tree_root_index,
            vec![100, 101, 102, 103, 104, 105, 106, 107]
        );
    }

    #[test]
    fn rejects_wrong_input_count() {
        let proof_bytes: ProofBytes = [0u8; 192];
        let encrypted_utxo = sample_encrypted_utxo();
        let err = build_spp_zone_merge_data(SppZoneMergeParams {
            expiry_unix_ts: 0,
            merge_view_tag: [0u8; 32],
            private_tx_hash: [0u8; 32],
            output_utxo_hash: [0u8; 32],
            spp_proof: &proof_bytes,
            input_contexts: &[],
            encrypted_utxo: &encrypted_utxo,
        })
        .expect_err("wrong input count must be rejected");
        assert_eq!(err, SquadsZoneError::InvalidInstructionData);
    }

    #[test]
    fn rejects_wrong_encrypted_utxo_prefix() {
        let proof_bytes: ProofBytes = [0u8; 192];
        let input_contexts = sample_input_contexts();
        let err = build_spp_zone_merge_data(SppZoneMergeParams {
            expiry_unix_ts: 0,
            merge_view_tag: [0u8; 32],
            private_tx_hash: [0u8; 32],
            output_utxo_hash: [0u8; 32],
            spp_proof: &proof_bytes,
            input_contexts: &input_contexts,
            encrypted_utxo: &[0u8; 110],
        })
        .expect_err("wrong prefix must be rejected");
        assert_eq!(err, SquadsZoneError::InvalidInstructionData);
    }
}
