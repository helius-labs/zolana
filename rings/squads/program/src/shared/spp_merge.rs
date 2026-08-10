//! Builds the SPP `merge_ring` instruction data (tag-prefixed, wincode
//! serialized) the zone forwards via CPI.

use zolana_interface::instruction::{
    instruction_data::merge_transact::MergeProof,
    instruction_data::merge_transact::MERGE_INPUT_COUNT, tag::RING_MERGE_TRANSACT, MergeRingIxData,
    MergeTransactIxData as SppMergeTransactIxData,
};
use zolana_squads_interface::{
    error::SquadsZoneError, instruction::instruction_data::transact::InputContext,
    types::ProofBytes,
};

/// Inputs needed to build SPP's `merge_ring` instruction data.
pub struct SppZoneMergeParams<'a> {
    pub expiry_unix_ts: u64,
    /// Indexes the merged output for wallet discovery. The merge proof asserts
    /// it against the output UTXO's `ring_data_hash`.
    pub output_ring_data_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub output_utxo_hash: [u8; 32],
    pub spp_proof: &'a ProofBytes,
    pub input_contexts: &'a [InputContext],
}

/// `eddsa_owner` is always `false` because the zone's merge users are always
/// P256-owned. SPP's `merge_ring` path never reads the flag. It binds the owner
/// via the signing `RingConfig`, so this is convention rather than a gate.
pub fn build_spp_zone_merge_data(
    params: SppZoneMergeParams<'_>,
) -> Result<Vec<u8>, SquadsZoneError> {
    if params.input_contexts.len() != MERGE_INPUT_COUNT {
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
        proof: merge_proof(params.spp_proof)?,
        output_utxo_hash: params.output_utxo_hash,
        nullifiers,
        utxo_tree_root_index,
        nullifier_tree_root_index,
        private_tx_hash: params.private_tx_hash,
        eddsa_owner: false,
    };
    let ix_data = MergeRingIxData {
        output_ring_data_hash: params.output_ring_data_hash,
        merge,
    };

    let mut instruction_data = vec![RING_MERGE_TRANSACT];
    instruction_data.extend_from_slice(
        &ix_data
            .serialize()
            .map_err(|_| SquadsZoneError::Serialization)?,
    );
    Ok(instruction_data)
}

/// The merge circuit is uncommitted Groth16, so only the leading 128 bytes of
/// the zone's flat proof carry it and the BSB22 tail must stay unread.
fn merge_proof(bytes: &ProofBytes) -> Result<MergeProof, SquadsZoneError> {
    let err = SquadsZoneError::InvalidProofEncoding;
    Ok(MergeProof {
        a: bytes.get(0..32).ok_or(err)?.try_into().map_err(|_| err)?,
        b: bytes.get(32..96).ok_or(err)?.try_into().map_err(|_| err)?,
        c: bytes.get(96..128).ok_or(err)?.try_into().map_err(|_| err)?,
    })
}

#[cfg(test)]
mod tests {
    use zolana_interface::instruction::{tag, MergeRingIxData as SppMergeZoneIxData};

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

    #[test]
    fn builds_expected_spp_ix_data() {
        let proof_bytes: ProofBytes = [3u8; 192];
        let input_contexts = sample_input_contexts();

        let instruction_data = build_spp_zone_merge_data(SppZoneMergeParams {
            expiry_unix_ts: 1_700_000_000,
            output_ring_data_hash: [5u8; 32],
            private_tx_hash: [6u8; 32],
            output_utxo_hash: [7u8; 32],
            spp_proof: &proof_bytes,
            input_contexts: &input_contexts,
        })
        .expect("build");

        assert_eq!(
            instruction_data.first().copied(),
            Some(tag::RING_MERGE_TRANSACT)
        );
        let parsed =
            SppMergeZoneIxData::deserialize(instruction_data.get(1..).expect("tag-stripped bytes"))
                .expect("SPP must accept the constructed bytes");

        assert_eq!(parsed.output_ring_data_hash, [5u8; 32]);
        assert_eq!(parsed.merge.expiry_unix_ts, 1_700_000_000);
        assert_eq!(parsed.merge.output_utxo_hash, [7u8; 32]);
        assert_eq!(parsed.merge.private_tx_hash, [6u8; 32]);
        assert!(!parsed.merge.eddsa_owner);
        assert_eq!(
            parsed.merge.proof,
            MergeProof {
                a: [3u8; 32],
                b: [3u8; 64],
                c: [3u8; 32],
            }
        );
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
        let err = build_spp_zone_merge_data(SppZoneMergeParams {
            expiry_unix_ts: 0,
            output_ring_data_hash: [0u8; 32],
            private_tx_hash: [0u8; 32],
            output_utxo_hash: [0u8; 32],
            spp_proof: &proof_bytes,
            input_contexts: &[],
        })
        .expect_err("wrong input count must be rejected");
        assert_eq!(err, SquadsZoneError::InvalidInstructionData);
    }
}
