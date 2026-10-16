//! The outflow of one transfer per limited asset, as the circuit sums it.

use solana_address::Address;
use zolana_ring_policy::{Member, OutflowLimit};
use zolana_transaction::{instructions::transact::SppProofOutputUtxo, utxo::SppProofInputUtxo};

use crate::{OutflowLimitProofInput, RingError, RingIdentity};

pub(crate) struct Outflows<'a> {
    pub sender: Member,
    pub ring: Address,
    pub inputs: &'a [SppProofInputUtxo],
    pub outputs: &'a [SppProofOutputUtxo],
}

impl Outflows<'_> {
    /// Inputs of the mint less the sender's change inside the ring.
    fn outflow(&self, asset: &[u8; 32]) -> Result<u64, RingError> {
        let mut inflow: u128 = 0;
        for input in self.inputs.iter().filter(|input| !input.is_dummy()) {
            if Member::asset(&input.utxo.asset.asset)?.as_bytes() == asset {
                inflow += u128::from(input.utxo.amount);
            }
        }
        let mut change: u128 = 0;
        for output in self.outputs {
            let Some(address) = output.owner_address.as_ref() else {
                continue;
            };
            if Member::asset(&output.asset.asset)?.as_bytes() == asset
                && address.signing_pubkey.owner_proof_input_hash()? == *self.sender.as_bytes()
                && output.ring_program_id == Some(self.ring)
            {
                change += u128::from(output.amount);
            }
        }
        let outflow = inflow
            .checked_sub(change)
            .ok_or(RingError::ChangeExceedsInflow { asset: *asset })?;
        u64::try_from(outflow).map_err(|_| RingError::OutflowOverflow)
    }
}

/// Refuses a capped outflow above its cap, a zero bound is off.
pub(crate) fn bound(
    limits: &[OutflowLimit],
    outflows: &Outflows<'_>,
    identity: RingIdentity,
) -> Result<OutflowLimitProofInput, RingError> {
    let mut input = OutflowLimitProofInput::none(identity);
    input.limit_count = limits.len() as u8;
    for (slot, limit) in input.limits.iter_mut().zip(limits) {
        let outflow = outflows.outflow(&limit.asset)?;
        *slot = *limit;
        input.approval_required |= limit.cosign_above != 0 && outflow > limit.cosign_above;
        if limit.cap != 0 && outflow > limit.cap {
            return Err(RingError::OutflowCapExceeded {
                asset: limit.asset,
                cap: limit.cap,
                outflow,
            });
        }
    }
    Ok(input)
}

#[cfg(test)]
mod tests {
    use zolana_keypair::PublicKey;
    use zolana_transaction::{Data, Mint, Utxo};

    use super::*;
    use crate::entry::zero_nullifier_key;

    fn identity() -> RingIdentity {
        RingIdentity {
            ring_id: [1; 32],
            namespace_owner_hash: [2; 32],
        }
    }

    fn mint() -> Mint {
        Mint::new(Address::new_from_array([9; 32]), 9)
    }

    fn asset() -> [u8; 32] {
        *Member::asset(&mint().asset).unwrap().as_bytes()
    }

    fn money_input(mint: Mint, amount: u64) -> SppProofInputUtxo {
        let utxo = Utxo {
            owner: PublicKey::from_pda(&Address::new_from_array([7; 32])),
            asset: mint,
            amount,
            blinding: [0; 32],
            ring_program_id: None,
            data: Data::default(),
        };
        let key = zero_nullifier_key();
        let nullifier_pubkey = key.pubkey().unwrap();
        let utxo_hash = utxo.hash(&nullifier_pubkey, &[0; 32], &[0; 32], 0).unwrap();
        SppProofInputUtxo {
            utxo,
            nullifier_pubkey,
            utxo_hash,
            nullifier: key.nullifier(&utxo_hash, &[0; 32]).unwrap(),
            data_hash: None,
            ring_data_hash: None,
            tree_id: 0,
            leaf_index: 0,
            cache_slot: None,
            compact: false,
        }
    }

    fn bound_one(
        amount: u64,
        cap: u64,
        cosign_above: u64,
    ) -> Result<OutflowLimitProofInput, RingError> {
        let inputs = [money_input(mint(), amount)];
        let outputs: [SppProofOutputUtxo; 0] = [];
        let outflows = Outflows {
            sender: Member::owner_tag(&[1; 32]).unwrap(),
            ring: Address::default(),
            inputs: &inputs,
            outputs: &outputs,
        };
        let limit = OutflowLimit {
            asset: asset(),
            cap,
            cosign_above,
        };
        bound(&[limit], &outflows, identity())
    }

    #[test]
    fn a_transfer_up_to_the_cap_commits_the_limit() {
        let input = bound_one(100, 1000, 0).unwrap();
        assert_eq!(input.limit_count, 1);
        assert_eq!(input.limits[0].cap, 1000);
        assert!(!input.approval_required);
        assert_eq!(bound_one(1000, 1000, 0).unwrap().limit_count, 1);
    }

    #[test]
    fn a_transfer_over_the_cap_is_refused_with_its_outflow() {
        assert!(matches!(
            bound_one(1001, 1000, 0),
            Err(RingError::OutflowCapExceeded { asset: limited, cap: 1000, outflow: 1001 })
                if limited == asset()
        ));
    }

    #[test]
    fn the_cosign_threshold_reads_the_outflow_alone() {
        assert!(bound_one(600, 0, 500).unwrap().approval_required);
        assert!(!bound_one(500, 0, 500).unwrap().approval_required);
        assert!(!bound_one(600, 1000, 0).unwrap().approval_required);
    }

    #[test]
    fn an_unlimited_mint_is_not_summed() {
        let other = Mint::new(Address::new_from_array([8; 32]), 6);
        let inputs = [money_input(other, u64::MAX), money_input(mint(), 3)];
        let outputs: [SppProofOutputUtxo; 0] = [];
        let outflows = Outflows {
            sender: Member::owner_tag(&[1; 32]).unwrap(),
            ring: Address::default(),
            inputs: &inputs,
            outputs: &outputs,
        };
        let limit = OutflowLimit {
            asset: asset(),
            cap: 5,
            cosign_above: 0,
        };
        assert!(bound(&[limit], &outflows, identity()).is_ok());
    }
}
