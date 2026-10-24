use anyhow::{bail, Result};
use dynamic_swap_program::circuits::{
    PoolDeposit, PoolDepositPrivateInputs, PoolDepositPublicInputs,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::utxo::ProofInputUtxo;
use zolana_transaction::{
    instructions::transact::{asset_field, PrivateTxHash},
    utxo::SppProofInputUtxo,
};

use crate::{err, state::PoolUtxo};

/// Proof-input params for the `pool_deposit` circuit: 1-in (the depositor's
/// source note) / 1-out (the new pool note). SPP proves the transaction at
/// IN1_OUT2 with a compact second output, which leaves the private transaction
/// hash unchanged. The transact carries no public transfer: the source holds
/// exactly `amount` of the destination asset and the pool note holds and books
/// all of it. The source must not be a pool note, because the program signs
/// the transact as the pool authority.
///
/// The pool note's blinding is SPP's derivation for output 0, so the caller
/// fixes it before building the transact and finishes the witness here with
/// the same note.
pub struct DepositProofInputParams {
    pub source_in: SppProofInputUtxo,
    pub pool_out: PoolUtxo,
    /// The pool authority address for the pair (see
    /// `state::pool_authority_address`); owner of the pool note.
    pub pool_authority: ShieldedAddress,
    pub amount: u64,
    /// The `Pair` account's on-chain `destination_asset`.
    pub destination_asset: [u8; 32],
    /// `SppProofInputs::private_tx_blinding()`, the last `private_tx_hash`
    /// preimage element.
    pub private_tx_blinding: [u8; 32],
    /// Raw id of the tree the pool note is appended to; its commitment folds
    /// it in. The source carries its own tree id.
    pub tree_id: u16,
}

impl DepositProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<PoolDeposit> {
        if self.amount == 0 {
            bail!("deposit amount must be nonzero");
        }
        if asset_field(&self.source_in.utxo.asset.asset).map_err(err)? != self.destination_asset {
            bail!("source_in asset does not match the pair destination asset");
        }
        if self.source_in.utxo.amount != self.amount {
            bail!("source_in amount does not equal the deposited amount");
        }
        if asset_field(&self.pool_out.asset.asset).map_err(err)? != self.destination_asset {
            bail!("pool_out asset does not match the pair destination asset");
        }
        if self.pool_out.amount != self.amount {
            bail!("pool_out amount does not equal the deposited amount");
        }
        if self.pool_out.booked != self.amount {
            bail!("pool_out must book the full deposited amount");
        }

        let pool_authority_owner_hash = self.pool_authority.owner_hash().map_err(err)?;
        let source_in = ProofInputUtxo::try_from(&self.source_in).map_err(err)?;
        if source_in.owner_hash == pool_authority_owner_hash {
            bail!("source_in must not be a pool note");
        }
        let spp_output = self.pool_out.output_utxo(&self.pool_authority)?;
        let pool_out = ProofInputUtxo::try_from((&spp_output, self.tree_id)).map_err(err)?;

        let private_tx_hash = PrivateTxHash::new(
            &[source_in.hash().map_err(err)?],
            &[pool_out.hash().map_err(err)?],
            &self.private_tx_blinding,
        )
        .hash()
        .map_err(err)?;

        Ok(PoolDeposit {
            private: PoolDepositPrivateInputs {
                private_tx_hash,
                source_in: source_in.into(),
                pool_out: pool_out.into(),
                private_tx_blinding: self.private_tx_blinding,
            },
            public: PoolDepositPublicInputs {
                pool_authority_owner_hash,
                destination_asset: self.destination_asset,
                amount: self.amount,
            },
        })
    }
}
