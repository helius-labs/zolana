use zolana_program::{
    circuit::{Assert, Circuit, PublicInputs, U64},
    conversion::ProofInput,
    CircuitError, ZkProgramCircuit,
};

use super::{shared::check_private_tx_hash, Commitment, ProofInputUtxo};

#[derive(Clone, Debug, ZkProgramCircuit)]
pub struct PoolDeposit {
    pub private: PoolDepositPrivateInputs,
    pub public: PoolDepositPublicInputs,
}

#[derive(Clone, Debug, ProofInput)]
pub struct PoolDepositPrivateInputs {
    pub private_tx_hash: [u8; 32],
    pub source_in: ProofInputUtxo,
    pub pool_out: ProofInputUtxo,
    pub private_tx_blinding: [u8; 32],
}

#[derive(Clone, Debug, PublicInputs)]
pub struct PoolDepositPublicInputs {
    pub pool_authority_owner_hash: [u8; 32],
    pub destination_asset: [u8; 32],
    pub amount: u64,
}

impl Circuit for PoolDepositCircuit {
    type Output = Commitment;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let private = &self.private;
        let public = &self.public;
        let source = &private.source_in;
        let pool = &private.pool_out;
        source.assert_default_ring()?;
        source.owner_hash.assert_not_equal(
            &public.pool_authority_owner_hash,
            "depositing an existing pool note would book liquidity twice",
        )?;
        source.asset.assert_equal(
            &public.destination_asset,
            "the deposited note holds another asset",
        )?;
        source.amount.assert_equal(
            &public.amount.var(),
            "the source note does not hold exactly the deposited amount",
        )?;

        pool.assert_default_ring()?;
        pool.owner_hash.assert_equal(
            &public.pool_authority_owner_hash,
            "the deposited liquidity is not locked to the pool authority",
        )?;
        pool.asset.assert_equal(
            &public.destination_asset,
            "the pool note holds another asset",
        )?;
        pool.amount.assert_equal(
            &public.amount.var(),
            "the pool note does not hold the deposited amount",
        )?;
        let _ = U64::from_var(&pool.amount, "the deposited amount overflows u64")?;
        pool.data_hash.assert_equal(
            &public.amount.var(),
            "the pool note does not book the full deposit",
        )?;

        check_private_tx_hash(
            &[source.hash()?],
            &[pool.hash()?],
            &private.private_tx_blinding,
            &private.private_tx_hash,
        )?;
        Ok(Commitment(public.hash(&private.private_tx_hash)?))
    }
}
