use zolana_program::{
    circuit::{Assert, Circuit, PublicInputs, U64},
    conversion::ProofInput,
    CircuitError, ZkProgramCircuit,
};

use super::{shared::check_private_tx_hash, Commitment, ProofInputUtxo};

#[derive(Clone, Debug, ZkProgramCircuit)]
pub struct PoolWithdraw {
    pub private: PoolWithdrawPrivateInputs,
    pub public: PoolWithdrawPublicInputs,
}

#[derive(Clone, Debug, ProofInput)]
pub struct PoolWithdrawPrivateInputs {
    pub private_tx_hash: [u8; 32],
    pub pool_in: ProofInputUtxo,
    pub pool_out: ProofInputUtxo,
    pub private_tx_blinding: [u8; 32],
}

#[derive(Clone, Debug, PublicInputs)]
pub struct PoolWithdrawPublicInputs {
    pub pool_authority_owner_hash: [u8; 32],
    pub destination_asset: [u8; 32],
    pub amount: u64,
}

impl Circuit for PoolWithdrawCircuit {
    type Output = Commitment;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let private = &self.private;
        let public = &self.public;
        let input = &private.pool_in;
        let output = &private.pool_out;
        for pool in [input, output] {
            pool.assert_default_ring()?;
            pool.owner_hash.assert_equal(
                &public.pool_authority_owner_hash,
                "withdrawn liquidity must remain locked to the pool authority",
            )?;
            pool.asset.assert_equal(
                &public.destination_asset,
                "the withdrawn pool note holds another asset",
            )?;
        }
        let _ = U64::from_var(&input.data_hash, "the input booked amount overflows u64")?;
        output.amount.assert_equal(
            &input.amount.minus(&public.amount.var()),
            "the pool change does not conserve the withdrawn amount",
        )?;
        let _ = U64::from_var(&output.amount, "the withdrawal exceeds the pool balance")?;
        output.data_hash.assert_equal(
            &input.data_hash.minus(&public.amount.var()),
            "the withdrawal does not consume the booked liquidity",
        )?;
        let _ = U64::from_var(
            &output.data_hash,
            "the withdrawal exceeds the booked liquidity",
        )?;

        check_private_tx_hash(
            &[input.hash()?],
            &[output.hash()?],
            &private.private_tx_blinding,
            &private.private_tx_hash,
        )?;
        Ok(Commitment(public.hash(&private.private_tx_hash)?))
    }
}
