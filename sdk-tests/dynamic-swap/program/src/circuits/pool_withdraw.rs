use spr_program::{circuit::PublicInputs, input, require_eq, CircuitError, Field, ZkProgram};

use super::{
    shared::{check_private_tx_hash, require_u64},
    Commitment, ProofInputUtxo,
};

#[input]
#[derive(ZkProgram)]
#[zk_program(raw_client)]
pub struct PoolWithdraw {
    pub private: PoolWithdrawPrivateInputs,
    pub public: PoolWithdrawPublicInputs,
}

#[input]
pub struct PoolWithdrawPrivateInputs {
    pub private_tx_hash: Field,
    pub pool_in: ProofInputUtxo,
    pub pool_out: ProofInputUtxo,
    pub private_tx_blinding: Field,
}

#[input]
#[derive(PublicInputs)]
pub struct PoolWithdrawPublicInputs {
    pub pool_authority_owner_hash: Field,
    pub destination_asset: Field,
    pub amount: u64,
}

impl PoolWithdraw {
    pub fn execute(&self) -> Result<Commitment, CircuitError> {
        let private = &self.private;
        let public = &self.public;
        let input = &private.pool_in;
        let output = &private.pool_out;
        let amount = Field::from(public.amount);
        // Withdrawn liquidity stays locked to the pool authority.
        for pool in [input, output] {
            pool.assert_default_ring();
            require_eq(pool.owner_hash, public.pool_authority_owner_hash);
            require_eq(pool.asset, public.destination_asset);
        }
        require_u64(input.data_hash);
        // The pool change conserves the withdrawn amount, which may not
        // exceed the pool balance.
        require_eq(output.amount, input.amount - amount);
        require_u64(output.amount);
        // The withdrawal consumes booked liquidity, never more than is booked.
        require_eq(output.data_hash, input.data_hash - amount);
        require_u64(output.data_hash);

        check_private_tx_hash(
            &[input.hash()?],
            &[output.hash()?],
            private.private_tx_blinding,
            private.private_tx_hash,
        )?;
        Ok(Commitment(public.hash(&private.private_tx_hash)?))
    }
}
