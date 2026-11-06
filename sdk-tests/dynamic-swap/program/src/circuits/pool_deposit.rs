use spr_program::{
    circuit::PublicInputs, input, require, require_eq, CircuitError, Field, ZkProgram,
};

use super::{
    shared::{check_private_tx_hash, require_u64},
    Commitment, ProofInputUtxo,
};

#[input]
#[derive(ZkProgram)]
#[zk_program(raw_client)]
pub struct PoolDeposit {
    pub private: PoolDepositPrivateInputs,
    pub public: PoolDepositPublicInputs,
}

#[input]
pub struct PoolDepositPrivateInputs {
    pub private_tx_hash: Field,
    pub source_in: ProofInputUtxo,
    pub pool_out: ProofInputUtxo,
    pub private_tx_blinding: Field,
}

#[input]
#[derive(PublicInputs)]
pub struct PoolDepositPublicInputs {
    pub pool_authority_owner_hash: Field,
    pub destination_asset: Field,
    pub amount: u64,
}

impl PoolDeposit {
    pub fn execute(&self) -> Result<Commitment, CircuitError> {
        let private = &self.private;
        let public = &self.public;
        let source = &private.source_in;
        let pool = &private.pool_out;
        let amount = Field::from(public.amount);

        source.assert_default_ring();
        // Depositing an existing pool note would book its liquidity twice.
        require(source.owner_hash != public.pool_authority_owner_hash);
        require_eq(source.asset, public.destination_asset);
        require_eq(source.amount, amount);

        pool.assert_default_ring();
        require_eq(pool.owner_hash, public.pool_authority_owner_hash);
        require_eq(pool.asset, public.destination_asset);
        require_eq(pool.amount, amount);
        require_u64(pool.amount);
        // The pool note books the full deposit.
        require_eq(pool.data_hash, amount);

        check_private_tx_hash(
            &[source.hash()?],
            &[pool.hash()?],
            private.private_tx_blinding,
            private.private_tx_hash,
        )?;
        Ok(Commitment(public.hash(&private.private_tx_hash)?))
    }
}
