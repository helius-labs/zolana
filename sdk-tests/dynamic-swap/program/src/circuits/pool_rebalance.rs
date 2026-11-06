use spr_program::{
    circuit::PublicInputs, input, require, require_eq, CircuitError, Field, ZkProgram,
};

use super::{
    shared::{check_private_tx_hash, require_u64},
    Commitment, ProofInputUtxo,
};

pub const REBALANCE_INPUT_SLOTS: usize = 5;
pub const REBALANCE_OUTPUT_SLOTS: usize = 4;

#[input]
#[derive(ZkProgram)]
#[zk_program(raw_client)]
pub struct PoolRebalance {
    pub private: PoolRebalancePrivateInputs,
    pub public: PoolRebalancePublicInputs,
}

#[input]
pub struct PoolRebalancePrivateInputs {
    pub private_tx_hash: Field,
    pub inputs: [ProofInputUtxo; REBALANCE_INPUT_SLOTS],
    pub outputs: [ProofInputUtxo; REBALANCE_OUTPUT_SLOTS],
    pub private_tx_blinding: Field,
}

#[input]
#[derive(PublicInputs)]
pub struct PoolRebalancePublicInputs {
    pub pool_authority_owner_hash: Field,
    pub destination_asset: Field,
    pub credit: u64,
}

impl PoolRebalance {
    pub fn execute(&self) -> Result<Commitment, CircuitError> {
        let private = &self.private;
        let public = &self.public;
        let mut amount_in = Field::zero();
        let mut booked_in = Field::zero();
        let mut input_hashes = [Field::zero(); REBALANCE_INPUT_SLOTS];
        for ((slot, utxo), hash) in private.inputs.iter().enumerate().zip(&mut input_hashes) {
            *hash = self.check_pool_slot(utxo, slot == 0)?;
            amount_in += utxo.amount;
            booked_in += utxo.data_hash;
        }
        let mut amount_out = Field::zero();
        let mut booked_out = Field::zero();
        let mut output_hashes = [Field::zero(); REBALANCE_OUTPUT_SLOTS];
        for ((slot, utxo), hash) in private.outputs.iter().enumerate().zip(&mut output_hashes) {
            *hash = self.check_pool_slot(utxo, slot == 0)?;
            // An output books no liquidity it does not hold.
            require(utxo.data_hash.le::<64>(utxo.amount));
            amount_out += utxo.amount;
            booked_out += utxo.data_hash;
        }
        // The rebalance keeps the pool's token amount, and the published
        // credit is exactly the additional booked liquidity.
        require_eq(amount_out, amount_in);
        require_eq(booked_out, booked_in + Field::from(public.credit));
        check_private_tx_hash(
            &input_hashes,
            &output_hashes,
            private.private_tx_blinding,
            private.private_tx_hash,
        )?;
        Ok(Commitment(public.hash(&private.private_tx_hash)?))
    }

    /// A slot is a pool utxo or a dummy that carries no value; its hash
    /// enters the transaction only when real.
    fn check_pool_slot(
        &self,
        utxo: &ProofInputUtxo,
        must_be_real: bool,
    ) -> Result<Field, CircuitError> {
        let real = utxo.domain == Field::from(spr_interface::UTXO_DOMAIN);
        let dummy = utxo.domain == Field::from(spr_interface::DUMMY_DOMAIN);
        require(real | dummy);
        if must_be_real {
            require(real);
        }
        if dummy {
            for value in [utxo.owner_hash, utxo.asset, utxo.amount, utxo.data_hash] {
                require_eq(value, Field::zero());
            }
        }
        if real {
            require_eq(utxo.owner_hash, self.public.pool_authority_owner_hash);
            require_eq(utxo.asset, self.public.destination_asset);
        }
        require_eq(utxo.ring_data_hash, Field::zero());
        require_eq(utxo.ring_program_id, Field::zero());
        require_u64(utxo.amount);
        require_u64(utxo.data_hash);
        let hash = utxo.hash()?;
        Ok(if real { hash } else { Field::zero() })
    }
}
