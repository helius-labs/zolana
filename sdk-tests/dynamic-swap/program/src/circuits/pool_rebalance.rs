use zolana_program::{
    circuit::{constant, zero, Assert, Circuit, CircuitVar, PublicInputs, U64},
    conversion::ProofInput,
    CircuitError, ZkProgramCircuit,
};

use super::{shared::check_private_tx_hash, Commitment, ProofInputUtxo, ProofInputUtxoCircuit};

pub const REBALANCE_INPUT_SLOTS: usize = 5;
pub const REBALANCE_OUTPUT_SLOTS: usize = 4;

#[derive(Clone, Debug, ZkProgramCircuit)]
pub struct PoolRebalance {
    pub private: PoolRebalancePrivateInputs,
    pub public: PoolRebalancePublicInputs,
}

#[derive(Clone, Debug, ProofInput)]
pub struct PoolRebalancePrivateInputs {
    pub private_tx_hash: [u8; 32],
    pub inputs: [ProofInputUtxo; REBALANCE_INPUT_SLOTS],
    pub outputs: [ProofInputUtxo; REBALANCE_OUTPUT_SLOTS],
    pub private_tx_blinding: [u8; 32],
}

#[derive(Clone, Debug, PublicInputs)]
pub struct PoolRebalancePublicInputs {
    pub pool_authority_owner_hash: [u8; 32],
    pub destination_asset: [u8; 32],
    pub credit: u64,
}

impl Circuit for PoolRebalanceCircuit {
    type Output = Commitment;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let private = &self.private;
        let public = &self.public;
        let mut amount_in = zero();
        let mut booked_in = zero();
        let mut input_hashes = Vec::with_capacity(REBALANCE_INPUT_SLOTS);
        for (slot, utxo) in private.inputs.iter().enumerate() {
            input_hashes.push(self.check_pool_slot(utxo, slot == 0)?);
            amount_in = amount_in.plus(&utxo.amount);
            booked_in = booked_in.plus(&utxo.data_hash);
        }
        let mut amount_out = zero();
        let mut booked_out = zero();
        let mut output_hashes = Vec::with_capacity(REBALANCE_OUTPUT_SLOTS);
        for (slot, utxo) in private.outputs.iter().enumerate() {
            output_hashes.push(self.check_pool_slot(utxo, slot == 0)?);
            U64::from_var(&utxo.data_hash, "the booked output overflows u64")?
                .assert_less_or_equal(
                    &U64::from_var(&utxo.amount, "the output amount overflows u64")?,
                    "the output books liquidity it does not hold",
                )?;
            amount_out = amount_out.plus(&utxo.amount);
            booked_out = booked_out.plus(&utxo.data_hash);
        }
        amount_out.assert_equal(&amount_in, "the rebalance changes the pool's token amount")?;
        booked_out.assert_equal(
            &booked_in.plus(&public.credit.var()),
            "the published credit does not match the additional booked liquidity",
        )?;
        check_private_tx_hash(
            &input_hashes,
            &output_hashes,
            &private.private_tx_blinding,
            &private.private_tx_hash,
        )?;
        Ok(Commitment(public.hash(&private.private_tx_hash)?))
    }
}

impl PoolRebalanceCircuit {
    fn check_pool_slot(
        &self,
        utxo: &ProofInputUtxoCircuit,
        must_be_real: bool,
    ) -> Result<CircuitVar, CircuitError> {
        let real = utxo
            .domain
            .is_equal(&constant(u64::from(zolana_interface::UTXO_DOMAIN)))?;
        let dummy = utxo
            .domain
            .is_equal(&constant(u64::from(zolana_interface::DUMMY_DOMAIN)))?;
        real.or(&dummy)
            .assert_true("a rebalance slot is neither a pool utxo nor a dummy")?;
        if must_be_real {
            real.assert_true("the first rebalance input and output must be real")?;
        }
        for value in [&utxo.owner_hash, &utxo.asset, &utxo.amount, &utxo.data_hash] {
            value.assert_equal_if(&zero(), &dummy, "a dummy utxo carries a value")?;
        }
        utxo.owner_hash.assert_equal_if(
            &self.public.pool_authority_owner_hash,
            &real,
            "a rebalance utxo is not locked to the pool authority",
        )?;
        utxo.asset.assert_equal_if(
            &self.public.destination_asset,
            &real,
            "a rebalance utxo holds another destination asset",
        )?;
        utxo.ring_data_hash
            .assert_equal(&zero(), "a rebalance utxo belongs to a ring")?;
        utxo.ring_program_id
            .assert_equal(&zero(), "a rebalance utxo belongs to a ring")?;
        let _ = U64::from_var(&utxo.amount, "a rebalance amount overflows u64")?;
        let _ = U64::from_var(&utxo.data_hash, "a rebalance booked value overflows u64")?;
        Ok(real.select(&utxo.hash()?, &zero()))
    }
}
