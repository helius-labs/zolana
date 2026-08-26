use anyhow::{bail, Result};
use dynamic_swap_program::instructions::rebalance_liquidity::PoolRebalancePublicInput;
use dynamic_swap_prover::{
    PoolRebalanceProofInputs, ProofInputUtxo, REBALANCE_INPUT_SLOTS, REBALANCE_OUTPUT_SLOTS,
};
use solana_address::Address;
use zolana_keypair::{random_salt, viewing_key::random_blinding, ShieldedAddress, ViewingKeyTrait};
use zolana_transaction::{
    instructions::{
        transact::{
            encode_confidential_slots, first_nullifier, resolve_shape,
            spp_proof_inputs::asset_field, PreparedTransfer, PrivateTxHash, SppProofInputs,
            SppProofOutputUtxo,
        },
        types::SppProofInputUtxo,
    },
    AssetRegistry,
};

use crate::state::PoolUtxo;

fn err(e: impl core::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!("{e:?}")
}

/// Proof-input params for the `pool_rebalance` circuit: 1..=5 real pool notes
/// in, 1..=4 real pool notes out, dummy-padded to the fixed IN5_OUT4 shape.
/// Checks conservation, per-output `booked <= amount`, and
/// `sum(booked_out) = sum(booked_in) + credit`. `credit = 0` is a pure
/// merge/split/re-blind.
///
/// Two-phase: `prepare()` validates and pads the slots (the dummies' fresh
/// random blindings are generated exactly once there), the caller builds the
/// transact's external data from the padded outputs, then
/// `PreparedRebalance::to_proof_inputs(external_data_hash)` finishes the
/// witness -- so the swap proof and the SPP transact commit to identical slot
/// layouts by construction.
pub struct RebalanceProofInputParams {
    /// Real input pool notes (dummies are appended after them).
    pub inputs: Vec<PoolUtxo>,
    /// Real output pool notes.
    pub outputs: Vec<PoolUtxo>,
    /// The pool authority address for the pair, with the maker's derived
    /// pool-role viewing pubkey (see `state::pool_authority_identity`); owner
    /// of every real slot and the encryption target of the output notes.
    pub pool_authority: ShieldedAddress,
    /// The published surplus the program adds to `available_liquidity`.
    pub credit: u64,
    /// The `Pair` account's on-chain `destination_asset`.
    pub destination_asset: [u8; 32],
}

/// The validated, dummy-padded slot layout. `spp_inputs`/`spp_outputs` are
/// what the transact must be built from, verbatim.
pub struct PreparedRebalance {
    pub spp_inputs: Vec<SppProofInputUtxo>,
    pub spp_outputs: Vec<SppProofOutputUtxo>,
    real_inputs: usize,
    real_outputs: usize,
    pool_authority: ShieldedAddress,
    pool_authority_owner_hash: [u8; 32],
    destination_asset: [u8; 32],
    credit: u64,
}

/// The rebalance proof inputs together with the padded slot vectors.
pub struct RebalanceProofBundle {
    pub proof_inputs: PoolRebalanceProofInputs,
}

impl RebalanceProofInputParams {
    pub fn prepare(&self) -> Result<PreparedRebalance> {
        if self.inputs.is_empty() || self.inputs.len() > REBALANCE_INPUT_SLOTS {
            bail!(
                "rebalance takes 1..={REBALANCE_INPUT_SLOTS} input notes, got {}",
                self.inputs.len()
            );
        }
        if self.outputs.is_empty() || self.outputs.len() > REBALANCE_OUTPUT_SLOTS {
            bail!(
                "rebalance takes 1..={REBALANCE_OUTPUT_SLOTS} output notes, got {}",
                self.outputs.len()
            );
        }
        for note in self.inputs.iter().chain(&self.outputs) {
            if asset_field(&note.asset).map_err(err)? != self.destination_asset {
                bail!("pool note asset does not match the pair destination asset");
            }
        }
        for note in &self.outputs {
            if note.booked > note.amount {
                bail!("output booked exceeds its amount");
            }
        }
        let sum = |notes: &[PoolUtxo], f: fn(&PoolUtxo) -> u64| -> Result<u64> {
            notes
                .iter()
                .try_fold(0u64, |acc, note| acc.checked_add(f(note)))
                .ok_or_else(|| err("pool note sum overflows"))
        };
        let (amount_in, booked_in) = (
            sum(&self.inputs, |n| n.amount)?,
            sum(&self.inputs, |n| n.booked)?,
        );
        let (amount_out, booked_out) = (
            sum(&self.outputs, |n| n.amount)?,
            sum(&self.outputs, |n| n.booked)?,
        );
        if amount_out != amount_in {
            bail!("output amounts do not conserve the input amounts");
        }
        if booked_out
            != booked_in
                .checked_add(self.credit)
                .ok_or_else(|| err("booked_in + credit overflows"))?
        {
            bail!("sum(booked_out) does not equal sum(booked_in) + credit");
        }

        // Real slots first, dummy padding trailing -- the wire/discovery
        // convention; the circuit itself classifies slots by domain.
        let mut spp_inputs: Vec<SppProofInputUtxo> = self
            .inputs
            .iter()
            .map(|note| note.to_input_utxo(&self.pool_authority))
            .collect::<Result<_>>()?;
        spp_inputs.resize_with(REBALANCE_INPUT_SLOTS, SppProofInputUtxo::new_dummy);

        let mut spp_outputs: Vec<SppProofOutputUtxo> = self
            .outputs
            .iter()
            .map(|note| note.output_utxo(&self.pool_authority))
            .collect::<Result<_>>()?;
        spp_outputs.resize_with(REBALANCE_OUTPUT_SLOTS, || SppProofOutputUtxo {
            blinding: random_blinding(),
            ..Default::default()
        });

        Ok(PreparedRebalance {
            spp_inputs,
            spp_outputs,
            real_inputs: self.inputs.len(),
            real_outputs: self.outputs.len(),
            pool_authority: self.pool_authority,
            pool_authority_owner_hash: self.pool_authority.owner_hash().map_err(err)?,
            destination_asset: self.destination_asset,
            credit: self.credit,
        })
    }
}

impl PreparedRebalance {
    /// Assemble the SPP transact proof inputs through the canonical padded
    /// path (`PreparedTransfer::finalize`): dummy slots get a participant
    /// owner tag, and the interface-transfer list stays empty. Every output
    /// slot then ships WITHOUT a ciphertext: at the fixed IN5_OUT4 shape the
    /// 5 input entries plus 4 ciphertext-bearing outputs do not fit Solana's
    /// 1232-byte packet even behind a lookup table, and the maker authored
    /// every rebalance note itself, so nothing needs an encrypted handoff
    /// (dummy and real slots also stay indistinguishable this way). The
    /// returned inputs' `external_data.hash()` is the value to pass into
    /// [`Self::to_proof_inputs`].
    pub fn spp_proof_inputs<K: ViewingKeyTrait>(
        &self,
        keypair: &K,
        assets: &AssetRegistry,
        payer: Address,
    ) -> Result<SppProofInputs> {
        let first_nullifier = first_nullifier(&self.spp_inputs).map_err(err)?;
        let shape =
            resolve_shape(None, self.spp_inputs.len(), self.spp_outputs.len()).map_err(err)?;
        let viewing_key = keypair
            .get_transaction_viewing_key(&first_nullifier)
            .map_err(err)?;
        let salt = random_salt();
        let slots = encode_confidential_slots(&self.spp_outputs, assets, &viewing_key, salt)
            .map_err(err)?;
        let mut spp_proof_inputs = PreparedTransfer {
            owner: self.pool_authority,
            inputs: self.spp_inputs.clone(),
            outputs: self.spp_outputs.clone(),
            first_nullifier,
            shape,
            payer,
            interface_transfers: Vec::new(),
        }
        .finalize(viewing_key.pubkey(), salt, slots)
        .map_err(err)?;
        for output in &mut spp_proof_inputs.external_data.outputs {
            output.data = None;
        }
        Ok(spp_proof_inputs)
    }

    pub fn to_proof_inputs(&self, external_data_hash: [u8; 32]) -> Result<RebalanceProofBundle> {
        let input_utxos: Vec<ProofInputUtxo> = self
            .spp_inputs
            .iter()
            .map(ProofInputUtxo::try_from)
            .collect::<Result<_, _>>()
            .map_err(err)?;
        let output_utxos: Vec<ProofInputUtxo> = self
            .spp_outputs
            .iter()
            .map(ProofInputUtxo::try_from)
            .collect::<Result<_, _>>()
            .map_err(err)?;

        // The private-tx-hash chains zero dummy slots, matching both the SPP
        // transfer circuit and pool_rebalance.
        let chain_hash = |utxo: &ProofInputUtxo, real: bool| -> Result<[u8; 32]> {
            if real {
                utxo.hash().map_err(err)
            } else {
                Ok([0u8; 32])
            }
        };
        let input_hashes: Vec<[u8; 32]> = input_utxos
            .iter()
            .enumerate()
            .map(|(i, utxo)| chain_hash(utxo, i < self.real_inputs))
            .collect::<Result<_>>()?;
        let output_hashes: Vec<[u8; 32]> = output_utxos
            .iter()
            .enumerate()
            .map(|(i, utxo)| chain_hash(utxo, i < self.real_outputs))
            .collect::<Result<_>>()?;

        let private_tx_hash =
            PrivateTxHash::new(&input_hashes, &output_hashes, &external_data_hash)
                .hash()
                .map_err(err)?;

        let public_input_hash = PoolRebalancePublicInput {
            private_tx_hash: &private_tx_hash,
            pool_authority_owner_hash: &self.pool_authority_owner_hash,
            destination_asset: &self.destination_asset,
            credit: self.credit,
        }
        .hash()
        .map_err(err)?;

        let inputs: [ProofInputUtxo; REBALANCE_INPUT_SLOTS] = input_utxos
            .try_into()
            .map_err(|_| err("input slot count mismatch"))?;
        let outputs: [ProofInputUtxo; REBALANCE_OUTPUT_SLOTS] = output_utxos
            .try_into()
            .map_err(|_| err("output slot count mismatch"))?;

        Ok(RebalanceProofBundle {
            proof_inputs: PoolRebalanceProofInputs {
                public_input_hash,
                private_tx_hash,
                pool_authority_owner_hash: self.pool_authority_owner_hash,
                destination_asset: self.destination_asset,
                credit: self.credit,
                inputs,
                outputs,
                external_data_hash,
            },
        })
    }
}
