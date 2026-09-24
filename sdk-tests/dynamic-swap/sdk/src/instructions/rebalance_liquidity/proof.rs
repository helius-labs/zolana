use anyhow::{bail, Result};
use dynamic_swap_program::instructions::rebalance_liquidity::PoolRebalancePublicInput;
use dynamic_swap_prover::{
    PoolRebalanceProofInputs, ProofInputUtxo, REBALANCE_INPUT_SLOTS, REBALANCE_OUTPUT_SLOTS,
};
use solana_address::Address;
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{random_salt, viewing_key::random_blinding, ShieldedAddress, ViewingKeyTrait};
use zolana_transaction::{
    instructions::transact::{
        asset_field, ExternalData, PrivateTxHash, SppProofInputs, SppProofOutputUtxo,
    },
    utxo::SppProofInputUtxo,
};

use crate::{
    shared::transaction_blindings,
    state::{IndexedPoolNote, PoolUtxo},
};

fn err(e: impl core::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!("{e:?}")
}

/// Proof-input params for the `pool_rebalance` circuit: 1..=5 real pool notes
/// in, 1..=4 real pool notes out, dummy-padded to the fixed IN5_OUT4 shape.
/// Checks conservation, per-output `booked <= amount`, and
/// `sum(booked_out) = sum(booked_in) + credit`. `credit = 0` is a pure
/// merge/split/re-blind.
///
/// Two-phase: `prepare()` validates and pads the slots and fixes every output
/// blinding, the caller builds the transact from the padded slots, then
/// `PreparedRebalance::to_proof_inputs(external_data_hash)` finishes the
/// witness -- so the swap proof and the SPP transact commit to identical slot
/// layouts by construction.
pub struct RebalanceProofInputParams {
    /// Real input pool notes (dummies are appended after them).
    pub inputs: Vec<IndexedPoolNote>,
    /// Real output pool notes. Their blindings are replaced: SPP derives every
    /// output blinding from the transaction's seed, see
    /// [`PreparedRebalance::outputs`].
    pub outputs: Vec<PoolUtxo>,
    /// The pool authority address for the pair, with the maker's derived
    /// pool-role viewing pubkey (see `state::pool_authority_identity`); owner
    /// of every real slot.
    pub pool_authority: ShieldedAddress,
    /// The published surplus the program adds to `available_liquidity`.
    pub credit: u64,
    /// The `Pair` account's on-chain `destination_asset`.
    pub destination_asset: [u8; 32],
    /// Raw id of the tree the notes are spent from and appended to.
    pub tree_id: u16,
}

/// The validated, dummy-padded slot layout. `spp_inputs`/`spp_outputs` are
/// what the transact must be built from, verbatim.
pub struct PreparedRebalance {
    pub spp_inputs: Vec<SppProofInputUtxo>,
    pub spp_outputs: Vec<SppProofOutputUtxo>,
    /// The real output notes with the blindings SPP derived for their slots;
    /// the maker keeps these to spend them later.
    pub outputs: Vec<PoolUtxo>,
    blinding_seed: [u8; 32],
    private_tx_blinding: [u8; 32],
    real_inputs: usize,
    real_outputs: usize,
    pool_authority: ShieldedAddress,
    pool_authority_owner_hash: [u8; 32],
    destination_asset: [u8; 32],
    credit: u64,
    tree_id: u16,
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
        let input_notes: Vec<PoolUtxo> =
            self.inputs.iter().map(|spent| spent.note.clone()).collect();
        for note in input_notes.iter().chain(&self.outputs) {
            if asset_field(&note.asset.asset).map_err(err)? != self.destination_asset {
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
            sum(&input_notes, |n| n.amount)?,
            sum(&input_notes, |n| n.booked)?,
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
            .map(|spent| spent.to_input_utxo(&self.pool_authority, self.tree_id))
            .collect::<Result<_>>()?;
        while spp_inputs.len() < REBALANCE_INPUT_SLOTS {
            spp_inputs.push(SppProofInputUtxo::dummy(self.tree_id).map_err(err)?);
        }

        // SPP derives every output blinding, padding included, from one seed
        // and the first nullifier.
        let blinding_seed = random_blinding();
        let first_nullifier = spp_inputs
            .first()
            .ok_or_else(|| err("rebalance has no input"))?
            .nullifier();
        let (private_tx_blinding, blindings) = transaction_blindings(
            &first_nullifier,
            &blinding_seed,
            REBALANCE_OUTPUT_SLOTS as u32,
        )?;
        let outputs: Vec<PoolUtxo> = self
            .outputs
            .iter()
            .zip(&blindings)
            .map(|(note, blinding)| PoolUtxo {
                blinding: *blinding,
                ..note.clone()
            })
            .collect();
        let mut spp_outputs: Vec<SppProofOutputUtxo> = outputs
            .iter()
            .map(|note| note.output_utxo(&self.pool_authority))
            .collect::<Result<_>>()?;
        // A dummy slot's published owner tag must name a transaction
        // participant; the pool authority is one (an owner signer).
        let pool_authority_tag = self
            .pool_authority
            .signing_pubkey
            .confidential_view_tag()
            .map_err(err)?;
        for blinding in blindings.iter().skip(outputs.len()) {
            spp_outputs.push(SppProofOutputUtxo {
                blinding: *blinding,
                owner_tag: Some(pool_authority_tag),
                ..Default::default()
            });
        }

        Ok(PreparedRebalance {
            spp_inputs,
            spp_outputs,
            outputs,
            blinding_seed,
            private_tx_blinding,
            real_inputs: self.inputs.len(),
            real_outputs: self.outputs.len(),
            pool_authority: self.pool_authority,
            pool_authority_owner_hash: self.pool_authority.owner_hash().map_err(err)?,
            destination_asset: self.destination_asset,
            credit: self.credit,
            tree_id: self.tree_id,
        })
    }
}

impl PreparedRebalance {
    /// Assemble the SPP transact proof inputs. Every output slot ships WITHOUT
    /// a ciphertext: the maker authored every rebalance note itself, so nothing
    /// needs an encrypted handoff, and dummy and real slots stay
    /// indistinguishable. Every slot's owner tag names the pool authority, the
    /// transaction participant SPP requires a dummy slot's tag to name. The
    /// returned inputs' `external_data.hash()` is the value to pass into
    /// [`Self::to_proof_inputs`].
    pub fn spp_proof_inputs<K: ViewingKeyTrait>(
        &self,
        keypair: &K,
        payer: Address,
    ) -> Result<SppProofInputs> {
        let first_nullifier = self
            .spp_inputs
            .first()
            .ok_or_else(|| err("rebalance has no input"))?
            .nullifier();
        let viewing_key = keypair
            .get_transaction_viewing_key(&first_nullifier)
            .map_err(err)?;
        let owner_tag = self
            .pool_authority
            .signing_pubkey
            .confidential_view_tag()
            .map_err(err)?;
        let outputs = self
            .spp_outputs
            .iter()
            .map(|output| {
                Ok(TransactOutput {
                    utxo_hash: output.hash(self.tree_id).map_err(err)?,
                    owner_tag: OwnerTag::Inline(owner_tag),
                    data: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let external_data = ExternalData::new(
            *viewing_key.pubkey().as_bytes(),
            random_salt(),
            outputs,
            vec![owner_tag; self.spp_outputs.len()],
            vec![],
        );
        Ok(SppProofInputs {
            input_utxos: self.spp_inputs.clone(),
            output_utxos: self.spp_outputs.clone(),
            blinding_seed: self.blinding_seed,
            output_tree_id: self.tree_id,
            external_data,
            payer,
        })
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
            .map(|output| ProofInputUtxo::try_from((output, self.tree_id)))
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

        let private_tx_hash = PrivateTxHash::new(
            &input_hashes,
            &output_hashes,
            &external_data_hash,
            &self.private_tx_blinding,
        )
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
                private_tx_blinding: self.private_tx_blinding,
            },
        })
    }
}
