//! `program-governed transact` step and the World operation. Spends a sender's SOL
//! UTXO through a real program-governed `transact` that mints a recipient output
//! carrying the CPI fixture program as its per-utxo `program_id`.
//!
//! Because that per-utxo `program_id` is non-zero, the circuit's `bindIfSet`
//! REQUIRES the public `program_id` to equal `pk_field(cpi-test-program id)`; the
//! `cpi_signer` threaded through `external_data` is what supplies that public value
//! (SPP folds `solana_pk_hash(cpi_signer.program_id)`). The instruction is wrapped
//! in an outer instruction targeting the CPI fixture, which flips the CPI-signer PDA
//! to a signer inside its `invoke_signed`.
//!
//! The high-level builder deducts `add_output` custom outputs from the sender's change
//! (alongside `send` recipients), so the program-governed recipient output carries a
//! real positive value and the sender keeps the remainder as change while value is
//! conserved. The recipient wallet discovers the output against real Photon and
//! reconstructs its non-zero per-utxo `program_id`.

use anyhow::{anyhow, Result};
use cucumber::{then, when};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    assemble, ProverClient, ProverInputs, SpendProof, SpendUtxo, Transaction as ClientTransaction,
};
use zolana_interface::{
    instruction::{CpiSignerData, Transact, TransactIxData},
    pda,
};
use zolana_keypair::PublicKey;
use zolana_test_utils::test_validator_asserts::{
    wait_for_indexed_transaction, wait_for_merkle_proof, wait_for_non_inclusion_proof,
};
use zolana_transaction::{instructions::transact::Shape, OutputUtxo, SOL_MINT};

use cpi_test_program::CPI_TEST_PROGRAM_ID;

use crate::{
    localnet::{send_transaction, transact_proof},
    CpiLifecycleWorld,
};

/// The recipient output's blinding; the builder mints custom outputs verbatim, so the
/// recipient wallet reconstructs the leaf with this exact value.
const RECIPIENT_BLINDING: [u8; 31] = [17u8; 31];

/// The sender shields 1 SOL; the recipient receives this much and the sender keeps the
/// remainder as change. The builder deducts the custom output from change, so value is
/// conserved.
const RECIPIENT_AMOUNT: u64 = 400_000_000;

/// `ShieldedPoolError::UnauthorizedCaller`: SPP rejects a `cpi_signer` account that is
/// not the declared program's canonical CPI-signer PDA.
const UNAUTHORIZED_CALLER: u32 = 7003;

/// A built program-governed `transact`: the proof-carrying instruction data bound to
/// the CPI fixture program, plus what the submit paths need.
struct BuiltProgramGoverned {
    ix_data: TransactIxData,
    cpi_signer_pda: Pubkey,
    fee_payer: Keypair,
    recipient_view_tag: [u8; 32],
    to_signing_pubkey: PublicKey,
}

impl CpiLifecycleWorld {
    /// Build a program-governed `transact`: spend `from`'s SOL UTXO, mint a real
    /// program-governed output to `to` (sender keeps the remainder as change), and bind
    /// the CPI fixture program. The output's non-zero per-utxo `program_id` forces the
    /// circuit's `bindIfSet`; `external_data.cpi_signer` (set before `assemble`) supplies
    /// the public `program_id` and the canonical PDA bump. Returns the proven instruction
    /// data; the caller chooses how to submit it.
    fn build_program_governed(&mut self, from: &str, to: &str) -> Result<BuiltProgramGoverned> {
        self.ensure_actor(from)?;
        self.ensure_actor(to)?;

        let input = {
            let actor = self.actor_mut(from);
            let pos = actor
                .spendable
                .iter()
                .position(|u| u.asset == SOL_MINT)
                .ok_or_else(|| anyhow!("{from} needs a spendable SOL UTXO"))?;
            actor.spendable.remove(pos)
        };

        let from_keypair = self.actor(from).keypair.clone();
        let to_keypair = self.actor(to).keypair.clone();
        let to_address = to_keypair.shielded_address()?;
        let recipient_view_tag = to_keypair.signing_pubkey().confidential_view_tag()?;

        // The eddsa actor pays and signs its own spend (the owner sits at signer index
        // 0 / the fee payer), so the validator verifies the vanilla Groth16 proof.
        let fee_payer = self
            .actor(from)
            .solana_signer
            .as_ref()
            .map(|k| k.insecure_clone())
            .unwrap_or_else(|| self.payer.insecure_clone());
        let payer_address = Address::new_from_array(fee_payer.pubkey().to_bytes());

        let cpi_program = Pubkey::new_from_array(CPI_TEST_PROGRAM_ID);
        let (cpi_signer_pda, bump) = pda::cpi_signer(&cpi_program);

        // `with_program_data` sets the recipient's per-utxo `program_id` to the CPI
        // fixture; the leaf `program_data_hash` stays zero so `Wallet::sync` reproduces
        // the on-chain commitment.
        let spend = SpendUtxo::from_keypair(input, &from_keypair);
        let mut tx =
            ClientTransaction::new(from_keypair.shielded_address()?, vec![spend], payer_address)
                .with_shape(Shape::new(2, 3));
        tx.add_output(
            OutputUtxo {
                asset: SOL_MINT,
                amount: RECIPIENT_AMOUNT,
                blinding: RECIPIENT_BLINDING,
                owner_address: Some(to_address),
                ..Default::default()
            }
            .with_program_data(
                Address::new_from_array(CPI_TEST_PROGRAM_ID),
                Vec::new(),
                [0u8; 32],
            ),
        )?;

        let mut signed = tx.sign(&from_keypair, &self.assets)?;
        // Bind the invoking program before `assemble`: the public `program_id` and the
        // `external_data_hash` both fold `cpi_signer`, so it must be set first.
        signed.external_data.cpi_signer = Some(CpiSignerData {
            program_id: CPI_TEST_PROGRAM_ID,
            bump,
        });

        // Fetch the spend's state inclusion + nullifier non-inclusion proofs from Photon.
        let commitments = signed.input_commitments()?;
        let mut spend_proofs = Vec::new();
        for commitment in &commitments {
            let state =
                wait_for_merkle_proof(&self.indexer, self.tree_address, commitment.utxo_hash);
            let nullifier = wait_for_non_inclusion_proof(
                &self.indexer,
                self.tree_address,
                commitment.nullifier,
            );
            spend_proofs.push(SpendProof { state, nullifier });
        }

        let assembled = assemble(signed, &spend_proofs)?;
        let inputs = match &assembled.prover_inputs {
            ProverInputs::Eddsa(inputs) => inputs.clone(),
            ProverInputs::P256(_) => {
                return Err(anyhow!(
                    "payer-owned ed25519 input must select the eddsa rail"
                ))
            }
        };
        let proof = ProverClient::local().prove_transfer(&inputs)?;
        let ix_data = assembled.with_proof(transact_proof(&proof)?);

        Ok(BuiltProgramGoverned {
            ix_data,
            cpi_signer_pda,
            fee_payer,
            recipient_view_tag,
            to_signing_pubkey: to_keypair.signing_pubkey(),
        })
    }

    /// Submit a program-governed transact through the CPI fixture (which signs the
    /// CPI-signer PDA), minting a program-governed output to `to`. Records the expected
    /// recipient UTXO so the standard `sync` + `assert_utxos` steps verify discovery.
    pub(crate) fn program_governed_transact(&mut self, from: &str, to: &str) -> Result<()> {
        let built = self.build_program_governed(from, to)?;

        // Inner SPP instruction (pure transfer) with the CPI-signer PDA as a readonly
        // signer.
        let inner = Transact {
            payer: built.fee_payer.pubkey(),
            tree: self.tree,
            cpi_signer: Some(built.cpi_signer_pda),
            withdrawal: None,
            data: built.ix_data,
        }
        .instruction();

        // Outer instruction targets the CPI fixture; account order is identical, but the
        // CPI-signer PDA is NOT a transaction-level signer (the fixture flips it to a
        // signer inside its `invoke_signed`).
        let outer_accounts: Vec<AccountMeta> = inner
            .accounts
            .iter()
            .map(|meta| {
                if meta.pubkey == built.cpi_signer_pda {
                    AccountMeta::new_readonly(meta.pubkey, false)
                } else {
                    meta.clone()
                }
            })
            .collect();
        let outer = Instruction {
            program_id: Pubkey::new_from_array(CPI_TEST_PROGRAM_ID),
            accounts: outer_accounts,
            data: inner.data,
        };

        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let signature = send_transaction(
            &mut self.rpc,
            &[compute_budget, outer],
            &built.fee_payer.pubkey(),
            &[&built.fee_payer],
        )?;

        // Wait for Photon to index the transaction, located by the recipient's view tag.
        let indexed =
            wait_for_indexed_transaction(&self.indexer, built.recipient_view_tag, signature);

        // The recipient output's hash folds the program hash (zero program_data_hash);
        // record the expected UTXO with `program_id: Some(..)` so `assert_utxos`
        // cross-checks the recipient's synced wallet against the full struct.
        let recipient_utxo = self.build_expected(
            to,
            built.to_signing_pubkey,
            SOL_MINT,
            RECIPIENT_AMOUNT,
            RECIPIENT_BLINDING,
            Some(Address::new_from_array(CPI_TEST_PROGRAM_ID)),
            &indexed,
        )?;
        self.actor_mut(to).expected.push(recipient_utxo);
        self.indexed.push(indexed);
        Ok(())
    }

    /// Forge a program-governed transact: the proof binds the CPI fixture program, but
    /// the instruction is submitted DIRECTLY to SPP with a `cpi_signer` account that is
    /// an arbitrary signer, not the program's canonical PDA. SPP's `verify_cpi_signer`
    /// derivation check rejects it with `UnauthorizedCaller` before the proof is checked,
    /// so claiming a program's id without controlling its PDA cannot authorize the spend.
    pub(crate) fn program_governed_transact_forged(&mut self, from: &str, to: &str) -> Result<()> {
        let built = self.build_program_governed(from, to)?;
        let imposter = Keypair::new();

        let inner = Transact {
            payer: built.fee_payer.pubkey(),
            tree: self.tree,
            cpi_signer: Some(imposter.pubkey()),
            withdrawal: None,
            data: built.ix_data,
        }
        .instruction();

        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        match send_transaction(
            &mut self.rpc,
            &[compute_budget, inner],
            &built.fee_payer.pubkey(),
            &[&built.fee_payer, &imposter],
        ) {
            Ok(_) => Err(anyhow!(
                "forged program-governed transact unexpectedly succeeded"
            )),
            Err(error) => {
                assert_rpc_custom_error(&error, UNAUTHORIZED_CALLER);
                Ok(())
            }
        }
    }
}

/// Assert a transaction failed with the given custom program error, by decimal code or
/// its hex form, as the validator surfaces it.
#[track_caller]
fn assert_rpc_custom_error(error: &anyhow::Error, code: u32) {
    let message = error.to_string().to_lowercase();
    let hex = format!("0x{code:x}");
    assert!(
        message.contains(&code.to_string()) || message.contains(&hex),
        "expected custom program error {code} ({hex}), got: {message}"
    );
}

#[when(expr = "{word} program-governed transacts to {word}")]
fn program_governed_transacts(world: &mut CpiLifecycleWorld, from: String, to: String) {
    world
        .program_governed_transact(&from, &to)
        .expect("program-governed transact through cpi");
}

#[then(expr = "a forged program-governed transact from {word} to {word} is rejected")]
fn forged_program_governed_rejected(world: &mut CpiLifecycleWorld, from: String, to: String) {
    world
        .program_governed_transact_forged(&from, &to)
        .expect("forged transact must be rejected");
}
