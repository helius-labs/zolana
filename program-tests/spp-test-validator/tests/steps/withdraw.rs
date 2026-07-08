//! `withdraw` (unshield) steps and the World withdrawal operation. A withdrawal
//! spends the sender's SOL UTXOs and moves the public SOL amount out of the pool
//! to an external recipient account, keeping a SOL change UTXO for the sender.
//! Mirrors `execute_transfer` except it calls `tx.withdraw(..)` instead of
//! `tx.send(..)` and sets `withdrawal: Some(..)` on the `Transact` builder, so the
//! builder appends the `sol_interface` custody PDA and the recipient account.

use anyhow::{anyhow, Result};
use cucumber::when;
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    assemble, ProverClient, ProverInputs, SpendProof, SpendUtxo, Transaction as ClientTransaction,
    WithdrawalTarget,
};
use zolana_interface::instruction::{Transact, TransactSolWithdrawal, TransactWithdrawal};
use zolana_test_utils::test_validator_asserts::{
    wait_for_indexed_transaction, wait_for_merkle_proof, wait_for_non_inclusion_proof,
};
use zolana_transaction::{utxo::derive_blinding, Utxo, SOL_MINT};

use crate::{
    localnet::{send_transaction, transact_proof, SOL_CHANGE_POSITION, ZERO},
    world::Rail,
    LifecycleWorld,
};

impl LifecycleWorld {
    /// Withdraw `amount` lamports of SOL from `from` to a fresh external recipient
    /// account, spending two of `from`'s spendable SOL UTXOs (the supported (2, 3)
    /// shape). The chosen inputs must total more than `amount` so a SOL change UTXO
    /// is emitted back to the sender. Mirrors `execute_transfer`, but the public SOL
    /// leaves the pool to `recipient` and there is no recipient UTXO.
    pub(crate) fn withdraw_sol(&mut self, from: &str, amount: u64) -> Result<Signature> {
        self.ensure_actor(from)?;

        // Pick two spendable SOL UTXOs (the (2, 3) shape); their total must exceed
        // `amount` so there is SOL change to track.
        let inputs: Vec<Utxo> = {
            let actor = self.actor_mut(from);
            let mut taken = Vec::new();
            for _ in 0..2 {
                let pos = actor
                    .spendable
                    .iter()
                    .position(|u| u.asset == SOL_MINT)
                    .ok_or_else(|| anyhow!("{from} needs two spendable SOL UTXOs"))?;
                taken.push(actor.spendable.remove(pos));
            }
            taken
        };
        let input_sum: u64 = inputs.iter().map(|u| u.amount).sum();
        if input_sum <= amount {
            return Err(anyhow!(
                "{from} has {input_sum} SOL across two UTXOs, need more than {amount} for change"
            ));
        }

        // Fresh external recipient: airdrop a small balance so the account exists,
        // then assert the withdrawn lamports land on it.
        let recipient = Keypair::new();
        self.rpc.airdrop(&recipient.pubkey(), 1_000_000)?;
        let recipient_before = self.rpc.client().get_balance(&recipient.pubkey())?;

        let from_keypair = self.actor(from).keypair.clone();
        // An eddsa actor pays and signs its own spend (the owner sits at signer index
        // 0 / the fee payer); a P256 actor falls back to the global payer.
        let fee_payer = self
            .actor(from)
            .solana_signer
            .as_ref()
            .map(|k| k.insecure_clone())
            .unwrap_or_else(|| self.payer.insecure_clone());
        let payer_address = Address::new_from_array(fee_payer.pubkey().to_bytes());
        let sender_view_tag = from_keypair.signing_pubkey().confidential_view_tag()?;

        let spends: Vec<SpendUtxo> = inputs
            .iter()
            .map(|u| SpendUtxo::from_keypair(u.clone(), &from_keypair))
            .collect();
        let mut tx =
            ClientTransaction::new(from_keypair.shielded_address()?, spends, payer_address);
        tx.withdraw(
            SOL_MINT,
            amount,
            WithdrawalTarget::Sol {
                user_sol_account: Address::new_from_array(recipient.pubkey().to_bytes()),
            },
        )?;
        let signed = tx.sign(&from_keypair, &self.assets)?;

        let commitments = signed.input_utxo_hashes()?;
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
        let (proof, rail) = match &assembled.prover_inputs {
            ProverInputs::P256(inputs) => (
                ProverClient::local().prove_transfer_p256(inputs)?,
                Rail::P256,
            ),
            ProverInputs::Eddsa(inputs) => {
                (ProverClient::local().prove_transfer(inputs)?, Rail::Eddsa)
            }
        };
        self.last_rail = Some(rail);
        let ix_data = assembled.with_proof(transact_proof(&proof)?);

        let withdraw_ix = Transact {
            payer: fee_payer.pubkey(),
            tree: self.tree,
            withdrawal: Some(TransactWithdrawal::Sol(TransactSolWithdrawal {
                recipient: recipient.pubkey(),
            })),
            data: ix_data,
        }
        .instruction();
        let compute_budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let sig = send_transaction(
            &mut self.rpc,
            &[compute_budget, withdraw_ix.clone()],
            &fee_payer.pubkey(),
            &[&fee_payer],
        )?;
        self.last_transact = Some((sig, withdraw_ix));

        // The withdrawal has no recipient slot, so locate the indexed transaction by
        // the sender's view tag. Decode the sender bundle for the change seed: the
        // expected set is rebuilt independently from the seed (not from `Wallet::sync`)
        // so `assert_utxos` is a real cross-check of the synced wallet.
        let indexed = wait_for_indexed_transaction(&self.indexer, sender_view_tag, sig);
        let seed = super::transfer::decode_sender_seed(&from_keypair.viewing_key, &indexed)?;

        // The only output is the sender's SOL change (= sum(inputs) - amount) at the
        // fixed SOL change position. No recipient UTXO: the SOL left the pool.
        let change = input_sum - amount;
        if change > 0 {
            let change_utxo = self.build_expected(
                from,
                from_keypair.signing_pubkey(),
                SOL_MINT,
                change,
                derive_blinding(&seed, SOL_CHANGE_POSITION),
                &indexed,
            )?;
            self.actor_mut(from).expected.push(change_utxo);
        }
        self.indexed.push(indexed);

        // Mark consumed inputs spent if they were decrypted (tracked) UTXOs.
        let nullifier_pk = from_keypair.nullifier_key.pubkey()?;
        for input in &inputs {
            let consumed_hash = input.hash(&nullifier_pk, &ZERO, &ZERO)?;
            if let Some(note) = self
                .actor_mut(from)
                .expected
                .iter_mut()
                .find(|n| n.output_context.hash == consumed_hash)
            {
                note.spent = true;
            }
        }

        // The withdrawn SOL is custodied in `sol_interface` and drained to the
        // external recipient: its on-chain balance grows by exactly `amount`.
        let recipient_after = self.rpc.client().get_balance(&recipient.pubkey())?;
        assert_eq!(
            recipient_after,
            recipient_before + amount,
            "withdrawal recipient credited with the unshielded amount"
        );

        Ok(sig)
    }
}

#[when(expr = "{word} withdraws {int} lamports of SOL")]
fn withdraws(world: &mut LifecycleWorld, name: String, amount: i64) {
    world.withdraw_sol(&name, amount as u64).expect("withdraw");
}
