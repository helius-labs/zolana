//! `withdraw` (unshield) helpers and the Harness withdrawal operation. A withdrawal
//! spends the sender's SOL UTXOs and moves the public SOL amount out of the pool
//! to an external recipient account, keeping a SOL change UTXO for the sender.
//! Mirrors `execute_transfer` except it calls `transfer.withdraw(..)` instead of
//! `transfer.send(..)` and adds a SOL interface transfer to the `Transact` builder, so
//! the builder appends the `sol_interface` custody PDA and the recipient account.

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{assemble, ComputeBudgetConfig, ProverClient, SpendProof};
use zolana_program::instruction::{
    Transact, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
};
use zolana_transaction::instructions::transact::ConfidentialTransaction;
use zolana_transaction::{SppProofOutputUtxo, Utxo, SOL_MINT};

use super::LifecycleHarness;
use crate::{
    localnet::send_transaction_with_budget,
    test_validator_asserts::{
        wait_for_indexed_transaction, wait_for_merkle_proof, wait_for_non_inclusion_proof,
    },
};

impl LifecycleHarness {
    /// Withdraw `amount` lamports of SOL from `from` to a fresh external recipient
    /// account, spending two of `from`'s spendable SOL UTXOs (the 2x2 shape). The chosen inputs must total more than `amount` so a SOL change UTXO
    /// is emitted back to the sender. Mirrors `execute_transfer`, but the public SOL
    /// leaves the pool to `recipient` and there is no recipient UTXO.
    pub fn withdraw_sol(&mut self, from: &str, amount: u64) -> Result<Signature> {
        self.ensure_fresh_actor(from)?;

        // Pick two spendable SOL UTXOs (the 2x2 shape); their total must exceed
        // `amount` so there is SOL change to track.
        let inputs: Vec<Utxo> = {
            let actor = self.actor_mut(from);
            let mut taken = Vec::new();
            for _ in 0..2 {
                let pos = actor
                    .spendable
                    .iter()
                    .position(|u| u.asset.asset == SOL_MINT)
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
        // 0 / the fee payer).
        let fee_payer = self
            .actor(from)
            .solana_signer
            .as_ref()
            .expect("lifecycle actors are eddsa-owned")
            .insecure_clone();
        let payer_address = Address::new_from_array(fee_payer.pubkey().to_bytes());
        let sender_view_tag = from_keypair.signing_pubkey().confidential_view_tag()?;

        let nullifier_pk = from_keypair.nullifier_key.pubkey()?;
        let hashes = inputs
            .iter()
            .map(|utxo| utxo.hash(&nullifier_pk, &[0; 32], &[0; 32], self.tree_id))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let states = crate::test_validator_asserts::wait_for_merkle_proofs(
            &self.indexer,
            self.tree_address,
            &hashes,
        );
        let indexed_inputs = inputs
            .iter()
            .zip(&states)
            .map(|(utxo, state)| {
                crate::utxo::wallet(
                    utxo.clone(),
                    &from_keypair.nullifier_key,
                    self.tree_id,
                    state.leaf_index,
                    None,
                    None,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let mut transfer = ConfidentialTransaction::new(indexed_inputs, payer_address)?;
        transfer.withdraw_sol(amount, recipient.pubkey())?;
        let proof_inputs = transfer.encrypt(&from_keypair)?;
        let finalized_outputs = proof_inputs.output_utxos.clone();

        let commitments = proof_inputs.input_utxo_hashes()?;
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
        // The circuit checks non-inclusion for every slot, so each padding dummy
        // needs a real low-element witness for its own nullifier.
        let dummy_proofs: Vec<_> = proof_inputs
            .dummy_nullifiers()
            .into_iter()
            .map(|nullifier| {
                wait_for_non_inclusion_proof(&self.indexer, self.tree_address, nullifier)
            })
            .collect();

        let mut assembled = assemble(proof_inputs, &spend_proofs, &dummy_proofs)?;
        let proof = assembled.prove(&ProverClient::local(), &from_keypair.nullifier_key)?;
        let ix_data = assembled.with_proof(proof);

        let withdraw_ix = Transact {
            payer: fee_payer.pubkey(),
            input_trees: vec![self.tree],
            output_tree: self.tree,
            owner_signers: Vec::new(),
            interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts {
                    recipient: recipient.pubkey(),
                },
            )],
            data: ix_data,
        }
        .instruction();
        let sig = send_transaction_with_budget(
            &mut self.rpc,
            std::slice::from_ref(&withdraw_ix),
            &fee_payer.pubkey(),
            &[&fee_payer],
            ComputeBudgetConfig::new(1_400_000),
        )?;
        self.last_transact = Some((sig, withdraw_ix));

        // The withdrawal has no recipient slot, so locate the indexed transaction by
        // the sender's view tag. Decode the committed change blinding from the
        // sender side: the expected set is rebuilt independently from the on-chain
        // ciphertext (not from `Wallet::sync`) so `assert_utxos` is a real
        // cross-check of the synced wallet.
        let indexed = wait_for_indexed_transaction(&self.indexer, sender_view_tag, sig);

        assert_eq!(indexed.output_slots.len(), finalized_outputs.len());
        let (change, dummies) = finalized_outputs
            .split_first()
            .ok_or_else(|| anyhow!("withdrawal without a change slot"))?;
        assert!(dummies.iter().all(SppProofOutputUtxo::is_dummy));
        let change_amount = input_sum - amount;
        assert_eq!(
            (change.asset.asset, change.amount),
            (SOL_MINT, change_amount)
        );
        let note = self.build_expected(
            from,
            from_keypair.signing_pubkey(),
            SOL_MINT,
            change_amount,
            super::transfer::decode_output_blinding(&from_keypair.viewing_key, &indexed, 0)?,
            &indexed,
        )?;
        self.actor_mut(from).expected.push(note);
        self.indexed.push(indexed);

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
