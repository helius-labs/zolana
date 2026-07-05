//! Squads zone transfer steps routed through the backend.
//!
//! Sync: the suite deposits two vault UTXOs, reads them via the backend
//! `get_balances`, builds a `PrivateTransactionIntent` (the recipient output owned
//! by the recipient VKA), and calls `request_transact` on the smart-account rail
//! (`sender_owner_pubkey = None`). The backend re-derives the sender secrets via the
//! auditor key, fetches spend proofs, builds the paired zone + SPP proofs, and
//! returns the `transact` instruction with the relayer (the zone co-signer) as both
//! payer and co-signer; the suite sends it as a v0+ALT transaction signed by the
//! relayer.
//!
//! Async: `create_proposal` is client-built (encrypting the REAL blinding), then the
//! autonomous background crank discovers, decrypts, proves, and settles it. The
//! scenario waits for settlement (the crank closes the proposal PDA); balances are
//! asserted separately through the backend `get_balances`.

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use cucumber::when;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_keypair::{hash::poseidon, P256Pubkey};
use zolana_squads_client::{
    OutputUtxo, PrivateTransactionIntent, RequestTransactRequest, RequestTransactResponse,
    TransactionType, SOL_ASSET_ID,
};
use zolana_squads_interface::{
    instruction::{
        builders::CreateProposal, instruction_data::EncryptedUtxos, CreateProposalIxData,
    },
    types::Address as SquadsAddress,
    PROPOSAL_PDA_SEED, SQUADS_ZONE_PROGRAM_ID,
};
use zolana_squads_sdk::proposal::{build_proposal_ciphertext, proposal_hash};
use zolana_test_utils::smart_account::execute_sync_ix;
use zolana_transaction::{Address, SOL_MINT};

use crate::{
    deposit_action::random_blinding,
    fixture::{recipient_owner_field, TRANSFER_PROPOSAL_AMOUNT, VAULT_SENDER},
    localnet::{create_address_lookup_table, send_transaction, send_v0_transaction},
    world::SquadsLifecycleWorld,
};

/// A far-future expiry so scenarios never expire against the cluster clock.
const EXPIRY: i64 = i64::MAX;

/// A fresh 32-byte ephemeral scalar for the proposal ciphertext (top byte cleared).
fn random_ephemeral() -> [u8; 32] {
    let blinding = random_blinding();
    let mut eph = [0u8; 32];
    eph[1..].copy_from_slice(&blinding);
    eph
}

/// A zeroed `EncryptedUtxos`; the smart-account rail rebuilds the real ciphertexts
/// from the proof, so the intent's copy is unused.
pub(crate) fn placeholder_encrypted_utxos() -> EncryptedUtxos {
    EncryptedUtxos {
        tx_viewing_pk: [0u8; 33],
        sender_ciphertext: [0u8; 40],
        recipient_ciphertexts: vec![],
    }
}

impl SquadsLifecycleWorld {
    /// Sync `transact` transfer of SOL through the backend: the vault funds two zone
    /// UTXOs (`amount_a`, `amount_b`), the backend proves the `(2, 2)` spend routing
    /// `transferred` to `recipient` with the change returning to the vault.
    pub(crate) fn transfer_sol(
        &mut self,
        _sender: &str,
        transferred: u64,
        recipient: &str,
        amount_a: u64,
        amount_b: u64,
    ) -> Result<()> {
        // Value already parked in the vault before this transfer's own deposits; the
        // crank consolidates it together with the two fresh deposits into one UTXO.
        let existing = self.vault_sol_total()?;
        self.deposit_sol_input(amount_a)?;
        self.deposit_sol_input(amount_b)?;
        let funded = existing + amount_a + amount_b;
        // The crank auto-merges the vault balance into a single UTXO, so the transfer
        // settles from ONE merged input (1 real input + a prover-synthesized dummy,
        // keeping the (2, 2) shape) rather than two fragmented deposits.
        let merged = self.wait_for_consolidated(VAULT_SENDER, SOL_ASSET_ID, funded)?;

        let recipient_vka = self.viewing_key_account_address(recipient);
        let recipient_output = OutputUtxo {
            owner: Address::new_from_array(recipient_owner_field(recipient)),
            asset_id: SOL_ASSET_ID,
            amount: transferred,
            blinding: random_blinding(),
        };
        let intent = PrivateTransactionIntent {
            sender_viewing_key_account: self.viewing_key_account_address(VAULT_SENDER),
            inputs: vec![merged],
            outputs: vec![recipient_output],
            encrypted_utxos: placeholder_encrypted_utxos(),
            expiry: EXPIRY,
        };
        let response = self
            .backend
            .request_transact(RequestTransactRequest {
                transaction_type: TransactionType::Transfer {
                    recipient_viewing_key_account: recipient_vka,
                },
                intent,
                sender_owner_pubkey: None,
                sender_vault: Some(Address::new_from_array(self.proposer_vault.to_bytes())),
                owner_signature: None,
            })
            .map_err(|e| anyhow!("backend request_transact transfer: {e}"))?;
        let instruction = match response {
            RequestTransactResponse::Instruction(ix) => ix,
            RequestTransactResponse::Signature(_) => {
                return Err(anyhow!("smart-account transfer returned a signature"))
            }
        };
        self.send_execute_v0_alt(instruction)?;

        // Leave the vault settled at its change (one UTXO) so a follow-up transfer in
        // the same scenario reads an accurate starting balance, and so the settlement
        // is confirmed indexed before the step returns.
        let change = funded.saturating_sub(transferred);
        if change > 0 {
            self.wait_for_consolidated(VAULT_SENDER, SOL_ASSET_ID, change)?;
        }
        Ok(())
    }

    /// The vault sender's total spendable SOL across its current unspent UTXOs
    /// (auditor decrypt), used to anchor the post-merge consolidated amount when a
    /// scenario runs more than one transfer.
    fn vault_sol_total(&self) -> Result<u64> {
        Ok(self
            .backend_utxos(VAULT_SENDER, SOL_ASSET_ID)?
            .iter()
            .map(|utxo| utxo.amount)
            .sum())
    }

    /// Create the async transfer proposal (owned by the vault): fund two inputs and
    /// queue the proposal on-chain via `create_proposal` wrapped in
    /// `executeTransactionSyncV2`. The background crank settles it.
    pub(crate) fn create_transfer_proposal(
        &mut self,
        _sender: &str,
        transferred: u64,
        recipient: &str,
        amount_a: u64,
        amount_b: u64,
    ) -> Result<()> {
        if transferred != TRANSFER_PROPOSAL_AMOUNT {
            return Err(anyhow!(
                "transfer proposal amount {transferred} != fixture {TRANSFER_PROPOSAL_AMOUNT}"
            ));
        }
        self.deposit_sol_input(amount_a)?;
        self.deposit_sol_input(amount_b)?;
        // Let the crank consolidate the two deposits into one UTXO BEFORE the proposal
        // PDA exists: the crank refuses to merge an owner that has an open proposal
        // (its settlement would spend those inputs), so the merge must complete first.
        // The proposal then settles from the single merged input (1 real + dummy).
        self.wait_for_consolidated(VAULT_SENDER, SOL_ASSET_ID, amount_a + amount_b)?;

        let recipient_vka = self.viewing_key_account_address(recipient);
        let recipient_account = self
            .backend
            .load_viewing_key_account(recipient_vka)
            .map_err(|e| anyhow!("load recipient viewing key account: {e}"))?;
        let recipient_owner = recipient_owner_field(recipient);

        // The transfer proposal binds the recipient by owner_hash =
        // Poseidon(owner_pk_field, nullifier_pubkey) and encrypts (amount, blinding)
        // to the recipient's shared viewing key so the crank recovers them.
        let owner_hash = poseidon(&[
            recipient_owner.as_ref(),
            recipient_account.nullifier_pubkey.as_ref(),
        ])
        .map_err(|e| anyhow!("recipient owner hash: {e:?}"))?;
        let blinding = random_blinding();
        let hash = proposal_hash(transferred, &owner_hash, &blinding, 0)
            .map_err(|e| anyhow!("transfer proposal hash: {e}"))?;
        let cipher_recipient = P256Pubkey::from_bytes(recipient_account.shared_viewing_key)
            .map_err(|e| anyhow!("recipient shared key: {e:?}"))?;

        let proposal_address = self.queue_proposal(
            hash,
            SquadsAddress::new_from_array(recipient_owner),
            SquadsAddress::new_from_array(SOL_MINT.to_bytes()),
            &cipher_recipient,
            transferred,
            &blinding,
        )?;

        self.pending_proposal = Some(proposal_address);
        Ok(())
    }

    /// Create the proposal PDA on-chain: build the ciphertext, derive the PDA, and
    /// send `create_proposal` wrapped in `executeTransactionSyncV2`. Both the inner
    /// `fee_payer` and `owner` are the vault: Squads only grants signer privilege to
    /// the vault PDA in the wrapped CPI (never to the top-level members that sign the
    /// outer transaction), so the vault is the only account able to satisfy the
    /// program's `fee_payer`/`owner` signer checks and fund the proposal rent.
    /// Returns the proposal address.
    ///
    /// `blinding` is the 31-byte proposal blinding bound into `proposal_hash`; it is
    /// encrypted into the ciphertext so the auditor / crank recovers the exact value
    /// that re-derives the on-chain `proposal_hash`.
    pub(crate) fn queue_proposal(
        &mut self,
        proposal_hash: [u8; 32],
        recipient: SquadsAddress,
        asset: SquadsAddress,
        cipher_recipient: &P256Pubkey,
        cipher_amount: u64,
        blinding: &[u8; 31],
    ) -> Result<Pubkey> {
        let sender_vka =
            Pubkey::new_from_array(self.viewing_key_account_address(VAULT_SENDER).to_bytes());
        let ephemeral = random_ephemeral();
        let cipher_text =
            build_proposal_ciphertext(cipher_amount, blinding, cipher_recipient, &ephemeral)
                .map_err(|e| anyhow!("build proposal ciphertext: {e}"))?;

        let squads_program = Pubkey::new_from_array(SQUADS_ZONE_PROGRAM_ID);
        let cipher_seed = cipher_text
            .get(..32)
            .ok_or_else(|| anyhow!("proposal ciphertext too short"))?;
        let (proposal_address, _) = Pubkey::find_program_address(
            &[PROPOSAL_PDA_SEED, &self.owner_field, cipher_seed],
            &squads_program,
        );

        // Fund the vault so it can pay the proposal rent as the inner fee payer.
        self.rpc.airdrop(&self.proposer_vault, 1_000_000_000)?;

        let create_ix = CreateProposal {
            fee_payer: self.proposer_vault,
            proposal: proposal_address,
            viewing_key_account: sender_vka,
            system_program: Pubkey::default(),
            owner: self.proposer_vault,
            data: CreateProposalIxData {
                recipient,
                asset,
                proposal_hash,
                cipher_text,
                expiry: EXPIRY,
            },
        }
        .instruction();
        let ix = execute_sync_ix(
            &self.proposer_settings,
            0,
            &self.proposer_member_pubkeys(),
            &[create_ix],
        );

        let payer = self.payer.insecure_clone();
        let member = self.proposer_member.insecure_clone();
        let member_b = self.proposer_member_b.insecure_clone();
        send_transaction(
            &mut self.rpc,
            &[ix],
            &payer.pubkey(),
            &[&payer, &member, &member_b],
        )?;

        Ok(proposal_address)
    }

    /// Send `[budget, ix]` as a v0 transaction backed by an ALT, signed by the
    /// relayer (the backend sets the instruction's payer + co-signer to it) with the
    /// suite payer funding the transaction.
    pub(crate) fn send_execute_v0_alt(&mut self, ix: Instruction) -> Result<Signature> {
        let payer = self.payer.insecure_clone();
        let co_signer = self.co_signer.insecure_clone();
        let signer_pubkeys = [payer.pubkey(), co_signer.pubkey()];
        let signers: [&Keypair; 2] = [&payer, &co_signer];
        self.send_v0_with_alt(ix, &signer_pubkeys, &signers)
    }

    /// Build an ALT over every non-signer, non-program account of `[budget, ix]` and
    /// send it as a v0 transaction.
    fn send_v0_with_alt(
        &mut self,
        ix: Instruction,
        signer_pubkeys: &[Pubkey],
        signers: &[&Keypair],
    ) -> Result<Signature> {
        let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let payer = self.payer.insecure_clone();
        let ixs = [budget, ix];

        let signer_keys: HashSet<Pubkey> = signer_pubkeys.iter().copied().collect();
        let program_ids: HashSet<Pubkey> = ixs.iter().map(|i| i.program_id).collect();
        let mut seen: HashSet<Pubkey> = HashSet::new();
        let mut alt_addresses: Vec<Pubkey> = Vec::new();
        for instruction in &ixs {
            for meta in &instruction.accounts {
                if !signer_keys.contains(&meta.pubkey)
                    && !program_ids.contains(&meta.pubkey)
                    && seen.insert(meta.pubkey)
                {
                    alt_addresses.push(meta.pubkey);
                }
            }
        }

        let alt_account = create_address_lookup_table(&mut self.rpc, &payer, &alt_addresses)?;
        send_v0_transaction(&mut self.rpc, &ixs, &payer, signers, &[alt_account])
    }
}

#[when(expr = "{word} transfers {int} lamports of SOL to {word} funded by {int} and {int}")]
fn transfers_sol(
    world: &mut SquadsLifecycleWorld,
    sender: String,
    transferred: i64,
    recipient: String,
    amount_a: i64,
    amount_b: i64,
) {
    world
        .transfer_sol(
            &sender,
            transferred as u64,
            &recipient,
            amount_a as u64,
            amount_b as u64,
        )
        .expect("transfer SOL");
}

#[when(
    expr = "{word} creates a proposal to transfer {int} lamports of SOL to {word} funded by {int} and {int}"
)]
fn creates_transfer_proposal(
    world: &mut SquadsLifecycleWorld,
    sender: String,
    transferred: i64,
    recipient: String,
    amount_a: i64,
    amount_b: i64,
) {
    world
        .create_transfer_proposal(
            &sender,
            transferred as u64,
            &recipient,
            amount_a as u64,
            amount_b as u64,
        )
        .expect("create transfer proposal");
}

#[when(expr = "the crank settles the transfer proposal")]
fn crank_settles_transfer(world: &mut SquadsLifecycleWorld) {
    let address = world
        .pending_proposal
        .expect("no pending transfer proposal");
    world
        .wait_for_proposal_settled(address)
        .expect("crank settle transfer proposal");
}
