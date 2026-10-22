//! Squads ring transfers owned by the proposer vault.
//!
//! Sync: the vault funds two deposits, the crank merges them, and the backend
//! proves the transfer on the signatureless ring-authority rail. Async: the
//! vault queues a `create_proposal` binding the recipient, amount, and a
//! blinding encrypted to the recipient's shared viewing key; the crank
//! decrypts, proves, and settles it.

use anyhow::{anyhow, Result};
use cucumber::when;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use squads_ring_tests::localnet::{squads_program_id, SOL_ASSET_ID};
use zolana_keypair::{hash::poseidon, random_blinding, X25519Pubkey};
use zolana_squads_client::{
    OutputUtxo, PrivateTransactionIntent, RequestTransactRequest, RequestTransactResponse,
    TransactionType,
};
use zolana_squads_interface::{
    instruction::{builders::CreateProposal, CreateProposalIxData},
    PROPOSAL_PDA_SEED,
};
use zolana_squads_sdk::proposal::{build_proposal_ciphertext, proposal_hash};
use zolana_test_utils::smart_account::execute_sync_ix;
use zolana_transaction::{Address, SOL_MINT};

use crate::{
    fixture::{
        recipient_owner_identity, vault_owner_identity, viewing_key_account_address,
        TRANSFER_PROPOSAL_AMOUNT, VAULT_SENDER,
    },
    world::SquadsLifecycleWorld,
};

pub(crate) const EXPIRY: i64 = i64::MAX;

/// A 31-byte proposal blinding, right-aligned into a field element by the
/// proposal hash.
pub(crate) fn random_proposal_blinding() -> [u8; 31] {
    let mut blinding = [0u8; 31];
    if let Some(tail) = random_blinding().get(1..) {
        blinding.copy_from_slice(tail);
    }
    blinding
}

fn to_address(pubkey: &Pubkey) -> Address {
    Address::new_from_array(pubkey.to_bytes())
}

impl SquadsLifecycleWorld {
    pub(crate) fn request_instruction(
        &self,
        request: RequestTransactRequest,
    ) -> Result<Instruction> {
        match self
            .net
            .backend
            .request_transact(request)
            .map_err(|e| anyhow!("backend request_transact: {e}"))?
        {
            RequestTransactResponse::Instruction(ix) => Ok(ix),
            RequestTransactResponse::Signature(_) => {
                Err(anyhow!("smart-account spend returned a signature"))
            }
        }
    }

    fn vault_sol_total(&self) -> Result<u64> {
        Ok(self
            .net
            .utxos(viewing_key_account_address(VAULT_SENDER), SOL_ASSET_ID)?
            .iter()
            .map(|utxo| utxo.amount)
            .sum())
    }

    pub(crate) fn transfer_sol(
        &mut self,
        transferred: u64,
        recipient: &str,
        amount_a: u64,
        amount_b: u64,
    ) -> Result<()> {
        let existing = self.vault_sol_total()?;
        self.deposit_sol_input(amount_a)?;
        self.deposit_sol_input(amount_b)?;
        let funded = existing + amount_a + amount_b;
        let vault_vka = viewing_key_account_address(VAULT_SENDER);
        let merged = self
            .net
            .wait_for_consolidated(vault_vka, SOL_ASSET_ID, funded)?;
        let change = funded
            .checked_sub(transferred)
            .ok_or_else(|| anyhow!("transfer of {transferred} exceeds the funded {funded}"))?;

        let ix = self.request_instruction(RequestTransactRequest {
            transaction_type: TransactionType::Transfer {
                recipient_viewing_key_account: to_address(&viewing_key_account_address(recipient)),
            },
            intent: PrivateTransactionIntent {
                sender_viewing_key_account: to_address(&vault_vka),
                inputs: vec![merged],
                outputs: vec![OutputUtxo {
                    owner: Address::new_from_array(recipient_owner_identity(recipient)),
                    asset_id: SOL_ASSET_ID,
                    amount: transferred,
                }],
                expiry: EXPIRY,
            },
            sender_owner_pubkey: None,
            owner_signature: None,
        })?;
        self.net.send_backend_instruction(ix)?;
        if change > 0 {
            self.net
                .wait_for_consolidated(vault_vka, SOL_ASSET_ID, change)?;
        }
        Ok(())
    }

    pub(crate) fn create_transfer_proposal(
        &mut self,
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
        // The crank does not merge an owner with an open proposal, so the two
        // deposits are consolidated before the proposal is queued.
        self.net.wait_for_consolidated(
            viewing_key_account_address(VAULT_SENDER),
            SOL_ASSET_ID,
            amount_a + amount_b,
        )?;

        let recipient_account = self.load_viewing_key_account(recipient)?;
        let recipient_identity = recipient_owner_identity(recipient);
        let owner_hash = poseidon(&[
            recipient_identity.as_ref(),
            recipient_account.nullifier_pubkey.as_ref(),
        ])
        .map_err(|e| anyhow!("recipient owner hash: {e:?}"))?;
        let blinding = random_proposal_blinding();
        let hash = proposal_hash(transferred, &owner_hash, &blinding, 0)
            .map_err(|e| anyhow!("transfer proposal hash: {e}"))?;
        let cipher_recipient = X25519Pubkey::from_bytes(recipient_account.shared_viewing_key)
            .map_err(|e| anyhow!("recipient shared viewing key: {e:?}"))?;

        let proposal = self.queue_proposal(
            hash,
            Address::new_from_array(recipient_identity),
            &cipher_recipient,
            transferred,
            &blinding,
        )?;
        self.pending_proposal = Some(proposal);
        Ok(())
    }

    /// Create the proposal PDA through `executeTransactionSyncV2`. The vault is
    /// both the rent payer and the owner, the only accounts Squads grants
    /// signer privilege in the wrapped CPI.
    pub(crate) fn queue_proposal(
        &mut self,
        proposal_hash: [u8; 32],
        recipient: Address,
        cipher_recipient: &X25519Pubkey,
        cipher_amount: u64,
        blinding: &[u8; 31],
    ) -> Result<Pubkey> {
        let ephemeral = random_blinding();
        let cipher_text =
            build_proposal_ciphertext(cipher_amount, blinding, cipher_recipient, &ephemeral)
                .map_err(|e| anyhow!("build proposal ciphertext: {e}"))?;
        let cipher_seed = cipher_text
            .get(..32)
            .ok_or_else(|| anyhow!("proposal ciphertext too short"))?;
        let (proposal, _) = Pubkey::find_program_address(
            &[PROPOSAL_PDA_SEED, &vault_owner_identity(), cipher_seed],
            &squads_program_id(),
        );

        self.net
            .base
            .rpc
            .airdrop(&self.proposer_vault, 1_000_000_000)?;
        let create = CreateProposal {
            fee_payer: self.proposer_vault,
            proposal,
            viewing_key_account: viewing_key_account_address(VAULT_SENDER),
            system_program: Pubkey::default(),
            owner: self.proposer_vault,
            data: CreateProposalIxData {
                recipient,
                asset: SOL_MINT,
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
            &[create],
        );
        self.send_as_proposer(&[ix])?;
        Ok(proposal)
    }
}

#[when(expr = "{word} transfers {int} lamports of SOL to {word} funded by {int} and {int}")]
fn transfers_sol(
    world: &mut SquadsLifecycleWorld,
    _sender: String,
    transferred: u64,
    recipient: String,
    amount_a: u64,
    amount_b: u64,
) {
    world
        .transfer_sol(transferred, &recipient, amount_a, amount_b)
        .expect("transfer SOL");
}

#[when(
    expr = "{word} creates a proposal to transfer {int} lamports of SOL to {word} funded by {int} and {int}"
)]
fn creates_transfer_proposal(
    world: &mut SquadsLifecycleWorld,
    _sender: String,
    transferred: u64,
    recipient: String,
    amount_a: u64,
    amount_b: u64,
) {
    world
        .create_transfer_proposal(transferred, &recipient, amount_a, amount_b)
        .expect("create transfer proposal");
}

#[when(expr = "the crank settles the transfer proposal")]
fn crank_settles_transfer(world: &mut SquadsLifecycleWorld) {
    let proposal = world
        .pending_proposal
        .expect("no pending transfer proposal");
    world
        .net
        .wait_for_closed(proposal)
        .expect("crank settles the transfer proposal");
}
