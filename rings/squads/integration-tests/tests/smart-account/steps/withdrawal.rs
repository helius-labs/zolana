//! Squads ring withdrawals owned by the proposer vault.
//!
//! Sync: the backend proves the `(1, 1)` spend on the signatureless
//! ring-authority rail. Async (SOL): the vault queues a withdrawal proposal
//! whose amount and blinding are encrypted to its own shared viewing key; the
//! crank settles it to the vault, the proposal's rent payer.

use anyhow::{anyhow, Result};
use cucumber::{then, when};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_ring_tests::{
    asserts::{assert_squads_withdrawal, SquadsWithdrawalAssertArgs, SquadsWithdrawalSettlement},
    localnet::{SOL_ASSET_ID, SPL_ASSET_ID},
};
use zolana_interface::pda;
use zolana_keypair::{NullifierKey, X25519Pubkey};
use zolana_squads_client::{
    tags::account_view_tag, DecryptedUtxo, PrivateTransactionIntent, RequestTransactRequest,
    TransactionType,
};
use zolana_squads_sdk::proposal::proposal_hash;
use zolana_test_utils::{
    spl::create_token_account,
    test_validator_asserts::{fetch_account, fetch_optional_account},
};

use crate::{
    fixture::{viewing_key_account_address, PROPOSAL_WITHDRAWN, VAULT_SENDER},
    steps::transfer::{random_proposal_blinding, EXPIRY},
    world::{SquadsLifecycleWorld, WithdrawalRecord, WithdrawalSettlement},
};

fn change_after(input: &DecryptedUtxo, withdrawn: u64) -> Result<u64> {
    input.amount.checked_sub(withdrawn).ok_or_else(|| {
        anyhow!(
            "withdrawal of {withdrawn} exceeds the {} input",
            input.amount
        )
    })
}

impl SquadsLifecycleWorld {
    fn single_vault_input(&self, asset_id: u64) -> Result<DecryptedUtxo> {
        let utxos =
            self.net
                .wait_for_utxos(viewing_key_account_address(VAULT_SENDER), asset_id, 1)?;
        match utxos.as_slice() {
            [utxo] => Ok(*utxo),
            other => Err(anyhow!(
                "the vault holds {} UTXOs of asset {asset_id}, a withdrawal spends one",
                other.len()
            )),
        }
    }

    fn vault_input_nullifier(&self, input: &DecryptedUtxo) -> Result<[u8; 32]> {
        let resolved = self
            .net
            .backend
            .resolve_shared_key(Address::new_from_array(
                viewing_key_account_address(VAULT_SENDER).to_bytes(),
            ))
            .map_err(|e| anyhow!("resolve the vault's shared key: {e}"))?;
        NullifierKey::from_secret(resolved.nullifier_secret)
            .nullifier(&input.utxo_hash, &input.blinding)
            .map_err(|e| anyhow!("input nullifier: {e:?}"))
    }

    fn withdrawal_instruction(
        &self,
        input: DecryptedUtxo,
        withdrawn: u64,
        recipient_account: Pubkey,
    ) -> Result<solana_instruction::Instruction> {
        self.request_instruction(RequestTransactRequest {
            transaction_type: TransactionType::Withdraw {
                public_amount: withdrawn,
                recipient_account: Address::new_from_array(recipient_account.to_bytes()),
            },
            intent: PrivateTransactionIntent {
                sender_viewing_key_account: Address::new_from_array(
                    viewing_key_account_address(VAULT_SENDER).to_bytes(),
                ),
                inputs: vec![input],
                outputs: Vec::new(),
                expiry: EXPIRY,
            },
            sender_owner_pubkey: None,
            owner_signature: None,
        })
    }

    pub(crate) fn withdraw_sol(&mut self, name: &str, withdrawn: u64) -> Result<()> {
        let input = self.single_vault_input(SOL_ASSET_ID)?;
        let nullifier = self.vault_input_nullifier(&input)?;
        let recipient = Keypair::new().pubkey();
        let sol_interface = pda::sol_interface();
        let ix = self.withdrawal_instruction(input, withdrawn, recipient)?;

        let rpc = &self.net.base.rpc;
        let tree_before = fetch_account(rpc, &self.net.base.tree)?;
        let sol_interface_before = fetch_account(rpc, &sol_interface)?;
        let recipient_before = fetch_optional_account(rpc, &recipient)?.unwrap_or_default();
        let signature = self.net.send_backend_instruction(ix)?;
        self.withdrawals.insert(
            name.to_string(),
            WithdrawalRecord {
                signature,
                asset_id: SOL_ASSET_ID,
                withdrawn,
                change: change_after(&input, withdrawn)?,
                nullifier,
                tree_before,
                settlement: WithdrawalSettlement::Sol {
                    sol_interface,
                    sol_interface_before,
                    recipient,
                    recipient_before,
                },
            },
        );
        Ok(())
    }

    pub(crate) fn withdraw_spl(&mut self, name: &str, withdrawn: u64) -> Result<()> {
        let spl = self.net.ensure_spl_asset()?;
        let input = self.single_vault_input(SPL_ASSET_ID)?;
        let nullifier = self.vault_input_nullifier(&input)?;
        let payer = self.net.payer();
        let recipient_token = create_token_account(
            &self.net.base.rpc,
            &payer,
            &spl.mint,
            &Keypair::new().pubkey(),
        )?;
        let ix = self.withdrawal_instruction(input, withdrawn, recipient_token)?;

        let rpc = &self.net.base.rpc;
        let tree_before = fetch_account(rpc, &self.net.base.tree)?;
        let vault_before = fetch_account(rpc, &spl.vault)?;
        let recipient_token_before = fetch_account(rpc, &recipient_token)?;
        let signature = self.net.send_backend_instruction(ix)?;
        self.withdrawals.insert(
            name.to_string(),
            WithdrawalRecord {
                signature,
                asset_id: SPL_ASSET_ID,
                withdrawn,
                change: change_after(&input, withdrawn)?,
                nullifier,
                tree_before,
                settlement: WithdrawalSettlement::Spl {
                    vault: spl.vault,
                    vault_before,
                    recipient_token,
                    recipient_token_before,
                },
            },
        );
        Ok(())
    }

    pub(crate) fn create_withdrawal_proposal(&mut self) -> Result<()> {
        self.single_vault_input(SOL_ASSET_ID)?;
        let sender_account = self.load_viewing_key_account(VAULT_SENDER)?;
        let cipher_recipient = X25519Pubkey::from_bytes(sender_account.shared_viewing_key)
            .map_err(|e| anyhow!("vault shared viewing key: {e:?}"))?;
        let blinding = random_proposal_blinding();
        let hash = proposal_hash(0, &[0u8; 32], &blinding, PROPOSAL_WITHDRAWN)
            .map_err(|e| anyhow!("withdrawal proposal hash: {e}"))?;
        let proposal = self.queue_proposal(
            hash,
            Address::default(),
            &cipher_recipient,
            PROPOSAL_WITHDRAWN,
            &blinding,
        )?;
        self.pending_proposal = Some(proposal);
        Ok(())
    }

    pub(crate) fn assert_withdrew(&self, name: &str, withdrawn: u64) -> Result<()> {
        let record = self
            .withdrawals
            .get(name)
            .ok_or_else(|| anyhow!("{name} has no recorded withdrawal"))?;
        if record.withdrawn != withdrawn {
            return Err(anyhow!(
                "recorded withdrawal of {} does not match asserted {withdrawn}",
                record.withdrawn
            ));
        }
        let change = self.net.wait_for_consolidated(
            viewing_key_account_address(VAULT_SENDER),
            record.asset_id,
            record.change,
        )?;
        let settlement = match &record.settlement {
            WithdrawalSettlement::Sol {
                sol_interface,
                sol_interface_before,
                recipient,
                recipient_before,
            } => SquadsWithdrawalSettlement::Sol {
                sol_interface,
                sol_interface_before,
                recipient,
                recipient_before,
            },
            WithdrawalSettlement::Spl {
                vault,
                vault_before,
                recipient_token,
                recipient_token_before,
            } => SquadsWithdrawalSettlement::Spl {
                vault,
                vault_before,
                recipient_token,
                recipient_token_before,
            },
        };
        assert_squads_withdrawal(
            &self.net.base.rpc,
            &self.net.base.indexer,
            SquadsWithdrawalAssertArgs {
                tree: &self.net.base.tree,
                withdrawn,
                change_utxo_hash: change.utxo_hash,
                nullifier: record.nullifier,
                sender_view_tag: account_view_tag(&self.load_viewing_key_account(VAULT_SENDER)?),
                signature: record.signature,
                tree_before: &record.tree_before,
                settlement,
            },
        )?;
        Ok(())
    }
}

#[when(expr = "{word} withdraws {int} lamports of SOL")]
fn withdraws_sol(world: &mut SquadsLifecycleWorld, name: String, amount: u64) {
    world.withdraw_sol(&name, amount).expect("withdraw SOL");
}

#[then(expr = "{word} received {int} lamports of SOL from the pool")]
fn received_sol(world: &mut SquadsLifecycleWorld, name: String, amount: u64) {
    world
        .assert_withdrew(&name, amount)
        .expect("assert SOL withdrawal");
}

#[when(expr = "{word} withdraws {int} tokens")]
fn withdraws_tokens(world: &mut SquadsLifecycleWorld, name: String, amount: u64) {
    world.withdraw_spl(&name, amount).expect("withdraw tokens");
}

#[then(expr = "{word} received {int} tokens from the pool")]
fn received_tokens(world: &mut SquadsLifecycleWorld, name: String, amount: u64) {
    world
        .assert_withdrew(&name, amount)
        .expect("assert token withdrawal");
}

#[when(expr = "{word} creates a SOL withdrawal proposal")]
fn creates_sol_proposal(world: &mut SquadsLifecycleWorld, _name: String) {
    world
        .create_withdrawal_proposal()
        .expect("create SOL withdrawal proposal");
}

#[when(expr = "the crank settles the withdrawal proposal")]
fn crank_settles_withdrawal(world: &mut SquadsLifecycleWorld) {
    let proposal = world
        .pending_proposal
        .expect("no pending withdrawal proposal");
    world
        .net
        .wait_for_closed(proposal)
        .expect("crank settles the withdrawal proposal");
}
