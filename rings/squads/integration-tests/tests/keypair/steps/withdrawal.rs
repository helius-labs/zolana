//! Squads ring withdrawals on the Ed25519 keypair rail. The backend probes the
//! spend for its transaction message digest, the owner signs that digest,
//! and the backend proves both legs and returns the `transact` instruction,
//! which its relayer pays for and co-signs.

use anyhow::{anyhow, Result};
use cucumber::{then, when};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use squads_ring_tests::{
    asserts::{assert_squads_withdrawal, SquadsWithdrawalAssertArgs, SquadsWithdrawalSettlement},
    localnet::{SOL_ASSET_ID, SPL_ASSET_ID},
};
use zolana_interface::pda;
use zolana_keypair::NullifierKey;
use zolana_squads_client::{
    tags::account_view_tag, DecryptedUtxo, PrivateTransactionIntent, RequestTransactRequest,
    RequestTransactResponse, TransactionType,
};
use zolana_test_utils::{
    spl::create_token_account,
    test_validator_asserts::{fetch_account, fetch_optional_account},
};

use crate::{
    fixture::{owner_keypair, viewing_key_account_address},
    world::{SquadsLifecycleWorld, WithdrawalRecord, WithdrawalSettlement},
};

pub(crate) const EXPIRY: i64 = i64::MAX;

fn change_after(input: &DecryptedUtxo, withdrawn: u64) -> Result<u64> {
    input.amount.checked_sub(withdrawn).ok_or_else(|| {
        anyhow!(
            "withdrawal of {withdrawn} exceeds the {} input",
            input.amount
        )
    })
}

impl SquadsLifecycleWorld {
    /// The keypair rail: probe, sign the transaction message digest with the owner
    /// key, finalize.
    pub(crate) fn ed25519_transact(
        &self,
        signer_name: &str,
        mut request: RequestTransactRequest,
    ) -> Result<Instruction> {
        let message_hash = self
            .net
            .backend
            .request_transact_probe(&request)
            .map_err(|e| anyhow!("request_transact probe: {e}"))?;
        let signature = owner_keypair(signer_name)
            .signing_key()
            .sign_message(&message_hash)
            .map_err(|e| anyhow!("sign transaction message hash: {e:?}"))?;
        request.owner_signature = Some(signature);
        match self
            .net
            .backend
            .request_transact(request)
            .map_err(|e| anyhow!("request_transact finalize: {e}"))?
        {
            RequestTransactResponse::Instruction(ix) => Ok(ix),
            RequestTransactResponse::Signature(_) => Err(anyhow!(
                "backend unexpectedly sent the transact transaction"
            )),
        }
    }

    fn single_input(&self, name: &str, asset_id: u64) -> Result<DecryptedUtxo> {
        let utxos = self
            .net
            .wait_for_utxos(viewing_key_account_address(name), asset_id, 1)?;
        match utxos.as_slice() {
            [utxo] => Ok(*utxo),
            other => Err(anyhow!(
                "{name} holds {} UTXOs of asset {asset_id}, a withdrawal spends one",
                other.len()
            )),
        }
    }

    fn input_nullifier(&self, name: &str, input: &DecryptedUtxo) -> Result<[u8; 32]> {
        let resolved = self
            .net
            .backend
            .resolve_shared_key(Address::new_from_array(
                viewing_key_account_address(name).to_bytes(),
            ))
            .map_err(|e| anyhow!("resolve {name}'s shared key: {e}"))?;
        NullifierKey::from_secret(resolved.nullifier_secret)
            .nullifier(&input.utxo_hash, &input.blinding)
            .map_err(|e| anyhow!("input nullifier: {e:?}"))
    }

    fn withdrawal_request(
        &self,
        name: &str,
        input: DecryptedUtxo,
        withdrawn: u64,
        recipient_account: Pubkey,
    ) -> RequestTransactRequest {
        RequestTransactRequest {
            transaction_type: TransactionType::Withdraw {
                public_amount: withdrawn,
                recipient_account: Address::new_from_array(recipient_account.to_bytes()),
            },
            intent: PrivateTransactionIntent {
                sender_viewing_key_account: Address::new_from_array(
                    viewing_key_account_address(name).to_bytes(),
                ),
                inputs: vec![input],
                outputs: Vec::new(),
                expiry: EXPIRY,
            },
            sender_owner_pubkey: Some(owner_keypair(name).owner_pubkey_bytes()),
            owner_signature: None,
        }
    }

    pub(crate) fn withdraw_sol(&mut self, name: &str, withdrawn: u64) -> Result<()> {
        let input = self.single_input(name, SOL_ASSET_ID)?;
        let nullifier = self.input_nullifier(name, &input)?;
        let recipient = Keypair::new().pubkey();
        let sol_interface = pda::sol_interface();
        let ix = self.ed25519_transact(
            name,
            self.withdrawal_request(name, input, withdrawn, recipient),
        )?;

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
        let input = self.single_input(name, SPL_ASSET_ID)?;
        let nullifier = self.input_nullifier(name, &input)?;
        let payer = self.net.payer();
        let recipient_token = create_token_account(
            &self.net.base.rpc,
            &payer,
            &spl.mint,
            &Keypair::new().pubkey(),
        )?;
        let ix = self.ed25519_transact(
            name,
            self.withdrawal_request(name, input, withdrawn, recipient_token),
        )?;

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
        let vka = viewing_key_account_address(name);
        let change = self
            .net
            .wait_for_consolidated(vka, record.asset_id, record.change)?;
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
                sender_view_tag: account_view_tag(&self.load_viewing_key_account(name)?),
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
