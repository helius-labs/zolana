use anyhow::{anyhow, Result};
use borsh::BorshDeserialize;
use solana_address::Address;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{ComputeBudgetConfig, Rpc};
use zolana_event::OutputDataEncoding;
use zolana_interface::{instruction::TransactIxData, pda};
use zolana_keypair::{constants::P256_PUBKEY_LEN, NullifierKey, P256Pubkey, ShieldedAddress};
use zolana_program::instruction::Transact;
use zolana_program_test::localnet::FixtureLocalnet;
use zolana_test_utils::{
    utxo::{
        encrypt_transaction_data, get_transaction_viewing_key, prepare_output_blindings, ProofKeys,
    },
    wallet::{
        create_withdrawal, sign_private_transaction_sync, Filter, KeypairWalletAuthority,
        WithdrawalLeg, WithdrawalParams,
    },
};
use zolana_transaction::{
    instructions::transact::{ExternalData, SppProofInputs},
    serialization::confidential::{Confidential, ConfidentialOutputPlaintext},
    utxo::SppProofInputUtxo,
    EncryptedScheme, SppProofOutputUtxo, WalletUtxo,
};

use crate::{
    kvault::{self, token_balance, UserAccounts, VaultAccounts, VaultState},
    shared::{send, TestWallet},
};

const FULL_BPS: u64 = 10_000;
const TRANSACT_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SwapError {
    #[error(
        "the market maker's largest {asset} utxo holds {available}, the fill needs {required}"
    )]
    InsufficientInventory {
        asset: Address,
        required: u64,
        available: u64,
    },
    #[error("the user has no {asset} utxo covering {required}")]
    InsufficientFunds { asset: Address, required: u64 },
    #[error("the swap carries {count} interface transfers")]
    PublicTransfer { count: usize },
    #[error("the swap spends {spent} of the user's utxos, the order offers exactly one")]
    UnexpectedInputs { spent: usize },
    #[error("output {slot} does not open to its commitment")]
    CommitmentMismatch { slot: usize },
    #[error("the user receives {received} {asset} change, expected {expected}")]
    WrongChange {
        asset: Address,
        expected: u64,
        received: u64,
    },
    #[error("the fill pays {offered}, the vault rate minus the fee pays {expected}")]
    BelowRate { expected: u64, offered: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Deposit,
    Exit,
}

impl Direction {
    pub fn assets(self, vault: &VaultAccounts) -> (Address, Address) {
        match self {
            Self::Deposit => (vault.token_mint, vault.shares_mint),
            Self::Exit => (vault.shares_mint, vault.token_mint),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quote {
    pub direction: Direction,
    pub amount_in: u64,
    pub amount_out: u64,
}

impl Quote {
    pub fn price(
        rate: &VaultState,
        direction: Direction,
        amount_in: u64,
        fee_bps: u64,
    ) -> Result<Self> {
        let gross = match direction {
            Direction::Deposit => rate.deposit(amount_in)?.shares,
            Direction::Exit => rate.withdraw(amount_in)?.tokens,
        };
        let amount_out = u64::try_from(
            u128::from(gross) * u128::from(FULL_BPS.saturating_sub(fee_bps)) / u128::from(FULL_BPS),
        )?;
        Ok(Self {
            direction,
            amount_in,
            amount_out,
        })
    }
}

pub struct Order {
    pub quote: Quote,
    pub input: WalletUtxo,
    pub owner: ShieldedAddress,
}

pub struct Fill {
    pub data: TransactIxData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultOperation {
    pub before: VaultState,
    pub after: VaultState,
    pub tokens: u64,
    pub shares: u64,
}

impl TestWallet {
    pub fn order(&self, vault: &VaultAccounts, quote: Quote) -> Result<Order> {
        let (asset_in, _) = quote.direction.assets(vault);
        let input = self
            .balance(asset_in, Some(Filter::MinAmount(quote.amount_in)))?
            .utxos
            .first()
            .cloned()
            .ok_or(SwapError::InsufficientFunds {
                asset: asset_in,
                required: quote.amount_in,
            })?;
        Ok(Order {
            quote,
            input,
            owner: self.identity,
        })
    }

    pub fn verify_quote(
        &self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        order: &Order,
        fill: &Fill,
        fee_bps: u64,
    ) -> Result<()> {
        if !fill.data.interface_transfers.is_empty() {
            return Err(SwapError::PublicTransfer {
                count: fill.data.interface_transfers.len(),
            }
            .into());
        }
        let spent: Vec<[u8; 32]> = fill
            .data
            .inputs
            .iter()
            .map(|input| input.nullifier_hash)
            .filter(|nullifier| self.unspent().any(|utxo| utxo.nullifier == *nullifier))
            .collect();
        if spent != [order.input.nullifier] {
            return Err(SwapError::UnexpectedInputs { spent: spent.len() }.into());
        }
        let rate = VaultState::read(localnet.client.rpc(), &vault.vault)?;
        let expected = Quote::price(&rate, order.quote.direction, order.quote.amount_in, fee_bps)?;
        let (asset_in, asset_out) = order.quote.direction.assets(vault);
        let mut received_in = 0u64;
        let mut received_out = 0u64;
        for (slot, output) in fill.data.outputs.iter().enumerate() {
            let Some(plaintext) = self.decrypt_output(output.data.as_deref(), fill, slot)? else {
                continue;
            };
            let utxo = plaintext.into_utxo(self.identity.signing_pubkey, &self.registry)?;
            let hash = utxo.hash(
                &self.identity.nullifier_pubkey,
                &[0; 32],
                &[0; 32],
                localnet.tree_id,
            )?;
            if hash != output.utxo_hash {
                return Err(SwapError::CommitmentMismatch { slot }.into());
            }
            if utxo.asset.asset == asset_in {
                received_in += utxo.amount;
            } else if utxo.asset.asset == asset_out {
                received_out += utxo.amount;
            }
        }
        let expected_change = order.input.utxo.amount - order.quote.amount_in;
        if received_in != expected_change {
            return Err(SwapError::WrongChange {
                asset: asset_in,
                expected: expected_change,
                received: received_in,
            }
            .into());
        }
        if received_out < expected.amount_out {
            return Err(SwapError::BelowRate {
                expected: expected.amount_out,
                offered: received_out,
            }
            .into());
        }
        Ok(())
    }

    fn decrypt_output(
        &self,
        data: Option<&[u8]>,
        fill: &Fill,
        slot: usize,
    ) -> Result<Option<ConfidentialOutputPlaintext>> {
        let Some(data) = data else {
            return Ok(None);
        };
        let OutputDataEncoding::Encrypted(blob) = OutputDataEncoding::try_from_slice(data)? else {
            return Ok(None);
        };
        let Some((&scheme, body)) = blob.split_first() else {
            return Ok(None);
        };
        if scheme != EncryptedScheme::Confidential.as_byte()
            || Confidential::embedded_viewing_pk(body)? != self.identity.viewing_pubkey
        {
            return Ok(None);
        }
        let ciphertext = body
            .get(P256_PUBKEY_LEN..)
            .ok_or_else(|| anyhow!("output {slot} ciphertext is truncated"))?;
        let bytes = self.keypair.decrypt_utxo(
            ciphertext,
            &P256Pubkey::from_bytes(fill.data.tx_viewing_pk)?,
            fill.data.salt,
            u32::try_from(slot)?,
        )?;
        Ok(Some(ConfidentialOutputPlaintext::deserialize(&bytes)?))
    }
}

pub struct MarketMaker {
    pub trader: TestWallet,
    pub fee_bps: u64,
}

impl MarketMaker {
    pub fn quote(
        &self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        direction: Direction,
        amount_in: u64,
    ) -> Result<Quote> {
        let rate = VaultState::read(localnet.client.rpc(), &vault.vault)?;
        Quote::price(&rate, direction, amount_in, self.fee_bps)
    }

    pub fn fill(
        &self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        order: &Order,
        user_nullifier_key: &NullifierKey,
    ) -> Result<Fill> {
        let quote = order.quote;
        let (asset_in, asset_out) = quote.direction.assets(vault);
        let inventory = self.trader.balance(asset_out, None)?;
        let maker_input = inventory
            .utxos
            .iter()
            .max_by_key(|utxo| utxo.utxo.amount)
            .filter(|utxo| utxo.utxo.amount >= quote.amount_out)
            .cloned()
            .ok_or_else(|| SwapError::InsufficientInventory {
                asset: asset_out,
                required: quote.amount_out,
                available: inventory
                    .utxos
                    .iter()
                    .map(|utxo| utxo.utxo.amount)
                    .max()
                    .unwrap_or_default(),
            })?;
        let user_address = order.owner;
        let maker_address = self.trader.identity;
        let registry = &self.trader.registry;
        let inputs = vec![
            SppProofInputUtxo::from(maker_input.clone()),
            SppProofInputUtxo::from(order.input.clone()),
        ];
        let mut outputs = vec![
            SppProofOutputUtxo::new(registry.mint(&asset_out)?, quote.amount_out, user_address)?,
            SppProofOutputUtxo::new(registry.mint(&asset_in)?, quote.amount_in, maker_address)?,
            SppProofOutputUtxo::new(
                registry.mint(&asset_in)?,
                order.input.utxo.amount - quote.amount_in,
                user_address,
            )?,
            SppProofOutputUtxo::new(
                registry.mint(&asset_out)?,
                maker_input.utxo.amount - quote.amount_out,
                maker_address,
            )?,
        ];
        let blinding_seed = prepare_output_blindings(&inputs, &mut outputs)?;
        let transaction_viewing_key = get_transaction_viewing_key(&self.trader.keypair, &inputs)
            .map_err(|e| anyhow!("transaction viewing key: {e:?}"))?;
        let encoded =
            encrypt_transaction_data(&outputs, &transaction_viewing_key, localnet.tree_id)?;
        let proof_inputs = SppProofInputs {
            input_utxos: inputs,
            output_utxos: encoded.output_utxos,
            external_data: ExternalData::new(
                *transaction_viewing_key.pubkey().as_bytes(),
                encoded.salt,
                encoded.outputs,
                encoded.resolved_owner_tags,
                vec![],
            ),
            payer: self.trader.address(),
            blinding_seed,
            output_tree_id: localnet.tree_id,
            cache_accounts: Default::default(),
        };
        let data = localnet
            .client
            .prove_transact(
                proof_inputs,
                None,
                &ProofKeys(&[&self.trader.keypair.nullifier_key, user_nullifier_key]),
            )
            .map_err(|e| anyhow!("prove swap: {e:?}"))?;
        Ok(Fill { data })
    }

    pub fn settle(
        &self,
        localnet: &FixtureLocalnet,
        fill: Fill,
        user: &dyn Signer,
    ) -> Result<Signature> {
        let ix = Transact {
            payer: self.trader.address(),
            input_trees: vec![localnet.tree],
            output_tree: localnet.tree,
            owner_signers: vec![user.pubkey()],
            interface_transfer_accounts: Vec::new(),
            data: fill.data,
        }
        .instruction();
        let signature = localnet.client.rpc().create_and_send_transaction(
            std::slice::from_ref(&ix),
            self.trader.address(),
            &[&self.trader.keypair, user],
            ComputeBudgetConfig::new(TRANSACT_COMPUTE_UNIT_LIMIT),
        )?;
        localnet
            .client
            .confirm_private_transaction_sync(signature)
            .map_err(|e| anyhow!("index swap {signature}: {e:?}"))?;
        Ok(signature)
    }

    pub fn bootstrap(
        &mut self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        usdc: u64,
    ) -> Result<VaultOperation> {
        let operation = self.kvault_deposit(localnet, vault, usdc)?;
        self.trader
            .shield(localnet, vault.shares_mint, operation.shares)?;
        Ok(operation)
    }

    pub fn rebalance_deposit(
        &mut self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        usdc: u64,
    ) -> Result<VaultOperation> {
        self.unshield(localnet, vault.token_mint, usdc)?;
        let operation = self.kvault_deposit(localnet, vault, usdc)?;
        self.trader
            .shield(localnet, vault.shares_mint, operation.shares)?;
        Ok(operation)
    }

    pub fn rebalance_withdraw(
        &mut self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        shares: u64,
    ) -> Result<VaultOperation> {
        self.unshield(localnet, vault.shares_mint, shares)?;
        let operation = self.kvault_withdraw(localnet, vault, shares)?;
        self.trader
            .shield(localnet, vault.token_mint, operation.tokens)?;
        Ok(operation)
    }

    fn public_accounts(&self, vault: &VaultAccounts) -> UserAccounts {
        let owner = self.trader.address();
        UserAccounts {
            user: owner,
            token_account: pda::associated_token_address(&owner, &vault.token_mint),
            shares_account: pda::associated_token_address(&owner, &vault.shares_mint),
        }
    }

    fn kvault_operation(
        &self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        instruction: solana_instruction::Instruction,
    ) -> Result<VaultOperation> {
        let rpc = localnet.client.rpc();
        let accounts = self.public_accounts(vault);
        let before = VaultState::read(rpc, &vault.vault)?;
        let tokens_before = token_balance(rpc, &accounts.token_account)?;
        let shares_before = token_balance(rpc, &accounts.shares_account)?;
        send(
            rpc,
            &[instruction],
            &self.trader.keypair,
            &[&self.trader.keypair],
        )?;
        let tokens_after = token_balance(rpc, &accounts.token_account)?;
        let shares_after = token_balance(rpc, &accounts.shares_account)?;
        Ok(VaultOperation {
            before,
            after: VaultState::read(rpc, &vault.vault)?,
            tokens: tokens_before.abs_diff(tokens_after),
            shares: shares_before.abs_diff(shares_after),
        })
    }

    fn kvault_deposit(
        &self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        usdc: u64,
    ) -> Result<VaultOperation> {
        let accounts = self.public_accounts(vault);
        let ix = kvault::Deposit {
            vault,
            user: &accounts,
            max_amount: usdc,
        }
        .instruction();
        self.kvault_operation(localnet, vault, ix)
    }

    fn kvault_withdraw(
        &self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        shares: u64,
    ) -> Result<VaultOperation> {
        let accounts = self.public_accounts(vault);
        let ix = kvault::WithdrawFromAvailable {
            vault,
            user: &accounts,
            shares,
        }
        .instruction();
        self.kvault_operation(localnet, vault, ix)
    }

    fn unshield(&mut self, localnet: &FixtureLocalnet, mint: Address, amount: u64) -> Result<()> {
        let owner = self.trader.address();
        let created = create_withdrawal(WithdrawalParams {
            wallet: &self.trader.wallet,
            payer: owner,
            legs: vec![WithdrawalLeg {
                recipient: owner,
                asset: mint,
                amount,
                spl_token_program: Some(pda::spl_token_program_id()),
            }],
        })?;
        let transaction = sign_private_transaction_sync(
            created.transaction,
            &self.trader.wallet,
            &KeypairWalletAuthority::new(owner, &self.trader.keypair),
            &localnet.client,
            &self.trader.keypair,
        )?;
        let signature = localnet.client.rpc().process_transaction(transaction)?;
        localnet
            .client
            .confirm_private_transaction_sync(signature)
            .map_err(|e| anyhow!("index unshield of {amount} {mint}: {e:?}"))?;
        self.trader.sync(localnet)
    }
}
