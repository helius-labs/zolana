use std::cmp::Reverse;

use anyhow::Result;
use kamino_vault_rfq_sdk::{
    kvault::{VaultAccounts, VaultState},
    swap::{Holdings, Offer, Order, SwapError},
    user::{QuoteCheck, Receiver, UserOrder},
};
use solana_address::Address;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_keypair::ShieldedAddress;
use zolana_program_test::localnet::FixtureLocalnet;
use zolana_transaction::WalletUtxo;

use crate::setup::{blocking, TestWallet};

pub struct User {
    wallet: TestWallet,
    fee_bps: u64,
}

impl User {
    pub fn new(wallet: TestWallet, fee_bps: u64) -> Self {
        Self { wallet, fee_bps }
    }

    pub fn wallet(&self) -> &TestWallet {
        &self.wallet
    }

    pub fn identity(&self) -> ShieldedAddress {
        self.wallet.identity
    }

    pub async fn sync(&mut self, localnet: &FixtureLocalnet) -> Result<()> {
        blocking(|| self.wallet.sync(localnet))
    }

    pub fn holdings(&self, vault: &VaultAccounts) -> Result<Holdings> {
        self.wallet.holdings(vault)
    }

    pub async fn order(
        &self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        offer: &Offer,
        pending: &[[u8; 32]],
    ) -> Result<Order> {
        self.order_with_width(localnet, vault, offer, pending, None)
            .await
    }

    pub async fn order_with_width(
        &self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        offer: &Offer,
        pending: &[[u8; 32]],
        width: Option<usize>,
    ) -> Result<Order> {
        let (asset_in, _) = offer.quote.direction.assets(vault);
        let inputs = self.select_inputs(asset_in, offer.quote.amount_in, pending)?;
        blocking(|| {
            UserOrder {
                offer: *offer,
                inputs,
                width,
                tree: localnet.tree,
                tree_id: localnet.tree_id,
            }
            .prove(&localnet.client, &self.wallet.keypair)
        })
    }

    fn select_inputs(
        &self,
        asset: Address,
        amount: u64,
        pending: &[[u8; 32]],
    ) -> Result<Vec<WalletUtxo>> {
        let mut candidates: Vec<WalletUtxo> = self
            .wallet
            .balance(asset, None)?
            .utxos
            .into_iter()
            .filter(|utxo| !pending.contains(&utxo.nullifier))
            .collect();
        candidates.sort_by_key(|utxo| Reverse(utxo.utxo.amount));
        let mut inputs = Vec::new();
        let mut total = 0u64;
        for utxo in candidates {
            if total >= amount {
                break;
            }
            total = total.saturating_add(utxo.utxo.amount);
            inputs.push(utxo);
        }
        if total < amount {
            return Err(SwapError::InsufficientFunds {
                asset,
                required: amount,
            }
            .into());
        }
        Ok(inputs)
    }

    pub async fn verify_quote(
        &self,
        localnet: &FixtureLocalnet,
        vault: &VaultAccounts,
        order: &Order,
        message: &VersionedMessage,
    ) -> Result<()> {
        let rate = blocking(|| VaultState::read(localnet.client.rpc(), &vault.vault))?;
        QuoteCheck {
            order,
            message,
            vault,
            rate: &rate,
            fee_bps: self.fee_bps,
        }
        .verify(&Receiver {
            keypair: &self.wallet.keypair,
            registry: &self.wallet.registry,
            tree_id: localnet.tree_id,
        })
    }

    pub fn sign(&self, message: &VersionedMessage) -> Result<Signature> {
        Ok(self.wallet.keypair.try_sign_message(&message.serialize())?)
    }
}
