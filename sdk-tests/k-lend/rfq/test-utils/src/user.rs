use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use k_lend_rfq_sdk::{
    pair::{Pair, VaultState},
    swap::{Offer, Order, SwapError},
    transfer::Receiver,
    user::{select_inputs, QuoteCheck, UserOrder},
};
use solana_message::VersionedMessage;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_keypair::ShieldedAddress;
use zolana_program_test::localnet::FixtureLocalnet;

use k_lend_market_maker::Holdings;

use crate::{chain::blocking, wallet::TestWallet};

pub struct User {
    wallet: TestWallet,
    transfer_ttl: Duration,
}

impl User {
    pub fn new(wallet: TestWallet, transfer_ttl: Duration) -> Self {
        Self {
            wallet,
            transfer_ttl,
        }
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

    pub fn holdings(&self, pair: &Pair) -> Result<Holdings> {
        self.wallet.holdings(pair)
    }

    pub async fn order(
        &self,
        localnet: &FixtureLocalnet,
        pair: &Pair,
        offer: &Offer,
    ) -> Result<Order> {
        self.order_with_width(localnet, pair, offer, None).await
    }

    pub async fn order_with_width(
        &self,
        localnet: &FixtureLocalnet,
        pair: &Pair,
        offer: &Offer,
        width: Option<usize>,
    ) -> Result<Order> {
        if offer.pair != *pair {
            return Err(SwapError::WrongPair.into());
        }
        let rate = blocking(|| VaultState::read(localnet.client.rpc(), &pair.vault))?;
        offer.verify_price(&rate)?;
        let (asset_in, _) = offer.quote.direction.assets(pair);
        let inputs = select_inputs(
            self.wallet.balance(asset_in, None)?.utxos,
            asset_in,
            offer.quote.amount_in,
            offer.max_user_inputs,
        )?;
        blocking(|| {
            let expiry_unix_ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .checked_add(self.transfer_ttl)
                .ok_or_else(|| anyhow!("user transfer expiry exceeds the timestamp range"))?
                .as_secs();
            UserOrder {
                offer: *offer,
                inputs,
                width,
                tree: localnet.tree,
                tree_id: localnet.tree_id,
                expiry_unix_ts,
            }
            .prove(&localnet.client, &self.wallet.keypair)
        })
    }

    pub async fn verify_quote(
        &self,
        localnet: &FixtureLocalnet,
        pair: &Pair,
        order: &Order,
        message: &VersionedMessage,
    ) -> Result<()> {
        QuoteCheck {
            order,
            message,
            pair,
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
