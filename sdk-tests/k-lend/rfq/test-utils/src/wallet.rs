use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_signer::Signer;
use zolana_keypair::{ShieldedKeypair, SigningKey};
use zolana_program_test::{fixture, localnet::FixtureLocalnet};
use zolana_test_utils::wallet::{sync_wallet, Wallet};
use zolana_transaction::AssetRegistry;

use k_lend_market_maker::Holdings;
use k_lend_rfq_sdk::pair::Pair;

pub struct TestWallet {
    pub wallet: Wallet,
    pub keypair: ShieldedKeypair,
}

impl std::ops::Deref for TestWallet {
    type Target = Wallet;
    fn deref(&self) -> &Self::Target {
        &self.wallet
    }
}

impl TestWallet {
    pub fn new(actor: u8, assets: &AssetRegistry) -> Result<Self> {
        let solana = fixture::actor(actor);
        let seed: [u8; 32] = solana
            .to_bytes()
            .get(..32)
            .ok_or_else(|| anyhow!("ed25519 keypair without a seed"))?
            .try_into()?;
        let keypair = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&seed))?;
        let wallet = Wallet::new(keypair.shielded_address()?, assets.clone())
            .map_err(|e| anyhow!("wallet of actor {actor}: {e:?}"))?;
        Ok(Self { wallet, keypair })
    }

    pub fn address(&self) -> Address {
        self.keypair.pubkey()
    }

    pub fn sync(&mut self, localnet: &FixtureLocalnet) -> Result<()> {
        sync_wallet(&mut self.wallet, &self.keypair, localnet.client.indexer())
            .map_err(|e| anyhow!("sync wallet {}: {e:?}", self.keypair.pubkey()))?;
        Ok(())
    }

    pub fn holdings(&self, pair: &Pair) -> Result<Holdings> {
        Ok(Holdings {
            collateral: self.balance(pair.token_mint, None)?.amount,
            shares: self.balance(pair.shares_mint, None)?.amount,
        })
    }
}
