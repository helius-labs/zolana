//! A shielded participant in a zone lifecycle scenario.

#![allow(dead_code)]

use anyhow::Result;
use solana_account::Account;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_interface::instruction::ZoneDepositIxData;
use zolana_keypair::{ShieldedKeypair, ViewingKey};
use zolana_transaction::{AssetRegistry, Utxo, Wallet, WalletUtxo};

/// What a zone deposit's action recorded, so the separate assert step can verify
/// it with `assert_zone_deposit` (which needs the sent data and the pre-deposit
/// account snapshots). `spl` is `Some` for token zone deposits.
#[derive(Clone)]
pub(crate) struct ZoneDepositRecord {
    pub(crate) signature: Signature,
    pub(crate) data: ZoneDepositIxData,
    pub(crate) tree_before: Account,
    pub(crate) spl: Option<SplZoneDepositAccounts>,
}

/// The extra account snapshots an SPL zone-deposit assert needs.
#[derive(Clone)]
pub(crate) struct SplZoneDepositAccounts {
    pub(crate) mint: Pubkey,
    pub(crate) vault: Pubkey,
    pub(crate) user_token: Pubkey,
    pub(crate) vault_before: Account,
    pub(crate) user_token_before: Account,
}

/// One shielded participant: its key material, the wallet it syncs into, the
/// notes it can currently spend, and the full set of notes its wallet is expected
/// to hold after a sync (with `spent` flags), tracked for full-struct assertions.
pub(crate) struct Actor {
    pub(crate) keypair: ShieldedKeypair,
    pub(crate) wallet: Wallet,
    pub(crate) spendable: Vec<Utxo>,
    pub(crate) expected: Vec<WalletUtxo>,
    pub(crate) last_zone_deposit: Option<ZoneDepositRecord>,
    /// The ed25519 keypair that authorizes this actor's eddsa spends. The eddsa rail
    /// reads the owner at signer index 0 (the fee payer), so an eddsa actor pays and
    /// signs its own transfers/withdrawals with this key. `None` for P256 actors,
    /// which prove ownership in the proof and let the global payer fund the spend.
    pub(crate) solana_signer: Option<Keypair>,
}

impl Actor {
    pub(crate) fn new() -> Result<Self> {
        Self::with_keypair(ShieldedKeypair::new()?)
    }

    pub(crate) fn with_keypair(keypair: ShieldedKeypair) -> Result<Self> {
        let wallet = Wallet::new(keypair.shielded_address()?, AssetRegistry::default())?;
        Ok(Self {
            keypair,
            wallet,
            spendable: Vec::new(),
            expected: Vec::new(),
            last_zone_deposit: None,
            solana_signer: None,
        })
    }

    /// An eddsa-rail actor whose shielded identity is derived from `signer`'s ed25519
    /// seed (so its shielded signing pubkey equals `signer`'s pubkey) and which
    /// authorizes its own spends with `signer`.
    pub(crate) fn eddsa(signer: Keypair) -> Result<Self> {
        let seed: [u8; 32] = signer.to_bytes()[..32]
            .try_into()
            .expect("ed25519 seed is the first 32 bytes");
        let keypair = ShieldedKeypair::from_ed25519(&seed, ViewingKey::new())?;
        let mut actor = Self::with_keypair(keypair)?;
        actor.solana_signer = Some(signer);
        Ok(actor)
    }
}
