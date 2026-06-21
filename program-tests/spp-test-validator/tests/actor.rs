//! A shielded participant in a lifecycle scenario.

use anyhow::Result;
use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_interface::instruction::DepositIxData;
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{Utxo, Wallet, WalletUtxo};

/// What a deposit's action recorded, so the separate assert step can verify it
/// with `assert_deposit`/`assert_spl_deposit` (which need the sent data and the
/// pre-deposit account snapshots). `spl` is `Some` for token deposits.
#[derive(Clone)]
pub(crate) struct DepositRecord {
    pub(crate) signature: Signature,
    pub(crate) data: DepositIxData,
    pub(crate) tree_before: Account,
    pub(crate) spl: Option<SplDepositAccounts>,
}

/// The extra account snapshots an SPL deposit assert needs.
#[derive(Clone)]
pub(crate) struct SplDepositAccounts {
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
    pub(crate) send_counter: u64,
    pub(crate) last_deposit: Option<DepositRecord>,
}

impl Actor {
    pub(crate) fn new() -> Result<Self> {
        Self::with_keypair(ShieldedKeypair::new()?)
    }

    pub(crate) fn with_keypair(keypair: ShieldedKeypair) -> Result<Self> {
        let wallet = Wallet::new(keypair.clone())?;
        Ok(Self {
            keypair,
            wallet,
            spendable: Vec::new(),
            expected: Vec::new(),
            send_counter: 0,
            last_deposit: None,
        })
    }
}
