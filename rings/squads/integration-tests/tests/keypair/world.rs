//! The cucumber `World`: a fresh [`SquadsLocalnet`] per scenario plus what the
//! action steps record for their separate assert steps. The operations live
//! next to their steps in `steps/*`.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use solana_account::Account;
use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use squads_ring_tests::localnet::SquadsLocalnet;

use crate::fixture::auditor_secret;

#[derive(Clone)]
pub(crate) enum SettlementSnapshot {
    Sol {
        sol_interface: Pubkey,
        sol_interface_before: Account,
    },
    Spl {
        vault: Pubkey,
        user_token: Pubkey,
        vault_before: Account,
        user_token_before: Account,
    },
}

#[derive(Clone)]
pub(crate) struct DepositRecord {
    pub(crate) signature: Signature,
    pub(crate) view_tag: [u8; 32],
    pub(crate) blinding: [u8; 32],
    pub(crate) asset: Address,
    pub(crate) tree_before: Account,
    pub(crate) settlement: SettlementSnapshot,
}

#[derive(Clone)]
pub(crate) enum WithdrawalSettlement {
    Sol {
        sol_interface: Pubkey,
        sol_interface_before: Account,
        recipient: Pubkey,
        recipient_before: Account,
    },
    Spl {
        vault: Pubkey,
        vault_before: Account,
        recipient_token: Pubkey,
        recipient_token_before: Account,
    },
}

#[derive(Clone)]
pub(crate) struct WithdrawalRecord {
    pub(crate) signature: Signature,
    pub(crate) asset_id: u64,
    pub(crate) withdrawn: u64,
    pub(crate) change: u64,
    pub(crate) nullifier: [u8; 32],
    pub(crate) tree_before: Account,
    pub(crate) settlement: WithdrawalSettlement,
}

#[derive(Clone)]
pub(crate) struct TransferRecord {
    pub(crate) sender: String,
    pub(crate) transferred: u64,
    pub(crate) change_amount: u64,
    pub(crate) pool_before: Account,
    pub(crate) pool_account: Pubkey,
}

#[derive(cucumber::World)]
#[world(init = Self::new)]
pub struct SquadsLifecycleWorld {
    pub(crate) net: SquadsLocalnet,
    pub(crate) deposits: BTreeMap<String, DepositRecord>,
    pub(crate) withdrawals: BTreeMap<String, WithdrawalRecord>,
    pub(crate) transfers: BTreeMap<String, TransferRecord>,
    pub(crate) viewing_key_accounts: BTreeSet<String>,
}

impl std::fmt::Debug for SquadsLifecycleWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SquadsLifecycleWorld")
    }
}

impl SquadsLifecycleWorld {
    async fn new() -> Result<Self> {
        Ok(Self {
            net: SquadsLocalnet::start("zolana-squads-keypair", auditor_secret())?,
            deposits: BTreeMap::new(),
            withdrawals: BTreeMap::new(),
            transfers: BTreeMap::new(),
            viewing_key_accounts: BTreeSet::new(),
        })
    }
}
