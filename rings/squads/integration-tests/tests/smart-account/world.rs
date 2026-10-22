//! The cucumber `World`: a fresh [`SquadsLocalnet`] per scenario, the 2-of-2
//! proposer smart account whose vault owns the sender's UTXOs, and what the
//! action steps record for their assert steps.

use std::collections::BTreeMap;

use anyhow::Result;
use solana_account::Account;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use squads_ring_tests::localnet::SquadsLocalnet;
use zolana_smart_account_client::create_smart_account_ix;
use zolana_test_utils::smart_account::{self, Permissions, SmartAccountSigner};

use crate::fixture::{auditor_secret, proposer_settings, proposer_vault, PROPOSER_SETTINGS_SEED};

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

#[derive(cucumber::World)]
#[world(init = Self::new)]
pub struct SquadsLifecycleWorld {
    pub(crate) net: SquadsLocalnet,
    pub(crate) proposer_settings: Pubkey,
    pub(crate) proposer_vault: Pubkey,
    pub(crate) proposer_members: [Keypair; 2],
    pub(crate) deposits: BTreeMap<String, DepositRecord>,
    pub(crate) withdrawals: BTreeMap<String, WithdrawalRecord>,
    pub(crate) pending_proposal: Option<Pubkey>,
}

impl std::fmt::Debug for SquadsLifecycleWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SquadsLifecycleWorld")
    }
}

impl SquadsLifecycleWorld {
    async fn new() -> Result<Self> {
        let mut net = SquadsLocalnet::start("zolana-squads-smart-account", auditor_secret())?;
        let payer = net.payer();
        let proposer_members = [Keypair::new(), Keypair::new()];
        for member in &proposer_members {
            net.base.rpc.airdrop(&member.pubkey(), 5_000_000_000)?;
        }
        let create_proposer = create_smart_account_ix(
            &payer.pubkey(),
            &smart_account::treasury_pda(),
            PROPOSER_SETTINGS_SEED,
            None,
            &proposer_members
                .iter()
                .map(|member| SmartAccountSigner {
                    key: member.pubkey(),
                    permissions: Permissions::all(),
                })
                .collect::<Vec<_>>(),
            2,
            0,
        );
        net.send(&[create_proposer], &payer, &[&payer])?;
        let proposer_vault = proposer_vault();
        net.base.rpc.airdrop(&proposer_vault, 5_000_000_000)?;

        Ok(Self {
            net,
            proposer_settings: proposer_settings(),
            proposer_vault,
            proposer_members,
            deposits: BTreeMap::new(),
            withdrawals: BTreeMap::new(),
            pending_proposal: None,
        })
    }

    pub(crate) fn proposer_member_pubkeys(&self) -> [Pubkey; 2] {
        let [a, b] = &self.proposer_members;
        [a.pubkey(), b.pubkey()]
    }

    /// Send `ixs` paid by the suite payer and signed by both proposer members,
    /// the threshold an `executeTransactionSyncV2` of the proposer needs.
    pub(crate) fn send_as_proposer(
        &mut self,
        ixs: &[solana_instruction::Instruction],
    ) -> Result<Signature> {
        let payer = self.net.payer();
        let [a, b] = &self.proposer_members;
        let (a, b) = (a.insecure_clone(), b.insecure_clone());
        self.net.send(ixs, &payer, &[&payer, &a, &b])
    }
}
