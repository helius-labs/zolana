//! Default-ring (plain-pool) lifecycle fixture: the [`LifecycleHarness`] and
//! its action implementations.
//!
//! The validator/prover/indexer bring-up, actor management, and SPL asset
//! registration live in [`crate::harness::LocalnetHarness`]; this struct embeds
//! it and adds the merge-specific state only the plain-pool lifecycle needs.
//! Both `spp-test-validator` test binaries (`lifecycle` and `proof_cu`)
//! consume this module, so each composes exactly the fixture surface it uses.

mod decode;
mod deposit;
pub(crate) mod merge;
pub mod randomized;
mod transfer;
mod wallet_sync;
mod withdraw;

use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
};

use anyhow::Result;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{ClientError, Rpc};
use zolana_interface::instruction::{
    AssetDeposit, Deposit as DepositInstruction, DepositAsset, DepositSplAccounts,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Data, Utxo, SOL_MINT};

use crate::{
    harness::{BootstrapConfig, LocalnetHarness},
    test_validator_asserts::wait_for_indexed_transaction,
};

/// The extra account snapshots an SPL deposit assert needs.
pub(crate) use crate::harness::SplDepositAccounts;

/// What a deposit's action recorded, so the separate assert step can verify it
/// with `assert_deposit`/`assert_spl_deposit` (which need the sent data and the
/// pre-deposit account snapshots). `spl` is `Some` for token deposits.
pub(crate) type DepositRecord = crate::harness::DepositRecord<AssetDeposit>;

/// One shielded participant: its key material, the wallet it syncs into, the
/// UTXOs it can currently spend, and the full set of UTXOs its wallet is expected
/// to hold after a sync (with `spent` flags), tracked for full-struct assertions.
pub(crate) type Actor = crate::harness::Actor<AssetDeposit>;

pub struct LifecycleHarness {
    pub(crate) base: LocalnetHarness<AssetDeposit>,
    /// The Solana keypair each actor registered on the user-registry under, kept so
    /// the merge step can derive the `user_record` PDA the program reads.
    pub(crate) merge_owners: BTreeMap<String, Keypair>,
    /// The most recent `transact` instruction and its transaction signature, kept
    /// so the decode step can re-parse the exact bytes and accounts that were sent.
    pub(crate) last_transact: Option<(Signature, Instruction)>,
    /// The most recent merge, kept so the consolidated-output assert can reconstruct
    /// and verify the merged UTXO.
    pub(crate) last_merge: Option<merge::MergeRecord>,
    pub(crate) merge_key: Keypair,
}

impl std::fmt::Debug for LifecycleHarness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LifecycleHarness")
    }
}

impl Deref for LifecycleHarness {
    type Target = LocalnetHarness<AssetDeposit>;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for LifecycleHarness {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

impl LifecycleHarness {
    pub fn new() -> Result<Self> {
        let (base, merge_key) = LocalnetHarness::bootstrap(BootstrapConfig {
            label: "zolana-spp",
            extra_programs: Vec::new(),
            ring_creation_is_permissionless: false,
            fund_merge_vault: true,
        })?;
        Ok(Self {
            base,
            merge_owners: BTreeMap::new(),
            last_transact: None,
            last_merge: None,
            merge_key,
        })
    }
}

/// Outcome of a shield: the on-chain signature and the created UTXO, ready to
/// spend (and re-discoverable by `Wallet::sync` from the deposit's `owner`).
#[derive(Clone, Debug)]
pub(crate) struct DepositResult {
    pub(crate) signature: Signature,
    pub(crate) utxo: Utxo,
    /// The deposit that was sent, for asserting the indexed deposit.
    pub(crate) data: AssetDeposit,
}

/// A direct (non-ring) proofless shield that appends a recipient-hidden,
/// wallet-discoverable UTXO.
///
/// The asset is inferred from `sender`: a system-owned account shields SOL; an
/// SPL token account shields its mint, with the mint, vault and registry PDAs,
/// and owning token program all derived from it. The caller passes none of them.
///
/// The recipient is identified by its public [`ShieldedAddress`] only, so a
/// depositor can shield to a third party without holding any of its secrets.
pub(crate) struct Deposit<'a> {
    /// State tree the deposit appends to.
    pub(crate) tree: Pubkey,
    /// Public shielded identity the UTXO becomes spendable by and discoverable for.
    pub(crate) recipient: &'a ShieldedAddress,
    /// Funding account: a SOL system account or an SPL token account. The asset
    /// (and, for SPL, the mint/vault/registry/token-program) is detected from it.
    pub(crate) sender: Pubkey,
    /// Public amount to shield (lamports for SOL, base units for SPL).
    pub(crate) amount: u64,
}

impl Deposit<'_> {
    /// Build and send the shield. `payer` funds the fee; `authority` signs the
    /// debit of `sender` (for SOL it must equal `sender`; for SPL it is the token
    /// account's owner).
    pub(crate) fn execute<R: Rpc, I: Rpc>(
        self,
        rpc: &R,
        indexer: &I,
        payer: &Keypair,
        authority: &Keypair,
    ) -> Result<DepositResult, ClientError> {
        // The recipient `owner_hash` is computed from public address material, so
        // the depositor needs no shared secret; the recipient re-derives the UTXO
        // from the deposit event.
        let owner = self.recipient.owner_hash()?;
        let view_tag = self.recipient.viewing_pubkey.x();

        let sender_account = rpc.get_account(Address::new_from_array(self.sender.to_bytes()))?;
        let system_owned = sender_account
            .as_ref()
            .map(|account| account.owner == Pubkey::new_from_array([0u8; 32]))
            .unwrap_or(true);

        let (asset, deposit_asset) = if system_owned {
            // SOL: the funding system account must itself sign the debit.
            if self.sender != authority.pubkey() {
                return Err(ClientError::DepositSenderNotSigner {
                    sender: self.sender.to_bytes(),
                });
            }
            (SOL_MINT, DepositAsset::Sol)
        } else {
            // SPL: `sender` is a token account; everything else derives from it.
            let account = sender_account.ok_or(ClientError::AccountNotFound {
                address: self.sender.to_bytes(),
            })?;
            let mint_bytes: [u8; 32] = account
                .data
                .get(0..32)
                .and_then(|slice| slice.try_into().ok())
                .ok_or(ClientError::AccountNotFound {
                    address: self.sender.to_bytes(),
                })?;
            let mint = Pubkey::new_from_array(mint_bytes);
            (
                Address::new_from_array(mint_bytes),
                DepositAsset::Spl(DepositSplAccounts {
                    mint,
                    user_token: self.sender,
                    token_program: zolana_interface::pda::spl_token_program_id(),
                }),
            )
        };

        let data = AssetDeposit {
            asset: deposit_asset,
            view_tag,
            owner,
            amount: self.amount,
            utxo_data: None,
            memo: None,
        };
        let ix = DepositInstruction {
            tree: self.tree,
            depositor: authority.pubkey(),
            deposits: vec![data.clone()],
        }
        .instruction()?;
        let mut signers: Vec<&dyn Signer> = vec![payer];
        if authority.pubkey() != payer.pubkey() {
            signers.push(authority);
        }
        let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
        let signature = rpc.create_and_send_transaction(&[ix], payer_address, &signers)?;
        // SPP derives the blinding from the leaf index the output lands at, so
        // it is unknown until the deposit executes. A proofless deposit
        // publishes it in the clear, so the depositor reads the UTXO back from
        // the indexer instead of predicting where the append lands.
        let indexed = wait_for_indexed_transaction(indexer, view_tag, signature);
        let deposited = indexed
            .output_slots
            .iter()
            .filter(|slot| slot.view_tag == view_tag)
            .find_map(|slot| slot.proofless_output().filter(|out| out.owner == owner))
            .ok_or_else(|| {
                ClientError::Rpc(format!("no indexed deposit output for {signature}"))
            })?;
        let utxo = Utxo {
            owner: self.recipient.signing_pubkey,
            asset,
            amount: self.amount,
            blinding: deposited.blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        Ok(DepositResult {
            signature,
            utxo,
            data,
        })
    }
}
