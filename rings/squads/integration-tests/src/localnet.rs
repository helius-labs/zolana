//! Localnet bootstrap for the Squads ring BDD lifecycle suites.
//!
//! [`SquadsLocalnet::start`] restarts a validator + Photon with the shielded
//! pool (upgradeable, so its upgrade authority initializes the protocol
//! config), the user registry, the smart-account program, and the Squads ring
//! program, then creates a tree, the ring's own config, registers it with SPP
//! through `init_spp_ring_config`, and has governance activate it with the
//! ring-authority rail enabled. The backend mock runs its settlement crank
//! against the same endpoints.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc, ZolanaIndexer};
use zolana_interface::{
    instruction::{EncryptedRingDepositData, RingDepositIxData},
    pda, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::X25519Keypair;
use zolana_program::instruction::{DepositAsset, RingAssetDeposit, RingDeposit, SetRingActivation};
use zolana_squads_client::{
    AssetBalance, DecryptedUtxo, GetBalancesRequest, RequestCreateViewingKeyAccountRequest,
    RequestCreateViewingKeyAccountResponse, SquadsBackend,
};
use zolana_squads_interface::{
    instruction::{
        builders::{CreateRingConfig, Deposit, InitSppRingConfig},
        CreateRingConfigIxData, DepositIxData,
    },
    types::X25519Pubkey,
    RING_CONFIG_PDA_SEED, SQUADS_RING_PROGRAM_ID, VIEWING_KEY_ACCOUNT_PDA_SEED,
};
use zolana_test_utils::{
    harness::{BootstrapConfig, LocalnetHarness, SplAsset},
    localnet::send_transaction,
    smart_account::{execute_sync_ix, standard_accounts},
};

use crate::prover_url;

/// SOL is asset id 1 and the first registered SPL mint asset id 2.
pub const SOL_ASSET_ID: u64 = zolana_squads_client::SOL_ASSET_ID;
pub const SPL_ASSET_ID: u64 = 2;

/// Lamports the ring co-signer holds: it is the backend relayer, so it pays the
/// fees of every backend-built transaction and the rent of every viewing key
/// account.
const CO_SIGNER_FUNDING: u64 = 50_000_000_000;

/// The proof-bearing ring instructions verify two Groth16 proofs.
const PROOF_CU_LIMIT: u32 = 1_400_000;

const BALANCE_TIMEOUT: Duration = Duration::from_secs(60);
const CONSOLIDATION_TIMEOUT: Duration = Duration::from_secs(180);
const POLL_INTERVAL: Duration = Duration::from_millis(500);

pub fn squads_program_id() -> Pubkey {
    Pubkey::new_from_array(SQUADS_RING_PROGRAM_ID)
}

pub fn ring_config_pda() -> Pubkey {
    Pubkey::find_program_address(&[RING_CONFIG_PDA_SEED], &squads_program_id()).0
}

/// The canonical viewing key account of an owner identity.
pub fn viewing_key_account_pda(owner: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(
        &[VIEWING_KEY_ACCOUNT_PDA_SEED, owner.as_ref()],
        &squads_program_id(),
    )
    .0
}

fn squads_program_path() -> String {
    std::env::var("SQUADS_RING_PROGRAM_PATH")
        .unwrap_or_else(|_| "rings/squads/target/deploy/zolana_squads_program.so".to_string())
}

/// A validator + Photon running SPP and the Squads ring, with the backend mock.
pub struct SquadsLocalnet {
    pub base: LocalnetHarness<()>,
    /// The ring's `ring_auth` PDA, which is SPP's `RingConfig` account.
    pub ring_auth: Pubkey,
    /// The configured ring co-signer, also the backend relayer and merge authority.
    pub co_signer: Keypair,
    pub backend: SquadsBackend<ZolanaIndexer, SolanaRpc>,
}

impl SquadsLocalnet {
    pub fn start(label: &'static str, auditor: X25519Keypair) -> Result<Self> {
        let (mut base, _) = LocalnetHarness::<()>::bootstrap(BootstrapConfig {
            label,
            extra_programs: vec![(squads_program_id().to_string(), squads_program_path())],
            ring_activation_is_permissionless: false,
            fund_merge_vault: false,
        })?;
        base.rpc.assert_executable(&squads_program_id())?;

        let payer = base.payer.insecure_clone();
        let squads_authority = Keypair::new();
        base.rpc
            .airdrop(&squads_authority.pubkey(), 1_000_000_000)?;
        let co_signer = Keypair::new();
        base.rpc.airdrop(&co_signer.pubkey(), CO_SIGNER_FUNDING)?;

        let auditor_pubkey = auditor.pubkey();
        let auditor_key: X25519Pubkey = *auditor_pubkey.as_bytes();
        let create_ring_config = CreateRingConfig {
            creator: payer.pubkey(),
            ring_config: ring_config_pda(),
            system_program: Pubkey::default(),
            data: CreateRingConfigIxData {
                authority: squads_authority.pubkey(),
                co_signer: co_signer.pubkey(),
                max_proposal_lifetime: 3_600,
                auditor_keys: vec![auditor_key],
                merge_authorities: vec![co_signer.pubkey()],
            },
        }
        .instruction();
        send_transaction(
            &mut base.rpc,
            &[create_ring_config],
            &payer.pubkey(),
            &[&payer],
        )?;

        let ring_auth = pda::ring_auth(&squads_program_id()).0;
        let init = InitSppRingConfig {
            authority: squads_authority.pubkey(),
            ring_config: ring_config_pda(),
            protocol_config: pda::protocol_config(),
            ring_auth,
            system_program: Pubkey::default(),
            spp_program: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        }
        .instruction();
        send_transaction(
            &mut base.rpc,
            &[init],
            &payer.pubkey(),
            &[&payer, &squads_authority],
        )?;

        let accounts = standard_accounts();
        let activate = SetRingActivation {
            authority: accounts.ring_vault,
            ring_config: ring_auth,
            activated: true,
            ring_authority_transact_is_enabled: true,
        }
        .instruction();
        let ring_key = base.ring_key.insecure_clone();
        let activate_sync = execute_sync_ix(
            &accounts.ring_settings,
            0,
            &[ring_key.pubkey()],
            &[activate],
        );
        send_transaction(
            &mut base.rpc,
            &[activate_sync],
            &payer.pubkey(),
            &[&payer, &ring_key],
        )?;

        let rpc_url = zolana_test_utils::localnet::localnet_rpc_url();
        let indexer_url = zolana_test_utils::localnet::localnet_indexer_url();
        let backend = SquadsBackend::new_with_crank(
            auditor,
            co_signer.insecure_clone(),
            Address::new_from_array(ring_config_pda().to_bytes()),
            base.tree_id,
            prover_url("http://127.0.0.1:3001"),
            indexer_url,
            rpc_url,
        );

        Ok(Self {
            base,
            ring_auth,
            co_signer,
            backend,
        })
    }

    pub fn payer(&self) -> Keypair {
        self.base.payer.insecure_clone()
    }

    /// Send `ixs` as a v1 transaction paid by `payer`.
    pub fn send(
        &mut self,
        ixs: &[Instruction],
        payer: &Keypair,
        signers: &[&Keypair],
    ) -> Result<Signature> {
        Ok(send_transaction(
            &mut self.base.rpc,
            ixs,
            &payer.pubkey(),
            signers,
        )?)
    }

    /// Send a backend-built instruction. Its payer and co-signer are both the
    /// backend relayer, so the relayer is the only signer.
    pub fn send_backend_instruction(&mut self, ix: Instruction) -> Result<Signature> {
        let budget =
            solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
                PROOF_CU_LIMIT,
            );
        let relayer = self.co_signer.insecure_clone();
        self.send(&[budget, ix], &relayer, &[&relayer])
    }

    /// Register the scenario's SPL asset (idempotent) on-chain and with the
    /// backend.
    pub fn ensure_spl_asset(&mut self) -> Result<SplAsset> {
        self.base.ensure_spl_asset()?;
        let spl = *self.base.spl_asset()?;
        self.backend
            .register_asset(SPL_ASSET_ID, Address::new_from_array(spl.mint.to_bytes()));
        Ok(spl)
    }

    /// Create the viewing key account of `owner` through the backend
    /// (auditor-only, no owner signature) and return its address.
    pub fn create_viewing_key_account(
        &mut self,
        owner: [u8; 32],
        owner_kind: u8,
    ) -> Result<Pubkey> {
        let response = self
            .backend
            .request_create_viewing_key_account(RequestCreateViewingKeyAccountRequest {
                owner: Address::new_from_array(owner),
                recovery_keys: Vec::new(),
                owner_signature: None,
                owner_kind,
            })
            .map_err(|e| anyhow!("request create viewing key account: {e}"))?;
        let (address, instruction) = match response {
            RequestCreateViewingKeyAccountResponse::Instruction {
                viewing_key_account,
                instruction,
            } => (
                Pubkey::new_from_array(viewing_key_account.to_bytes()),
                instruction,
            ),
            RequestCreateViewingKeyAccountResponse::Signature { .. } => {
                return Err(anyhow!("backend unexpectedly sent the viewing key account"));
            }
        };
        let expected = viewing_key_account_pda(&owner);
        if address != expected {
            return Err(anyhow!(
                "backend viewing key account {address} is not the canonical PDA {expected}"
            ));
        }
        self.send_backend_instruction(instruction)?;
        Ok(address)
    }

    /// The squads `deposit` of one output to `recipient_vka`, forwarding the SPP
    /// `ring_deposit` account list for `asset`.
    pub fn deposit_instruction(
        &self,
        depositor: Pubkey,
        recipient_vka: Pubkey,
        view_tag: [u8; 32],
        blinding: [u8; 32],
        amount: u64,
        asset: DepositAsset,
    ) -> Result<Instruction> {
        let spp = RingDeposit {
            tree: self.base.tree,
            depositor,
            ring_program_id: squads_program_id(),
            deposits: vec![RingAssetDeposit {
                asset,
                view_tag,
                owner_utxo_hash: [0u8; 32],
                amount,
                ring_data_hash: [0u8; 32],
                encrypted: EncryptedRingDepositData {
                    tx_viewing_pk: [0u8; 33],
                    salt: [0u8; 16],
                    ciphertext: blinding.to_vec(),
                },
            }],
        }
        .instruction()
        .map_err(|e| anyhow!("ring deposit accounts: {e:?}"))?;
        let spp_data = spp
            .data
            .get(1..)
            .ok_or_else(|| anyhow!("ring deposit carries no data"))?;
        let asset_kind = RingDepositIxData::deserialize(spp_data)
            .map_err(|e| anyhow!("decode ring deposit data: {e:?}"))?
            .assets
            .first()
            .copied()
            .ok_or_else(|| anyhow!("ring deposit names no asset"))?;
        Ok(Deposit {
            recipient_viewing_key_account: recipient_vka,
            spp_accounts: spp.accounts,
            data: DepositIxData {
                view_tag,
                blinding,
                amount,
                asset: asset_kind,
            },
        }
        .instruction())
    }

    pub fn balances(&self, viewing_key_account: Pubkey) -> Result<Vec<AssetBalance>> {
        Ok(self
            .backend
            .get_balances(GetBalancesRequest {
                viewing_key_account: Address::new_from_array(viewing_key_account.to_bytes()),
                skip_utxos: false,
                signature: [0u8; 64],
            })
            .map_err(|e| anyhow!("backend get_balances: {e}"))?
            .balances)
    }

    /// The unspent UTXOs of `asset_id` the backend decrypts for the account.
    pub fn utxos(&self, viewing_key_account: Pubkey, asset_id: u64) -> Result<Vec<DecryptedUtxo>> {
        Ok(self
            .balances(viewing_key_account)?
            .into_iter()
            .find(|balance| balance.asset_id == asset_id)
            .map(|balance| balance.utxos)
            .unwrap_or_default())
    }

    /// Poll until the backend decrypts at least `count` unspent UTXOs of
    /// `asset_id` for the account.
    pub fn wait_for_utxos(
        &self,
        viewing_key_account: Pubkey,
        asset_id: u64,
        count: usize,
    ) -> Result<Vec<DecryptedUtxo>> {
        let started = Instant::now();
        loop {
            let utxos = self.utxos(viewing_key_account, asset_id)?;
            if utxos.len() >= count {
                return Ok(utxos);
            }
            if started.elapsed() > BALANCE_TIMEOUT {
                return Err(anyhow!(
                    "{viewing_key_account} has {} unspent UTXOs of asset {asset_id}, expected {count}",
                    utxos.len()
                ));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// Poll until the account holds exactly one unspent UTXO of `asset_id`
    /// worth `amount`: the crank consolidates fragmented balances, so a single
    /// UTXO (rather than a matching total) shows a merge settled.
    pub fn wait_for_consolidated(
        &self,
        viewing_key_account: Pubkey,
        asset_id: u64,
        amount: u64,
    ) -> Result<DecryptedUtxo> {
        let started = Instant::now();
        loop {
            let utxos = self.utxos(viewing_key_account, asset_id)?;
            if let [utxo] = utxos.as_slice() {
                if utxo.amount == amount {
                    return Ok(*utxo);
                }
            }
            if started.elapsed() > CONSOLIDATION_TIMEOUT {
                let amounts: Vec<u64> = utxos.iter().map(|utxo| utxo.amount).collect();
                return Err(anyhow!(
                    "{viewing_key_account} did not consolidate asset {asset_id} into one \
                     {amount} UTXO, holds {amounts:?}"
                ));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// Poll until the backend-decrypted balance of `asset_id` equals `amount`.
    pub fn wait_for_balance(
        &self,
        viewing_key_account: Pubkey,
        asset_id: u64,
        amount: u64,
    ) -> Result<()> {
        let started = Instant::now();
        loop {
            let balance = self
                .balances(viewing_key_account)?
                .into_iter()
                .find(|balance| balance.asset_id == asset_id)
                .map(|balance| balance.amount)
                .unwrap_or(0);
            if balance == amount {
                return Ok(());
            }
            if started.elapsed() > BALANCE_TIMEOUT {
                return Err(anyhow!(
                    "backend decrypts {balance} of asset {asset_id} for \
                     {viewing_key_account}, expected {amount}"
                ));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// Poll until `address` no longer exists (a settled proposal is closed).
    pub fn wait_for_closed(&self, address: Pubkey) -> Result<()> {
        let started = Instant::now();
        loop {
            if self
                .base
                .rpc
                .get_account(Address::new_from_array(address.to_bytes()))?
                .is_none()
            {
                return Ok(());
            }
            if started.elapsed() > CONSOLIDATION_TIMEOUT {
                return Err(anyhow!("{address} was not closed in time"));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}
