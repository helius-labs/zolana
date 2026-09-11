//! `create_ring_config` / `update_ring_config` / `update_ring_config_owner` /
//! `set_ring_activation` admin helpers, the Harness operations, and the
//! full-struct state assert.

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{CreateRingConfig, SetRingActivation, UpdateRingConfig, UpdateRingConfigOwner},
    pda,
    state::{discriminator::RING_CONFIG, RingConfig},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program_test::{Rejection, RING_TEST_PROGRAM_ID};
use zolana_smart_account_client::execute_sync_ix;

use super::RingHarness;
use crate::{
    localnet::send_transaction,
    smart_account::standard_accounts,
    test_validator_asserts::{
        assert_account_unchanged, assert_optional_account_unchanged, fetch_account,
        fetch_optional_account,
    },
};

/// The on-chain `RingConfig` state read back for a full-struct assert.
#[derive(Debug, PartialEq, Eq)]
struct RingConfigState {
    authority: Pubkey,
    program_id: Pubkey,
    ring_authority_transact_is_enabled: bool,
    paused: bool,
    activated: bool,
    bump: u8,
}

impl RingHarness {
    /// Create a ring config under a fresh authority keypair and have governance
    /// enable the authority-transact rail, tracking the keypair as
    /// `self.ring_authority` for the later update/rotate operations. The fixture
    /// runs with `ring_activation_is_permissionless`, so creation already lands
    /// activated; only the rail needs governance.
    pub fn create_enabled_ring_config(&mut self) -> Result<Signature> {
        let authority = Keypair::new();
        let signature =
            self.create_ring_config(&Address::new_from_array(authority.pubkey().to_bytes()))?;
        self.ring_authority = Some(authority);
        self.set_ring_activation(true, true)?;
        Ok(signature)
    }

    /// Governance sets the two flags it owns, signing through the ring role's
    /// smart account (`protocol_config.ring_creation_authority` is its vault).
    pub fn set_ring_activation(
        &mut self,
        activated: bool,
        ring_authority_transact_is_enabled: bool,
    ) -> Result<()> {
        let ring_config = self.ring_config.ok_or_else(|| anyhow!("no ring config"))?;
        // The role PDAs are derived, not stored, exactly as the bootstrap does.
        let accounts = standard_accounts();
        let ix = SetRingActivation {
            authority: accounts.ring_vault,
            ring_config,
            activated,
            ring_authority_transact_is_enabled,
        }
        .instruction();
        let sync = execute_sync_ix(&accounts.ring_settings, 0, &[self.ring_key.pubkey()], &[ix]);
        let payer = self.payer.insecure_clone();
        let ring_key = self.ring_key.insecure_clone();
        send_transaction(
            &mut self.rpc,
            &[sync],
            &payer.pubkey(),
            &[&payer, &ring_key],
        )?;
        Ok(())
    }

    /// Read the ring config account and decode it into a full `RingConfigState`.
    fn ring_config_state(&self) -> Result<RingConfigState> {
        let ring_config = self.ring_config.ok_or_else(|| anyhow!("no ring config"))?;
        let account = self
            .rpc
            .get_account(Address::new_from_array(ring_config.to_bytes()))?
            .ok_or_else(|| anyhow!("ring config account missing"))?;
        let bytes = account.data.as_slice();
        if bytes.len() != RingConfig::SIZE {
            return Err(anyhow!("ring config size mismatch"));
        }
        if bytes.first().copied() != Some(RING_CONFIG) {
            return Err(anyhow!("ring config discriminator mismatch"));
        }
        let cfg: &RingConfig = bytemuck::from_bytes(bytes);
        Ok(RingConfigState {
            authority: Pubkey::new_from_array(cfg.authority.to_bytes()),
            program_id: Pubkey::new_from_array(cfg.program_id.to_bytes()),
            ring_authority_transact_is_enabled: cfg.enabled(),
            paused: cfg.is_paused(),
            activated: cfg.is_activated(),
            bump: cfg.bump,
        })
    }

    /// Full-struct assert of the ring config. `activated` is asserted true
    /// because the fixture bootstraps with permissionless activation.
    pub fn assert_ring_config(&self, enabled: bool, paused: bool) -> Result<()> {
        let authority = self
            .ring_authority
            .as_ref()
            .ok_or_else(|| anyhow!("no authority"))?
            .pubkey();
        let bump = pda::ring_auth(&self.ring_program_id).1;
        assert_eq!(
            self.ring_config_state()?,
            RingConfigState {
                authority,
                program_id: Pubkey::new_from_array(RING_TEST_PROGRAM_ID),
                ring_authority_transact_is_enabled: enabled,
                paused,
                activated: true,
                bump,
            }
        );
        Ok(())
    }

    /// Update the paused flag, signed by the current authority. The ring cannot
    /// reach the governance-owned flags.
    pub fn update_ring_config(&mut self, paused: bool) -> Result<()> {
        let authority = self
            .ring_authority
            .as_ref()
            .ok_or_else(|| anyhow!("no authority"))?
            .insecure_clone();
        let ring_config = self.ring_config.ok_or_else(|| anyhow!("no ring config"))?;
        let ix = UpdateRingConfig {
            authority: authority.pubkey(),
            ring_config,
            paused,
        }
        .instruction();
        let payer = self.payer.insecure_clone();
        send_transaction(&mut self.rpc, &[ix], &payer.pubkey(), &[&payer, &authority])?;
        Ok(())
    }

    /// Rotate the config owner to a fresh authority, signed by both the current and
    /// the new authority. The previous owner is kept for the negative path.
    pub fn rotate_ring_config_owner(&mut self) -> Result<()> {
        let authority = self
            .ring_authority
            .as_ref()
            .ok_or_else(|| anyhow!("no authority"))?
            .insecure_clone();
        let ring_config = self.ring_config.ok_or_else(|| anyhow!("no ring config"))?;
        let next = Keypair::new();
        let ix = UpdateRingConfigOwner {
            authority: authority.pubkey(),
            ring_config,
            new_authority: Address::new_from_array(next.pubkey().to_bytes()),
        }
        .instruction();
        let payer = self.payer.insecure_clone();
        send_transaction(
            &mut self.rpc,
            &[ix],
            &payer.pubkey(),
            &[&payer, &authority, &next],
        )?;
        self.previous_ring_authority = Some(authority);
        self.ring_authority = Some(next);
        Ok(())
    }

    /// Attempt an update signed by the previous (rotated-out) owner; must fail with
    /// `UnauthorizedCaller`.
    pub fn old_owner_update_rejected(&mut self) -> Result<()> {
        let stale = self
            .previous_ring_authority
            .as_ref()
            .ok_or_else(|| anyhow!("no previous authority"))?
            .insecure_clone();
        let ring_config = self.ring_config.ok_or_else(|| anyhow!("no ring config"))?;
        let config_before = fetch_account(&self.rpc, &ring_config)?;
        let ix = UpdateRingConfig {
            authority: stale.pubkey(),
            ring_config,
            paused: false,
        }
        .instruction();
        let payer = self.payer.insecure_clone();
        match send_transaction(&mut self.rpc, &[ix], &payer.pubkey(), &[&payer, &stale]) {
            Ok(_) => Err(anyhow!("stale owner update unexpectedly succeeded")),
            Err(error) => {
                Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_client(&error);
                assert_account_unchanged(&self.rpc, &ring_config, &config_before)?;
                Ok(())
            }
        }
    }

    /// Attempt to create a ring config with a bogus (non-PDA) ring authority account,
    /// sent straight to SPP; the canonical derivation check must reject it with
    /// `InvalidRingConfig`.
    pub fn create_invalid_ring_authority_rejected(&mut self) -> Result<()> {
        let payer = self.payer.insecure_clone();
        let mut ix = CreateRingConfig {
            payer: payer.pubkey(),
            program_id: Address::new_from_array(RING_TEST_PROGRAM_ID),
            authority: Address::new_from_array(payer.pubkey().to_bytes()),
        }
        .instruction()
        .map_err(|e| anyhow!("ring config PDA: {e}"))?;
        ix.program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        let canonical_ring_config = ix
            .accounts
            .get(2)
            .ok_or_else(|| anyhow!("missing ring config account meta"))?
            .pubkey;
        let config_before = fetch_optional_account(&self.rpc, &canonical_ring_config)?;
        // Swap the config account (the ring's `ring_auth` PDA, index 2) for a bogus
        // signer: the on-chain canonical derivation check must reject it.
        let meta = ix
            .accounts
            .get_mut(2)
            .ok_or_else(|| anyhow!("missing ring config account meta"))?;
        meta.pubkey = payer.pubkey();
        match send_transaction(&mut self.rpc, &[ix], &payer.pubkey(), &[&payer]) {
            Ok(_) => Err(anyhow!(
                "invalid ring authority create unexpectedly succeeded"
            )),
            Err(error) => {
                Rejection::pool(ShieldedPoolError::InvalidRingConfig).assert_client(&error);
                assert_optional_account_unchanged(
                    &self.rpc,
                    &canonical_ring_config,
                    &config_before,
                )?;
                Ok(())
            }
        }
    }
}
