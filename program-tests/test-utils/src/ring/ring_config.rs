//! `create_ring_config` / `update_ring_config` / `update_ring_config_owner` admin
//! helpers, the Harness operations, and the full-struct state assert.

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{CreateRingConfig, UpdateRingConfig, UpdateRingConfigOwner},
    pda,
    state::{discriminator::RING_CONFIG, RingConfig},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program_test::{Rejection, RING_TEST_PROGRAM_ID};

use super::RingHarness;
use crate::{
    localnet::send_transaction,
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
    bump: u8,
}

impl RingHarness {
    /// Create an enabled ring config under a fresh authority keypair, tracking that
    /// keypair as `self.ring_authority` for the later update/rotate operations.
    pub fn create_enabled_ring_config(&mut self) -> Result<()> {
        let authority = Keypair::new();
        self.create_ring_config(
            &Address::new_from_array(authority.pubkey().to_bytes()),
            true,
        )?;
        self.ring_authority = Some(authority);
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
            bump: cfg.bump,
        })
    }

    /// Full-struct assert of the freshly created, enabled ring config.
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
                bump,
            }
        );
        Ok(())
    }

    /// Update the enabled and paused flags, signed by the current authority.
    pub fn update_ring_config(&mut self, enabled: bool, paused: bool) -> Result<()> {
        let authority = self
            .ring_authority
            .as_ref()
            .ok_or_else(|| anyhow!("no authority"))?
            .insecure_clone();
        let ring_config = self.ring_config.ok_or_else(|| anyhow!("no ring config"))?;
        let ix = UpdateRingConfig {
            authority: authority.pubkey(),
            ring_config,
            ring_authority_transact_is_enabled: enabled,
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
            ring_authority_transact_is_enabled: true,
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
            ring_authority_transact_is_enabled: true,
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
