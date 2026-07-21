//! `create_zone_config` / `update_zone_config` / `update_zone_config_owner` admin
//! steps, the Harness operations, and the full-struct state assert.

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_interface::{
    instruction::{CreateZoneConfig, UpdateZoneConfig, UpdateZoneConfigOwner},
    pda,
    state::{discriminator::ZONE_CONFIG, ZoneConfig},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program_test::ZONE_TEST_PROGRAM_ID;
use zolana_test_utils::test_validator_asserts::{
    assert_account_unchanged, assert_custom_program_error, assert_optional_account_unchanged,
    fetch_account, fetch_optional_account,
};

use crate::{localnet::send_transaction, ZoneHarness};

/// `ShieldedPoolError::UnauthorizedCaller`.
const UNAUTHORIZED_CALLER: u32 = 7003;
/// `ShieldedPoolError::InvalidZoneConfig`.
const INVALID_ZONE_CONFIG: u32 = 7014;

/// The on-chain `ZoneConfig` state read back for a full-struct assert.
#[derive(Debug, PartialEq, Eq)]
struct ZoneConfigState {
    authority: Pubkey,
    program_id: Pubkey,
    zone_authority_transact_is_enabled: bool,
    bump: u8,
}

impl ZoneHarness {
    /// Create an enabled zone config under a fresh authority keypair, tracking that
    /// keypair as `self.zone_authority` for the later update/rotate steps.
    pub(crate) fn create_enabled_zone_config(&mut self) -> Result<()> {
        let authority = Keypair::new();
        self.create_zone_config(
            &Address::new_from_array(authority.pubkey().to_bytes()),
            true,
        )?;
        self.zone_authority = Some(authority);
        Ok(())
    }

    /// Read the zone config account and decode it into a full `ZoneConfigState`.
    fn zone_config_state(&self) -> Result<ZoneConfigState> {
        let zone_config = self.zone_config.ok_or_else(|| anyhow!("no zone config"))?;
        let account = self
            .rpc
            .get_account(Address::new_from_array(zone_config.to_bytes()))?
            .ok_or_else(|| anyhow!("zone config account missing"))?;
        let bytes = account.data.as_slice();
        if bytes.len() != ZoneConfig::SIZE {
            return Err(anyhow!("zone config size mismatch"));
        }
        if bytes.first().copied() != Some(ZONE_CONFIG) {
            return Err(anyhow!("zone config discriminator mismatch"));
        }
        let cfg: &ZoneConfig = bytemuck::from_bytes(bytes);
        Ok(ZoneConfigState {
            authority: Pubkey::new_from_array(cfg.authority.to_bytes()),
            program_id: Pubkey::new_from_array(cfg.program_id.to_bytes()),
            zone_authority_transact_is_enabled: cfg.enabled(),
            bump: cfg.bump,
        })
    }

    /// Full-struct assert of the freshly created, enabled zone config.
    pub(crate) fn assert_zone_config(&self, enabled: bool) -> Result<()> {
        let authority = self
            .zone_authority
            .as_ref()
            .ok_or_else(|| anyhow!("no authority"))?
            .pubkey();
        let bump = pda::zone_auth(&self.zone_program_id).1;
        assert_eq!(
            self.zone_config_state()?,
            ZoneConfigState {
                authority,
                program_id: Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID),
                zone_authority_transact_is_enabled: enabled,
                bump,
            }
        );
        Ok(())
    }

    /// Update the enabled flag, signed by the current authority.
    pub(crate) fn update_zone_config(&mut self, enabled: bool) -> Result<()> {
        let authority = self
            .zone_authority
            .as_ref()
            .ok_or_else(|| anyhow!("no authority"))?
            .insecure_clone();
        let zone_config = self.zone_config.ok_or_else(|| anyhow!("no zone config"))?;
        let ix = UpdateZoneConfig {
            authority: authority.pubkey(),
            zone_config,
            zone_authority_transact_is_enabled: enabled,
        }
        .instruction();
        let payer = self.payer.insecure_clone();
        send_transaction(&mut self.rpc, &[ix], &payer.pubkey(), &[&payer, &authority])?;
        Ok(())
    }

    /// Rotate the config owner to a fresh authority, signed by both the current and
    /// the new authority. The previous owner is kept for the negative path.
    pub(crate) fn rotate_zone_config_owner(&mut self) -> Result<()> {
        let authority = self
            .zone_authority
            .as_ref()
            .ok_or_else(|| anyhow!("no authority"))?
            .insecure_clone();
        let zone_config = self.zone_config.ok_or_else(|| anyhow!("no zone config"))?;
        let next = Keypair::new();
        let ix = UpdateZoneConfigOwner {
            authority: authority.pubkey(),
            zone_config,
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
        self.previous_zone_authority = Some(authority);
        self.zone_authority = Some(next);
        Ok(())
    }

    /// Attempt an update signed by the previous (rotated-out) owner; must fail with
    /// `UnauthorizedCaller`.
    pub(crate) fn old_owner_update_rejected(&mut self) -> Result<()> {
        let stale = self
            .previous_zone_authority
            .as_ref()
            .ok_or_else(|| anyhow!("no previous authority"))?
            .insecure_clone();
        let zone_config = self.zone_config.ok_or_else(|| anyhow!("no zone config"))?;
        let config_before = fetch_account(&self.rpc, &zone_config)?;
        let ix = UpdateZoneConfig {
            authority: stale.pubkey(),
            zone_config,
            zone_authority_transact_is_enabled: true,
        }
        .instruction();
        let payer = self.payer.insecure_clone();
        match send_transaction(&mut self.rpc, &[ix], &payer.pubkey(), &[&payer, &stale]) {
            Ok(_) => Err(anyhow!("stale owner update unexpectedly succeeded")),
            Err(error) => {
                assert_eq!(assert_custom_program_error(&error, UNAUTHORIZED_CALLER), 0);
                assert_account_unchanged(&self.rpc, &zone_config, &config_before)?;
                Ok(())
            }
        }
    }

    /// Attempt to create a zone config with a bogus (non-PDA) zone authority account,
    /// sent straight to SPP; the canonical derivation check must reject it with
    /// `InvalidZoneConfig`.
    pub(crate) fn create_invalid_zone_authority_rejected(&mut self) -> Result<()> {
        let payer = self.payer.insecure_clone();
        let mut ix = CreateZoneConfig {
            payer: payer.pubkey(),
            program_id: Address::new_from_array(ZONE_TEST_PROGRAM_ID),
            authority: Address::new_from_array(payer.pubkey().to_bytes()),
            zone_authority_transact_is_enabled: true,
        }
        .instruction()
        .map_err(|e| anyhow!("zone config PDA: {e}"))?;
        ix.program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        let canonical_zone_config = ix
            .accounts
            .get(2)
            .ok_or_else(|| anyhow!("missing zone config account meta"))?
            .pubkey;
        let config_before = fetch_optional_account(&self.rpc, &canonical_zone_config)?;
        // Swap the config account (the zone's `zone_auth` PDA, index 2) for a bogus
        // signer: the on-chain canonical derivation check must reject it.
        let meta = ix
            .accounts
            .get_mut(2)
            .ok_or_else(|| anyhow!("missing zone config account meta"))?;
        meta.pubkey = payer.pubkey();
        match send_transaction(&mut self.rpc, &[ix], &payer.pubkey(), &[&payer]) {
            Ok(_) => Err(anyhow!(
                "invalid zone authority create unexpectedly succeeded"
            )),
            Err(error) => {
                assert_eq!(assert_custom_program_error(&error, INVALID_ZONE_CONFIG), 0);
                assert_optional_account_unchanged(
                    &self.rpc,
                    &canonical_zone_config,
                    &config_before,
                )?;
                Ok(())
            }
        }
    }
}
