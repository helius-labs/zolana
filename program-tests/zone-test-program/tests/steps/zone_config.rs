//! `create_zone_config` / `update_zone_config` / `update_zone_config_owner` admin
//! steps, the World operations, and the full-struct state assert.

use anyhow::{anyhow, Result};
use cucumber::{given, then, when};
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

use crate::{localnet::send_transaction, ZoneLifecycleWorld};

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

impl ZoneLifecycleWorld {
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
    fn assert_zone_config_created(&self) -> Result<()> {
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
                zone_authority_transact_is_enabled: true,
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
        send_transaction(&mut self.rpc, &[ix], &authority.pubkey(), &[&authority])?;
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
        send_transaction(
            &mut self.rpc,
            &[ix],
            &authority.pubkey(),
            &[&authority, &next],
        )?;
        self.previous_zone_authority = Some(authority);
        self.zone_authority = Some(next);
        Ok(())
    }

    /// Attempt an update signed by the previous (rotated-out) owner; must fail with
    /// `UnauthorizedCaller`.
    fn old_owner_update_rejected(&mut self) -> Result<()> {
        let stale = self
            .previous_zone_authority
            .as_ref()
            .ok_or_else(|| anyhow!("no previous authority"))?
            .insecure_clone();
        let zone_config = self.zone_config.ok_or_else(|| anyhow!("no zone config"))?;
        let ix = UpdateZoneConfig {
            authority: stale.pubkey(),
            zone_config,
            zone_authority_transact_is_enabled: true,
        }
        .instruction();
        match send_transaction(&mut self.rpc, &[ix], &stale.pubkey(), &[&stale]) {
            Ok(_) => Err(anyhow!("stale owner update unexpectedly succeeded")),
            Err(error) => {
                assert_rpc_custom_error(&error, UNAUTHORIZED_CALLER);
                Ok(())
            }
        }
    }

    /// Attempt to create a zone config with a bogus (non-PDA) zone authority account,
    /// sent straight to SPP; the canonical derivation check must reject it with
    /// `InvalidZoneConfig`.
    fn create_invalid_zone_authority_rejected(&mut self) -> Result<()> {
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
                assert_rpc_custom_error(&error, INVALID_ZONE_CONFIG);
                Ok(())
            }
        }
    }
}

/// Assert a transaction failed with the given custom program error, by code (e.g.
/// `7003`) or its hex form (e.g. `0x1b6b`), as the validator surfaces it.
#[track_caller]
fn assert_rpc_custom_error(error: &anyhow::Error, code: u32) {
    let message = error.to_string().to_lowercase();
    let hex = format!("0x{code:x}");
    assert!(
        message.contains(&code.to_string()) || message.contains(&hex),
        "expected custom program error {code} ({hex}), got: {message}"
    );
}

#[when(expr = "the authority creates an enabled zone config")]
fn create_enabled(world: &mut ZoneLifecycleWorld) {
    world
        .create_enabled_zone_config()
        .expect("create zone config");
}

#[then(expr = "the zone config is owned by the authority and enabled")]
fn config_created(world: &mut ZoneLifecycleWorld) {
    world
        .assert_zone_config_created()
        .expect("assert zone config created");
}

#[when(expr = "the authority disables zone authority transact")]
fn disable(world: &mut ZoneLifecycleWorld) {
    world.update_zone_config(false).expect("disable");
}

#[then(expr = "the zone config is disabled and still owned by the authority")]
fn config_disabled(world: &mut ZoneLifecycleWorld) {
    let authority = world.zone_authority.as_ref().expect("authority").pubkey();
    let state = world.zone_config_state().expect("zone config state");
    assert_eq!(state.authority, authority);
    assert!(!state.zone_authority_transact_is_enabled);
}

#[when(expr = "the authority rotates the zone config owner")]
fn rotate(world: &mut ZoneLifecycleWorld) {
    world.rotate_zone_config_owner().expect("rotate owner");
}

#[then(expr = "the zone config is owned by the new owner")]
fn config_new_owner(world: &mut ZoneLifecycleWorld) {
    let next = world.zone_authority.as_ref().expect("authority").pubkey();
    let state = world.zone_config_state().expect("zone config state");
    assert_eq!(state.authority, next);
}

#[then(expr = "the old owner cannot update the zone config")]
fn old_owner_rejected(world: &mut ZoneLifecycleWorld) {
    world
        .old_owner_update_rejected()
        .expect("stale owner rejected with UnauthorizedCaller");
}

#[then(expr = "a zone config with an invalid zone authority cannot be created")]
fn invalid_authority_rejected(world: &mut ZoneLifecycleWorld) {
    world
        .create_invalid_zone_authority_rejected()
        .expect("invalid zone authority rejected with InvalidZoneConfig");
}

#[given(expr = "a zone config exists")]
fn zone_config_exists(world: &mut ZoneLifecycleWorld) {
    if world.zone_config.is_none() {
        world
            .create_enabled_zone_config()
            .expect("create zone config");
    }
}
