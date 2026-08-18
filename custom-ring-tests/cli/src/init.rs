//! Ring initialization: the program config with the auditor key, then the ring's
//! registration with SPP.

use anyhow::{anyhow, Result};
use custom_ring_program::{error::CustomRingError, state::RingProgramConfig};
use custom_ring_sdk::{config_pda, ring_auth_pda, CreateConfig, InitSppRingConfig};
use solana_instruction::error::InstructionError;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;
use zolana_client::{ClientError, Rpc, SolanaRpc};
use zolana_interface::{error::ShieldedPoolError, state::RingConfig};
use zolana_keypair::P256Pubkey;

pub struct InitOutcome {
    pub config_created: bool,
    pub ring_registered: bool,
}

/// Idempotent: each step is skipped when its account already exists, so a rerun
/// after a partial failure finishes the job.
pub fn init(
    rpc: &SolanaRpc,
    authority: &dyn Signer,
    auditor_pk: P256Pubkey,
) -> Result<InitOutcome> {
    let mut outcome = InitOutcome {
        config_created: false,
        ring_registered: false,
    };

    if read_config(rpc)?.is_none() {
        let ix = CreateConfig {
            payer: authority.pubkey(),
            authority: authority.pubkey(),
            auditor_pubkey: auditor_pk,
        }
        .instruction();
        rpc.create_and_send_transaction(&[ix], authority.pubkey(), &[authority])
            .map_err(|error| explain(error, "create_config"))?;
        outcome.config_created = true;
    }

    if read_ring_config(rpc)?.is_none() {
        let ix = InitSppRingConfig {
            payer: authority.pubkey(),
            authority: authority.pubkey(),
        }
        .instruction();
        rpc.create_and_send_transaction(&[ix], authority.pubkey(), &[authority])
            .map_err(|error| explain(error, "init_spp_ring_config"))?;
        outcome.ring_registered = true;
    }

    Ok(outcome)
}

pub fn read_config<R: Rpc>(rpc: &R) -> Result<Option<RingProgramConfig>> {
    let Some(account) = rpc.get_account(config_pda())? else {
        return Ok(None);
    };
    bytemuck::try_from_bytes::<RingProgramConfig>(&account.data)
        .map(|config| Some(*config))
        .map_err(|_| anyhow!("config account has an unexpected layout"))
}

pub fn read_ring_config<R: Rpc>(rpc: &R) -> Result<Option<RingConfig>> {
    let Some(account) = rpc.get_account(ring_auth_pda())? else {
        return Ok(None);
    };
    bytemuck::try_from_bytes::<RingConfig>(&account.data)
        .map(|config| Some(*config))
        .map_err(|_| anyhow!("SPP ring config account has an unexpected layout"))
}

/// Name the two failures an operator can act on; everything else passes through.
fn explain(error: ClientError, step: &str) -> anyhow::Error {
    let hint = match custom_error_code(&error) {
        Some(code) if code == CustomRingError::UnauthorizedInitializer as u32 => {
            "the program was deployed with an upgrade authority and only that key may create the config"
        }
        Some(code) if code == ShieldedPoolError::UnauthorizedCaller as u32 => {
            "ring creation on this cluster is gated by the SPP ring creation authority"
        }
        _ => return anyhow::Error::from(error).context(format!("{step} failed")),
    };
    anyhow::Error::from(error).context(format!("{step} failed, {hint}"))
}

fn custom_error_code(error: &ClientError) -> Option<u32> {
    let ClientError::SolanaRpcTransaction { source, .. } = error else {
        return None;
    };
    match source.get_transaction_error()? {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => Some(code),
        _ => None,
    }
}
