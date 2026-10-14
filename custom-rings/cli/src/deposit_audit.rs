use custom_ring_sdk::{compute_unit_limit, InstructionTag, RingError};
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{ClientError, ComputeBudgetConfig, Rpc};

use crate::{
    config::{ConfigError, RingConfig},
    line, Context, ContextError, DepositAuditCommand,
};

#[derive(Debug, Error)]
pub enum DepositAuditError {
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Ring(#[from] RingError),
    #[error(transparent)]
    Client(Box<ClientError>),
}

pub fn run(ctx: &mut Context, command: DepositAuditCommand) -> Result<(), DepositAuditError> {
    match command {
        DepositAuditCommand::Set { required } => {
            let authority = ctx.funded_authority()?;
            let instruction =
                ctx.ring
                    .set_deposit_audit(authority.pubkey(), authority.pubkey(), required)?;
            ctx.rpc
                .create_and_send_transaction(
                    &[instruction],
                    authority.pubkey(),
                    &[&authority],
                    ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::SetDepositAudit)),
                )
                .map_err(|error| DepositAuditError::Client(Box::new(error)))?;
            RingConfig::set_deposit_audit(&ctx.config_path, required)?;
            ctx.config.deposit_audit = required;
            line(
                "deposit audit",
                if required { "required" } else { "optional" },
            );
        }
        DepositAuditCommand::Show => {
            let zolana = ctx.zolana();
            let required = zolana.block_on(ctx.ring.deposit_audit(zolana.as_async()))?;
            line(
                "deposit audit",
                if required { "required" } else { "optional" },
            );
        }
    }
    Ok(())
}
