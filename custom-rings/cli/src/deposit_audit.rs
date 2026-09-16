use custom_ring_sdk::{AccountReadError, SetDepositAudit, SET_DEPOSIT_AUDIT_COMPUTE_UNIT_LIMIT};
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
    Account(#[from] AccountReadError),
    #[error(transparent)]
    Build(#[from] wincode::Error),
    #[error(transparent)]
    Client(Box<ClientError>),
}

pub fn run(ctx: &mut Context, command: DepositAuditCommand) -> Result<(), DepositAuditError> {
    match command {
        DepositAuditCommand::Set { required } => {
            let authority = ctx.funded_authority()?;
            let instruction = SetDepositAudit {
                ring: ctx.ring,
                payer: authority.pubkey(),
                authority: authority.pubkey(),
                required,
            }
            .instruction()?;
            ctx.rpc
                .create_and_send_transaction(
                    &[instruction],
                    authority.pubkey(),
                    &[&authority],
                    ComputeBudgetConfig::new(SET_DEPOSIT_AUDIT_COMPUTE_UNIT_LIMIT),
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
            let required = ctx.ring.read_deposit_audit(&ctx.rpc)?;
            line(
                "deposit audit",
                if required { "required" } else { "optional" },
            );
        }
    }
    Ok(())
}
