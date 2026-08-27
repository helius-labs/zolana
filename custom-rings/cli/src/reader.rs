use custom_ring_sdk::{
    AccountReadError, CustomRing, GrantReadAccess, ReaderKey, RevokeReadAccess,
    READ_ACCESS_COMPUTE_UNIT_LIMIT,
};
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::SolanaRpc;

use crate::{
    line,
    step::{no_hint, IdempotentStep, Observed, StepError, StepOutcome},
    Context, ContextError, ReaderCommand,
};

#[must_use]
pub struct ReaderAccess<'a> {
    pub ring: CustomRing,
    pub authority: &'a dyn Signer,
    pub reader: ReaderKey,
}

#[derive(Debug, Error)]
pub enum ReaderError {
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    Build(#[from] wincode::Error),
    #[error(transparent)]
    Step(#[from] StepError),
}

pub fn run(ctx: &mut Context, command: ReaderCommand) -> Result<(), ReaderError> {
    let authority = ctx.funded_authority()?;
    let (reader, outcome) = match command {
        ReaderCommand::Grant { reader } => (
            reader,
            ReaderAccess {
                ring: ctx.ring,
                authority: &authority,
                reader,
            }
            .grant(&ctx.rpc)?,
        ),
        ReaderCommand::Revoke { reader } => (
            reader,
            ReaderAccess {
                ring: ctx.ring,
                authority: &authority,
                reader,
            }
            .revoke(&ctx.rpc)?,
        ),
    };
    line(
        "reader",
        format_args!("{reader} {}", outcome_label(outcome)),
    );
    line("entry", ctx.ring.read_access_record_pda(&reader));
    Ok(())
}

fn outcome_label(outcome: StepOutcome) -> &'static str {
    match outcome {
        StepOutcome::Created => "granted",
        StepOutcome::Present => "already granted",
        StepOutcome::Closed => "revoked",
        StepOutcome::Absent => "not granted",
    }
}

impl ReaderAccess<'_> {
    pub fn grant(self, rpc: &SolanaRpc) -> Result<StepOutcome, ReaderError> {
        let observed = self.observed(rpc)?;
        Ok(self.step(rpc, "grant_read_access").ensure_present(
            observed,
            &[GrantReadAccess {
                ring: self.ring,
                payer: self.authority.pubkey(),
                authority: self.authority.pubkey(),
                reader: self.reader,
            }
            .instruction()?],
        )?)
    }

    pub fn revoke(self, rpc: &SolanaRpc) -> Result<StepOutcome, ReaderError> {
        let observed = self.observed(rpc)?;
        Ok(self.step(rpc, "revoke_read_access").ensure_absent(
            observed,
            &[RevokeReadAccess {
                ring: self.ring,
                authority: self.authority.pubkey(),
                reader: self.reader,
                rent_recipient: self.authority.pubkey(),
            }
            .instruction()?],
        )?)
    }

    fn observed(&self, rpc: &SolanaRpc) -> Result<Observed, ReaderError> {
        Ok(Observed::of(
            &self.ring.read_access_record(rpc, &self.reader)?,
        ))
    }

    fn step<'r>(&'r self, rpc: &'r SolanaRpc, name: &'static str) -> IdempotentStep<'r> {
        IdempotentStep {
            rpc,
            authority: self.authority,
            co_signers: &[],
            name,
            compute_unit_limit: READ_ACCESS_COMPUTE_UNIT_LIMIT,
            hint: no_hint,
        }
    }
}
