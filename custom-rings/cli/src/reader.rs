use custom_ring_sdk::{compute_unit_limit, CustomRing, InstructionTag, RingError};
use solana_signer::Signer;
use thiserror::Error;
use zolana_ring_client::ReaderKey;

use crate::{
    line,
    step::{no_hint, IdempotentStep, Observed, StepError, StepOutcome},
    Context, ContextError, ReaderCommand, Zolana,
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
    Ring(#[from] RingError),
    #[error(transparent)]
    Step(#[from] StepError),
}

pub fn run(ctx: &mut Context, command: ReaderCommand) -> Result<(), ReaderError> {
    let authority = ctx.funded_authority()?;
    let zolana = ctx.zolana();
    let (reader, outcome) = match command {
        ReaderCommand::Grant { reader } => (
            reader,
            ReaderAccess {
                ring: ctx.ring,
                authority: &authority,
                reader,
            }
            .grant(&zolana)?,
        ),
        ReaderCommand::Revoke { reader } => (
            reader,
            ReaderAccess {
                ring: ctx.ring,
                authority: &authority,
                reader,
            }
            .revoke(&zolana)?,
        ),
    };
    line(
        "reader",
        format_args!("{reader} {}", outcome_label(outcome)),
    );
    line("record", ctx.ring.read_access_record_pda(&reader));
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
    pub fn grant(self, zolana: &Zolana) -> Result<StepOutcome, ReaderError> {
        let observed = self.observed(zolana)?;
        let authority = self.authority.pubkey();
        let grant = self
            .ring
            .grant_read_access(authority, authority, self.reader)?;
        Ok(self
            .step(zolana, "grant_read_access")
            .ensure_present(observed, &[grant])?)
    }

    pub fn revoke(self, zolana: &Zolana) -> Result<StepOutcome, ReaderError> {
        let observed = self.observed(zolana)?;
        let authority = self.authority.pubkey();
        let revoke = self
            .ring
            .revoke_read_access(authority, self.reader, authority)?;
        Ok(self
            .step(zolana, "revoke_read_access")
            .ensure_absent(observed, &[revoke])?)
    }

    fn observed(&self, zolana: &Zolana) -> Result<Observed, ReaderError> {
        let record = self.ring.access_record(zolana.as_async(), &self.reader);
        Ok(Observed::of(&zolana.block_on(record)?))
    }

    fn step<'r>(&'r self, zolana: &'r Zolana, name: &'static str) -> IdempotentStep<'r> {
        IdempotentStep {
            rpc: zolana.rpc(),
            authority: self.authority,
            co_signers: &[],
            name,
            compute_unit_limit: compute_unit_limit(InstructionTag::GrantReadAccess),
            hint: no_hint,
        }
    }
}
