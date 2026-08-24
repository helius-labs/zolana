use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{error::InstructionError, Instruction};
use solana_signer::Signer;
use solana_transaction_error::TransactionError;
use thiserror::Error;
use zolana_client::{ClientError, Rpc, SolanaRpc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    Present,
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepOutcome {
    Created,
    Present,
    Closed,
    Absent,
}

#[derive(Debug, Error)]
pub enum StepError {
    #[error("{name} failed, {hint}")]
    Hinted {
        name: &'static str,
        hint: &'static str,
        #[source]
        source: Box<ClientError>,
    },
    #[error("{name} failed")]
    Send {
        name: &'static str,
        #[source]
        source: Box<ClientError>,
    },
}

/// One authority-signed instruction, skipped when the chain already agrees.
#[must_use]
pub struct IdempotentStep<'a> {
    pub rpc: &'a SolanaRpc,
    pub authority: &'a dyn Signer,
    pub name: &'static str,
    pub compute_unit_limit: u32,
    pub hint: fn(u32) -> Option<&'static str>,
}

impl Observed {
    pub fn of<T>(value: &Option<T>) -> Self {
        match value {
            Some(_) => Self::Present,
            None => Self::Absent,
        }
    }
}

impl StepOutcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Present => "already present",
            Self::Closed => "closed",
            Self::Absent => "absent",
        }
    }
}

impl IdempotentStep<'_> {
    pub fn ensure_present(
        self,
        observed: Observed,
        instruction: Instruction,
    ) -> Result<StepOutcome, StepError> {
        match observed {
            Observed::Present => Ok(StepOutcome::Present),
            Observed::Absent => {
                self.send(instruction)?;
                Ok(StepOutcome::Created)
            }
        }
    }

    pub fn ensure_absent(
        self,
        observed: Observed,
        instruction: Instruction,
    ) -> Result<StepOutcome, StepError> {
        match observed {
            Observed::Absent => Ok(StepOutcome::Absent),
            Observed::Present => {
                self.send(instruction)?;
                Ok(StepOutcome::Closed)
            }
        }
    }

    fn send(&self, instruction: Instruction) -> Result<(), StepError> {
        let instructions = [
            ComputeBudgetInstruction::set_compute_unit_limit(self.compute_unit_limit),
            instruction,
        ];
        self.rpc
            .create_and_send_transaction(&instructions, self.authority.pubkey(), &[self.authority])
            .map_err(
                |source| match custom_error_code(&source).and_then(self.hint) {
                    Some(hint) => StepError::Hinted {
                        name: self.name,
                        hint,
                        source: Box::new(source),
                    },
                    None => StepError::Send {
                        name: self.name,
                        source: Box::new(source),
                    },
                },
            )?;
        Ok(())
    }
}

pub fn no_hint(_code: u32) -> Option<&'static str> {
    None
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_follows_the_option() {
        assert_eq!(Observed::of(&Some(1)), Observed::Present);
        assert_eq!(Observed::of::<u8>(&None), Observed::Absent);
    }
}
