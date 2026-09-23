use custom_ring_sdk::{
    AccountReadError, ClearCoSigner, CoSignScope, CoSignThreshold, CustomRingCoSigner, SetCoSigner,
    SET_CO_SIGNER_COMPUTE_UNIT_LIMIT,
};
use serde::{Deserialize, Serialize};
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{ClientError, ComputeBudgetConfig, Rpc};

use crate::{
    config::{Base58Address, CoSignerSpec, Mint},
    line, CoSignerCommand, Context, ContextError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CoSignClass {
    Transfers,
    Deposits,
    Withdrawals,
}

#[derive(Debug, Error)]
pub enum CoSignerError {
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    Build(#[from] wincode::Error),
    #[error(transparent)]
    Client(Box<ClientError>),
    #[error("no signer given and ring.toml has no [cosigner] table")]
    NoSigner,
    #[error("the co-signer gates no operation class")]
    EmptyScope,
    #[error("the ring has no co-signer")]
    NotSet,
}

impl CoSignClass {
    pub const ALL: [Self; 3] = [Self::Transfers, Self::Deposits, Self::Withdrawals];

    pub const fn scope(self) -> CoSignScope {
        match self {
            Self::Transfers => CoSignScope::TRANSFERS,
            Self::Deposits => CoSignScope::DEPOSITS,
            Self::Withdrawals => CoSignScope::WITHDRAWALS,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Transfers => "transfers",
            Self::Deposits => "deposits",
            Self::Withdrawals => "withdrawals",
        }
    }
}

pub fn run(ctx: &mut Context, command: CoSignerCommand) -> Result<(), CoSignerError> {
    match command {
        CoSignerCommand::Set {
            signer,
            scope,
            threshold,
        } => {
            let spec = match signer {
                Some(signer) => CoSignerSpec {
                    key: Base58Address(signer),
                    scope,
                    thresholds: threshold,
                },
                None => ctx.config.cosigner.clone().ok_or(CoSignerError::NoSigner)?,
            };
            let authority = ctx.funded_authority()?;
            let instruction = SetCoSigner {
                ring: ctx.ring,
                payer: authority.pubkey(),
                authority: authority.pubkey(),
                signer: spec.key.0,
                scope: spec.scope().ok_or(CoSignerError::EmptyScope)?,
                thresholds: spec
                    .thresholds
                    .iter()
                    .map(|row| CoSignThreshold {
                        mint: row.mint.0,
                        amount: row.above,
                    })
                    .collect(),
            }
            .instruction()?;
            ctx.rpc.create_and_send_transaction(
                &[instruction],
                authority.pubkey(),
                &[&authority],
                ComputeBudgetConfig::new(SET_CO_SIGNER_COMPUTE_UNIT_LIMIT),
            )?;
            line("co-signer", format_args!("{} set", spec.key.0));
        }
        CoSignerCommand::Clear => {
            let authority = ctx.funded_authority()?;
            if ctx.ring.read_cosigner(&ctx.rpc)?.is_none() {
                return Err(CoSignerError::NotSet);
            }
            ctx.rpc.create_and_send_transaction(
                &[ClearCoSigner {
                    ring: ctx.ring,
                    authority: authority.pubkey(),
                    rent_recipient: authority.pubkey(),
                }
                .instruction()],
                authority.pubkey(),
                &[&authority],
                ComputeBudgetConfig::new(SET_CO_SIGNER_COMPUTE_UNIT_LIMIT),
            )?;
            line("co-signer", "cleared");
        }
        CoSignerCommand::Show => {}
    }
    match ctx.ring.read_cosigner(&ctx.rpc)? {
        Some(cosigner) => print(&cosigner),
        None => line("co-signer", "none"),
    }
    Ok(())
}

pub(crate) fn print(cosigner: &CustomRingCoSigner) {
    line("co-signer", cosigner.signer);
    line("scope", scope_names(cosigner.scope).join(","));
    for threshold in &cosigner.thresholds {
        line(
            "threshold",
            format_args!("{} above {}", Mint(threshold.mint), threshold.amount),
        );
    }
}

fn scope_names(scope: CoSignScope) -> Vec<&'static str> {
    CoSignClass::ALL
        .into_iter()
        .filter(|class| scope.contains(class.scope()))
        .map(CoSignClass::name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_threshold_parses_the_sol_alias_and_refuses_a_bare_amount() {
        use crate::config::ThresholdSpec;

        let sol: ThresholdSpec = "sol=5".parse().expect("parses");
        assert_eq!(sol.mint.0, zolana_transaction::SOL_MINT);
        assert_eq!(sol.above, 5);
        assert_eq!(
            "5".parse::<ThresholdSpec>(),
            Err(crate::config::ThresholdParseError::Shape)
        );
        assert!(matches!(
            "sol=many".parse::<ThresholdSpec>(),
            Err(crate::config::ThresholdParseError::Amount(_))
        ));
        assert!(matches!(
            "mint=1".parse::<ThresholdSpec>(),
            Err(crate::config::ThresholdParseError::Mint(_))
        ));
    }

    #[test]
    fn scope_names_follow_the_classes() {
        assert_eq!(
            scope_names(CoSignScope::TRANSFERS | CoSignScope::WITHDRAWALS),
            ["transfers", "withdrawals"]
        );
        let spec = CoSignerSpec {
            key: Base58Address(solana_address::Address::default()),
            scope: vec![CoSignClass::Deposits],
            thresholds: Vec::new(),
        };
        assert_eq!(spec.scope(), Some(CoSignScope::DEPOSITS));
    }
}
