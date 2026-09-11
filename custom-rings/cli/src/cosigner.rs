use std::str::FromStr;

use custom_ring_sdk::{
    AccountReadError, ClearCoSigner, CustomRingCoSigner, SetCoSigner, COSIGN_DEPOSITS,
    COSIGN_TRANSFERS, COSIGN_WITHDRAWALS, SET_CO_SIGNER_COMPUTE_UNIT_LIMIT,
};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{ClientError, Rpc};
use zolana_transaction::SOL_MINT;

use crate::{config::CoSignerSpec, line, ui, ui::Icon, Context, ContextError, CosignerCommand};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CosignScope {
    Transfers,
    Deposits,
    Withdrawals,
}

impl CosignScope {
    pub const fn bit(self) -> u8 {
        match self {
            Self::Transfers => COSIGN_TRANSFERS,
            Self::Deposits => COSIGN_DEPOSITS,
            Self::Withdrawals => COSIGN_WITHDRAWALS,
        }
    }
}

/// `<mint>=<amount>`, `sol` for the native token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Threshold {
    pub mint: Address,
    pub above: u64,
}

impl FromStr for Threshold {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, String> {
        let (mint, above) = value
            .split_once('=')
            .ok_or_else(|| "expected <mint>=<amount>".to_owned())?;
        let mint = if mint.eq_ignore_ascii_case("sol") {
            SOL_MINT
        } else {
            mint.parse().map_err(|_| format!("{mint} is not a mint"))?
        };
        let above = above
            .parse()
            .map_err(|_| format!("{above} is not an amount"))?;
        Ok(Self { mint, above })
    }
}

#[derive(Debug, Error)]
pub enum CosignerError {
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
    #[error("the ring has no co-signer")]
    NotSet,
}

impl From<ClientError> for CosignerError {
    fn from(error: ClientError) -> Self {
        Self::Client(Box::new(error))
    }
}

pub fn run(ctx: &mut Context, command: CosignerCommand) -> Result<(), CosignerError> {
    match command {
        CosignerCommand::Set {
            signer,
            scope,
            threshold,
        } => {
            let spec = match signer {
                Some(signer) => CoSignerSpec {
                    key: crate::config::Base58Address(signer),
                    scope,
                    thresholds: threshold
                        .iter()
                        .map(|row| crate::config::ThresholdSpec {
                            mint: crate::config::Base58Address(row.mint),
                            above: row.above,
                        })
                        .collect(),
                },
                None => ctx.config.cosigner.clone().ok_or(CosignerError::NoSigner)?,
            };
            let authority = ctx.funded_authority()?;
            let instruction = SetCoSigner {
                ring: ctx.ring,
                payer: authority.pubkey(),
                authority: authority.pubkey(),
                signer: spec.key.0,
                scope: spec.scope_bits(),
                thresholds: spec
                    .thresholds
                    .iter()
                    .map(|row| (row.mint.0, row.above))
                    .collect(),
            }
            .instruction()?;
            ctx.rpc.create_and_send_transaction(
                &[
                    ComputeBudgetInstruction::set_compute_unit_limit(
                        SET_CO_SIGNER_COMPUTE_UNIT_LIMIT,
                    ),
                    instruction,
                ],
                authority.pubkey(),
                &[&authority],
            )?;
            ui::heading(Icon::Auditor, &format!("co-signer {} set", spec.key.0));
        }
        CosignerCommand::Clear => {
            let authority = ctx.funded_authority()?;
            if ctx.ring.read_cosigner(&ctx.rpc)?.is_none() {
                return Err(CosignerError::NotSet);
            }
            ctx.rpc.create_and_send_transaction(
                &[
                    ComputeBudgetInstruction::set_compute_unit_limit(
                        SET_CO_SIGNER_COMPUTE_UNIT_LIMIT,
                    ),
                    ClearCoSigner {
                        ring: ctx.ring,
                        authority: authority.pubkey(),
                        rent_recipient: authority.pubkey(),
                    }
                    .instruction(),
                ],
                authority.pubkey(),
                &[&authority],
            )?;
            line("co-signer", "cleared");
        }
        CosignerCommand::Show => {}
    }
    match ctx.ring.read_cosigner(&ctx.rpc)? {
        Some(cosigner) => print(&cosigner),
        None => line("co-signer", "none"),
    }
    Ok(())
}

pub fn print(cosigner: &CustomRingCoSigner) {
    line("co-signer", cosigner.signer);
    line("scope", scope_names(cosigner.scope).join(","));
    for (mint, above) in &cosigner.thresholds {
        let mint = if *mint == SOL_MINT {
            "sol".to_owned()
        } else {
            mint.to_string()
        };
        line("threshold", format_args!("{mint} above {above}"));
    }
}

fn scope_names(scope: u8) -> Vec<&'static str> {
    [
        (COSIGN_TRANSFERS, "transfers"),
        (COSIGN_DEPOSITS, "deposits"),
        (COSIGN_WITHDRAWALS, "withdrawals"),
    ]
    .into_iter()
    .filter(|(bit, _)| scope & bit != 0)
    .map(|(_, name)| name)
    .collect()
}
