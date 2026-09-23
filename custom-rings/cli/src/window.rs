use custom_ring_sdk::{
    AccountReadError, ClearSpendWindow, CustomRingSpendWindow, SetSpendWindow,
    SET_SPEND_WINDOW_COMPUTE_UNIT_LIMIT,
};
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{ClientError, ComputeBudgetConfig, Rpc};

use crate::{config::Mint, line, Context, ContextError, WindowCommand};

#[derive(Debug, Error)]
pub enum WindowError {
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    Build(#[from] wincode::Error),
    #[error(transparent)]
    Client(Box<ClientError>),
    #[error("the mint has no spend window")]
    NotSet,
}

pub fn run(ctx: &mut Context, command: WindowCommand) -> Result<(), WindowError> {
    let mint = match command {
        WindowCommand::Set {
            mint,
            slots,
            deposit_cap,
            withdrawal_cap,
        } => {
            let authority = ctx.funded_authority()?;
            let instruction = SetSpendWindow {
                ring: ctx.ring,
                payer: authority.pubkey(),
                authority: authority.pubkey(),
                mint: mint.0,
                window_slots: slots,
                deposit_cap,
                withdrawal_cap,
            }
            .instruction()?;
            ctx.rpc.create_and_send_transaction(
                &[instruction],
                authority.pubkey(),
                &[&authority],
                ComputeBudgetConfig::new(SET_SPEND_WINDOW_COMPUTE_UNIT_LIMIT),
            )?;
            line("spend window", format_args!("{mint} set"));
            mint
        }
        WindowCommand::Clear { mint } => {
            let authority = ctx.funded_authority()?;
            if ctx.ring.read_spend_window(&ctx.rpc, &mint.0)?.is_none() {
                return Err(WindowError::NotSet);
            }
            ctx.rpc.create_and_send_transaction(
                &[ClearSpendWindow {
                    ring: ctx.ring,
                    authority: authority.pubkey(),
                    mint: mint.0,
                    rent_recipient: authority.pubkey(),
                }
                .instruction()],
                authority.pubkey(),
                &[&authority],
                ComputeBudgetConfig::new(SET_SPEND_WINDOW_COMPUTE_UNIT_LIMIT),
            )?;
            line("spend window", "cleared");
            mint
        }
        WindowCommand::Show { mint } => mint,
    };
    match ctx.ring.read_spend_window(&ctx.rpc, &mint.0)? {
        Some(window) => print(&window),
        None => line("spend window", format_args!("{mint} uncapped")),
    }
    Ok(())
}

fn print(window: &CustomRingSpendWindow) {
    line("spend window", Mint(window.mint));
    line("slots", window.window_slots);
    line("window start", window.window_start_slot);
    line(
        "deposits",
        format_args!("{} of {}", window.deposited, cap(window.deposit_cap)),
    );
    line(
        "withdrawals",
        format_args!("{} of {}", window.withdrawn, cap(window.withdrawal_cap)),
    );
}

fn cap(cap: u64) -> String {
    if cap == 0 {
        "uncapped".to_owned()
    } else {
        cap.to_string()
    }
}
