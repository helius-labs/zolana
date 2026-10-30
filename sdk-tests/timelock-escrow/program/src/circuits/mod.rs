#[cfg(all(not(xark), not(xark_client)))]
mod authority;
mod escrow;
mod state;
mod withdraw;

#[cfg(all(not(xark), not(xark_client)))]
pub use authority::escrow_authority;
pub use escrow::{ESCROW_TOKEN_INPUTS, Escrow, EscrowPrivateInputs, EscrowPublicInputs};
pub use state::EscrowTerms;
pub use withdraw::{Withdraw, WithdrawPrivateInputs, WithdrawPublicInputs};

#[cfg(all(not(xark), not(xark_client)))]
pub use escrow::{EscrowClient, EscrowPrivateInputsClient, EscrowPublicInputsClient};
#[cfg(all(not(xark), not(xark_client)))]
pub use withdraw::{WithdrawClient, WithdrawPrivateInputsClient, WithdrawPublicInputsClient};
