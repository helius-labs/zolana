//! Shared helpers reused across the Squads zone instructions: Groth16 proof
//! verification and the public-input field math (`proof`), PDA derivation and
//! account creation (`pda`), the zone-auth CPI signer plus stubbed SPP CPIs
//! (`cpi`), and account closing (`close`). Per-account loaders live in their
//! instruction family folder (e.g. `instructions::zone_config::loader`).

pub mod close;
pub mod cpi;
pub mod key_encryption_proof;
pub mod pda;
pub mod proof;
pub mod shapes;
pub mod spp_deposit;
pub mod spp_merge;
pub mod spp_transact;
pub mod withdrawal;
pub mod zone_proof;
