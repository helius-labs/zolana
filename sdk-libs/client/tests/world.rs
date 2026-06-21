//! The cucumber `World` and the declarative `TransferPlan` its steps accumulate.
//!
//! The build/prove/verify operation lives next to its cucumber steps in
//! `steps/transfer.rs` as an `impl TransferWorld` block; the plan and the small
//! fixture helpers here are `pub(crate)` so the step modules can drive the World.

use rand::{rngs::ThreadRng, RngCore};
use solana_address::Address;
use zolana_transaction::SOL_MINT;

/// Registry id for the single test SPL mint (SOL is the reserved id 1).
pub(crate) const SPL_ASSET_ID: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Owner {
    P256,
    Solana,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Asset {
    Sol,
    Spl,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct InputSpec {
    pub owner: Owner,
    pub asset: Asset,
    pub amount: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SendSpec {
    pub asset: Asset,
    pub amount: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct WithdrawSpec {
    pub asset: Asset,
    pub amount: u64,
}

#[derive(Debug, Default)]
pub(crate) struct TransferPlan {
    pub inputs: Vec<InputSpec>,
    pub sends: Vec<SendSpec>,
    pub withdraw: Option<WithdrawSpec>,
    pub declared_shape: bool,
}

/// The cucumber world: a declarative plan accumulated by the Given/When steps and
/// executed by the single `the proof verifies` Then. The step grammar is
/// rail-agnostic; ownership is named per input ("a P256 SOL input", "a Solana SPL
/// input"), so the same steps drive the eddsa, P256, and mixed-owner features.
#[derive(Debug, Default, cucumber::World)]
pub struct TransferWorld {
    pub(crate) plan: TransferPlan,
}

pub(crate) fn owner(word: &str) -> Owner {
    match word {
        "P256" => Owner::P256,
        "Solana" => Owner::Solana,
        other => panic!("unknown owner type: {other}"),
    }
}

pub(crate) fn asset_kind(word: &str) -> Asset {
    match word {
        "SOL" => Asset::Sol,
        "SPL" => Asset::Spl,
        other => panic!("unknown asset: {other}"),
    }
}

pub(crate) fn spl_mint() -> Address {
    Address::new_from_array([2u8; 32])
}

pub(crate) fn asset_addr(asset: Asset) -> Address {
    match asset {
        Asset::Sol => SOL_MINT,
        Asset::Spl => spl_mint(),
    }
}

pub(crate) fn random_blinding(rng: &mut ThreadRng) -> [u8; 31] {
    let mut b = [0u8; 31];
    rng.fill_bytes(&mut b);
    b
}

pub(crate) fn random_32(rng: &mut ThreadRng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b
}
