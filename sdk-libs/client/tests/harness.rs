//! Declarative transfer case data shared by the proving matrix.

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

/// A single transfer proof case.
#[derive(Debug, Default)]
pub struct TransferHarness {
    pub(crate) plan: TransferPlan,
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

pub(crate) fn random_blinding(rng: &mut ThreadRng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b[1..]);
    b
}

pub(crate) fn random_32(rng: &mut ThreadRng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b
}
