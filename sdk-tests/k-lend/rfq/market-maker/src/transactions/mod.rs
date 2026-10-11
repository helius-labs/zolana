pub mod budget;
pub mod confirm;
pub mod coordinator;
pub mod kvault;
pub mod prove;
pub mod send;
pub mod shield;
pub mod steps;
pub mod transfer;

use std::sync::Arc;

use solana_address::Address;
use zolana_keypair::{ShieldedAddress, ShieldedKeypair};

#[derive(Clone)]
pub struct Identity {
    pub keys: Arc<ShieldedKeypair>,
    pub own: ShieldedAddress,
    pub payer: Address,
    pub tree: Address,
    pub tree_id: u16,
}
