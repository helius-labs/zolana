use solana_address::Address;
use spr_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, HasherError, Poseidon,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicTransfer {
    pub mint: Address,
    pub is_deposit: bool,
    pub amount: u64,
    pub account: Address,
}

impl PublicTransfer {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let asset_hash = hash_bytes(self.mint.as_array())?;
        let amount = right_align(&self.amount.to_be_bytes());
        let is_deposit = right_align(&u64::from(self.is_deposit).to_be_bytes());
        let account_hash = hash_bytes(self.account.as_array())?;
        Poseidon::hashv(&[
            asset_hash.as_slice(),
            amount.as_slice(),
            is_deposit.as_slice(),
            account_hash.as_slice(),
        ])
    }
}

pub fn transaction_hash(
    private_tx_hash: &[u8; 32],
    transfers: &[PublicTransfer],
) -> Result<[u8; 32], HasherError> {
    if transfers.is_empty() {
        return Ok(*private_tx_hash);
    }
    let transfers_hash = transfers.iter().try_fold([0u8; 32], |chain, transfer| {
        Poseidon::hashv(&[chain.as_slice(), transfer.hash()?.as_slice()])
    })?;
    Poseidon::hashv(&[private_tx_hash.as_slice(), transfers_hash.as_slice()])
}
