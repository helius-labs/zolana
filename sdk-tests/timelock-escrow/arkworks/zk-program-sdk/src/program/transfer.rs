use solana_address::Address;
use zolana_hasher::{primitives::hash_bytes, Hasher, HasherError, Poseidon};

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
        let amount = integer(self.amount);
        let is_deposit = integer(u64::from(self.is_deposit));
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

fn integer(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (target, source) in bytes.iter_mut().rev().zip(value.to_be_bytes().iter().rev()) {
        *target = *source;
    }
    bytes
}
