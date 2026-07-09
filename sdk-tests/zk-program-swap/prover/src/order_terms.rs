use solana_address::Address;
use swap_program::instructions::shared::u64_to_field;
use zolana_keypair::{
    hash::{hash_field, poseidon},
    KeypairError,
};

pub const FILL_MODE_DERIVED: u64 = 0;
pub const FILL_MODE_VERIFIABLE: u64 = 1;

pub const FILL_ENC_KDF_DOMAIN: u64 = 0x5357_4150_4649_4c4c;

fn pack33(bytes: &[u8; 33]) -> ([u8; 32], [u8; 32]) {
    let mut lo = [0u8; 32];
    lo[1..32].copy_from_slice(&bytes[0..31]);
    let mut hi = [0u8; 32];
    hi[30] = bytes[31];
    hi[31] = bytes[32];
    (lo, hi)
}

pub fn maker_address_fe(
    owner_hash: &[u8; 32],
    viewing_pk: &[u8; 33],
) -> Result<[u8; 32], KeypairError> {
    let (lo, hi) = pack33(viewing_pk);
    poseidon(&[owner_hash, &lo, &hi])
}

#[derive(Debug, Clone, Copy)]
pub struct OrderTerms {
    pub destination_asset: Address,
    pub destination_amount: u64,
    pub destination: [u8; 32],
    pub expiry: u64,
    pub taker: [u8; 32],
    pub fill_mode: u64,
}

impl OrderTerms {
    pub fn data_hash(&self) -> Result<[u8; 32], KeypairError> {
        let destination_asset = hash_field(self.destination_asset.as_array())?;
        let destination_amount = u64_to_field(self.destination_amount);
        let expiry = u64_to_field(self.expiry);
        poseidon(&[
            &destination_asset,
            &destination_amount,
            &self.destination,
            &expiry,
            &self.taker,
            &u64_to_field(self.fill_mode),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maker_address_fe_matches_program() {
        let owner_hash = [3u8; 32];
        let mut viewing_pk = [0u8; 33];
        viewing_pk[0] = 2;
        viewing_pk[17] = 42;
        viewing_pk[32] = 5;
        let ours = maker_address_fe(&owner_hash, &viewing_pk).unwrap();
        let theirs =
            swap_program::instructions::shared::maker_address_fe(&owner_hash, &viewing_pk).unwrap();
        assert_eq!(ours, theirs);
    }

    fn sample_terms(fill_mode: u64) -> OrderTerms {
        let mut viewing_pk = [0u8; 33];
        viewing_pk[0] = 2;
        viewing_pk[32] = 9;
        OrderTerms {
            destination_asset: Address::new_from_array([2u8; 32]),
            destination_amount: 250,
            destination: maker_address_fe(&[7u8; 32], &viewing_pk).expect("destination fe"),
            expiry: 1_700_000_000,
            taker: [11u8; 32],
            fill_mode,
        }
    }

    #[test]
    fn data_hash_binds_fill_mode() {
        let derived = sample_terms(FILL_MODE_DERIVED).data_hash().unwrap();
        let verifiable = sample_terms(FILL_MODE_VERIFIABLE).data_hash().unwrap();
        assert_ne!(
            derived, verifiable,
            "escrow dataHash must distinguish the authorized fill instruction, so an escrow created for one fill cannot be settled by the other"
        );
    }
}
