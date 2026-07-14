use solana_address::Address;
use swap_program::instructions::shared::u64_to_field;
use zolana_keypair::{
    hash::{hash_field, poseidon},
    KeypairError,
};

pub const FILL_MODE_DERIVED: u64 = 0;
pub const FILL_MODE_VERIFIABLE: u64 = 1;

pub const FILL_ENC_KDF_DOMAIN: u64 = 0x5357_4150_4649_4c4c;

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
    use zolana_keypair::{CompressedShieldedAddress, P256Pubkey, ViewingKey};

    use super::*;

    fn sample_viewing_pk(seed: u8) -> P256Pubkey {
        ViewingKey::from_seed(&[seed; 32], b"order-terms-test")
            .unwrap()
            .pubkey()
    }

    #[test]
    fn compressed_address_hash_matches_program() {
        let owner_hash = [3u8; 32];
        let viewing_pubkey = sample_viewing_pk(42);
        let ours = CompressedShieldedAddress {
            owner_hash,
            viewing_pubkey,
        }
        .hash()
        .unwrap();
        let theirs = swap_program::instructions::shared::maker_address_fe(
            &owner_hash,
            viewing_pubkey.as_bytes(),
        )
        .unwrap();
        assert_eq!(ours, theirs);
    }

    fn sample_terms(fill_mode: u64) -> OrderTerms {
        OrderTerms {
            destination_asset: Address::new_from_array([2u8; 32]),
            destination_amount: 250,
            destination: CompressedShieldedAddress {
                owner_hash: [7u8; 32],
                viewing_pubkey: sample_viewing_pk(9),
            }
            .hash()
            .expect("destination hash"),
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
