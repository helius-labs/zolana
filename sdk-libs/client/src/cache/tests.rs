use super::*;
use bytemuck::Zeroable;
use solana_account::Account;
use solana_address::Address;
use spr_interface::{instruction::instruction_data::CreateCacheData, state::discriminator};

struct Chain {
    address: Address,
    account: Option<Account>,
}
impl Rpc for Chain {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        assert_eq!(address, self.address);
        Ok(self.account.clone())
    }
}

#[test]
fn authenticates_cache_metadata_and_each_requested_slot() {
    let create = CreateCache {
        payer: Address::new_from_array([1; 32]),
        data: CreateCacheData {
            write_authority: Address::new_from_array([2; 32]),
            nonce: 9,
            tree_id: 3,
            expires_at: 100,
        },
    };
    let mut cache = CacheAccount::zeroed();
    cache.discriminator = discriminator::CACHE;
    cache.rent_sponsor = create.payer;
    cache.write_authority = create.data.write_authority;
    cache.tree_id = create.data.tree_id.to_le_bytes();
    cache.expires_at = create.data.expires_at.to_le_bytes();
    cache.utxo_hashes[2] = [7; 32];
    cache.utxo_hashes[5] = [8; 32];
    let account = |cache: &CacheAccount| Account {
        owner: PROGRAM_ID_PUBKEY,
        data: bytemuck::bytes_of(cache).to_vec(),
        ..Default::default()
    };
    let check = |account, slots: &[(u8, [u8; 32])], now| {
        verify_cache(
            &Chain {
                address: create.cache(),
                account,
            },
            &create,
            slots,
            now,
        )
    };
    let slots = [(2, [7; 32]), (5, [8; 32])];
    check(Some(account(&cache)), &slots, 99).unwrap();
    for mutation in 0..7 {
        let mut wrong = cache;
        match mutation {
            0 => wrong.discriminator = 0,
            1 => wrong.rent_sponsor = Address::default(),
            2 => wrong.write_authority = Address::default(),
            3 => wrong.tree_id = 4u16.to_le_bytes(),
            4 => wrong.expires_at = 101i64.to_le_bytes(),
            5 => wrong.utxo_hashes[2] = [0; 32],
            _ => wrong.utxo_hashes[5] = [9; 32],
        }
        assert!(
            check(Some(account(&wrong)), &slots, 99).is_err(),
            "mutation {mutation}"
        );
    }
    let mut wrong_owner = account(&cache);
    wrong_owner.owner = Address::default();
    assert!(check(Some(wrong_owner), &slots, 99).is_err());
    let mut wrong_size = account(&cache);
    wrong_size.data.push(0);
    assert!(check(Some(wrong_size), &slots, 99).is_err());
    assert!(check(None, &slots, 99).is_err());
    assert!(check(Some(account(&cache)), &slots, 100).is_err());
    for invalid in [
        vec![],
        vec![slots[0], slots[0]],
        vec![(36, [7; 32])],
        vec![(0, [0; 32])],
    ] {
        assert!(check(Some(account(&cache)), &invalid, 99).is_err());
    }
}
