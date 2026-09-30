use proptest::prelude::*;
use solana_address::Address;
use zolana_program::{transaction_hash, PublicTransfer};

use super::vectors::{poseidon, reference_hash};

prop_compose! {
    fn arbitrary_transfer()(
        mint in any::<[u8; 32]>(),
        is_deposit in any::<bool>(),
        amount in any::<u64>(),
        account in any::<[u8; 32]>(),
    ) -> PublicTransfer {
        PublicTransfer {
            mint: Address::new_from_array(mint),
            is_deposit,
            amount,
            account: Address::new_from_array(account),
        }
    }
}

fn canonical() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>().prop_map(|mut bytes| {
        bytes[0] = 0;
        bytes
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn every_transfer_hashes_to_the_reference_hash(transfer in arbitrary_transfer()) {
        prop_assert_eq!(transfer.hash().expect("transfer hash"), reference_hash(&transfer));
    }

    #[test]
    fn every_transaction_hash_is_the_chain_definition(
        private in canonical(),
        transfers in prop::collection::vec(arbitrary_transfer(), 0..4),
    ) {
        let chain = transfers
            .iter()
            .fold([0u8; 32], |chain, transfer| poseidon(&[chain, reference_hash(transfer)]));
        let expected = if transfers.is_empty() { private } else { poseidon(&[private, chain]) };
        prop_assert_eq!(transaction_hash(&private, &transfers).expect("transaction hash"), expected);
    }
}
