use ark_bn254::Fr;
use proptest::prelude::*;
use solana_address::Address;
use zolana_hasher::primitives::hash_bytes;
use zolana_transaction::Mint;

use super::{
    fixtures::{AssetHash, IsEqual, HASH_BROKEN, HASH_WIRE},
    r1cs::HASH_ROW,
    vectors::field_of,
};
use crate::harness::fixture::{assignment, first_unsatisfied, native, with_wires};

fn arbitrary_mint() -> impl Strategy<Value = Mint> {
    (any::<[u8; 32]>(), any::<u64>())
        .prop_map(|(bytes, asset_id)| Mint::new(Address::new_from_array(bytes), asset_id))
}

fn hash(mint: &Mint) -> zk_program_sdk::circuit::Field {
    field_of(&hash_bytes(mint.asset.as_array()).expect("hash_bytes"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn every_mint_hashes_to_its_native_hash_natively_and_in_r1cs(mint in arbitrary_mint()) {
        let fixture = AssetHash { hash: hash(&mint), mint };
        let honest = assignment(&fixture);
        prop_assert_eq!(
            (native(&fixture), first_unsatisfied::<AssetHash>(&honest)),
            (Ok(()), None)
        );
    }

    #[test]
    fn a_hash_claimed_for_another_mint_is_refused_natively_and_in_r1cs(
        mint in arbitrary_mint(),
        other in arbitrary_mint(),
    ) {
        prop_assume!(mint.asset != other.asset);
        let fixture = AssetHash { hash: hash(&mint), mint };
        let tampered = with_wires(assignment(&fixture), &[(HASH_WIRE, Fr::from(hash(&other)))]);
        prop_assert_eq!(
            (
                native(&AssetHash { hash: hash(&other), mint }),
                first_unsatisfied::<AssetHash>(&tampered),
            ),
            (Err(HASH_BROKEN), Some(HASH_ROW))
        );
    }

    #[test]
    fn is_equal_holds_exactly_for_equal_mint_bytes(
        mint in arbitrary_mint(),
        other in arbitrary_mint(),
        same in any::<bool>(),
    ) {
        let right = if same { mint } else { other };
        let equal = mint.asset == right.asset;
        prop_assert_eq!(
            (
                native(&IsEqual { left: mint, right, claimed: equal }),
                native(&IsEqual { left: mint, right, claimed: !equal }).is_err(),
            ),
            (Ok(()), true)
        );
    }
}
