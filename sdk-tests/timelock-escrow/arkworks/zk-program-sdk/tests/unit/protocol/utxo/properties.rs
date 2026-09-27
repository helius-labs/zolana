use ark_bn254::Fr;
use proptest::prelude::*;
use solana_address::Address;
use zolana_transaction::Mint;

use super::{
    fixtures::{UtxoHash, CLAIM_WIRE, HASH_BROKEN},
    r1cs::HASH_ROW,
    vectors::Preimage,
};
use crate::{
    harness::fixture::{assignment, first_unsatisfied, native, with_wires},
    protocol::owner::keys,
};

fn canonical() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>().prop_map(|mut bytes| {
        bytes[0] = 0;
        bytes
    })
}

prop_compose! {
    fn arbitrary_preimage()(
        seed in any::<u8>(),
        mint in any::<[u8; 32]>(),
        amount in any::<u64>(),
        blinding in canonical(),
        data_hash in prop::option::of(canonical()),
        ring in prop::option::of((canonical(), any::<[u8; 32]>())),
        tree_id in any::<u16>(),
    ) -> Preimage {
        Preimage {
            name: "random",
            key: keys::ed25519(seed),
            mint: Mint::new(Address::new_from_array(mint), 1),
            amount,
            blinding,
            data_hash,
            ring_data_hash: ring.map(|(data, _)| data),
            ring_program_id: ring.map(|(_, program)| Address::new_from_array(program)),
            tree_id,
            latest_tree_id: None,
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    #[test]
    fn every_random_preimage_hashes_to_its_native_commitment_natively_and_in_r1cs(
        preimage in arbitrary_preimage(),
    ) {
        let fixture = UtxoHash { hash: preimage.hash(), utxo: preimage.wallet() };
        prop_assert_eq!(
            (native(&fixture), first_unsatisfied::<UtxoHash>(&assignment(&fixture))),
            (Ok(()), None)
        );
    }

    #[test]
    fn a_commitment_claimed_for_another_amount_is_refused_natively_and_in_r1cs(
        preimage in arbitrary_preimage(),
        other_amount in any::<u64>(),
    ) {
        prop_assume!(other_amount != preimage.amount);
        let other = Preimage { amount: other_amount, ..preimage.clone() };
        let fixture = UtxoHash { hash: preimage.hash(), utxo: preimage.wallet() };
        let tampered = with_wires(assignment(&fixture), &[(CLAIM_WIRE, Fr::from(other.hash()))]);
        prop_assert_eq!(
            (
                native(&UtxoHash { hash: other.hash(), utxo: preimage.wallet() }),
                first_unsatisfied::<UtxoHash>(&tampered),
            ),
            (Err(HASH_BROKEN), Some(HASH_ROW))
        );
    }
}
