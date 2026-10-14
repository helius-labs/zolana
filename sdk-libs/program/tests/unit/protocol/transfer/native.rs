use solana_address::Address;
use zolana_program::{
    circuit::{constant, poseidon, value, Asset, Bytes},
    transaction_hash, PublicTransfer,
};

use super::vectors::{poseidon as native_poseidon, reference_hash, Vector, TRANSFERS};
use crate::{
    harness::{
        field::{be_bytes, MODULUS},
        fixture::per_vector,
    },
    protocol::{asset::vectors::field_of, utxo::vectors::blinding},
};

fn hash(transfer: &PublicTransfer) -> [u8; 32] {
    transfer.hash().expect("transfer hash")
}

fn private_tx_hash() -> [u8; 32] {
    blinding(31)
}

#[test]
fn the_transfer_hash_is_poseidon_of_asset_hash_amount_direction_and_account_hash() {
    assert_eq!(
        per_vector(&TRANSFERS, |vector| hash(&vector.transfer)),
        per_vector(&TRANSFERS, |vector| reference_hash(&vector.transfer))
    );
}

#[test]
fn every_single_field_change_changes_the_transfer_hash() {
    let changed = |vector: &Vector| {
        let transfer = vector.transfer;
        let base = hash(&transfer);
        [
            PublicTransfer {
                mint: Address::new_from_array([77u8; 32]),
                ..transfer
            },
            PublicTransfer {
                is_deposit: !transfer.is_deposit,
                ..transfer
            },
            PublicTransfer {
                amount: transfer.amount ^ 1,
                ..transfer
            },
            PublicTransfer {
                account: Address::new_from_array([78u8; 32]),
                ..transfer
            },
        ]
        .map(|changed| {
            let changed_hash = hash(&changed);
            (
                changed_hash == reference_hash(&changed),
                changed_hash == base,
            )
        })
    };
    assert_eq!(
        per_vector(&TRANSFERS, changed),
        per_vector(&TRANSFERS, |_| [(true, false); 4])
    );
}

#[test]
fn the_public_builtins_the_circuit_transfer_hash_composes_give_the_native_hash_on_constants() {
    let composed = |transfer: &PublicTransfer| {
        let hash = poseidon(&[
            Asset::constant(&transfer.mint).hash().expect("asset hash"),
            constant(transfer.amount),
            constant(u64::from(transfer.is_deposit)),
            Bytes::constant(transfer.account.as_array())
                .hash_bytes()
                .expect("account hash"),
        ])
        .expect("poseidon");
        value(&hash).expect("constant hash")
    };
    assert_eq!(
        per_vector(&TRANSFERS, |vector| composed(&vector.transfer)),
        per_vector(&TRANSFERS, |vector| field_of(&hash(&vector.transfer)))
    );
}

#[test]
fn with_no_transfer_the_transaction_hash_is_the_private_hash() {
    assert_eq!(
        transaction_hash(&private_tx_hash(), &[]).map_err(|error| error.to_string()),
        Ok(private_tx_hash())
    );
}

#[test]
fn the_transaction_hash_chains_the_transfer_hashes_from_zero_then_hashes_with_the_private_hash() {
    let transfers: Vec<PublicTransfer> = TRANSFERS.iter().map(|vector| vector.transfer).collect();
    let prefixes: Vec<[u8; 32]> = (1..=transfers.len())
        .map(|length| transaction_hash(&private_tx_hash(), &transfers[..length]).expect("hash"))
        .collect();
    let expected: Vec<[u8; 32]> = (1..=transfers.len())
        .map(|length| {
            let chain = transfers[..length]
                .iter()
                .fold([0u8; 32], |chain, transfer| {
                    native_poseidon(&[chain, reference_hash(transfer)])
                });
            native_poseidon(&[private_tx_hash(), chain])
        })
        .collect();
    assert_eq!(prefixes, expected);
}

#[test]
fn the_transaction_hash_depends_on_the_transfer_order_and_the_private_hash() {
    let (first, second) = (TRANSFERS[0].transfer, TRANSFERS[1].transfer);
    let hash = |private: [u8; 32], transfers: &[PublicTransfer]| {
        transaction_hash(&private, transfers).expect("transaction hash")
    };
    let ordered = hash(private_tx_hash(), &[first, second]);
    assert_eq!(
        (
            ordered == hash(private_tx_hash(), &[second, first]),
            ordered == hash(blinding(32), &[first, second]),
            hash(private_tx_hash(), &[first]) == private_tx_hash(),
        ),
        (false, false, false)
    );
}

#[test]
fn a_private_hash_of_at_least_p_is_refused_exactly_when_a_transfer_is_chained_to_it() {
    let p = be_bytes(MODULUS);
    let hash = |transfers: &[PublicTransfer]| {
        transaction_hash(&p, transfers).map_err(|error| error.to_string())
    };
    assert_eq!(
        (hash(&[]), hash(&[TRANSFERS[0].transfer])),
        (
            Ok(p),
            Err(
                "Poseidon hasher error: Input is larger than the modulus of the prime field."
                    .to_string()
            )
        )
    );
}
