use solana_address::Address;
use zk_program_sdk::{
    circuit::{constant, value, Asset, CircuitVar, Field, Utxo},
    conversion::{Allocator, ProofInput},
    CircuitError,
};
use zolana_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, Poseidon,
};
use zolana_interface::{tree_slot::tree_id_field, DUMMY_DOMAIN, UTXO_DOMAIN};
use zolana_transaction::{
    utxo::{ProofInputUtxo, SppProofInputUtxo, SppProofOutputUtxo},
    Mint, WalletUtxo,
};

use super::{
    fixtures::{hashed_dummy_preimages_commitment, Carried, UtxoHash, CARRIED_BROKEN, HASH_BROKEN},
    vectors::{blinding, dummy, preimages, Preimage, TREE_ID},
};
use crate::{
    harness::{
        field::{be_bytes, MODULUS, MODULUS_MINUS_1},
        fixture::{check_constraints, native, per_vector},
    },
    protocol::{asset::vectors::field_of, owner::keys},
};

fn circuit(wallet: &WalletUtxo) -> Utxo {
    wallet
        .instantiate(&Allocator::native())
        .expect("native utxo")
}

fn constant_of(var: &CircuitVar) -> Field {
    value(var).expect("constant")
}

fn hash_of(utxo: &Utxo) -> Field {
    constant_of(&utxo.hash().expect("utxo hash"))
}

fn fixture(preimage: &Preimage) -> UtxoHash {
    UtxoHash {
        hash: preimage.hash(),
        utxo: preimage.wallet(),
    }
}

fn var_of(bytes: &[u8; 32]) -> CircuitVar {
    constant(field_of(bytes))
}

#[test]
fn every_preimage_hashes_to_the_native_utxo_commitment() {
    let preimages = preimages();
    assert_eq!(
        per_vector(&preimages, |preimage| (
            hash_of(&circuit(&preimage.wallet())),
            field_of(&preimage.fields().hash().expect("proof input hash")),
            field_of(&preimage.wallet().utxo_hash),
        )),
        per_vector(&preimages, |preimage| (
            preimage.hash(),
            preimage.hash(),
            preimage.hash()
        ))
    );
}

#[test]
fn every_preimage_hashes_when_spent_to_its_native_output_commitment() {
    let preimages = preimages();
    assert_eq!(
        per_vector(&preimages, |preimage| hash_of(&circuit(&preimage.wallet()))),
        per_vector(&preimages, |preimage| {
            let output = SppProofOutputUtxo {
                asset: preimage.mint,
                amount: preimage.amount,
                blinding: preimage.blinding,
                ring_program_id: preimage.ring_program_id,
                ring_data_hash: preimage.ring_data_hash,
                data_hash: preimage.data_hash,
                owner_address: Some(preimage.key.address),
                ..SppProofOutputUtxo::default()
            };
            field_of(&output.hash(preimage.tree_id).expect("output commitment"))
        })
    );
}

#[test]
fn every_preimage_holds_natively_with_its_native_commitment() {
    let preimages = preimages();
    assert_eq!(
        per_vector(&preimages, |preimage| native(&fixture(preimage))),
        per_vector(&preimages, |_| Ok(()))
    );
}

#[test]
fn a_claimed_commitment_of_another_preimage_breaks_exactly_the_hash_rule() {
    let preimages = preimages();
    let refused: Vec<_> = preimages
        .iter()
        .enumerate()
        .map(|(index, preimage)| {
            native(&UtxoHash {
                hash: preimages[(index + 1) % preimages.len()].hash(),
                utxo: preimage.wallet(),
            })
        })
        .collect();
    assert_eq!(refused, vec![Err(HASH_BROKEN); preimages.len()]);
}

#[test]
fn the_circuit_fields_are_the_native_proof_input_fields() {
    let preimages = preimages();
    assert_eq!(
        per_vector(&preimages, |preimage| {
            let utxo = circuit(&preimage.wallet());
            [
                constant_of(&utxo.domain),
                constant_of(&utxo.tree_id),
                constant_of(&utxo.asset.hash().expect("asset hash")),
                constant_of(&utxo.owner.hash().expect("owner hash")),
                constant_of(&utxo.blinding),
                constant_of(&utxo.data_hash),
                constant_of(&utxo.ring_data_hash),
                constant_of(&utxo.ring_program_id),
            ]
        }),
        per_vector(&preimages, |preimage| {
            let fields = preimage.fields();
            [
                &fields.domain,
                &fields.tree_id,
                &fields.asset,
                &fields.owner_hash,
                &fields.blinding,
                &fields.data_hash,
                &fields.ring_data_hash,
                &fields.ring_program_id,
            ]
            .map(field_of)
        })
    );
}

type Change = (&'static str, fn(&mut Utxo), fn(&mut ProofInputUtxo));

const OTHER_MINT: Mint = Mint::new(Address::new_from_array([77u8; 32]), 77);

fn changes() -> [Change; 8] {
    [
        (
            "domain",
            |utxo| utxo.domain = constant(u64::from(DUMMY_DOMAIN)),
            |fields| {
                fields.domain = right_align(&DUMMY_DOMAIN.to_be_bytes());
                fields.owner_hash = [0; 32];
                fields.asset = [0; 32];
            },
        ),
        (
            "tree id",
            |utxo| utxo.tree_id = constant(u64::from(TREE_ID + 1)),
            |fields| fields.tree_id = tree_id_field(TREE_ID + 1),
        ),
        (
            "asset",
            |utxo| utxo.asset = Asset::constant(&OTHER_MINT.asset),
            |fields| fields.asset = hash_bytes(OTHER_MINT.asset.as_array()).expect("hash_bytes"),
        ),
        (
            "owner",
            |utxo| utxo.owner = circuit_owner(),
            |fields| fields.owner_hash = keys::p256(99).native_hash(),
        ),
        (
            "blinding",
            |utxo| utxo.blinding = var_of(&blinding(10)),
            |fields| fields.blinding = blinding(10),
        ),
        (
            "data hash",
            |utxo| utxo.data_hash = var_of(&blinding(11)),
            |fields| fields.data_hash = blinding(11),
        ),
        (
            "ring data hash",
            |utxo| utxo.ring_data_hash = var_of(&blinding(12)),
            |fields| fields.ring_data_hash = blinding(12),
        ),
        (
            "ring program id",
            |utxo| utxo.ring_program_id = var_of(&blinding(13)),
            |fields| fields.ring_program_id = blinding(13),
        ),
    ]
}

fn circuit_owner() -> zk_program_sdk::circuit::Owner {
    keys::p256(99)
        .address
        .instantiate(&Allocator::native())
        .expect("native owner")
}

#[test]
fn every_preimage_field_change_moves_the_hash_to_the_native_commitment_of_the_change() {
    let base = &preimages()[3];
    let base_hash = base.hash();
    let changed: Vec<_> = changes()
        .iter()
        .map(|(name, change_circuit, change_fields)| {
            let mut utxo = circuit(&base.wallet());
            change_circuit(&mut utxo);
            let mut fields = base.fields();
            change_fields(&mut fields);
            let hash = hash_of(&utxo);
            (
                *name,
                hash == field_of(&fields.hash().expect("native hash")),
                hash == base_hash,
            )
        })
        .collect();
    let amount = Preimage {
        amount: base.amount + 1,
        ..base.clone()
    };
    let amount_hash = hash_of(&circuit(&amount.wallet()));
    assert_eq!(
        (
            changed,
            amount_hash == amount.hash(),
            amount_hash == base_hash
        ),
        (
            changes()
                .iter()
                .map(|(name, _, _)| (*name, true, false))
                .collect::<Vec<_>>(),
            true,
            false
        )
    );
}

#[test]
fn the_carried_nullifier_is_the_wallets_native_nullifier() {
    let preimages = preimages();
    assert_eq!(
        per_vector(&preimages, |preimage| (
            constant_of(&circuit(&preimage.wallet()).nullifier),
            field_of(&preimage.wallet().nullifier),
        )),
        per_vector(&preimages, |preimage| {
            let secret = preimage.key.nullifier_key.secret();
            let nullifier = Poseidon::hashv(&[
                &preimage.native_hash(),
                &preimage.blinding,
                &right_align(&*secret),
            ])
            .expect("poseidon");
            (field_of(&nullifier), field_of(&nullifier))
        })
    );
}

#[test]
fn the_sdk_carries_a_nullifier_it_does_not_check() {
    let preimage = &preimages()[0];
    let foreign = preimages()[1].native_nullifier();
    let wallet = WalletUtxo {
        nullifier: foreign,
        ..preimage.wallet()
    };
    assert_eq!(
        (
            native(&UtxoHash {
                hash: preimage.hash(),
                utxo: wallet.clone(),
            }),
            native(&Carried {
                nullifier: field_of(&foreign),
                latest_tree_id: Field::from(0u64),
                has_latest_tree_id: false,
                utxo: wallet,
            }),
        ),
        (Ok(()), Ok(()))
    );
}

#[test]
fn the_latest_tree_id_and_its_flag_carry_the_wallets_value() {
    let preimages = preimages();
    let carried = |preimage: &Preimage, latest: u16, has: bool| {
        native(&Carried {
            nullifier: field_of(&preimage.native_nullifier()),
            latest_tree_id: Field::from(u64::from(latest)),
            has_latest_tree_id: has,
            utxo: preimage.wallet(),
        })
    };
    assert_eq!(
        per_vector(&preimages, |preimage| {
            let latest = preimage.latest_tree_id;
            (
                carried(preimage, latest.unwrap_or(0), latest.is_some()),
                carried(preimage, latest.unwrap_or(0), latest.is_none()),
                carried(preimage, latest.unwrap_or(0) + 1, latest.is_some()),
            )
        }),
        per_vector(&preimages, |_| (
            Ok(()),
            Err(CARRIED_BROKEN),
            Err(CARRIED_BROKEN)
        ))
    );
}

#[test]
fn the_circuit_dummy_has_the_dummy_domain_and_no_nullifier_key() {
    let dummy = Utxo::dummy();
    let default = Utxo::default();
    let sol = field_of(&hash_bytes(&[0u8; 32]).expect("hash_bytes"));
    let zero = Field::from(0u64);
    let fields = |utxo: &Utxo| {
        [
            constant_of(&utxo.domain),
            constant_of(utxo.owner.key().tag()),
            constant_of(utxo.owner.nullifier_pk()),
            constant_of(&utxo.asset.hash().expect("asset hash")),
            constant_of(&utxo.blinding),
            constant_of(&utxo.data_hash),
            constant_of(&utxo.ring_data_hash),
            constant_of(&utxo.ring_program_id),
            constant_of(&utxo.tree_id),
            constant_of(&utxo.nullifier),
            constant_of(&utxo.latest_tree_id),
            constant_of(&CircuitVar::from(utxo.has_latest_tree_id.clone())),
        ]
    };
    let mut expected = [zero; 12];
    expected[0] = Field::from(u64::from(DUMMY_DOMAIN));
    expected[3] = sol;
    let mut expected_default = expected;
    expected_default[0] = zero;
    assert_eq!(
        (fields(&dummy), fields(&default), DUMMY_DOMAIN, UTXO_DOMAIN),
        (expected, expected_default, 1, 3)
    );
}

#[test]
fn a_dummy_wallet_utxo_instantiates_with_an_all_zero_owner_preimage_and_skips_the_tag_check() {
    let wallet = dummy(blinding(5), TREE_ID);
    let utxo = circuit(&wallet);
    let zero = Field::from(0u64);
    assert_eq!(
        (
            wallet.utxo.owner.is_zero(),
            constant_of(&utxo.domain),
            constant_of(utxo.owner.key().tag()),
            constant_of(utxo.owner.nullifier_pk()),
            constant_of(&utxo.owner.key().identity().expect("identity")),
            constant_of(&utxo.blinding),
            constant_of(&utxo.tree_id),
        ),
        (
            true,
            Field::from(u64::from(DUMMY_DOMAIN)),
            zero,
            zero,
            field_of(&hash_bytes(&[0u8; 33]).expect("hash_bytes")),
            field_of(&blinding(5)),
            Field::from(u64::from(TREE_ID)),
        )
    );
}

#[test]
fn the_hash_of_a_dummy_is_the_native_dummy_commitment() {
    for tree in [0, TREE_ID, u16::MAX] {
        for blinding in [
            [0; 32],
            be_bytes("1"),
            blinding(5),
            be_bytes(MODULUS_MINUS_1),
        ] {
            let wallet = dummy(blinding, tree);
            let mut constructed = Utxo::dummy();
            constructed.blinding = var_of(&blinding);
            constructed.tree_id = constant(u64::from(tree));
            let expected = field_of(&wallet.utxo_hash);
            let native_fields = ProofInputUtxo::try_from(&SppProofInputUtxo::from(&wallet))
                .expect("native dummy fields");
            assert_eq!(
                expected,
                field_of(&native_fields.hash().expect("native dummy commitment"))
            );
            assert_eq!(
                (hash_of(&circuit(&wallet)), hash_of(&constructed)),
                (expected, expected)
            );
            let incorrect = hashed_dummy_preimages_commitment(&wallet);
            assert_ne!(incorrect, expected);
            assert_eq!(
                native(&UtxoHash {
                    hash: incorrect,
                    utxo: wallet
                }),
                Err(HASH_BROKEN)
            );
        }
    }
}

#[test]
fn a_utxo_field_of_at_least_p_is_refused_before_it_reaches_the_circuit() {
    let p = be_bytes(MODULUS);
    let base = preimages()[3].clone();
    let cases = [
        (
            "utxo blinding",
            Preimage {
                blinding: p,
                ..base.clone()
            },
            base.native_nullifier(),
        ),
        (
            "utxo data hash",
            Preimage {
                data_hash: Some(p),
                ..base.clone()
            },
            base.native_nullifier(),
        ),
        (
            "utxo ring data hash",
            Preimage {
                ring_data_hash: Some(p),
                ..base.clone()
            },
            base.native_nullifier(),
        ),
        ("utxo nullifier", base.clone(), p),
    ];
    let refused: Vec<_> = cases
        .iter()
        .map(|(name, preimage, nullifier)| {
            let wallet = WalletUtxo {
                utxo: preimage.utxo(),
                data_hash: preimage.data_hash,
                ring_data_hash: preimage.ring_data_hash,
                nullifier: *nullifier,
                ..base.wallet()
            };
            (
                *name,
                preimage
                    .utxo()
                    .hash(
                        &preimage.key.address.nullifier_pubkey,
                        &preimage.data_hash.unwrap_or_default(),
                        &preimage.ring_data_hash.unwrap_or_default(),
                        preimage.tree_id,
                    )
                    .map(|_| ())
                    .map_err(|error| error.to_string()),
                wallet
                    .instantiate(&Allocator::native())
                    .map(|_| ())
                    .map_err(|error: CircuitError| (error.name(), error.to_string())),
                check_constraints(&UtxoHash {
                    hash: Field::from(0u64),
                    utxo: wallet,
                }),
            )
        })
        .collect();
    let poseidon_refuses = Err("keypair error: poseidon hash failed (code 8002)".to_string());
    assert_eq!(
        refused,
        cases
            .iter()
            .map(|(name, _, _)| (
                *name,
                if *name == "utxo nullifier" {
                    Ok(())
                } else {
                    poseidon_refuses.clone()
                },
                Err((
                    "CircuitError.BytesTooLarge",
                    format!("{name} is too large for a circuit value")
                )),
                Err(("CircuitError.BytesTooLarge", None, None)),
            ))
            .collect::<Vec<_>>()
    );
}
