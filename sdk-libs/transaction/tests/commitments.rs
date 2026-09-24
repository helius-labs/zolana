mod common;

use common::{keypair, wallet_utxo};
use solana_address::Address;
use zolana_hasher::primitives::{hash_bytes, solana_owner_identity};
use zolana_keypair::{hash::sha256, NullifierKey, PublicKey, ShieldedKeypair, SigningKey};
use zolana_transaction::{
    instructions::transact::{PrivateTxHash, SppProofInputs},
    utxo::{
        derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
        program_id_proof_input_hash, ring_program_id_proof_input_hash, SppProofInputUtxo,
    },
    Data, DataRecord, ExternalData, Mint, SppProofOutputUtxo, TransactionError, Utxo,
};

fn address(byte: u8) -> Address {
    Address::new_from_array([byte; 32])
}
fn field(value: u8) -> [u8; 32] {
    let mut out = [0; 32];
    out[31] = value;
    out
}
fn output() -> SppProofOutputUtxo {
    SppProofOutputUtxo {
        asset: Mint::new(address(4), 5),
        amount: 123,
        blinding: field(3),
        ring_program_id: Some(address(5)),
        ring_data_hash: Some(field(6)),
        data_hash: Some(field(7)),
        owner_address: Some(keypair(7).shielded_address().unwrap()),
        owner_tag: Some([8; 32]),
        data: Data::default(),
    }
}
fn as_utxo(output: &SppProofOutputUtxo) -> Utxo {
    Utxo {
        owner: output.owner_address.unwrap().signing_pubkey,
        asset: output.asset,
        amount: output.amount,
        blinding: output.blinding,
        ring_program_id: output.ring_program_id,
        data: output.data.clone(),
    }
}
fn utxo_hash(output: &SppProofOutputUtxo, tree: u16) -> [u8; 32] {
    as_utxo(output)
        .hash(
            &output.owner_address.unwrap().nullifier_pubkey,
            &output.data_hash.unwrap_or_default(),
            &output.ring_data_hash.unwrap_or_default(),
            tree,
        )
        .unwrap()
}
fn proof() -> SppProofInputs {
    SppProofInputs {
        input_utxos: vec![SppProofInputUtxo::from(wallet_utxo(
            &keypair(7),
            Mint::SOL,
            10,
            0,
            1,
        ))],
        output_utxos: vec![],
        blinding_seed: field(42),
        output_tree_id: 0,
        external_data: ExternalData::new([2; 33], [3; 16], vec![], vec![], vec![]),
        payer: address(9),
    }
}

#[test]
fn commitments_bind_each_spend_field_in_both_input_and_output_representations() {
    let base = output();
    let expected = base.hash(4).unwrap();
    assert_eq!(utxo_hash(&base, 4), expected);
    let mutations: &[fn(&mut SppProofOutputUtxo)] = &[
        |o| o.asset.asset = address(9),
        |o| o.amount += 1,
        |o| o.blinding = field(9),
        |o| o.ring_program_id = Some(address(9)),
        |o| o.ring_data_hash = Some(field(9)),
        |o| o.data_hash = Some(field(9)),
        |o| o.owner_address.as_mut().unwrap().signing_pubkey = keypair(9).signing_pubkey(),
        |o| {
            o.owner_address.as_mut().unwrap().nullifier_pubkey =
                keypair(9).shielded_address().unwrap().nullifier_pubkey
        },
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut changed = base.clone();
        mutate(&mut changed);
        assert_ne!(changed.hash(4).unwrap(), expected, "output field {index}");
        assert_ne!(utxo_hash(&changed, 4), expected, "input field {index}");
        assert_eq!(changed.hash(4).unwrap(), utxo_hash(&changed, 4));
    }
    assert_ne!(base.hash(5).unwrap(), expected);
    assert_ne!(utxo_hash(&base, 5), expected);
}

#[test]
fn commitments_do_not_bind_compact_ids_viewing_keys_cached_tags_or_raw_preimages() {
    let base = output();
    let expected = base.hash(4).unwrap();
    let mutations: &[fn(&mut SppProofOutputUtxo)] = &[
        |o| o.asset.asset_id = 99,
        |o| o.owner_tag = Some([99; 32]),
        |o| {
            o.owner_address.as_mut().unwrap().viewing_pubkey =
                keypair(9).shielded_address().unwrap().viewing_pubkey
        },
        |o| {
            o.data = Data::new(vec![
                DataRecord::RingData(vec![1]),
                DataRecord::UtxoData(vec![2]),
                DataRecord::Memo(vec![3]),
            ])
        },
    ];
    for mutate in mutations {
        let mut changed = base.clone();
        mutate(&mut changed);
        assert_eq!(changed.hash(4).unwrap(), expected);
        assert_eq!(utxo_hash(&changed, 4), expected);
    }
}

#[test]
fn wallet_conversions_preserve_every_proof_field_without_recomputation() {
    let mut note = wallet_utxo(&keypair(7), Mint::new(address(4), 5), 123, 42, 9);
    // Deliberately inconsistent cached values prove this conversion is a field
    // move. Commitment verification belongs to construction/scanning.
    note.utxo_hash = field(91);
    note.nullifier = field(92);
    note.nullifier_pubkey = field(93);
    note.data_hash = Some(field(94));
    note.ring_data_hash = Some(field(95));
    note.utxo.data = Data::new(vec![
        DataRecord::RingData(vec![1]),
        DataRecord::UtxoData(vec![2]),
        DataRecord::Memo(vec![3]),
    ]);
    note.utxo.ring_program_id = Some(address(8));
    note.leaf_index = 987654;
    let before = note.clone();
    for converted in [
        SppProofInputUtxo::from(&note),
        SppProofInputUtxo::from(note.clone()),
    ] {
        assert_eq!(
            (
                converted.utxo,
                converted.nullifier_pubkey,
                converted.utxo_hash,
                converted.nullifier,
                converted.data_hash,
                converted.ring_data_hash,
                converted.tree_id,
                converted.leaf_index
            ),
            (
                note.utxo.clone(),
                field(93),
                field(91),
                field(92),
                Some(field(94)),
                Some(field(95)),
                42,
                987654
            )
        );
    }
    assert_eq!(note, before);
    assert_eq!(note.tree_id(), 42);
}

#[test]
fn data_setters_replace_one_record_per_kind_and_keep_canonical_order() {
    let base = output();
    let first = base
        .clone()
        .with_memo(vec![1])
        .with_utxo_data(vec![2], field(2))
        .with_ring_data(address(4), vec![3], field(3));
    let second = base
        .with_ring_data(address(4), vec![3], field(3))
        .with_memo(vec![1])
        .with_utxo_data(vec![2], field(2));
    assert_eq!(first, second);
    let changed = first
        .with_utxo_data(vec![4], field(4))
        .with_ring_data(address(5), vec![5], field(5))
        .with_memo(vec![6]);
    assert_eq!(
        changed.data,
        Data::new(vec![
            DataRecord::RingData(vec![5]),
            DataRecord::UtxoData(vec![4]),
            DataRecord::Memo(vec![6])
        ])
    );
    assert_eq!(
        (
            changed.data_hash,
            changed.ring_data_hash,
            changed.ring_program_id
        ),
        (Some(field(4)), Some(field(5)), Some(address(5)))
    );
    let committed = changed.hash(4).unwrap();
    assert_eq!(changed.with_memo(vec![7, 8, 9]).hash(4).unwrap(), committed);
}

#[test]
fn program_and_data_hash_defaults_distinguish_absence_from_a_present_zero_address() {
    assert_eq!(program_id_proof_input_hash(&None).unwrap(), [0; 32]);
    assert_eq!(ring_program_id_proof_input_hash(&None).unwrap(), [0; 32]);
    for program in [address(0), address(5), address(99)] {
        let expected = hash_bytes(program.as_array()).unwrap();
        assert_eq!(
            program_id_proof_input_hash(&Some(program)).unwrap(),
            expected
        );
        assert_eq!(
            ring_program_id_proof_input_hash(&Some(program)).unwrap(),
            expected
        );
        assert_ne!(expected, [0; 32]);
    }
    let mut base = output();
    base.ring_program_id = None;
    base.data_hash = None;
    base.ring_data_hash = None;
    let no_hashes = base.hash(4).unwrap();
    for (data, ring) in [
        (Some([0; 32]), None),
        (None, Some([0; 32])),
        (Some([0; 32]), Some([0; 32])),
    ] {
        let mut changed = base.clone();
        changed.data_hash = data;
        changed.ring_data_hash = ring;
        assert_eq!(changed.hash(4).unwrap(), no_hashes);
    }
    base.ring_program_id = Some(address(0));
    assert_ne!(base.hash(4).unwrap(), no_hashes);
}

#[test]
fn ownerless_outputs_and_dummy_inputs_contribute_zero_but_owned_zero_outputs_are_committed() {
    let mut tx = proof();
    let real_hash = tx.input_utxos.first().unwrap().hash();
    tx.input_utxos
        .push(SppProofInputUtxo::dummy_with_blinding(field(7), 0).unwrap());
    let ownerless = SppProofOutputUtxo {
        blinding: field(8),
        ..Default::default()
    };
    let owned = SppProofOutputUtxo {
        amount: 0,
        ..output()
    };
    tx.output_utxos = vec![ownerless.clone(), owned.clone()];
    let expected_private = PrivateTxHash::new(
        &[real_hash, [0; 32]],
        &[[0; 32], owned.hash(0).unwrap()],
        &tx.external_data.hash().unwrap(),
        &tx.private_tx_blinding().unwrap(),
    )
    .hash()
    .unwrap();
    assert_eq!(tx.message_hash().unwrap(), sha256(&expected_private));
    let expected = tx.message_hash().unwrap();
    tx.input_utxos.last_mut().unwrap().utxo_hash = field(91);
    tx.output_utxos.first_mut().unwrap().blinding = field(92);
    assert_eq!(tx.message_hash().unwrap(), expected);
    tx.output_utxos.last_mut().unwrap().blinding = field(93);
    assert_ne!(tx.message_hash().unwrap(), expected);
    assert!(ownerless.is_dummy());
    assert!(!owned.is_dummy());
}

#[test]
fn private_transaction_hash_binds_every_chain_order_external_hash_and_blinding() {
    let inputs = [field(1), field(2)];
    let outputs = [field(3), field(4)];
    let external = field(5);
    let blinding = field(6);
    let zeros = [[0; 32]; 2];
    let base = PrivateTxHash::new(&inputs, &outputs, &external, &blinding)
        .hash()
        .unwrap();
    let mut explicit = PrivateTxHash::new(&inputs, &outputs, &external, &blinding);
    explicit.address_nullifiers = Some(&zeros);
    assert_eq!(explicit.hash().unwrap(), base);
    for changed_inputs in [
        [field(7), field(2)],
        [field(1), field(7)],
        [field(2), field(1)],
    ] {
        assert_ne!(
            PrivateTxHash::new(&changed_inputs, &outputs, &external, &blinding)
                .hash()
                .unwrap(),
            base
        );
    }
    for changed_outputs in [
        [field(7), field(4)],
        [field(3), field(7)],
        [field(4), field(3)],
    ] {
        assert_ne!(
            PrivateTxHash::new(&inputs, &changed_outputs, &external, &blinding)
                .hash()
                .unwrap(),
            base
        );
    }
    assert_ne!(
        PrivateTxHash::new(&inputs, &outputs, &field(7), &blinding)
            .hash()
            .unwrap(),
        base
    );
    assert_ne!(
        PrivateTxHash::new(&inputs, &outputs, &external, &field(7))
            .hash()
            .unwrap(),
        base
    );
    let mut address_hashes = Vec::new();
    for nullifiers in [
        [field(7), field(8)],
        [field(8), field(7)],
        [field(7), field(9)],
        [field(9), field(8)],
    ] {
        let mut hash = PrivateTxHash::new(&inputs, &outputs, &external, &blinding);
        hash.address_nullifiers = Some(&nullifiers);
        let hash = hash.hash().unwrap();
        assert_ne!(hash, base);
        assert!(!address_hashes.contains(&hash));
        address_hashes.push(hash);
    }
}

#[test]
fn derivation_domains_match_committed_cross_language_vectors_and_bind_each_parameter() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test-vectors/transact_derivation.json"
    ))
    .unwrap();
    let v = &vector["blinding_seed"];
    let first = field(u8::try_from(v["first_nullifier"].as_u64().unwrap()).unwrap());
    let secret = field(u8::try_from(v["blinding_seed"].as_u64().unwrap()).unwrap());
    let index = u32::try_from(v["output_index"].as_u64().unwrap()).unwrap();
    let seed = derive_output_blinding_seed(&first, &secret).unwrap();
    let private = derive_private_tx_blinding(&first, &secret).unwrap();
    assert_eq!(
        hex::encode(seed),
        v["output_blinding_seed"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(private),
        v["private_tx_blinding"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(derive_transact_output_blinding(&first, &secret, index).unwrap()),
        v["output_blinding"].as_str().unwrap()
    );
    let output = derive_transact_output_blinding(&first, &seed, index).unwrap();
    assert_eq!(
        hex::encode(output),
        v["output_blinding_derived"].as_str().unwrap()
    );
    assert_ne!(seed, private);
    assert_ne!(output, seed);
    assert_ne!(output, private);
    for (changed_first, changed_secret) in [(field(8), secret), (first, field(43))] {
        assert_ne!(
            derive_output_blinding_seed(&changed_first, &changed_secret).unwrap(),
            seed
        );
        assert_ne!(
            derive_private_tx_blinding(&changed_first, &changed_secret).unwrap(),
            private
        );
    }
    for (changed_first, changed_seed, changed_index) in [
        (field(8), seed, index),
        (first, field(43), index),
        (first, seed, index + 1),
    ] {
        assert_ne!(
            derive_transact_output_blinding(&changed_first, &changed_seed, changed_index).unwrap(),
            output
        );
    }
}

#[test]
fn dummy_hash_has_fixed_domain_and_tree_bound_zero_secret_nullifier() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test-vectors/transact_derivation.json"
    ))
    .unwrap();
    let dummy = SppProofInputUtxo::dummy_with_blinding(field(7), 0).unwrap();
    assert_eq!(
        hex::encode(dummy.hash()),
        vector["dummy_utxo_hash"]["hash"].as_str().unwrap()
    );
    assert_eq!(
        dummy.nullifier(),
        NullifierKey::from_secret([0; zolana_keypair::constants::BLINDING_LEN])
            .nullifier(&dummy.hash(), &field(7))
            .unwrap()
    );
    let other_tree = SppProofInputUtxo::dummy_with_blinding(field(7), 1).unwrap();
    assert_ne!(other_tree.hash(), dummy.hash());
    assert_ne!(other_tree.nullifier(), dummy.nullifier());
    assert_eq!(
        other_tree.nullifier(),
        NullifierKey::from_secret([0; zolana_keypair::constants::BLINDING_LEN])
            .nullifier(&other_tree.hash(), &field(7))
            .unwrap()
    );
}

#[test]
fn signers_are_payer_first_deduplicated_by_identity_and_exclude_dummies_and_p256() {
    let alice = keypair(7);
    let bob = keypair(9);
    let p256 =
        ShieldedKeypair::from_keypair(SigningKey::from_p256_bytes(&[11; 32]).unwrap()).unwrap();
    let mut tx = proof();
    let alice_input = SppProofInputUtxo::from(wallet_utxo(&alice, Mint::SOL, 10, 0, 1));
    let mut same_owner = alice_input.clone();
    same_owner.nullifier_pubkey = field(99);
    let bob_input = SppProofInputUtxo::from(wallet_utxo(&bob, Mint::SOL, 10, 0, 2));
    let p256_input = SppProofInputUtxo::from(wallet_utxo(&p256, Mint::SOL, 10, 0, 3));
    let mut pda_input = alice_input.clone();
    pda_input.utxo.owner = PublicKey::from_pda(&address(13));
    tx.input_utxos = vec![
        alice_input.clone(),
        SppProofInputUtxo::dummy_with_blinding(field(7), 0).unwrap(),
        p256_input.clone(),
        bob_input.clone(),
        same_owner,
        pda_input.clone(),
        bob_input,
    ];
    let alice_address =
        Address::new_from_array(alice.signing_pubkey().confidential_view_tag().unwrap());
    let bob_address =
        Address::new_from_array(bob.signing_pubkey().confidential_view_tag().unwrap());
    assert_eq!(
        tx.owner_signer_pubkeys().unwrap(),
        vec![alice_address, bob_address, address(13)]
    );
    let expected: Vec<_> = [address(9), alice_address, bob_address, address(13)]
        .iter()
        .map(|a| solana_owner_identity(a.as_array()).unwrap())
        .collect();
    assert_eq!(tx.signer_pk_hashes(4).unwrap(), expected);
    let mut padded = expected;
    padded.extend([[0; 32]; 2]);
    assert_eq!(tx.signer_pk_hashes(6).unwrap(), padded);
    for width in [0, 1, 3] {
        assert!(matches!(
            tx.signer_pk_hashes(width),
            Err(TransactionError::UnsupportedShape { n_in: 7, n_out: 0 })
        ));
    }
    tx.payer = alice_address;
    assert_eq!(
        tx.owner_signer_pubkeys().unwrap(),
        vec![bob_address, address(13)]
    );
    tx.payer = address(13);
    assert_eq!(
        tx.owner_signer_pubkeys().unwrap(),
        vec![alice_address, bob_address]
    );
    tx.input_utxos = vec![p256_input];
    assert_eq!(tx.owner_signer_pubkeys().unwrap(), vec![]);
    assert_eq!(
        tx.signer_pk_hashes(1).unwrap(),
        vec![solana_owner_identity(address(13).as_array()).unwrap()]
    );
    assert!(matches!(
        tx.signer_pk_hashes(0),
        Err(TransactionError::UnsupportedShape { n_in: 1, n_out: 0 })
    ));
    // This committed identity vector independently pins the primitive used by signer assembly.
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test-vectors/transact_derivation.json"
    ))
    .unwrap();
    let public: [u8; 32] = hex::decode(vector["owner_identity"]["solana_pubkey"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        hex::encode(solana_owner_identity(&public).unwrap()),
        vector["owner_identity"]["solana_owner_identity"]
            .as_str()
            .unwrap()
    );
}

#[test]
fn data_bearing_output_owners_follow_input_owners_as_signers() {
    let alice = keypair(7);
    let alice_address =
        Address::new_from_array(alice.signing_pubkey().confidential_view_tag().unwrap());
    let pda = address(13);
    let pda_owner = keypair(21).shielded_address().unwrap();
    let mut pda_output = output();
    pda_output.owner_address = Some(zolana_keypair::ShieldedAddress {
        signing_pubkey: PublicKey::from_pda(&pda),
        ..pda_owner
    });
    let mut dataless_output = pda_output.clone();
    dataless_output.data_hash = None;
    let mut zero_data_output = pda_output.clone();
    zero_data_output.data_hash = Some([0; 32]);
    let mut alice_data_output = output();
    alice_data_output.owner_address = Some(alice.shielded_address().unwrap());

    let mut tx = proof();
    tx.output_utxos = vec![dataless_output.clone(), zero_data_output];
    assert_eq!(tx.owner_signer_pubkeys().unwrap(), vec![alice_address]);

    tx.output_utxos = vec![
        pda_output.clone(),
        alice_data_output,
        pda_output,
        dataless_output,
    ];
    assert_eq!(tx.owner_signer_pubkeys().unwrap(), vec![alice_address, pda]);
    let expected: Vec<_> = [address(9), alice_address, pda]
        .iter()
        .map(|a| solana_owner_identity(a.as_array()).unwrap())
        .collect();
    assert_eq!(tx.signer_pk_hashes(3).unwrap(), expected);

    tx.payer = pda;
    assert_eq!(tx.owner_signer_pubkeys().unwrap(), vec![alice_address]);
}
