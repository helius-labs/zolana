use zolana_hasher::{sha256::Sha256BE, Hasher};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{
            CircuitId, ExternalDataPreimage, InputUtxo, InterfaceTransfer, MessageData, OwnerTag,
            TransactIxData, TransactIxDataRef, TransactOutput, TransactProof,
        },
        tag,
    },
    SOL_INTERFACE,
};
use zolana_program::{ExternalDataHashError, SettlementAccounts, TransactExternalData};

const TRANSACT_TAG: [u8; 1] = [tag::TRANSACT];

fn proof() -> TransactProof {
    TransactProof {
        a: [1u8; 32],
        b: [2u8; 128],
        c: [3u8; 32],
    }
}

fn output(utxo_hash: [u8; 32], owner_tag: OwnerTag, data: Option<Vec<u8>>) -> TransactOutput {
    TransactOutput {
        utxo_hash,
        owner_tag,
        data,
    }
}

fn mixed_outputs() -> Vec<TransactOutput> {
    vec![
        output(
            [10u8; 32],
            OwnerTag::Inline([11u8; 32]),
            Some(vec![1, 2, 3]),
        ),
        output([12u8; 32], OwnerTag::Account(2), None),
        output(
            [13u8; 32],
            OwnerTag::Inline([14u8; 32]),
            Some(vec![4, 5, 6, 7]),
        ),
    ]
}

fn ix_data() -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: 7,
        tx_viewing_pk: [4u8; 33],
        salt: [6u8; 16],
        interface_transfers: vec![
            InterfaceTransfer::SolWithdrawal { amount: 5 },
            InterfaceTransfer::SplDeposit {
                amount: 7,
                spl_interface_bump: 42,
            },
        ],
        data_hash: None,
        ring_data_hash: None,
        outputs: mixed_outputs(),
        messages: vec![MessageData {
            view_tag: [30u8; 32],
            data: vec![8, 9],
        }],
        private_tx_hash: [9u8; 32],
        circuit: CircuitId::ConfidentialEddsa(1, 3, 3),
        proof: proof(),
        inputs: vec![InputUtxo {
            nullifier_hash: [1u8; 32],
            nullifier_tree_root_index: 2,
            utxo_tree_root_index: 3,
        }],
    }
}

fn external_only(outputs: Vec<TransactOutput>, messages: Vec<MessageData>) -> TransactExternalData {
    let mut data = TransactExternalData::from(&ix_data());
    data.interface_transfers = Vec::new();
    data.outputs = outputs;
    data.messages = messages;
    data
}

fn prefix_of(data: &TransactExternalData) -> Vec<u8> {
    data.serialize().unwrap()
}

fn hash_with_addresses(data: &TransactExternalData, addresses: &[[u8; 32]]) -> [u8; 32] {
    let prefix = prefix_of(data);
    let mut preimage = ExternalDataPreimage::new(&TRANSACT_TAG, &prefix);
    for address in addresses {
        preimage
            .push_owner_tag(&OwnerTag::Account(0), address)
            .unwrap();
    }
    preimage.finish().unwrap()
}

#[test]
fn external_data_is_the_serialized_head_of_the_instruction() {
    let owned = ix_data();
    let bytes = owned.serialize().unwrap();
    let prefix = prefix_of(&TransactExternalData::from(&owned));
    assert!(bytes.starts_with(&prefix));
    assert!(prefix.len() < bytes.len());
    let (_, parsed_prefix) = TransactIxDataRef::parse_with_external_data_prefix(&bytes).unwrap();
    assert_eq!(parsed_prefix, prefix.as_slice());
}

#[test]
fn into_ix_data_round_trips_through_from() {
    let owned = ix_data();
    let external = TransactExternalData::from(&owned);
    let rebuilt = external.clone().into_ix_data(
        owned.private_tx_hash,
        owned.circuit,
        owned.proof,
        owned.inputs.clone(),
    );
    assert_eq!(rebuilt, owned);
    assert_eq!(TransactExternalData::from(&rebuilt), external);
}

#[test]
fn single_output_carries_only_the_output() {
    let single = output([1u8; 32], OwnerTag::Inline([2u8; 32]), Some(vec![3]));
    let external = TransactExternalData::single_output(single.clone());
    assert_eq!(
        external,
        TransactExternalData {
            expiry_unix_ts: u64::MAX,
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![single],
            messages: Vec::new(),
        }
    );
}

#[test]
fn external_data_serialization_validates_interface_transfers() {
    let mut data = TransactExternalData::from(&ix_data());
    data.interface_transfers = vec![InterfaceTransfer::SolDeposit { amount: 0 }];
    assert!(data.serialize().is_err());
    assert!(matches!(
        data.hash(tag::TRANSACT, &[[[0u8; 32]; 2]], &[[0u8; 32]; 3]),
        Err(ExternalDataHashError::Serialize(_))
    ));
}

#[test]
fn hash_requires_one_settlement_pair_per_leg_and_one_owner_tag_per_output() {
    let data = TransactExternalData::from(&ix_data());
    let pairs: Vec<SettlementAccounts> = vec![[[1u8; 32], [2u8; 32]], [[3u8; 32], [4u8; 32]]];
    let owners = vec![[5u8; 32]; 3];
    assert!(matches!(
        data.hash(tag::TRANSACT, &pairs[..1], &owners),
        Err(ExternalDataHashError::SettlementAccountCount {
            expected: 2,
            provided: 1
        })
    ));
    assert!(matches!(
        data.hash(tag::TRANSACT, &pairs, &owners[..2]),
        Err(ExternalDataHashError::ResolvedOwnerTagCount {
            expected: 3,
            provided: 2
        })
    ));
    assert!(data.hash(tag::TRANSACT, &pairs, &owners).is_ok());
}

#[test]
fn hash_appends_settlement_pairs_then_account_owner_addresses() {
    let data = TransactExternalData::from(&ix_data());
    let pairs: Vec<SettlementAccounts> = vec![[[1u8; 32], [2u8; 32]], [[3u8; 32], [4u8; 32]]];
    let owners = [[11u8; 32], [12u8; 32], [14u8; 32]];
    let got = data.hash(tag::TRANSACT, &pairs, &owners).unwrap();
    let prefix = prefix_of(&data);
    let expected = Sha256BE::hashv(&[
        &TRANSACT_TAG,
        prefix.as_slice(),
        &[1u8; 32],
        &[2u8; 32],
        &[3u8; 32],
        &[4u8; 32],
        &[12u8; 32],
    ])
    .unwrap();
    assert_eq!(got, expected);
}

#[test]
fn external_data_preimage_matches_hand_assembled_bytes() {
    let data = TransactExternalData::from(&ix_data());
    let prefix = prefix_of(&data);
    let addresses = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let mut expected = Vec::new();
    expected.extend_from_slice(&TRANSACT_TAG);
    expected.extend_from_slice(&prefix);
    for address in &addresses {
        expected.extend_from_slice(address);
    }
    assert_eq!(
        hash_with_addresses(&data, &addresses),
        Sha256BE::hash(&expected).unwrap()
    );
}

#[test]
fn external_data_hash_binds_discriminator_and_expiry() {
    let data = TransactExternalData::from(&ix_data());
    let prefix = prefix_of(&data);
    let ring_tag = [tag::RING_TRANSACT];
    assert_ne!(
        ExternalDataPreimage::new(&TRANSACT_TAG, &prefix)
            .finish()
            .unwrap(),
        ExternalDataPreimage::new(&ring_tag, &prefix)
            .finish()
            .unwrap()
    );

    let mut later = data.clone();
    later.expiry_unix_ts += 1;
    assert_ne!(
        hash_with_addresses(&data, &[]),
        hash_with_addresses(&later, &[])
    );
}

#[test]
fn external_data_hash_binds_encryption_context_and_optional_hash_presence() {
    let base = TransactExternalData::from(&ix_data());
    let base_hash = hash_with_addresses(&base, &[]);

    let mut different_pk = base.clone();
    different_pk.tx_viewing_pk[0] ^= 1;
    assert_ne!(base_hash, hash_with_addresses(&different_pk, &[]));

    let mut different_salt = base.clone();
    different_salt.salt[0] ^= 1;
    assert_ne!(base_hash, hash_with_addresses(&different_salt, &[]));

    let mut zero_data_hash = base.clone();
    zero_data_hash.data_hash = Some([0u8; 32]);
    assert_ne!(base_hash, hash_with_addresses(&zero_data_hash, &[]));

    let mut zero_ring_data_hash = base.clone();
    zero_ring_data_hash.ring_data_hash = Some([0u8; 32]);
    assert_ne!(base_hash, hash_with_addresses(&zero_ring_data_hash, &[]));
    assert_ne!(
        hash_with_addresses(&zero_data_hash, &[]),
        hash_with_addresses(&zero_ring_data_hash, &[])
    );
}

#[test]
fn external_data_hash_binds_transfer_count_order_direction_and_accounts() {
    let sol = InterfaceTransfer::SolWithdrawal { amount: u64::MAX };
    let spl = InterfaceTransfer::SplWithdrawal {
        amount: u64::MAX,
        spl_interface_bump: 42,
    };
    let sol_accounts = [[10u8; 32], [1u8; 32]];
    let spl_accounts = [[20u8; 32], [2u8; 32]];
    let with_legs = |legs: &[InterfaceTransfer], accounts: &[[u8; 32]]| {
        let mut data = external_only(Vec::new(), Vec::new());
        data.interface_transfers = legs.to_vec();
        hash_with_addresses(&data, accounts)
    };
    let one_sol = with_legs(&[sol], &sol_accounts);
    let two_sol = with_legs(&[sol, sol], &[sol_accounts, sol_accounts].concat());
    assert_ne!(one_sol, two_sol);

    let sol_then_spl = with_legs(&[sol, spl], &[sol_accounts, spl_accounts].concat());
    let spl_then_sol = with_legs(&[spl, sol], &[spl_accounts, sol_accounts].concat());
    assert_ne!(sol_then_spl, spl_then_sol);
    assert_ne!(one_sol, with_legs(&[spl], &spl_accounts));

    let other_recipient = [[10u8; 32], [3u8; 32]];
    assert_ne!(one_sol, with_legs(&[sol], &other_recipient));
    let other_mint = [[30u8; 32], [2u8; 32]];
    assert_ne!(
        with_legs(&[spl], &spl_accounts),
        with_legs(&[spl], &other_mint)
    );

    let deposit = InterfaceTransfer::SolDeposit { amount: u64::MAX };
    assert_ne!(one_sol, with_legs(&[deposit], &sol_accounts));

    let smaller = InterfaceTransfer::SolWithdrawal { amount: 1 };
    assert_ne!(one_sol, with_legs(&[smaller], &sol_accounts));
}

#[test]
fn external_data_hash_binds_account_owner_tags_through_the_resolved_address() {
    let data = external_only(
        vec![output([1u8; 32], OwnerTag::Account(2), None)],
        Vec::new(),
    );
    assert_ne!(
        data.hash(tag::TRANSACT, &[], &[[7u8; 32]]).unwrap(),
        data.hash(tag::TRANSACT, &[], &[[8u8; 32]]).unwrap()
    );
    assert_eq!(
        data.hash(tag::TRANSACT, &[], &[[7u8; 32]]).unwrap(),
        hash_with_addresses(&data, &[[7u8; 32]])
    );

    let inline = external_only(
        vec![output([1u8; 32], OwnerTag::Inline([7u8; 32]), None)],
        Vec::new(),
    );
    assert_eq!(
        inline.hash(tag::TRANSACT, &[], &[[7u8; 32]]).unwrap(),
        hash_with_addresses(&inline, &[])
    );
}

#[test]
fn external_data_hash_is_injective_across_output_message_boundary() {
    let value = [3u8; 32];
    let owner_tag = OwnerTag::Inline([2u8; 32]);
    let value_in_output = hash_with_addresses(
        &external_only(
            vec![output([1u8; 32], owner_tag, Some(value.to_vec()))],
            Vec::new(),
        ),
        &[],
    );
    let value_in_message = hash_with_addresses(
        &external_only(
            vec![output([1u8; 32], owner_tag, None)],
            vec![MessageData {
                view_tag: [2u8; 32],
                data: value.to_vec(),
            }],
        ),
        &[],
    );
    assert_ne!(value_in_output, value_in_message);
}

#[test]
fn external_data_hash_distinguishes_empty_data_from_none() {
    let owner_tag = OwnerTag::Inline([2u8; 32]);
    let some_empty = hash_with_addresses(
        &external_only(
            vec![output([1u8; 32], owner_tag, Some(Vec::new()))],
            Vec::new(),
        ),
        &[],
    );
    let none = hash_with_addresses(
        &external_only(vec![output([1u8; 32], owner_tag, None)], Vec::new()),
        &[],
    );
    assert_ne!(some_empty, none);
}

#[test]
fn external_data_hash_is_injective_across_owner_tag_data_boundary() {
    let value = [3u8; 32];
    let value_in_tag = hash_with_addresses(
        &external_only(
            vec![output([1u8; 32], OwnerTag::Inline(value), None)],
            Vec::new(),
        ),
        &[],
    );
    let value_in_data = hash_with_addresses(
        &external_only(
            vec![output(
                [1u8; 32],
                OwnerTag::Inline([0u8; 32]),
                Some(value.to_vec()),
            )],
            Vec::new(),
        ),
        &[],
    );
    assert_ne!(value_in_tag, value_in_data);
}

#[test]
fn external_data_hash_matches_canonical_parity_fixture() {
    let sol_recipient: [u8; 32] = core::array::from_fn(|i| 0x20 + i as u8);
    let spl_user: [u8; 32] = core::array::from_fn(|i| 0x40 + i as u8);
    let mint: [u8; 32] = core::array::from_fn(|i| 0x60 + i as u8);
    let sender_tag: [u8; 32] = core::array::from_fn(|i| i as u8);
    let mut first_hash = [0u8; 32];
    *first_hash.last_mut().unwrap() = 1;
    let mut second_hash = [0u8; 32];
    *second_hash.last_mut().unwrap() = 2;
    let encrypted = vec![
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let data = TransactExternalData {
        expiry_unix_ts: 1_234_567_890,
        tx_viewing_pk: core::array::from_fn(|i| 0x90 + i as u8),
        salt: core::array::from_fn(|i| 0xf0 + i as u8),
        interface_transfers: vec![
            InterfaceTransfer::SolWithdrawal {
                amount: 1_234_567_890,
            },
            InterfaceTransfer::SplDeposit {
                amount: 987_654_321,
                spl_interface_bump: 255,
            },
        ],
        data_hash: None,
        ring_data_hash: None,
        outputs: vec![
            output(first_hash, OwnerTag::Inline(sender_tag), Some(encrypted)),
            output(second_hash, OwnerTag::Inline(sender_tag), None),
        ],
        messages: Vec::new(),
    };
    let got = data
        .hash(
            tag::TRANSACT,
            &[[SOL_INTERFACE, sol_recipient], [mint, spl_user]],
            &[sender_tag, sender_tag],
        )
        .unwrap();
    assert_eq!(
        got,
        [
            0, 142, 130, 89, 21, 76, 129, 194, 35, 51, 6, 185, 217, 170, 76, 191, 1, 72, 23, 51,
            87, 165, 150, 154, 191, 235, 184, 134, 2, 121, 4, 222,
        ]
    );
}
