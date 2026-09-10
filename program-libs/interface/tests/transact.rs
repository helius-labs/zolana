use zolana_hasher::{sha256::Sha256BE, Hasher, HasherError};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{
            fetch_tag, validate_interface_transfers, Bsb22Commitment, CircuitId,
            ExternalDataPreimage, InputUtxo, InterfaceTransfer, MessageData, OwnerTag,
            RingP256ProofData, TransactIxData, TransactIxDataRef, TransactOutput, TransactProof,
            MAX_EXTERNAL_DATA_HASH_SLICES,
        },
        tag,
    },
    MAX_INTERFACE_TRANSFERS, MAX_OUTPUTS,
};

/// The selector is a 2-byte little-endian enum tag followed by its three
/// one-byte dimensions; unknown tags are rejected fail-closed.
#[test]
fn circuit_id_wire_layout_and_unknown_rejection() {
    let vanilla_ids = [
        CircuitId::ConfidentialEddsa(1, 2, 3),
        CircuitId::RingEddsa(2, 3, 3),
        CircuitId::RingAuthority(4, 4, 3),
    ];
    for (value, id) in vanilla_ids.into_iter().enumerate() {
        let bytes = wincode::serialize(&id).unwrap();
        let mut expected = (value as u16).to_le_bytes().to_vec();
        expected.extend_from_slice(&[
            id.num_inputs(),
            id.num_outputs(),
            id.num_public_asset_slots(),
        ]);
        assert_eq!(bytes, expected);
        assert_eq!(wincode::deserialize_exact::<CircuitId>(&bytes).unwrap(), id);
    }

    let commitment = Bsb22Commitment {
        commitment: [4u8; 32],
        commitment_pok: [5u8; 32],
    };
    let proof_data = RingP256ProofData {
        bsb22_commitment: commitment,
        default_owner_tag: None,
    };
    let p256 = CircuitId::RingP256(2, 3, 3, proof_data);
    let bytes = wincode::serialize(&p256).unwrap();
    let mut expected = 3u16.to_le_bytes().to_vec();
    expected.extend_from_slice(&[2, 3, 3]);
    expected.extend_from_slice(&commitment.commitment);
    expected.extend_from_slice(&commitment.commitment_pok);
    expected.push(0);
    expected.extend_from_slice(&[0u8; 32]);
    assert_eq!(bytes, expected);
    assert_eq!(
        wincode::deserialize_exact::<CircuitId>(&bytes).unwrap(),
        p256
    );

    let tagged = CircuitId::RingP256(
        2,
        3,
        3,
        RingP256ProofData {
            bsb22_commitment: commitment,
            default_owner_tag: Some([7u8; 32]),
        },
    );
    let tagged_bytes = wincode::serialize(&tagged).unwrap();
    assert_eq!(tagged_bytes[tagged_bytes.len() - 33], 1);
    assert_eq!(&tagged_bytes[tagged_bytes.len() - 32..], &[7u8; 32]);
    assert_eq!(
        wincode::deserialize_exact::<CircuitId>(&tagged_bytes).unwrap(),
        tagged
    );

    let mut noncanonical_none = bytes;
    *noncanonical_none.last_mut().unwrap() = 1;
    assert!(wincode::deserialize_exact::<CircuitId>(&noncanonical_none).is_err());

    let unknown = 4u16.to_le_bytes();
    assert!(wincode::deserialize_exact::<CircuitId>(&unknown).is_err());
}

fn proof() -> TransactProof {
    TransactProof {
        a: [1u8; 32],
        b: [2u8; 128],
        c: [3u8; 32],
    }
}

#[test]
fn transact_proof_round_trips() {
    let proof = proof();
    let bytes = wincode::serialize(&proof).unwrap();
    let decoded: TransactProof = wincode::deserialize_exact(&bytes).unwrap();
    assert_eq!(decoded, proof);
}

#[test]
fn proof_has_expected_wire_size() {
    let proof = wincode::serialize(&proof()).unwrap();
    assert_eq!(proof.len(), 192);
}

fn mixed_outputs() -> Vec<TransactOutput> {
    vec![
        TransactOutput {
            utxo_hash: [10u8; 32],
            owner_tag: OwnerTag::Inline([11u8; 32]),
            data: Some(vec![1, 2, 3]),
        },
        TransactOutput {
            utxo_hash: [12u8; 32],
            owner_tag: OwnerTag::Account(2),
            data: None,
        },
        TransactOutput {
            utxo_hash: [13u8; 32],
            owner_tag: OwnerTag::Inline([14u8; 32]),
            data: Some(vec![4, 5, 6, 7]),
        },
    ]
}

fn ix_data(proof: TransactProof) -> TransactIxData {
    TransactIxData {
        proof,
        expiry_unix_ts: 7,
        private_tx_hash: [9u8; 32],
        circuit: CircuitId::ConfidentialEddsa(1, 3, 3),
        inputs: vec![InputUtxo {
            nullifier_hash: [1u8; 32],
            nullifier_tree_root_index: 2,
            utxo_tree_root_index: 3,
        }],
        interface_transfers: vec![
            InterfaceTransfer::SolWithdrawal { amount: 5 },
            InterfaceTransfer::SplDeposit {
                amount: 7,
                spl_interface_bump: 42,
            },
        ],
        data_hash: None,
        ring_data_hash: None,
        tx_viewing_pk: [4u8; 33],
        salt: [6u8; 16],
        outputs: mixed_outputs(),
        messages: vec![MessageData {
            view_tag: [30u8; 32],
            data: vec![8, 9],
        }],
    }
}

/// Every field of the borrowed view aliases the same bytes the owned struct
/// serialized, so the swap program's owned-reserialize CPI path is byte-exact.
fn assert_ref_matches_owned(view: &TransactIxDataRef, owned: &TransactIxData) {
    assert_eq!(view.expiry_unix_ts, owned.expiry_unix_ts);
    assert_eq!(view.private_tx_hash, &owned.private_tx_hash);
    assert_eq!(view.circuit, owned.circuit);
    assert_eq!(view.tx_viewing_pk, &owned.tx_viewing_pk);
    assert_eq!(view.salt, &owned.salt);
    assert_eq!(view.proof, owned.proof);
    assert_eq!(view.inputs, owned.inputs);
    assert_eq!(view.interface_transfers, owned.interface_transfers);
    assert_eq!(view.data_hash, owned.data_hash);
    assert_eq!(view.ring_data_hash, owned.ring_data_hash);
    assert_eq!(view.outputs.len(), owned.outputs.len());
    for (got, want) in view.outputs.iter().zip(owned.outputs.iter()) {
        assert_eq!(got.utxo_hash, &want.utxo_hash);
        assert_eq!(got.owner_tag, want.owner_tag);
        assert_eq!(got.data, want.data.as_deref());
    }
    assert_eq!(view.messages.len(), owned.messages.len());
    for (got, want) in view.messages.iter().zip(owned.messages.iter()) {
        assert_eq!(got.view_tag, &want.view_tag);
        assert_eq!(got.data, want.data.as_slice());
    }
}

#[test]
fn ix_data_round_trips_owned_and_ref() {
    let owned = ix_data(proof());
    let bytes = owned.serialize().unwrap();
    assert_eq!(TransactIxData::deserialize(&bytes).unwrap(), owned);
    let view = TransactIxDataRef::from_bytes(&bytes).unwrap();
    assert_ref_matches_owned(&view, &owned);
}

/// Serialize owned, parse the borrowed view, and confirm every field matches:
/// the owned and Ref encodings are byte-identical, guarding the swap program's
/// owned-reserialize CPI path.
#[test]
fn owned_serialize_matches_ref_parse() {
    let owned = ix_data(proof());
    let bytes = owned.serialize().unwrap();
    let view = TransactIxDataRef::from_bytes(&bytes).unwrap();
    assert_ref_matches_owned(&view, &owned);
}

#[test]
fn rejects_retired_field_bearing_payload() {
    let owned = ix_data(proof());
    let current = owned.serialize().unwrap();
    let (_, prefix) = TransactIxDataRef::parse_with_external_data_prefix(&current).unwrap();
    let field_offset = prefix.len() + 32 + 5;
    let mut retired = Vec::with_capacity(current.len() + 33);
    retired.extend_from_slice(&current[..field_offset]);
    retired.push(1);
    retired.extend_from_slice(&[20u8; 32]);
    retired.extend_from_slice(&current[field_offset..]);
    assert!(TransactIxData::deserialize(&retired).is_err());
    assert!(TransactIxDataRef::from_bytes(&retired).is_err());
}

#[test]
fn rejects_retired_owner_tag_discriminant() {
    assert!(wincode::deserialize_exact::<OwnerTag>(&[2]).is_err());
}

#[test]
fn interface_transfer_sizes_and_helpers_are_stable() {
    let sol = InterfaceTransfer::SolWithdrawal { amount: u64::MAX };
    let spl = InterfaceTransfer::SplDeposit {
        amount: 9,
        spl_interface_bump: 42,
    };
    let variants = [
        InterfaceTransfer::SolDeposit { amount: 1 },
        InterfaceTransfer::SolWithdrawal { amount: 1 },
        InterfaceTransfer::SplDeposit {
            amount: 1,
            spl_interface_bump: 42,
        },
        InterfaceTransfer::SplWithdrawal {
            amount: 1,
            spl_interface_bump: 42,
        },
    ];
    for (expected_tag, transfer) in variants.into_iter().enumerate() {
        assert_eq!(
            wincode::serialize(&transfer).unwrap()[0],
            expected_tag as u8
        );
    }
    assert_eq!(wincode::serialize(&sol).unwrap().len(), 9);
    assert_eq!(wincode::serialize(&spl).unwrap().len(), 10);
    assert_eq!(sol.amount(), u64::MAX);
    assert_eq!(spl.amount(), 9);
    assert!(!sol.is_spl());
    assert!(spl.is_spl());
    assert!(!sol.is_deposit());
    assert!(spl.is_deposit());
}

#[test]
fn interface_transfer_validation_accepts_many_transfers_up_to_limit() {
    let repeated = vec![InterfaceTransfer::SolDeposit { amount: 1 }; MAX_INTERFACE_TRANSFERS];
    assert_eq!(validate_interface_transfers(&repeated), Ok(()));

    let too_many = vec![
        InterfaceTransfer::SplWithdrawal {
            amount: 1,
            spl_interface_bump: 42,
        };
        MAX_INTERFACE_TRANSFERS + 1
    ];
    assert_eq!(
        validate_interface_transfers(&too_many),
        Err(ShieldedPoolError::TooManyInterfaceTransfers)
    );
    assert_eq!(
        validate_interface_transfers(&[InterfaceTransfer::SolDeposit { amount: 0 }]),
        Err(ShieldedPoolError::ZeroInterfaceTransferAmount)
    );
}

#[test]
fn interface_transfer_count_rejects_protocol_overflow_during_serialization() {
    let mut data = ix_data(proof());
    data.interface_transfers =
        vec![InterfaceTransfer::SolDeposit { amount: 1 }; MAX_INTERFACE_TRANSFERS + 1];
    assert!(data.serialize().is_err());
}

#[test]
fn transact_output_serialized_sizes_per_owner_tag() {
    let inline = TransactOutput {
        utxo_hash: [0u8; 32],
        owner_tag: OwnerTag::Inline([0u8; 32]),
        data: None,
    };
    let account = TransactOutput {
        utxo_hash: [0u8; 32],
        owner_tag: OwnerTag::Account(0),
        data: None,
    };
    assert_eq!(wincode::serialize(&inline).unwrap().len(), 32 + 34);
    assert_eq!(wincode::serialize(&account).unwrap().len(), 32 + 3);

    let inline_some = TransactOutput {
        utxo_hash: [0u8; 32],
        owner_tag: OwnerTag::Inline([0u8; 32]),
        data: Some(vec![1, 2, 3]),
    };
    assert_eq!(
        wincode::serialize(&inline_some).unwrap().len(),
        32 + 33 + 1 + 2 + 3
    );
}

#[test]
fn fetch_tag_resolves_every_variant() {
    let accounts = |i: u8| if i == 2 { Some([22u8; 32]) } else { None };

    assert_eq!(
        fetch_tag(&OwnerTag::Inline([7u8; 32]), accounts),
        Ok([7u8; 32])
    );
    assert_eq!(fetch_tag(&OwnerTag::Account(2), accounts), Ok([22u8; 32]));
    assert_eq!(
        fetch_tag(&OwnerTag::Account(5), accounts),
        Err(ShieldedPoolError::OwnerTagAccountMissing)
    );
}

#[test]
fn external_data_preimage_hashes_tag_prefix_and_pushed_addresses_in_order() {
    let tag = [tag::TRANSACT];
    let prefix = [9u8; 8];
    let asset = [1u8; 32];
    let user = [2u8; 32];
    let owner = [3u8; 32];
    let mut preimage = ExternalDataPreimage::new(&tag, &prefix);
    preimage.push_settlement(&asset, &user).unwrap();
    preimage
        .push_owner_tag(&OwnerTag::Inline([4u8; 32]), &[4u8; 32])
        .unwrap();
    preimage
        .push_owner_tag(&OwnerTag::Account(0), &owner)
        .unwrap();
    assert_eq!(
        preimage.finish().unwrap(),
        Sha256BE::hashv(&[&tag, &prefix, &asset, &user, &owner]).unwrap()
    );
}

#[test]
fn external_data_preimage_rejects_slice_overflow() {
    let tag = [tag::TRANSACT];
    let prefix = [0u8; 8];
    let address = [1u8; 32];
    let mut preimage = ExternalDataPreimage::new(&tag, &prefix);
    for _ in 0..MAX_INTERFACE_TRANSFERS {
        preimage.push_settlement(&address, &address).unwrap();
    }
    for _ in 0..MAX_OUTPUTS {
        preimage
            .push_owner_tag(&OwnerTag::Account(0), &address)
            .unwrap();
    }
    assert_eq!(
        preimage.push_owner_tag(&OwnerTag::Account(0), &address),
        Err(HasherError::InvalidInputLength(
            MAX_EXTERNAL_DATA_HASH_SLICES,
            MAX_EXTERNAL_DATA_HASH_SLICES + 1
        ))
    );
}
