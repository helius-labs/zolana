use shielded_pool_program::testing::hash_external_data;
use zolana_hasher::{sha256::Sha256BE, Hasher};
use zolana_interface::instruction::{
    instruction_data::transact::{
        CircuitId, OwnerTag, ResolvedOutput, TransactIxData, TransactIxDataRef, TransactOutput,
        TransactProof,
    },
    tag::InstructionTag,
};

const ACCOUNT_OWNER_INDEX: u8 = 3;
const SECOND_ACCOUNT_OWNER_INDEX: u8 = 4;

fn serialized_ix(owner_tags: &[OwnerTag]) -> Vec<u8> {
    let outputs = owner_tags
        .iter()
        .enumerate()
        .map(|(i, owner_tag)| TransactOutput {
            utxo_hash: core::array::from_fn(|j| (i + j) as u8),
            owner_tag: *owner_tag,
            data: (i % 2 == 0).then(|| vec![0xaa; 16]),
        })
        .collect();
    TransactIxData {
        expiry_unix_ts: 1_234_567_890,
        tx_viewing_pk: core::array::from_fn(|i| 0x90 + i as u8),
        salt: core::array::from_fn(|i| 0xf0 + i as u8),
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: Some([7u8; 32]),
        outputs,
        messages: Vec::new(),
        private_tx_hash: [0u8; 32],
        circuit: CircuitId::ConfidentialEddsa(1, 2, 3),
        proof: TransactProof::zeroed(),
        inputs: Vec::new(),
    }
    .serialize()
    .unwrap()
}

fn resolve<'a>(ix: &TransactIxDataRef<'a>, owners: [(u8, [u8; 32]); 2]) -> Vec<ResolvedOutput<'a>> {
    ix.outputs
        .iter()
        .map(|output| {
            output
                .into_resolved(|index| {
                    owners
                        .iter()
                        .find(|(owner_index, _)| *owner_index == index)
                        .map(|(_, owner)| *owner)
                })
                .unwrap()
        })
        .collect()
}

#[test]
fn inline_owner_tags_hash_only_tag_and_prefix() {
    let inline_owner: [u8; 32] = core::array::from_fn(|i| i as u8);
    let bytes = serialized_ix(&[
        OwnerTag::Inline(inline_owner),
        OwnerTag::Inline(inline_owner),
    ]);
    let (ix, prefix) = TransactIxDataRef::parse_with_external_data_prefix(&bytes).unwrap();
    let resolved = resolve(
        &ix,
        [
            (ACCOUNT_OWNER_INDEX, [0u8; 32]),
            (SECOND_ACCOUNT_OWNER_INDEX, [0u8; 32]),
        ],
    );
    let tag = [InstructionTag::Transact as u8];

    let got = hash_external_data(&tag, prefix, &ix, &[], &resolved).unwrap();

    assert_eq!(got, Sha256BE::hashv(&[&tag, prefix]).unwrap());
}

#[test]
fn account_owner_tags_append_resolved_addresses_in_output_order() {
    let inline_owner: [u8; 32] = core::array::from_fn(|i| i as u8);
    let first_owner: [u8; 32] = core::array::from_fn(|i| 0x30 + i as u8);
    let second_owner: [u8; 32] = core::array::from_fn(|i| 0x50 + i as u8);
    let bytes = serialized_ix(&[
        OwnerTag::Account(SECOND_ACCOUNT_OWNER_INDEX),
        OwnerTag::Inline(inline_owner),
        OwnerTag::Account(ACCOUNT_OWNER_INDEX),
    ]);
    let (ix, prefix) = TransactIxDataRef::parse_with_external_data_prefix(&bytes).unwrap();
    let resolved = resolve(
        &ix,
        [
            (ACCOUNT_OWNER_INDEX, first_owner),
            (SECOND_ACCOUNT_OWNER_INDEX, second_owner),
        ],
    );
    let tag = [InstructionTag::RingTransact as u8];

    let got = hash_external_data(&tag, prefix, &ix, &[], &resolved).unwrap();

    assert_eq!(
        got,
        Sha256BE::hashv(&[&tag, prefix, &second_owner, &first_owner]).unwrap()
    );
    assert_ne!(
        got,
        Sha256BE::hashv(&[&tag, prefix, &first_owner, &second_owner]).unwrap()
    );
    assert_ne!(got, Sha256BE::hashv(&[&tag, prefix]).unwrap());
}
