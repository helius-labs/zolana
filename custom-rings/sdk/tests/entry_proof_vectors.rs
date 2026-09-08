//! Vectors shared with `sdk-libs/ts/test/ring-list-write.test.ts`.

use zolana_client::{PublicInputs, PublicTransfers};
use zolana_hasher::primitives::{hash_bytes, right_align};
use zolana_interface::{
    instruction::instruction_data::transact::{OwnerTag, TransactOutput},
    ADDRESS_DOMAIN,
};
use zolana_ring_policy::{
    entry_nullifier, entry_seed, EntryState, ListEntry, ListId, ListNamespace, Member,
};
use zolana_transaction::{
    instructions::transact::{ExternalData, PrivateTxHash},
    ProofInputUtxo,
};

const RECORDS_PDA: [u8; 32] = [0x11; 32];
const RECIPIENT_TAG: [u8; 32] = [0xa1; 32];
const PAYER: [u8; 32] = [0x01; 32];
const STATE_ROOT: [u8; 32] = [0x06; 32];
const NULLIFIER_ROOT: [u8; 32] = [0x07; 32];

const EXTERNAL_HASH: &str = "00cd3ab6720cc54f4119c19e017a3d4e0125cb4e7ba30b3e93b8a98046fbdc5f";
const CLAIM_PRIVATE_TX_HASH: &str =
    "1318c383e8274e82368af891aadcbdce782b933afd743800d14e9f7f05c769d3";
const CLAIM_PUBLIC_INPUT_HASH: &str =
    "0774564900eab14245f24d383e85928ca78588bc8f5417d642512f52d66dd55f";
const SPEND_PRIVATE_TX_HASH: &str =
    "0076a214396d186cf1bcea3941002c231d78bbdc3a24f90483a8322ae2ff9c6a";
const SPEND_PUBLIC_INPUT_HASH: &str =
    "18cd54d188bea439dac4f37a03e8ea18bec5effba436e24d43789a4322ae70ca";

struct Transition {
    external: [u8; 32],
    private_tx: [u8; 32],
    public_input: [u8; 32],
}

/// The namespace and member of the Go policy circuit fixture.
fn transition(spent: Option<ListEntry>) -> Transition {
    let owner = ListNamespace::new(&RECORDS_PDA).expect("owner");
    let member = Member::owner_tag(&RECIPIENT_TAG).expect("member");
    let entry = ListEntry {
        list_id: ListId::Allow,
        member,
        state: EntryState::Active,
        version: spent.map_or(0, |spent| spent.version + 1),
        content_hash: [0u8; 32],
    };
    let address = owner.address(ListId::Allow, &member).expect("address");
    let (input_hash, address_hash, nullifier) = match spent {
        None => {
            let seed = entry_seed(ListId::Allow, &member).expect("seed");
            let slot = ProofInputUtxo {
                domain: right_align(&ADDRESS_DOMAIN.to_be_bytes()),
                owner_hash: owner.owner_hash,
                blinding: seed,
                ..ProofInputUtxo::default()
            };
            ([0u8; 32], Some(slot.hash().expect("address slot")), address)
        }
        Some(spent) => {
            let spent_hash = spent.utxo_hash(&owner, &address).expect("spent hash");
            let nullifier = entry_nullifier(&spent_hash, &spent.blinding()).expect("nullifier");
            (spent_hash, None, nullifier)
        }
    };
    let output_hash = entry.utxo_hash(&owner, &address).expect("output hash");
    let external = ExternalData::new(
        [0u8; 33],
        [0u8; 16],
        vec![TransactOutput {
            utxo_hash: output_hash,
            owner_tag: OwnerTag::Inline(RECORDS_PDA),
            data: Some(entry.to_output_data().to_vec()),
        }],
        vec![RECORDS_PDA],
        Vec::new(),
    )
    .hash()
    .expect("external hash");
    let private_tx = PrivateTxHash {
        input_hashes: &[input_hash],
        output_hashes: &[output_hash],
        address_hashes: address_hash.as_ref().map(core::slice::from_ref),
        external_data_hash: &external,
    }
    .hash()
    .expect("private tx hash");
    let namespace_hash = hash_bytes(&RECORDS_PDA).expect("namespace");
    let payer_hash = hash_bytes(&PAYER).expect("payer");
    let public_input = PublicInputs {
        nullifiers: &[nullifier],
        output_hashes: &[output_hash],
        utxo_roots: &[STATE_ROOT],
        nullifier_tree_roots: &[NULLIFIER_ROOT],
        private_tx: &private_tx,
        external_data_hash: &external,
        public_transfers: &PublicTransfers::default(),
        ring_program_id: &[0u8; 32],
        allow_dummy_inputs: &right_align(&1u64.to_be_bytes()),
        signer_pk_hashes: &[payer_hash, namespace_hash],
        output_owner_pk_hashes: Some(&[namespace_hash]),
    }
    .hash()
    .expect("public input hash");
    Transition {
        external,
        private_tx,
        public_input,
    }
}

#[test]
fn a_claim_hashes_to_the_typescript_vector() {
    let claim = transition(None);
    assert_eq!(hex::encode(claim.external), EXTERNAL_HASH, "external");
    assert_eq!(
        hex::encode(claim.private_tx),
        CLAIM_PRIVATE_TX_HASH,
        "private"
    );
    assert_eq!(
        hex::encode(claim.public_input),
        CLAIM_PUBLIC_INPUT_HASH,
        "public"
    );
}

#[test]
fn a_spend_hashes_to_the_typescript_vector() {
    let spent = ListEntry {
        list_id: ListId::Allow,
        member: Member::owner_tag(&RECIPIENT_TAG).expect("member"),
        state: EntryState::Active,
        version: 0,
        content_hash: [0u8; 32],
    };
    let spend = transition(Some(spent));
    assert_eq!(
        hex::encode(spend.private_tx),
        SPEND_PRIVATE_TX_HASH,
        "private"
    );
    assert_eq!(
        hex::encode(spend.public_input),
        SPEND_PUBLIC_INPUT_HASH,
        "public"
    );
}
