use solana_address::Address;
use zolana_interface::event::{
    encode_merge_event, encode_transact_event, GeneralEvent, MergeEvent, TransactEvent,
};
use zolana_interface::instruction::instruction_data::{
    merge_ring::MergeRingIxData,
    merge_transact::{MergeProof, MergeTransactIxData},
    transact::CircuitId,
};
use zolana_interface::instruction::{
    tag, InputUtxo, InterfaceTransfer, OwnerTag, TransactIxData, TransactOutput, TransactProof,
};

pub const PUBLIC_ASSET_SLOTS: u8 = 3;

pub struct EventFixture {
    pub parent_data: Vec<u8>,
    pub parent_accounts: Vec<Address>,
    pub emit_event_data: Vec<u8>,
}

impl EventFixture {
    pub fn payload(&self) -> Vec<u8> {
        self.emit_event_data.get(1..).unwrap_or_default().to_vec()
    }
}

pub fn transact_fixture(
    spp: Address,
    source_instruction_tag: u8,
    event: &GeneralEvent,
) -> EventFixture {
    let input_tree = event
        .inputs
        .first()
        .map_or(event.output_tree, |input| input.tree);
    let mut parent_accounts = vec![
        Address::new_unique(),
        Address::new_from_array(input_tree),
        Address::new_from_array(event.output_tree),
        spp,
        Address::new_unique(),
    ];
    if source_instruction_tag != tag::TRANSACT {
        parent_accounts.push(Address::new_unique());
    }
    parent_accounts.extend(event.inputs.iter().map(|_| Address::new_unique()));

    let mut settlement_accounts = Vec::new();
    let interface_transfers = event
        .spl_transfers
        .iter()
        .map(|transfer| match (transfer.is_deposit, transfer.asset) {
            (true, None) => {
                settlement_accounts.extend([Address::new_unique(), Address::new_unique()]);
                InterfaceTransfer::SolDeposit {
                    amount: transfer.amount,
                }
            }
            (false, None) => {
                settlement_accounts.extend([Address::new_unique(), Address::new_unique()]);
                InterfaceTransfer::SolWithdrawal {
                    amount: transfer.amount,
                }
            }
            (true, Some(mint)) => {
                settlement_accounts.extend([
                    Address::new_from_array(mint),
                    Address::new_unique(),
                    Address::new_unique(),
                    Address::new_unique(),
                    Address::new_unique(),
                ]);
                InterfaceTransfer::SplDeposit {
                    amount: transfer.amount,
                    spl_interface_bump: 0,
                }
            }
            (false, Some(mint)) => {
                settlement_accounts.extend([
                    Address::new_unique(),
                    Address::new_from_array(mint),
                    Address::new_unique(),
                    Address::new_unique(),
                    Address::new_unique(),
                ]);
                InterfaceTransfer::SplWithdrawal {
                    amount: transfer.amount,
                    spl_interface_bump: 0,
                }
            }
        })
        .collect();
    parent_accounts.extend(settlement_accounts);

    let n_inputs = u8::try_from(event.inputs.len()).expect("input count fits in u8");
    let n_outputs = u8::try_from(event.outputs.len()).expect("output count fits in u8");
    let circuit = match source_instruction_tag {
        tag::TRANSACT => CircuitId::ConfidentialEddsa(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS),
        tag::RING_TRANSACT => CircuitId::RingEddsa(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS),
        tag::RING_AUTHORITY_TRANSACT => {
            CircuitId::RingAuthority(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS)
        }
        other => panic!("not a transact source tag: {other}"),
    };
    let data = TransactIxData {
        expiry_unix_ts: u64::MAX,
        tx_viewing_pk: event.tx_viewing_pk,
        salt: event.salt,
        interface_transfers,
        outputs: event
            .outputs
            .iter()
            .map(|output| TransactOutput {
                utxo_hash: output.utxo_hash,
                owner_tag: OwnerTag::Inline(output.view_tag),
                data: (!output.data.is_empty()).then(|| output.data.clone()),
            })
            .collect(),
        messages: event.messages.clone(),
        data_hash: None,
        ring_data_hash: None,
        circuit,
        proof: TransactProof::zeroed(),
        private_tx_hash: [0; 32],
        inputs: event
            .inputs
            .iter()
            .map(|input| InputUtxo {
                nullifier_hash: input.nullifier,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: 0,
            })
            .collect(),
    };
    let mut parent_data = vec![source_instruction_tag];
    parent_data.extend_from_slice(&data.serialize().expect("serialize transact fixture"));

    EventFixture {
        parent_data,
        parent_accounts,
        emit_event_data: encode_transact_event(&TransactEvent {
            first_input_queue_seq: event
                .inputs
                .first()
                .map_or(0, |input| input.input_queue_seq),
            first_output_leaf_index: event.first_output_leaf_index,
        })
        .to_vec(),
    }
}

pub fn merge_fixture(source_instruction_tag: u8, event: &GeneralEvent) -> EventFixture {
    let output = event.outputs.first().expect("merge event has one output");
    let input_tree = event
        .inputs
        .first()
        .map_or(event.output_tree, |input| input.tree);
    let mut parent_accounts = vec![
        Address::new_from_array(input_tree),
        Address::new_from_array(event.output_tree),
    ];
    parent_accounts.extend((0..4).map(|_| Address::new_unique()));
    parent_accounts.extend(event.inputs.iter().map(|_| Address::new_unique()));

    let input_count = event.inputs.len();
    let merge = MergeTransactIxData {
        expiry_unix_ts: u64::MAX,
        proof: MergeProof::zeroed(),
        output_utxo_hash: output.utxo_hash,
        eddsa_owner: false,
        private_tx_hash: [0; 32],
        nullifiers: event.inputs.iter().map(|input| input.nullifier).collect(),
        utxo_tree_root_index: vec![0; input_count],
        nullifier_tree_root_index: vec![0; input_count],
    };
    let (body, output_view_tag) = match source_instruction_tag {
        tag::MERGE_TRANSACT => (
            merge.serialize().expect("serialize merge fixture"),
            output.view_tag,
        ),
        tag::RING_MERGE_TRANSACT => {
            let output_ring_data_hash: [u8; 32] = output
                .data
                .as_slice()
                .try_into()
                .expect("ring merge output data is the 32-byte ring data hash");
            (
                MergeRingIxData {
                    output_ring_data_hash,
                    merge,
                }
                .serialize()
                .expect("serialize ring merge fixture"),
                [0u8; 32],
            )
        }
        other => panic!("not a merge source tag: {other}"),
    };
    let mut parent_data = vec![source_instruction_tag];
    parent_data.extend_from_slice(&body);

    EventFixture {
        parent_data,
        parent_accounts,
        emit_event_data: encode_merge_event(&MergeEvent {
            first_input_queue_seq: event
                .inputs
                .first()
                .map_or(0, |input| input.input_queue_seq),
            first_output_leaf_index: event.first_output_leaf_index,
            output_view_tag,
        })
        .to_vec(),
    }
}
