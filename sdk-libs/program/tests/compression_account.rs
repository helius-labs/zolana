#![cfg(feature = "compression")]

use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};
use pinocchio::{error::ProgramError, Address};
use zolana_hasher::{primitives::right_align, Hasher, Poseidon};
use zolana_interface::{
    event::OutputDataEncoding,
    instruction::instruction_data::transact::{
        CircuitId, InputUtxo, OwnerTag, TransactIxData, TransactProof, TreeContext,
    },
    N_PUBLIC_SLOTS,
};
use zolana_program::compression::{
    AddressSeed, CompressedAccount, CompressedAccountData, CompressedAccountError,
    CompressedAccountMeta, DataUtxo, NewAddress, PdaOwner, SppTransactCpi, ACCOUNT_BLINDING_SEED,
};

const ADDRESS_TREE_ID: u16 = 1;
const STATE_TREE_ID: u16 = 2;
const OUTPUT_TREE_ID: u16 = 4;
const ADDRESS_CONTEXT: TreeContext = TreeContext {
    utxo_tree_root_index: 3,
    nullifier_tree_root_index: 4,
};
const STATE_CONTEXT: TreeContext = TreeContext {
    utxo_tree_root_index: 7,
    nullifier_tree_root_index: 8,
};

/// A state that stores its address and blinding, as the trait asks.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
struct CounterState {
    address: [u8; 32],
    count: u8,
    blinding: [u8; 32],
}

impl CompressedAccountData for CounterState {
    fn data_hash(&self) -> Result<[u8; 32], ProgramError> {
        if self.count == 0 {
            return Ok([0u8; 32]);
        }
        Ok(Poseidon::hashv(&[
            &self.address,
            &right_align(&[self.count]),
            &self.blinding,
        ])?)
    }

    fn address_mut(&mut self) -> &mut [u8; 32] {
        &mut self.address
    }

    fn blinding_mut(&mut self) -> &mut [u8; 32] {
        &mut self.blinding
    }
}

fn owner(byte: u8) -> PdaOwner {
    PdaOwner::new(&Address::new_from_array([byte; 32])).unwrap()
}

fn meta(tree_context: TreeContext) -> CompressedAccountMeta {
    CompressedAccountMeta {
        address: right_align(&[6u8]),
        blinding: right_align(&[5u8]),
        tree_context,
    }
}

fn create(owner: &PdaOwner, count: u8) -> CompressedAccount<'_, CounterState> {
    let address = NewAddress::derive(owner, AddressSeed::owner(owner), ADDRESS_TREE_ID).unwrap();
    let mut account: CompressedAccount<'_, CounterState> =
        CompressedAccount::new_init(owner, address, ADDRESS_CONTEXT);
    account.count = count;
    account
}

fn update(
    owner: &PdaOwner,
    tree_context: TreeContext,
    current_count: u8,
    new_count: u8,
) -> CompressedAccount<'_, CounterState> {
    let mut account = CompressedAccount::new_mut(
        owner,
        &meta(tree_context),
        CounterState {
            count: current_count,
            ..CounterState::default()
        },
        STATE_TREE_ID,
    )
    .unwrap();
    account.count = new_count;
    account
}

fn proof() -> TransactProof {
    TransactProof {
        a: [1u8; 32],
        b: [2u8; 128],
        c: [3u8; 32],
    }
}

fn build(
    accounts: Vec<CompressedAccount<'_, CounterState>>,
) -> Result<TransactIxData, ProgramError> {
    Ok(accounts
        .into_iter()
        .try_fold(
            SppTransactCpi::new(proof()),
            SppTransactCpi::with_compressed_account,
        )?
        .into_ix_data(OUTPUT_TREE_ID)?)
}

/// The circuit's output blinding, spelled out from its Poseidon preimages
/// under the ASCII domain tags.
fn circuit_output_blinding(first_nullifier: &[u8; 32], slot: u32) -> [u8; 32] {
    let seed = Poseidon::hashv(&[
        &right_align(b"TXOS"),
        first_nullifier,
        &ACCOUNT_BLINDING_SEED,
    ])
    .unwrap();
    Poseidon::hashv(&[
        &right_align(b"TXOB"),
        first_nullifier,
        &seed,
        &right_align(&slot.to_be_bytes()),
    ])
    .unwrap()
}

/// The states the transaction publishes, decoded from its output data.
fn published_states(ix: &TransactIxData) -> Vec<CounterState> {
    ix.outputs
        .iter()
        .map(|output| {
            let OutputDataEncoding::Plaintext(state) =
                OutputDataEncoding::try_from_slice(output.data.as_deref().unwrap()).unwrap()
            else {
                panic!("output data is not plaintext");
            };
            CounterState::try_from_slice(&state).unwrap()
        })
        .collect()
}

#[test]
fn new_init_starts_from_the_default_state_at_the_address() {
    let owner = owner(4);
    let address = NewAddress::derive(&owner, AddressSeed::owner(&owner), ADDRESS_TREE_ID).unwrap();
    let account: CompressedAccount<'_, CounterState> =
        CompressedAccount::new_init(&owner, address, ADDRESS_CONTEXT);

    assert_eq!(
        (&*account, account.input_nullifier()),
        (
            &CounterState {
                address: *address.address(),
                ..CounterState::default()
            },
            address.address()
        )
    );
}

#[test]
fn new_mut_spends_the_state_with_the_meta_address_and_blinding() {
    let owner = owner(4);
    let meta = meta(STATE_CONTEXT);
    let account = update(&owner, STATE_CONTEXT, 9, 9);
    let current = CounterState {
        address: meta.address,
        count: 9,
        blinding: meta.blinding,
    };
    let current_nullifier = *DataUtxo {
        owner: &owner,
        data_hash: current.data_hash().unwrap(),
        blinding: meta.blinding,
    }
    .key(STATE_TREE_ID)
    .unwrap()
    .nullifier();

    assert_eq!(
        (&*account, *account.input_nullifier()),
        (&current, current_nullifier)
    );
}

/// A create and an update in one transaction: two slots, two trees, every
/// new state carrying the circuit's blinding for its slot and published as
/// plaintext borsh.
#[test]
fn into_ix_data_writes_every_account_in_slot_order() {
    let (creator, updater) = (owner(4), owner(5));
    let first_nullifier = *create(&creator, 11).input_nullifier();
    let second_nullifier = *update(&updater, STATE_CONTEXT, 9, 12).input_nullifier();
    let ix = build(vec![
        create(&creator, 11),
        update(&updater, STATE_CONTEXT, 9, 12),
    ])
    .unwrap();

    let expected_states = vec![
        CounterState {
            address: *create(&creator, 11).input_nullifier(),
            count: 11,
            blinding: circuit_output_blinding(&first_nullifier, 0),
        },
        CounterState {
            address: meta(STATE_CONTEXT).address,
            count: 12,
            blinding: circuit_output_blinding(&first_nullifier, 1),
        },
    ];
    let expected_outputs: Vec<([u8; 32], OwnerTag)> = [&creator, &updater]
        .into_iter()
        .zip(&expected_states)
        .map(|(owner, state)| {
            let hash = DataUtxo {
                owner,
                data_hash: state.data_hash().unwrap(),
                blinding: state.blinding,
            }
            .hash(OUTPUT_TREE_ID)
            .unwrap();
            (hash, OwnerTag::Inline(owner.pda().to_bytes()))
        })
        .collect();
    let outputs: Vec<([u8; 32], OwnerTag)> = ix
        .outputs
        .iter()
        .map(|output| (output.utxo_hash, output.owner_tag))
        .collect();

    assert_eq!(
        (
            ix.inputs.clone(),
            ix.tree_contexts.clone(),
            ix.circuit,
            outputs,
            published_states(&ix),
        ),
        (
            vec![
                InputUtxo {
                    nullifier_hash: first_nullifier,
                    tree_index: 0,
                },
                InputUtxo {
                    nullifier_hash: second_nullifier,
                    tree_index: 1,
                },
            ],
            vec![ADDRESS_CONTEXT, STATE_CONTEXT],
            CircuitId::ConfidentialEddsa(2, 2, N_PUBLIC_SLOTS as u8),
            expected_outputs,
            expected_states,
        )
    );
}

#[test]
fn into_ix_data_shares_one_context_between_inputs_of_one_tree() {
    let (first, second) = (owner(4), owner(5));
    let ix = build(vec![
        update(&first, STATE_CONTEXT, 9, 11),
        update(&second, STATE_CONTEXT, 9, 12),
    ])
    .unwrap();
    let tree_indexes: Vec<u8> = ix.inputs.iter().map(|input| input.tree_index).collect();

    assert_eq!(
        (tree_indexes, ix.tree_contexts),
        (vec![0, 0], vec![STATE_CONTEXT])
    );
}

/// Changing only the input, or only the output, changes the private
/// transaction hash.
#[test]
fn into_ix_data_binds_the_private_transaction_to_inputs_and_outputs() {
    let owner = owner(4);
    let base = build(vec![update(&owner, STATE_CONTEXT, 9, 11)]).unwrap();
    let other_input = build(vec![update(&owner, STATE_CONTEXT, 10, 11)]).unwrap();
    let other_output = build(vec![update(&owner, STATE_CONTEXT, 9, 12)]).unwrap();
    let address_input = build(vec![create(&owner, 11)]).unwrap();

    assert_eq!(
        (
            other_input.private_tx_hash != base.private_tx_hash,
            other_output.private_tx_hash != base.private_tx_hash,
            address_input.private_tx_hash != base.private_tx_hash,
        ),
        (true, true, true)
    );
}

/// Updates that never change the data still produce a fresh UTXO each time:
/// each new blinding derives from the nullifier of the UTXO it replaces, so
/// no UTXO hash or nullifier repeats although the blinding seed is fixed.
#[test]
fn repeated_updates_with_unchanged_data_never_repeat_a_utxo() {
    let owner = owner(4);
    let mut current = meta(STATE_CONTEXT);
    let mut hashes = HashSet::new();
    let mut nullifiers = HashSet::new();

    for _ in 0..8 {
        let account = CompressedAccount::new_mut(
            &owner,
            &current,
            CounterState {
                count: 9,
                ..CounterState::default()
            },
            STATE_TREE_ID,
        )
        .unwrap();
        nullifiers.insert(*account.input_nullifier());
        let ix = SppTransactCpi::new(proof())
            .with_compressed_account(account)
            .unwrap()
            .into_ix_data(STATE_TREE_ID)
            .unwrap();
        let [published] = published_states(&ix).try_into().unwrap();
        hashes.insert(ix.outputs.first().unwrap().utxo_hash);
        current.blinding = published.blinding;
    }

    assert_eq!((hashes.len(), nullifiers.len()), (8, 8));
}

#[test]
fn into_ix_data_rejects_invalid_account_sets() {
    let (first, second) = (owner(4), owner(5));
    let other_context = TreeContext {
        utxo_tree_root_index: 1,
        ..STATE_CONTEXT
    };
    let cases: Vec<(
        Vec<CompressedAccount<'_, CounterState>>,
        CompressedAccountError,
    )> = vec![
        (Vec::new(), CompressedAccountError::NoAccounts),
        (
            vec![
                update(&first, STATE_CONTEXT, 9, 11),
                create(&second, 12),
                update(&second, STATE_CONTEXT, 9, 13),
            ],
            CompressedAccountError::InputTreesNotContiguous,
        ),
        (
            vec![
                update(&first, STATE_CONTEXT, 9, 11),
                update(&second, other_context, 9, 12),
            ],
            CompressedAccountError::ConflictingTreeContexts,
        ),
    ];

    for (accounts, expected) in cases {
        assert_eq!(
            build(accounts).map(|ix| ix.private_tx_hash),
            Err(expected.into())
        );
    }
}

#[test]
fn with_compressed_account_rejects_a_zero_new_data_hash() {
    let owner = owner(4);

    assert_eq!(
        SppTransactCpi::new(proof())
            .with_compressed_account(create(&owner, 0))
            .and_then(|cpi| Ok(cpi.into_ix_data(OUTPUT_TREE_ID)?))
            .map(|ix| ix.private_tx_hash),
        Err(CompressedAccountError::ZeroDataHash.into())
    );
}

#[test]
fn new_mut_rejects_a_zero_current_data_hash() {
    let owner = owner(4);

    assert_eq!(
        CompressedAccount::new_mut(
            &owner,
            &meta(STATE_CONTEXT),
            CounterState::default(),
            STATE_TREE_ID
        )
        .map(|account| *account.input_nullifier()),
        Err(CompressedAccountError::ZeroDataHash.into())
    );
}
