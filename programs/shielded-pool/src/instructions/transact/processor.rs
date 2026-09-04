use crate::instructions::{
    event::emit_transact_event,
    nullifier_pda::create_nullifier_pdas,
    settlement::Settlement,
    shared::{caused_by, check_field_element, check_not_expired, collect_forester_fee},
    transact::verify::{OwnerHashCache, TransactProof, TransactProofInputs},
};
use arrayvec::ArrayVec;
use light_program_profiler::profile;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_event::TransactEvent;
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::{
            transact::{
                CircuitId, ExternalDataPreimage, InterfaceTransfer, OwnerTagRef, TransactIxDataRef,
                TransactOutputRef,
            },
            BorrowedList,
        },
        tag::InstructionTag,
    },
    MAX_TRANSACT_INPUTS, N_PUBLIC_SLOTS,
};

use super::{
    account::{RingTransactAccounts, TransactAccounts},
    interface_transfer::settle_interface_transfers,
    tree::{apply_input_tree, apply_output_tree},
};

/// Hash the serialized external-data prefix and the account addresses it names
/// before mutable account parsing. Both inputs are borrowed directly from the
/// runtime; this does not allocate or copy either instruction data or account
/// addresses.
#[inline(never)]
fn hash_external_data_from_accounts<'a>(
    instruction: InstructionTag,
    external_data_prefix: &'a [u8],
    accounts: &'a [AccountView],
    interface_transfers: BorrowedList<'_, InterfaceTransfer>,
    outputs: BorrowedList<'_, TransactOutputRef<'_>>,
) -> Result<[u8; 32], ProgramError> {
    let mut settlement_account_count = 0usize;
    for transfer in interface_transfers.try_iter() {
        settlement_account_count = settlement_account_count
            .checked_add(decode_item(transfer)?.settlement_account_count())
            .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?;
    }
    // Settlement groups are the final accounts; the account parser later
    // validates every selected account and rejects missing or extra accounts.
    let mut settlement_offset = accounts
        .len()
        .checked_sub(settlement_account_count)
        .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?;

    let discriminator = [instruction as u8];
    let mut preimage = ExternalDataPreimage::new(&discriminator, external_data_prefix);
    for transfer in interface_transfers.try_iter() {
        let transfer = decode_item(transfer)?;
        let group = accounts
            .get(settlement_offset..)
            .and_then(|rest| rest.get(..transfer.settlement_account_count()))
            .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?;
        let settlement = Settlement::from_group(transfer, group, 0)?;
        push_account_address(&mut preimage, settlement.user_account())?;
        if let Some(spl_interface) = settlement.spl_interface_account() {
            push_account_address(&mut preimage, spl_interface)?;
        }
        settlement_offset = settlement_offset
            .checked_add(group.len())
            .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?;
    }

    // Inline tags are already part of `external_data_prefix`. Account-backed
    // tags append the referenced runtime address in output order.
    for output in outputs.try_iter() {
        let output = decode_item(output)?;
        if let OwnerTagRef::Account(index) = output.owner_tag {
            let owner = accounts
                .get(usize::from(index))
                .ok_or(ShieldedPoolError::OwnerTagAccountMissing)?;
            push_account_address(&mut preimage, owner)?;
        }
    }

    preimage.finish().map_err(caused_by(
        ShieldedPoolError::TransactProofVerificationFailed,
    ))
}

#[inline]
fn push_account_address<'a>(
    preimage: &mut ExternalDataPreimage<'a>,
    account: &'a AccountView,
) -> ProgramResult {
    preimage
        .push_address(account.address().as_array())
        .map_err(|_| ShieldedPoolError::InvalidInstructionData.into())
}

#[inline]
fn decode_item<T, E>(item: Result<T, E>) -> Result<T, ProgramError> {
    item.map_err(|_| ProgramError::InvalidInstructionData)
}

fn validate_transfers(ix: &TransactIxDataRef<'_>) -> ProgramResult {
    for transfer in ix.interface_transfers.try_iter() {
        if decode_item(transfer)?.amount() == 0 {
            return Err(ShieldedPoolError::ZeroInterfaceTransferAmount.into());
        }
    }
    Ok(())
}

// 1. Deserialize instruction data.
// 2. Validate declared circuit type.
// 3. Check proof is not expired.
// 4. Hash external data directly from the instruction and account buffers.
// 5. Derive output-owner public inputs directly from those same buffers.
// 6. Validate and parse accounts.
#[inline(never)]
#[profile]
pub fn process_transact_ix(
    accounts: &mut [AccountView],
    data: &[u8],
    instruction: InstructionTag,
) -> ProgramResult {
    // 1. Deserialize instruction data.
    let (ix, external_data_hash) = TransactIxDataRef::parse_with_external_data(
        data,
        |external_data_prefix, interface_transfers, outputs| {
            hash_external_data_from_accounts(
                instruction,
                external_data_prefix,
                accounts,
                interface_transfers,
                outputs,
            )
        },
    )
    .map_err(|error| error.or_encoding(ProgramError::InvalidInstructionData))?;
    // 2. Validate declared circuit type.
    validate_circuit_type(&ix, instruction)?;
    validate_transfers(&ix)?;

    // 3. Check proof is not expired.
    let clock = Clock::get()?;
    check_not_expired(ix.expiry_unix_ts, &clock)?;

    // 4. The flat parser hashed the exact prefix at its `messages` boundary,
    // before it parsed `private_tx_hash` and the proof tail.
    let external_data_hash = external_data_hash?;

    // Both are stack-backed and sized by fixed protocol constants.
    let mut proof_inputs = TransactProofInputs::new(ix.circuit);
    let mut owner_hashes = OwnerHashCache::new();
    // 5. Derive the circuit-specific fixed-width output-owner commitment.
    proof_inputs.fill_output_owner_chain(
        ix.circuit.output_owner_mode(),
        &ix,
        accounts,
        &mut owner_hashes,
    )?;
    proof_inputs.assign_external_data_hash(external_data_hash);
    // 6. Check accounts.
    let transact_accounts = match ix.circuit {
        CircuitId::ConfidentialEddsa(..) => TransactAccounts::validate_and_parse(accounts, &ix)?,
        CircuitId::RingEddsa(..) | CircuitId::RingAuthority(..) | CircuitId::RingP256(..) => {
            let (transact_accounts, ring_program_id) =
                RingTransactAccounts::validate_and_parse(accounts, &ix, ix.circuit.is_authority())?;
            proof_inputs.assign_ring_program_id(hash_bytes(&ring_program_id)?);
            transact_accounts
        }
    };
    // 7. Add owner signer hashes to proof inputs.
    proof_inputs.fill_owner_signer_hashes(
        transact_accounts.payer,
        transact_accounts.owner_signers,
        &mut owner_hashes,
    )?;

    // 8. Process SOL and SPL transfers.
    proof_inputs.assign_public_amounts_and_assets(
        transact_accounts.settlements(ix.interface_transfers),
        usize::from(ix.circuit.num_public_asset_slots()),
    )?;
    let mut nullifiers: ArrayVec<&[u8; 32], MAX_TRANSACT_INPUTS> = ArrayVec::new();
    for input in ix.inputs.try_iter() {
        nullifiers
            .try_push(decode_item(input)?.nullifier_hash)
            .map_err(|_| ShieldedPoolError::InvalidTransactShape)?;
    }
    // 9. Insert nullifiers into the queue.
    let input_tree_result = apply_input_tree(transact_accounts.input_tree, &ix, &mut proof_inputs)?;
    // The fee transfer CPI includes the tree, so it must run before
    // create_nullifier_pdas moves tree lamports directly: a CPI boundary syncs
    // only its own accounts into the transaction context, and a pending tree
    // debit without the matching nullifier PDA credits trips the runtime's
    // UnbalancedInstruction check.
    collect_forester_fee(
        transact_accounts.payer,
        transact_accounts.input_tree,
        input_tree_result.forester_fee,
    )?;
    create_nullifier_pdas(
        transact_accounts.input_tree,
        transact_accounts.nullifier_pdas.iter_mut(),
        nullifiers.iter().copied(),
        &input_tree_result,
    )?;
    // 10. Append new UTXO hashes.
    let first_output_leaf_index = apply_output_tree(transact_accounts.output_tree, &ix)?;

    proof_inputs.ensure_complete()?;

    TransactProof::new(&ix, &proof_inputs).verify()?;

    settle_interface_transfers(transact_accounts.settlements(ix.interface_transfers))?;

    // Only the execution-assigned positions: an indexer rebuilds nullifiers,
    // outputs, messages and trees from this instruction and its account list.
    emit_transact_event(&TransactEvent {
        first_input_queue_seq: input_tree_result.first_input_queue_seq,
        first_output_leaf_index,
    })
}

/// Checks:
/// 1. Circuit is allowed for the instruction type
/// 2. Circuit parameters (in, out) match instruction data
/// 3. Circuit variant exists with in out public params is supported.
/// 4. Nullifiers, output utxo hashes, and the private tx hash are canonical
///    field elements.
pub fn validate_circuit_type(
    ix: &TransactIxDataRef<'_>,
    instruction_tag: InstructionTag,
) -> ProgramResult {
    // 1. Circuit is allowed for the instruction type.
    let circuit_matches = match instruction_tag {
        InstructionTag::Transact => matches!(ix.circuit, CircuitId::ConfidentialEddsa(..)),
        InstructionTag::RingTransact => {
            matches!(
                ix.circuit,
                CircuitId::RingEddsa(..) | CircuitId::RingP256(..)
            )
        }
        InstructionTag::RingAuthorityTransact => ix.circuit.is_authority(),
        _ => false,
    };
    if !circuit_matches {
        return Err(ShieldedPoolError::MismatchedCircuitType.into());
    }
    if usize::from(ix.circuit.num_inputs()) != ix.inputs.len() // 2.
        || usize::from(ix.circuit.num_outputs()) != ix.outputs.len() //2.
        || usize::from(ix.circuit.num_public_asset_slots()) > N_PUBLIC_SLOTS
        || !ix.circuit.is_supported()
    // 3.
    {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }
    for (index, input) in ix.inputs.try_iter().enumerate() {
        check_field_element(
            decode_item(input)?.nullifier_hash,
            "input nullifier",
            Some(index),
            ShieldedPoolError::NonCanonicalInputNullifier,
        )?;
    }
    for (index, output) in ix.outputs.try_iter().enumerate() {
        check_field_element(
            decode_item(output)?.utxo_hash,
            "output utxo hash",
            Some(index),
            ShieldedPoolError::NonCanonicalOutputUtxoHash,
        )?;
    }
    check_field_element(
        ix.private_tx_hash,
        "private tx hash",
        None,
        ShieldedPoolError::NonCanonicalPrivateTxHash,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_account_checks::account_info::test_account_info::get_account_view;
    use zolana_hasher::{sha256::Sha256BE, Hasher};
    use zolana_interface::instruction::{OwnerTag, TransactIxData, TransactOutput, TransactProof};

    fn account(address: u8) -> AccountView {
        get_account_view([address; 32], [0; 32], false, false, false, Vec::new())
    }

    #[test]
    fn external_data_hash_selects_accounts_in_protocol_order() {
        let owned = TransactIxData {
            expiry_unix_ts: 42,
            tx_viewing_pk: [26; 33],
            salt: [27; 16],
            interface_transfers: vec![
                InterfaceTransfer::SolDeposit { amount: 1 },
                InterfaceTransfer::SplWithdrawal {
                    amount: 2,
                    spl_interface_bump: 255,
                },
            ],
            data_hash: Some([24; 32]),
            ring_data_hash: Some([25; 32]),
            outputs: vec![
                TransactOutput {
                    utxo_hash: [28; 32],
                    owner_tag: OwnerTag::Inline([29; 32]),
                    data: Some(vec![30, 31]),
                },
                TransactOutput {
                    utxo_hash: [32; 32],
                    owner_tag: OwnerTag::Account(7),
                    data: None,
                },
            ],
            messages: vec![zolana_interface::instruction::MessageData {
                view_tag: [34; 32],
                data: vec![35, 36],
            }],
            private_tx_hash: [37; 32],
            circuit: CircuitId::RingEddsa(1, 2, 1),
            proof: TransactProof::zeroed(),
            inputs: vec![zolana_interface::instruction::InputUtxo {
                nullifier_hash: [38; 32],
                nullifier_tree_root_index: 39,
                utxo_tree_root_index: 40,
            }],
        };
        let bytes = owned.serialize().unwrap();
        let (ix, external_data_prefix) =
            TransactIxDataRef::parse_with_external_data_prefix(&bytes).unwrap();

        // This is the same complete fixture used by the Rust client, Go prover,
        // and TypeScript SDK. Account 7 is the account-backed output owner;
        // settlement groups are the suffix in instruction order. Arbitrary
        // non-committed slots make an adjacent-index mistake visible.
        let accounts = vec![
            account(1),
            account(2),
            account(3),
            account(4),
            account(5),
            account(6),
            account(7),
            account(33),
            // SOL deposit: [sol_interface, user].
            account(8),
            account(20),
            // SPL withdrawal: [cpi_authority, mint, spl_interface, user, token_program].
            account(9),
            account(21),
            account(23),
            account(22),
            account(10),
        ];

        let actual = hash_external_data_from_accounts(
            InstructionTag::RingTransact,
            external_data_prefix,
            &accounts,
            ix.interface_transfers,
            ix.outputs,
        )
        .unwrap();

        let mut expected_preimage = vec![InstructionTag::RingTransact as u8];
        expected_preimage.extend_from_slice(external_data_prefix);
        for byte in [20u8, 22, 23, 33] {
            expected_preimage.extend_from_slice(&[byte; 32]);
        }
        let expected = Sha256BE::hash(&expected_preimage).unwrap();

        assert_eq!(actual, expected);
        assert_eq!(
            actual,
            [
                0, 222, 47, 97, 173, 68, 253, 98, 205, 189, 27, 97, 10, 140, 198, 237, 212, 34,
                217, 98, 116, 208, 46, 158, 75, 101, 153, 36, 240, 42, 194, 155,
            ],
            "Rust program, Rust client, Go, and TypeScript must share this protocol vector",
        );
    }

    #[test]
    fn external_data_hash_rejects_missing_owner_account() {
        let owned = TransactIxData {
            expiry_unix_ts: 42,
            tx_viewing_pk: [3; 33],
            salt: [4; 16],
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![TransactOutput {
                utxo_hash: [8; 32],
                owner_tag: OwnerTag::Account(3),
                data: None,
            }],
            messages: Vec::new(),
            private_tx_hash: [9; 32],
            circuit: CircuitId::ConfidentialEddsa(0, 1, 1),
            proof: TransactProof::zeroed(),
            inputs: Vec::new(),
        };
        let bytes = owned.serialize().unwrap();
        let (ix, external_data_prefix) =
            TransactIxDataRef::parse_with_external_data_prefix(&bytes).unwrap();

        assert_eq!(
            hash_external_data_from_accounts(
                InstructionTag::Transact,
                external_data_prefix,
                &[account(1), account(2), account(3)],
                ix.interface_transfers,
                ix.outputs,
            ),
            Err(ProgramError::Custom(
                ShieldedPoolError::OwnerTagAccountMissing as u32
            ))
        );
    }
}
