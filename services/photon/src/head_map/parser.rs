use anyhow::{bail, Context, Result};
use custom_ring_interface::{instruction::tag, CustomRingTransactIxData, RegisterSpendIxData};
use solana_pubkey::Pubkey;
use zolana_indexer_api::{
    Base64String, Hash, RingHeadRecord, RingsMessage, RingsOutputContext, RingsOutputSlot,
    ShieldedTransaction,
};
use zolana_ring_policy::{entry_nullifier, spend_record_message_tag, ListNamespace, SpendRecord};

use crate::ingester::{
    parser::{rings_event_parser::parse_rings_events, state_update::RingsTransactionUpdate},
    typedefs::block_info::{Instruction, InstructionGroup, TransactionInfo},
};

/// Carries a proven registration or replacement for the head projection.
#[derive(Debug)]
pub enum Transition {
    Register {
        old_root: [u8; 32],
        new_root: [u8; 32],
        next_index: u64,
        member: [u8; 32],
        nullifier: [u8; 32],
        record: RingHeadRecord,
    },
    Transfer {
        old_root: [u8; 32],
        new_root: [u8; 32],
        member: [u8; 32],
        spent: [u8; 32],
        nullifier: [u8; 32],
        record: RingHeadRecord,
    },
}

/// Binds record reconstruction to the policy's entries tree.
pub struct TransitionContext {
    pub slot: u64,
    pub entries_tree: [u8; 32],
    pub entries_tree_id: u16,
}

/// Sibling invocations cannot supply a transition's SPP event.
pub fn invocations(tx: &TransactionInfo) -> Result<Vec<(Instruction, TransactionInfo)>> {
    if tx.error.is_some() {
        return Ok(vec![]);
    }
    let mut result = Vec::new();
    for group in &tx.instruction_groups {
        let all = std::iter::once(&group.outer_instruction)
            .chain(group.inner_instructions.iter())
            .collect::<Vec<_>>();
        for (position, instruction) in all.iter().enumerate() {
            if !matches!(
                instruction.data.first(),
                Some(&tag::CREATE_HEAD_MAP_ROOT)
                    | Some(&tag::REGISTER_SPEND)
                    | Some(&tag::TRANSACT)
            ) {
                continue;
            }
            let depth = instruction
                .stack_height
                .context("head-map invocation has no stack height")?;
            let mut children = Vec::new();
            for child in all.iter().skip(position + 1) {
                let child_depth = child
                    .stack_height
                    .context("head-map descendant has no stack height")?;
                if child_depth <= depth {
                    break;
                }
                children.push((*child).clone());
            }
            result.push((
                (*instruction).clone(),
                TransactionInfo {
                    instruction_groups: vec![InstructionGroup {
                        outer_instruction: (*instruction).clone(),
                        inner_instructions: children,
                    }],
                    signature: tx.signature,
                    error: None,
                },
            ));
        }
    }
    Ok(result)
}

pub fn root_address(program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[custom_ring_interface::HeadMapRoot::SEED], program).0
}

pub fn initialization(instruction: &Instruction) -> Option<[u8; 32]> {
    if instruction.data.first() != Some(&tag::CREATE_HEAD_MAP_ROOT) {
        return None;
    }
    let root = root_address(&instruction.program_id);
    (instruction.accounts.get(3) == Some(&root)).then_some(root.to_bytes())
}

pub fn transition(
    instruction: &Instruction,
    subtree: &TransactionInfo,
    context: TransitionContext,
) -> Result<Option<Transition>> {
    // 1. Bind the ring instruction to its canonical shared root.
    let (old_root, new_root, registration) = match instruction.data.first() {
        Some(&tag::REGISTER_SPEND) => {
            let data: RegisterSpendIxData = wincode::deserialize_exact(&instruction.data[1..])
                .context("invalid compressed registration wire")?;
            (data.head_old_root, data.head_new_root, Some(data))
        }
        Some(&tag::TRANSACT) => {
            let data: CustomRingTransactIxData = wincode::deserialize_exact(&instruction.data[1..])
                .context("invalid custom-ring transfer wire")?;
            let Some(head) = data.head_transition else {
                return Ok(None);
            };
            (head.old_root, head.new_root, None)
        }
        _ => return Ok(None),
    };
    let expected_slot = if registration.is_some() { 9 } else { 6 };
    if instruction.accounts.get(expected_slot) != Some(&root_address(&instruction.program_id)) {
        bail!("head-map transition does not name its canonical root");
    }
    // 2. Select the single SPP event produced by that invocation.
    let update = parse_rings_events(subtree, context.slot)?
        .context("head-map transition has no descendant SPP event")?;
    if update.rings_transactions.len() != 1 {
        bail!("head-map transition must have exactly one SPP event");
    }
    let event = &update.rings_transactions[0];
    let expected_source = if registration.is_some() {
        zolana_event::tag::TRANSACT
    } else {
        zolana_event::tag::RING_TRANSACT
    };
    if event.source_instruction_tag != i16::from(expected_source) {
        bail!("head-map transition used the wrong SPP rail");
    }
    let output = event
        .outputs
        .last()
        .context("head-map transition has no successor output")?;
    let namespace = Pubkey::find_program_address(
        &[zolana_ring_policy::NAMESPACE_PDA_SEED],
        &instruction.program_id,
    )
    .0
    .to_bytes();
    // 3. Reconstruct the successor commitment from its public record opening.
    let spend = successor(
        event,
        &SuccessorContext {
            namespace,
            registration: registration.is_some(),
            entries_tree: context.entries_tree,
            entries_tree_id: context.entries_tree_id,
        },
    )?;
    let nullifier = entry_nullifier(&output.utxo_hash, &spend.blinding)
        .map_err(|e| anyhow::anyhow!("record nullifier derivation failed ({e:?})"))?;
    let record = RingHeadRecord {
        transaction: transaction(event, instruction.program_id),
        output_index: u16::try_from(event.outputs.len() - 1)?,
    };
    let member = *spend.member.as_bytes();
    // 4. Bind registration to its signer or transfer to its consumed record.
    if let Some(data) = registration {
        let payer = instruction
            .accounts
            .get(2)
            .context("registration payer missing")?;
        let expected_member = zolana_ring_policy::Member::owner_tag(&payer.to_bytes())
            .map_err(|e| anyhow::anyhow!("registration member derivation failed ({e:?})"))?;
        if member != *expected_member.as_bytes()
            || spend.version != 0
            || spend.blinding != data.blinding
            || event.outputs.len() != 1
        {
            bail!("registration successor disagrees with authorized member");
        }
        Ok(Some(Transition::Register {
            old_root,
            new_root,
            next_index: data.head_next_index,
            member,
            nullifier,
            record,
        }))
    } else {
        let ring_auth = zolana_interface::pda::ring_auth(&instruction.program_id)
            .0
            .to_bytes();
        if event.ring_config != Some(ring_auth) {
            bail!("head-map SPP event belongs to another ring");
        }
        let spent = event
            .nullifiers
            .last()
            .context("head-map transfer has no consumed record")?
            .nullifier;
        Ok(Some(Transition::Transfer {
            old_root,
            new_root,
            member,
            spent,
            nullifier,
            record,
        }))
    }
}

/// Identifies the namespace and publication format of the successor record.
struct SuccessorContext {
    namespace: [u8; 32],
    registration: bool,
    entries_tree: [u8; 32],
    entries_tree_id: u16,
}

fn successor(event: &RingsTransactionUpdate, context: &SuccessorContext) -> Result<SpendRecord> {
    let output = event
        .outputs
        .last()
        .context("spend-record output missing")?;
    if output.view_tag != context.namespace {
        bail!("spend-record output belongs to another namespace");
    }
    let spend = if context.registration {
        SpendRecord::from_output_data(&output.payload)
            .context("malformed registration spend record")?
    } else {
        if output.payload.first() != Some(&zolana_event::OutputDataEncoding::ENCRYPTED_TAG) {
            bail!("transfer spend-record output is not confidential");
        }
        let tag = spend_record_message_tag(&context.namespace).map_err(|error| {
            anyhow::anyhow!("spend-record message tag derivation failed ({error:?})")
        })?;
        let mut messages = event
            .messages
            .iter()
            .filter(|message| message.view_tag == tag);
        let message = messages.next().context("spend-record message missing")?;
        if messages.next().is_some() {
            bail!("duplicate spend-record messages");
        }
        SpendRecord::from_output_data(&message.payload).context("malformed spend-record message")?
    };
    let owner = ListNamespace::new(&context.namespace)
        .map_err(|error| anyhow::anyhow!("spend-record namespace derivation failed ({error:?})"))?;
    let address = owner
        .spend_address(&spend.member, context.entries_tree_id)
        .map_err(|error| anyhow::anyhow!("spend-record address derivation failed ({error:?})"))?;
    let leaf = spend
        .utxo_hash(&owner, &address, context.entries_tree_id)
        .map_err(|error| anyhow::anyhow!("spend-record leaf hash failed ({error:?})"))?;
    if output.output_tree != context.entries_tree || output.utxo_hash != leaf {
        bail!("spend-record message does not open its successor output");
    }
    Ok(spend)
}

fn transaction(event: &RingsTransactionUpdate, program: Pubkey) -> ShieldedTransaction {
    ShieldedTransaction {
        slot: event.slot,
        tx_signature: event.signature.into(),
        tx_viewing_pk: event.tx_viewing_pk.clone().map(Base64String),
        salt: event.salt.clone().map(Base64String),
        output_slots: event
            .outputs
            .iter()
            .map(|output| RingsOutputSlot {
                view_tag: Hash(output.view_tag),
                output_context: RingsOutputContext {
                    hash: Hash(output.utxo_hash),
                    tree: Pubkey::new_from_array(output.output_tree).into(),
                    leaf_index: output.leaf_index,
                },
                payload: Base64String(output.payload.clone()),
            })
            .collect(),
        messages: event
            .messages
            .iter()
            .map(|message| RingsMessage {
                view_tag: Hash(message.view_tag),
                payload: Base64String(message.payload.clone()),
            })
            .collect(),
        nullifiers: event
            .nullifiers
            .iter()
            .map(|input| Hash(input.nullifier))
            .collect(),
        proofless: event.proofless,
        ring_config: event
            .ring_config
            .map(|key| Pubkey::new_from_array(key).into()),
        ring_program_id: Some(program.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester::parser::state_update::{RingsMessageUpdate, RingsOutputUpdate};
    use zolana_ring_policy::{Member, SpendCounters};

    fn fixture() -> (RingsTransactionUpdate, SuccessorContext, SpendRecord) {
        let context = SuccessorContext {
            namespace: Pubkey::new_from_array([9; 32]).to_bytes(),
            registration: false,
            entries_tree: zolana_interface::pda::tree(7).to_bytes(),
            entries_tree_id: 7,
        };
        let record = SpendRecord {
            member: Member::owner_tag(&[5; 32]).unwrap(),
            version: 1,
            window: 2,
            counters_commitment: SpendCounters::zero(&[]).commitment().unwrap(),
            blinding: {
                let mut value = [0; 32];
                value[31] = 13;
                value
            },
        };
        let owner = ListNamespace::new(&context.namespace).unwrap();
        let address = owner.spend_address(&record.member, 7).unwrap();
        let event = RingsTransactionUpdate {
            signature: solana_signature::Signature::from([1; 64]),
            event_index: 0,
            slot: 1,
            ring_config: None,
            source_instruction_tag: i16::from(zolana_event::tag::RING_TRANSACT),
            output_tree: context.entries_tree,
            first_output_leaf_index: 0,
            tx_viewing_pk: None,
            salt: None,
            proofless: false,
            encrypted_utxos: None,
            raw_event: None,
            parse_version: 1,
            outputs: vec![RingsOutputUpdate {
                output_index: 0,
                output_tree: context.entries_tree,
                leaf_index: 0,
                view_tag: context.namespace,
                utxo_hash: record.utxo_hash(&owner, &address, 7).unwrap(),
                payload: vec![zolana_event::OutputDataEncoding::ENCRYPTED_TAG],
            }],
            messages: vec![RingsMessageUpdate {
                message_index: 0,
                view_tag: spend_record_message_tag(&context.namespace).unwrap(),
                payload: record.to_output_data().to_vec(),
            }],
            nullifiers: vec![],
        };
        (event, context, record)
    }

    #[test]
    fn record_message_opens_the_confidential_successor_and_registration_stays_plaintext() {
        let (mut event, mut context, record) = fixture();
        assert_eq!(successor(&event, &context).unwrap(), record);
        context.registration = true;
        event.messages.clear();
        event.outputs[0].payload = record.to_output_data().to_vec();
        assert_eq!(successor(&event, &context).unwrap(), record);
    }

    #[test]
    fn missing_duplicate_foreign_and_malformed_record_messages_are_refused() {
        let (event, context, _) = fixture();
        let mut changed = event.clone();
        changed.messages.clear();
        assert!(successor(&changed, &context).is_err());
        let mut changed = event.clone();
        changed.messages.push(changed.messages[0].clone());
        assert!(successor(&changed, &context).is_err());
        let mut changed = event.clone();
        changed.messages[0].view_tag = context.namespace;
        assert!(successor(&changed, &context).is_err());
        let mut changed = event;
        changed.messages[0].payload.pop();
        assert!(successor(&changed, &context).is_err());
    }

    #[test]
    fn a_record_message_cannot_be_associated_with_another_output_or_tree() {
        let (event, context, record) = fixture();
        let mut changed = event.clone();
        changed.outputs[0].utxo_hash = [0; 32];
        assert!(successor(&changed, &context).is_err());
        let mut changed = event.clone();
        changed.outputs[0].output_tree = [0; 32];
        assert!(successor(&changed, &context).is_err());
        let mut changed = event.clone();
        changed.outputs[0].view_tag = [0; 32];
        assert!(successor(&changed, &context).is_err());
        let mut changed = event;
        changed.outputs[0].payload = record.to_output_data().to_vec();
        assert!(successor(&changed, &context).is_err());
    }
}
