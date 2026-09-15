use anyhow::{bail, Context, Result};
use custom_ring_interface::{
    instruction::{accounts, tag},
    CustomRingTransactIxData, PolicyConfig, RegisterSpendIxData,
};
use solana_pubkey::Pubkey;
use zolana_indexer_api::{
    Base64String, Hash, RingHeadRecord, RingsMessage, RingsOutputContext, RingsOutputSlot,
    ShieldedTransaction,
};
use zolana_ring_policy::{entry_nullifier, spend_record_message_tag, ListNamespace, SpendRecord};

use super::HeadMap;
use crate::{
    ingester::{
        parser::{rings_event_parser::parse_rings_events, state_update::RingsTransactionUpdate},
        typedefs::block_info::Instruction,
    },
    ring_projection::{fault, BlockEnv, Invocation, ProjectError, Projection},
};

#[derive(Debug)]
pub(crate) enum Transition {
    Register(Registration),
    Transfer(Transfer),
}

#[derive(Debug)]
pub(crate) struct Registration {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub next_index: u64,
    pub member: [u8; 32],
    pub nullifier: [u8; 32],
    pub record: RingHeadRecord,
}

#[derive(Debug)]
pub(crate) struct Transfer {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub member: [u8; 32],
    /// The member's head must be one of them.
    pub nullifiers: Vec<[u8; 32]>,
    pub nullifier: [u8; 32],
    pub record: RingHeadRecord,
}

pub(crate) enum Rail {
    Register { blinding: [u8; 32], next_index: u64 },
    Transfer,
}

impl Rail {
    fn root_slot(&self) -> usize {
        match self {
            Self::Register { .. } => accounts::REGISTER_SPEND_HEAD_ROOT,
            Self::Transfer => accounts::TRANSACT_HEAD_ROOT,
        }
    }

    fn source_tag(&self) -> u8 {
        match self {
            Self::Register { .. } => zolana_event::tag::TRANSACT,
            Self::Transfer => zolana_event::tag::RING_TRANSACT,
        }
    }
}

pub(crate) struct Decoded {
    pub rail: Rail,
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
}

pub(super) async fn transition(
    invocation: &Invocation<'_>,
    env: &mut BlockEnv<'_>,
) -> Result<Option<Transition>, ProjectError> {
    let instruction = invocation.instruction;
    let Some(decoded) = decode(instruction).map_err(invalid)? else {
        return Ok(None);
    };
    let root = HeadMap::root_address(&instruction.program_id).0;
    if instruction.accounts.get(decoded.rail.root_slot()) != Some(&root) {
        return Err(fault("transition does not name its canonical root"));
    }
    let policy = env.policy(&instruction.program_id).await?;
    reconstruct(invocation, decoded, &policy)
        .map(Some)
        .map_err(invalid)
}

fn invalid(error: anyhow::Error) -> ProjectError {
    fault(format!("{error:#}"))
}

pub(crate) fn decode(instruction: &Instruction) -> Result<Option<Decoded>> {
    match instruction.data.first() {
        Some(&tag::REGISTER_SPEND) => {
            let data: RegisterSpendIxData = wincode::deserialize_exact(&instruction.data[1..])
                .context("invalid compressed registration wire")?;
            Ok(Some(Decoded {
                rail: Rail::Register {
                    blinding: data.blinding,
                    next_index: data.head_next_index,
                },
                old_root: data.head_old_root,
                new_root: data.head_new_root,
            }))
        }
        Some(&tag::TRANSACT) => {
            let data: CustomRingTransactIxData = wincode::deserialize_exact(&instruction.data[1..])
                .context("invalid custom-ring transfer wire")?;
            Ok(data.head_transition.map(|head| Decoded {
                rail: Rail::Transfer,
                old_root: head.old_root,
                new_root: head.new_root,
            }))
        }
        _ => Ok(None),
    }
}

pub(crate) fn reconstruct(
    invocation: &Invocation<'_>,
    decoded: Decoded,
    policy: &PolicyConfig,
) -> Result<Transition> {
    let instruction = invocation.instruction;
    let Decoded {
        rail,
        old_root,
        new_root,
    } = decoded;
    let update = parse_rings_events(&invocation.subtree, invocation.slot)?
        .context("transition has no descendant SPP event")?;
    if update.rings_transactions.len() != 1 {
        bail!("transition must have exactly one SPP event");
    }
    let event = &update.rings_transactions[0];
    if event.source_instruction_tag != i16::from(rail.source_tag()) {
        bail!("transition used the wrong SPP rail");
    }
    let output = event
        .outputs
        .last()
        .context("transition has no successor output")?;
    let namespace = Pubkey::find_program_address(
        &[zolana_ring_policy::NAMESPACE_PDA_SEED],
        &instruction.program_id,
    )
    .0
    .to_bytes();
    let spend = successor(
        event,
        &SuccessorContext {
            namespace,
            rail: &rail,
            entries_tree: policy.entries_tree.to_bytes(),
            entries_tree_id: policy.entries_tree_id(),
        },
    )?;
    let nullifier = entry_nullifier(&output.utxo_hash, &spend.blinding)
        .map_err(|error| anyhow::anyhow!("record nullifier derivation failed ({error:?})"))?;
    let record = RingHeadRecord {
        transaction: transaction(event, instruction.program_id),
        output_index: u16::try_from(event.outputs.len() - 1)?,
    };
    let member = *spend.member.as_bytes();
    match rail {
        Rail::Register {
            blinding,
            next_index,
        } => {
            let payer = instruction
                .accounts
                .get(accounts::REGISTER_SPEND_PAYER)
                .context("registration payer missing")?;
            let expected_member = zolana_ring_policy::Member::owner_tag(&payer.to_bytes())
                .map_err(|error| {
                    anyhow::anyhow!("registration member derivation failed ({error:?})")
                })?;
            if member != *expected_member.as_bytes()
                || spend.version != 0
                || spend.blinding != blinding
                || event.outputs.len() != 1
            {
                bail!("registration successor disagrees with authorized member");
            }
            Ok(Transition::Register(Registration {
                old_root,
                new_root,
                next_index,
                member,
                nullifier,
                record,
            }))
        }
        Rail::Transfer => {
            let ring_auth = zolana_interface::pda::ring_auth(&instruction.program_id)
                .0
                .to_bytes();
            if event.ring_config != Some(ring_auth) {
                bail!("SPP event belongs to another ring");
            }
            let nullifiers = event
                .nullifiers
                .iter()
                .map(|input| input.nullifier)
                .collect::<Vec<_>>();
            if nullifiers.is_empty() {
                bail!("transfer has no consumed record");
            }
            Ok(Transition::Transfer(Transfer {
                old_root,
                new_root,
                member,
                nullifiers,
                nullifier,
                record,
            }))
        }
    }
}

pub(crate) struct SuccessorContext<'a> {
    pub namespace: [u8; 32],
    pub rail: &'a Rail,
    pub entries_tree: [u8; 32],
    pub entries_tree_id: u16,
}

pub(crate) fn successor(
    event: &RingsTransactionUpdate,
    context: &SuccessorContext<'_>,
) -> Result<SpendRecord> {
    let output = event
        .outputs
        .last()
        .context("spend-record output missing")?;
    if output.view_tag != context.namespace {
        bail!("spend-record output belongs to another namespace");
    }
    let spend = match context.rail {
        Rail::Register { .. } => SpendRecord::from_output_data(&output.payload)
            .context("malformed registration spend record")?,
        Rail::Transfer => {
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
            SpendRecord::from_output_data(&message.payload)
                .context("malformed spend-record message")?
        }
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
