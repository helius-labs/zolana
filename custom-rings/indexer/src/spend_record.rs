use crate::InstructionView;
use anyhow::{bail, Context, Result};
use custom_ring_interface::{
    instruction::{accounts, tag},
    PolicyConfig, RegisterSpendIxData,
};
use solana_address::Address;
use zolana_indexer_api::ShieldedTransaction;
use zolana_ring_policy::{entry_nullifier, spend_record_message_tag, ListNamespace, SpendRecord};

pub enum Rail {
    Register { blinding: [u8; 32] },
    Transfer,
}

impl Rail {
    fn source_tag(&self) -> u8 {
        match self {
            Self::Register { .. } => zolana_event::tag::TRANSACT,
            Self::Transfer => zolana_event::tag::RING_TRANSACT,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Successor {
    pub member: [u8; 32],
    /// Revealed by the transfer that spends it.
    pub nullifier: [u8; 32],
    pub output_index: u16,
}

pub fn decode(instruction: InstructionView<'_>) -> Result<Option<Rail>> {
    match instruction.data.first() {
        Some(&tag::REGISTER_SPEND) => {
            let data: RegisterSpendIxData = wincode::deserialize_exact(&instruction.data[1..])
                .context("invalid spend registration wire")?;
            Ok(Some(Rail::Register {
                blinding: data.blinding,
            }))
        }
        Some(&tag::TRANSACT) => Ok(Some(Rail::Transfer)),
        _ => Ok(None),
    }
}

pub struct Reconstruction<'a> {
    pub instruction: InstructionView<'a>,
    pub rail: Rail,
    pub policy: &'a PolicyConfig,
    pub event: &'a ShieldedTransaction,
    pub source_instruction_tag: u8,
}

impl Reconstruction<'_> {
    pub fn reconstruct(self) -> Result<Successor> {
        let Self {
            instruction,
            rail,
            policy,
            event,
            source_instruction_tag,
        } = self;
        if source_instruction_tag != rail.source_tag() {
            bail!("record update used the wrong SPP rail");
        }
        let output = event
            .output_slots
            .last()
            .context("record update has no successor output")?;
        let namespace = Address::find_program_address(
            &[zolana_ring_policy::NAMESPACE_PDA_SEED],
            instruction.program_id,
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
        let nullifier = entry_nullifier(&output.output_context.hash.0, &spend.blinding)
            .map_err(|error| anyhow::anyhow!("record nullifier derivation failed ({error:?})"))?;
        let member = *spend.member.as_bytes();
        match rail {
            Rail::Register { blinding } => {
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
                    || event.output_slots.len() != 1
                {
                    bail!("registration successor disagrees with authorized member");
                }
            }
            Rail::Transfer => {
                let ring_auth = zolana_interface::pda::ring_auth(instruction.program_id)
                    .0
                    .to_bytes();
                if event.ring_config.as_ref().map(|key| key.0.to_bytes()) != Some(ring_auth) {
                    bail!("SPP event belongs to another ring");
                }
            }
        }
        Ok(Successor {
            member,
            nullifier,
            output_index: u16::try_from(event.output_slots.len() - 1)?,
        })
    }
}

pub struct SuccessorContext<'a> {
    pub namespace: [u8; 32],
    pub rail: &'a Rail,
    pub entries_tree: [u8; 32],
    pub entries_tree_id: u16,
}

pub fn successor(
    event: &ShieldedTransaction,
    context: &SuccessorContext<'_>,
) -> Result<SpendRecord> {
    let output = event
        .output_slots
        .last()
        .context("spend-record output missing")?;
    if output.view_tag.0 != context.namespace {
        bail!("spend-record output belongs to another namespace");
    }
    let spend = match context.rail {
        Rail::Register { .. } => SpendRecord::from_output_data(&output.payload.0)
            .context("malformed registration spend record")?,
        Rail::Transfer => {
            if output.payload.0.first() != Some(&zolana_event::OutputDataEncoding::ENCRYPTED_TAG) {
                bail!("transfer spend-record output is not confidential");
            }
            let tag = spend_record_message_tag(&context.namespace).map_err(|error| {
                anyhow::anyhow!("spend-record message tag derivation failed ({error:?})")
            })?;
            let mut messages = event
                .messages
                .iter()
                .filter(|message| message.view_tag.0 == tag);
            let message = messages.next().context("spend-record message missing")?;
            if messages.next().is_some() {
                bail!("duplicate spend-record messages");
            }
            SpendRecord::from_output_data(&message.payload.0)
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
    if output.output_context.tree.0.to_bytes() != context.entries_tree
        || output.output_context.tree_id != context.entries_tree_id
        || output.output_context.hash.0 != leaf
    {
        bail!("spend-record message does not open its successor output");
    }
    Ok(spend)
}
