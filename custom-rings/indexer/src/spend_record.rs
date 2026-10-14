use crate::InstructionView;
use anyhow::{bail, Context, Result};
use custom_ring_interface::{
    instruction::{accounts, tag},
    PolicyConfig, RegisterSpendIxData,
};
use solana_address::Address;
use zolana_indexer_api::ShieldedTransaction;
use zolana_ring_policy::{entry_nullifier, ListNamespace, Member, SpendRecord};

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
                address_tree_id: policy.address_tree_id(),
            },
        )?;
        let nullifier = entry_nullifier(&output.output_context.hash.0, &spend.blinding)
            .context("record nullifier derivation failed")?;
        let member = *spend.member.as_bytes();
        match rail {
            Rail::Register { blinding } => {
                let payer = instruction
                    .accounts
                    .get(accounts::REGISTER_SPEND_PAYER)
                    .context("registration payer missing")?;
                let expected_member = Member::owner_tag(&payer.to_bytes())
                    .context("registration member derivation failed")?;
                if member != *expected_member.as_bytes()
                    || spend.version != 0
                    || spend.blinding != blinding
                    || event.output_slots.len() != 1
                {
                    bail!("registration successor disagrees with authorized member");
                }
            }
            Rail::Transfer => {
                let ring_auth = zolana_interface::pda::ring_auth(instruction.program_id).0;
                if event.ring_config.as_ref().map(|key| key.0.to_bytes())
                    != Some(ring_auth.to_bytes())
                {
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
    pub address_tree_id: u16,
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
    if matches!(context.rail, Rail::Transfer)
        && output.payload.0.first() != Some(&zolana_event::OutputDataEncoding::ENCRYPTED_TAG)
    {
        bail!("transfer spend-record output is not confidential");
    }
    let tree_id = output.output_context.tree_id;
    if output.output_context.tree.0.to_bytes() != zolana_interface::pda::tree(tree_id).to_bytes() {
        bail!("spend-record output names a tree its id does not derive");
    }
    let owner = ListNamespace::new(&context.namespace)
        .context("spend-record namespace derivation failed")?;
    let leaf = &output.output_context.hash.0;
    Ok(match context.rail {
        Rail::Register { .. } => {
            let spend = SpendRecord::from_output_data(&output.payload.0)
                .context("malformed registration spend record")?;
            spend.opens(&owner, context.address_tree_id, leaf, tree_id)?;
            spend
        }
        Rail::Transfer => SpendRecord::open_carrier(
            &context.namespace,
            &owner,
            context.address_tree_id,
            event
                .messages
                .iter()
                .map(|message| (&message.view_tag.0, message.payload.0.as_slice())),
            leaf,
            tree_id,
        )?,
    })
}
