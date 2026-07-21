//! Parse and assert the event emitted by a transact instruction.

use anyhow::{anyhow, Result};
use solana_pubkey::Pubkey;
use zolana_event::decode_event_instruction;
use zolana_interface::{instruction::tag, SHIELDED_POOL_PROGRAM_ID};

use crate::LifecycleHarness;

impl LifecycleHarness {
    pub(crate) fn assert_last_event_decodes(&self) -> Result<()> {
        let (signature, _) = self
            .last_transact
            .clone()
            .ok_or_else(|| anyhow!("no transact instruction was sent"))?;
        let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        let groups = self.rpc.fetch_confirmed_instruction_groups(&signature)?;
        let emit_event = groups
            .groups
            .iter()
            .flat_map(|group| &group.inner)
            .find(|ix| ix.program_id == program_id && ix.data.first() == Some(&tag::EMIT_EVENT))
            .ok_or_else(|| anyhow!("transact did not emit an event self-CPI"))?;
        let decoded = decode_event_instruction(&emit_event.data)
            .map_err(|error| anyhow!("emit_event payload did not decode: {error:?}"))?;
        println!("decoded transact event: {decoded:#?}");
        Ok(())
    }
}
