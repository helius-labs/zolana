//! Parse and assert the event emitted by a transact instruction.

use anyhow::{anyhow, Result};
use solana_pubkey::Pubkey;
use zolana_event::{general_event_from_indexed, indexed_events_from_instruction_groups};
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;

use super::LifecycleHarness;

impl LifecycleHarness {
    pub fn assert_last_event_decodes(&self) -> Result<()> {
        let (signature, _) = self
            .last_transact
            .clone()
            .ok_or_else(|| anyhow!("no transact instruction was sent"))?;
        let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        let groups = self.rpc.fetch_confirmed_instruction_groups(&signature)?;
        let events = indexed_events_from_instruction_groups(program_id, &groups.groups);
        let indexed_event = events
            .last()
            .ok_or_else(|| anyhow!("transact did not emit an event self-CPI"))?;
        let decoded = general_event_from_indexed(indexed_event)
            .map_err(|error| anyhow!("emit_event payload did not reconstruct: {error:?}"))?;
        println!("decoded transact event: {decoded:#?}");
        Ok(())
    }
}
