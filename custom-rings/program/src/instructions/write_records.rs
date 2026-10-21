use custom_ring_interface::{CustomRingError, WriteRecordsIxData};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_hasher::primitives::solana_owner_identity;
use zolana_ring_policy::Writer;

use crate::instructions::{
    insert_fee::{InsertFeeAccounts, MemberWrite},
    loader::{load_config, load_queue_mut, load_registry},
};

#[inline(never)]
pub fn process_write_records_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let lists = WriteRecordsIxData::parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let member = iter.next_signer("member")?;
    let config = iter.next_account("config")?;
    let registry = iter.next_account("registry")?;
    let queue = iter.next_mut("queue")?;

    let identity =
        solana_owner_identity(member.address().as_array()).map_err(CustomRingError::from)?;
    let entry = lists.entry(identity, Writer::Member)?;
    let config = load_config(program_id, config)?;
    let mut queue = load_queue_mut(program_id, queue)?;
    queue.admit_member_write(&*load_registry(program_id, registry)?)?;
    let write = MemberWrite {
        config: &config,
        writer: member.address(),
        entry: &entry,
    };
    if let Some(lamports) = write.fee() {
        InsertFeeAccounts::validate_and_parse(&mut iter, &config)?.pay(lamports)?;
    }
    write.push(&mut queue)
}
