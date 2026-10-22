use custom_ring_interface::{CustomRingError, MemberWriteIxData};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_hasher::primitives::solana_owner_identity;
use zolana_ring_policy::Writer;

use crate::instructions::{
    insert_fee::MemberWrite,
    loader::{load_config, load_queue_mut, load_registry},
};

#[inline(never)]
pub fn process_write_records_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix = MemberWriteIxData::parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let member = iter.next_signer("member")?;
    let config = iter.next_account("config")?;
    let registry = iter.next_account("registry")?;
    let queue = iter.next_mut("queue")?;

    // 1. The signer writes only its own record and only the lists members write.
    let identity =
        solana_owner_identity(member.address().as_array()).map_err(CustomRingError::from)?;
    let entry = ix.lists.entry(identity, Writer::Member)?;
    // 2. The member share of the queue and of the leaves keeps room for the authority.
    let config = load_config(program_id, config)?;
    let mut queue = load_queue_mut(program_id, queue)?;
    queue.admit_member_write(&*load_registry(program_id, registry)?)?;
    // 3. The writer pays the configured fee to the authority, at most what it signed for.
    let write = MemberWrite {
        config: &config,
        writer: member.address(),
        entry: &entry,
        max_fee: ix.max_fee(),
    };
    if let Some(fee) = write.validate_fee(&mut iter)? {
        fee.pay()?;
    }
    // 4. The chained entry waits in the queue for the next application.
    write.push(&mut queue)
}
