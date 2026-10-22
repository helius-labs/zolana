use custom_ring_interface::{
    key_catalog::RingCircuit, CustomRingError, EscrowKey, QueueEntry, RegisterKeyIxData,
    RegisterKeyStatement, RingMode,
};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_hasher::primitives::solana_owner_identity;

use crate::instructions::{
    insert_fee::{InsertFeeAccounts, MemberWrite},
    loader::{load_config, load_queue_mut, load_registry},
    verifier::{ring_key, RingProof},
};

/// Queues the escrow write for the next application.
#[inline(never)]
pub fn process_register_key_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix = RegisterKeyIxData::parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let member = iter.next_signer("member")?;
    let config = iter.next_account("config")?;
    let registry = iter.next_account("registry")?;
    let queue = iter.next_mut("queue")?;

    // 1. An anonymous ring escrows no key, its auditor already sees every opening.
    let config = load_config(program_id, config)?;
    if config.mode()? == RingMode::Anonymous {
        return Err(CustomRingError::AnonymousRingRefused.into());
    }
    // 2. The entry sets the signer's escrow bit and key together.
    let identity =
        solana_owner_identity(member.address().as_array()).map_err(CustomRingError::from)?;
    let entry = QueueEntry::escrow(
        identity,
        &EscrowKey {
            nullifier_pk: &ix.nullifier_pk,
            ciphertext: &ix.ciphertext,
        },
    )?;
    // 3. The member share of the queue and of the leaves keeps room for the authority.
    let mut queue = load_queue_mut(program_id, queue)?;
    queue.admit_member_write(&*load_registry(program_id, registry)?)?;
    // 4. A fee above what the writer signed for refuses before the pairing.
    let write = MemberWrite {
        config: &config,
        writer: member.address(),
        entry: &entry,
        max_fee: ix.max_fee(),
    };
    let fee = write.fee()?;
    // 5. The proof seals the nullifier secret behind `nullifier_pk` to the ring's auditor.
    let statement = RegisterKeyStatement {
        member: &identity,
        nullifier_pk: &ix.nullifier_pk,
        auditor_pubkey: &config.auditor_pubkey,
        eph_u: &ix.eph_u,
        ciphertext: &ix.ciphertext,
    }
    .hash()
    .map_err(CustomRingError::from)?;
    RingProof {
        proof: &ix.proof,
        statement,
        key: ring_key(RingCircuit::RegisterKey)?,
    }
    .verify()?;
    // 6. The writer pays the authority, then the entry waits for the next application.
    if let Some(lamports) = fee {
        InsertFeeAccounts::validate_and_parse(&mut iter, &config)?.pay(lamports)?;
    }
    write.push(&mut queue)
}
