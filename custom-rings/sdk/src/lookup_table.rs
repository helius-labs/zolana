//! v0 submission behind a throwaway address lookup table. The audited ring
//! transact forwards SPP's full `RING_TRANSACT` account list, which does not fit
//! a legacy transaction's 1232-byte packet.

use std::time::Duration;

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_address_lookup_table_interface::instruction::{
    create_lookup_table, extend_lookup_table,
};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_message::{v0, AddressLookupTableAccount, Message, VersionedMessage};
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::{versioned::VersionedTransaction, Transaction};
use zolana_client::SolanaRpc;

pub const TRANSACT_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

/// Send `ix` as a v0 transaction behind a fresh lookup table. `payer` pays for
/// the table and the transaction, `signers` are the other required signers.
pub fn send_v0_with_lookup_table(
    rpc: &SolanaRpc,
    payer: &dyn Signer,
    signers: &[&dyn Signer],
    ix: Instruction,
) -> Result<Signature> {
    let tx = build_v0_with_lookup_table(rpc, payer, signers, ix)?;
    rpc.client()
        .send_and_confirm_transaction(&tx)
        .map_err(|e| anyhow!("send v0: {e}"))
}

pub fn build_v0_with_lookup_table(
    rpc: &SolanaRpc,
    payer: &dyn Signer,
    signers: &[&dyn Signer],
    ix: Instruction,
) -> Result<VersionedTransaction> {
    let compute = ComputeBudgetInstruction::set_compute_unit_limit(TRANSACT_COMPUTE_UNIT_LIMIT);
    let alt_addresses = lookup_table_addresses(&ix, compute.program_id);

    let client = rpc.client();
    let recent_slot = client.get_slot().map_err(|e| anyhow!("get_slot: {e}"))?;
    wait_past_slot(rpc, recent_slot)?;
    let (lut_create_ix, table_address) =
        create_lookup_table(payer.pubkey(), payer.pubkey(), recent_slot);
    let lut_extend_ix = extend_lookup_table(
        table_address,
        payer.pubkey(),
        Some(payer.pubkey()),
        alt_addresses.clone(),
    );
    let blockhash = client
        .get_latest_blockhash()
        .map_err(|e| anyhow!("blockhash: {e}"))?;
    let setup = Transaction::new(
        &[payer],
        Message::new(&[lut_create_ix, lut_extend_ix], Some(&payer.pubkey())),
        blockhash,
    );
    client
        .send_and_confirm_transaction(&setup)
        .map_err(|e| anyhow!("create+extend ALT: {e}"))?;
    let extended_slot = client.get_slot().map_err(|e| anyhow!("get_slot: {e}"))?;
    wait_past_slot(rpc, extended_slot)?;

    let alt = AddressLookupTableAccount {
        key: table_address,
        addresses: alt_addresses,
    };
    let blockhash = client
        .get_latest_blockhash()
        .map_err(|e| anyhow!("blockhash: {e}"))?;
    let message = v0::Message::try_compile(
        &payer.pubkey(),
        &[compute, ix],
        std::slice::from_ref(&alt),
        blockhash,
    )
    .map_err(|e| anyhow!("compile v0: {e}"))?;
    let mut all_signers: Vec<&dyn Signer> = vec![payer];
    all_signers.extend(signers.iter().copied());
    VersionedTransaction::try_new(VersionedMessage::V0(message), &all_signers)
        .map_err(|e| anyhow!("sign v0: {e}"))
}

/// Every key the transaction needs except the signers, which stay static. The
/// compute budget program is included too, because a key left out of the table
/// costs 32 message bytes instead of a 1-byte index and the audited ring
/// transact has no such bytes to spare. Duplicates are dropped so one key never
/// claims two slots.
pub fn lookup_table_addresses(ix: &Instruction, compute_program: Address) -> Vec<Address> {
    let mut addresses: Vec<Address> = Vec::new();
    for address in ix
        .accounts
        .iter()
        .filter(|meta| !meta.is_signer)
        .map(|meta| meta.pubkey)
        .chain([ix.program_id, compute_program])
    {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    addresses
}

/// A lookup table is only usable from the slot after the one it was created (and
/// extended) in, so both writes have to root before the v0 transaction resolves
/// against them.
fn wait_past_slot(rpc: &SolanaRpc, slot: u64) -> Result<()> {
    let client = rpc.client();
    loop {
        let tip = client.get_slot().map_err(|e| anyhow!("get_slot: {e}"))?;
        if tip > slot {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use solana_instruction::AccountMeta;

    use super::*;

    #[test]
    fn table_holds_every_non_signer_once_plus_both_programs() {
        let program = Address::new_from_array([1; 32]);
        let compute = Address::new_from_array([2; 32]);
        let signer = Address::new_from_array([3; 32]);
        let shared = Address::new_from_array([4; 32]);
        let ix = Instruction {
            program_id: program,
            accounts: vec![
                AccountMeta::new(signer, true),
                AccountMeta::new(shared, false),
                AccountMeta::new_readonly(shared, false),
                AccountMeta::new_readonly(program, false),
            ],
            data: Vec::new(),
        };
        assert_eq!(
            lookup_table_addresses(&ix, compute),
            vec![shared, program, compute]
        );
    }
}
