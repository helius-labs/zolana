//! Lookup-table facts a custom-ring transact needs, independent of transport.
//!
//! A transact does not fit a legacy packet, so it must go out as a v0 message
//! over an address lookup table. Which accounts belong in that table is a
//! property of the instruction, not of how the caller reaches the chain, so it
//! lives here rather than in the RPC-driven `v0` module.

use solana_address::Address;
use solana_instruction::Instruction;

pub const TRANSACT_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

/// A key left out of the table costs 32 message bytes the transact cannot spare.
///
/// Signers are excluded: a lookup table cannot supply them.
pub fn lookup_table_addresses(instruction: &Instruction, compute_program: Address) -> Vec<Address> {
    let mut addresses = Vec::new();
    for address in instruction
        .accounts
        .iter()
        .filter(|meta| !meta.is_signer)
        .map(|meta| meta.pubkey)
        .chain([instruction.program_id, compute_program])
    {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    addresses
}

#[cfg(test)]
mod tests {
    use solana_instruction::{AccountMeta, Instruction};

    use super::*;

    fn address(byte: u8) -> Address {
        Address::new_from_array([byte; 32])
    }

    #[test]
    fn signers_are_excluded_and_every_key_appears_once() {
        let signer = address(1);
        let writable = address(2);
        let program = address(3);
        let compute = address(4);
        let instruction = Instruction {
            program_id: program,
            accounts: vec![
                AccountMeta::new(signer, true),
                AccountMeta::new(writable, false),
                // The same account twice must not consume two table slots.
                AccountMeta::new_readonly(writable, false),
            ],
            data: Vec::new(),
        };

        let addresses = lookup_table_addresses(&instruction, compute);

        // A lookup table cannot supply a signer, so including one would produce
        // a message the runtime rejects.
        assert!(!addresses.contains(&signer));
        assert_eq!(addresses, vec![writable, program, compute]);
    }
}
