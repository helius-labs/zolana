//! Deposits into a ring, which carry no auditor message.
//!
//! A deposit publishes its asset, amount and ring in the clear, so an auditor
//! reads it without a key. Only the blinding and any memo stay encrypted.

use borsh::BorshDeserialize;
use solana_address::Address;
use zolana_interface::output_data::{
    EncryptedRingDepositOutput, OutputDataEncoding, ENCRYPTED_RING_DEPOSIT_SCHEME,
};

/// One deposit slot of a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingDeposit {
    /// The owner tag of the note, so the account the value was shielded for.
    pub depositor: [u8; 32],
    pub asset: Address,
    pub amount: u64,
}

/// The deposits of `ring` in one indexed transaction, in slot order.
pub fn ring_deposits_in(
    slots: impl IntoIterator<Item = ([u8; 32], Vec<u8>)>,
    ring: Address,
) -> Vec<RingDeposit> {
    slots
        .into_iter()
        .filter_map(|(view_tag, payload)| deposit_of(&view_tag, &payload, ring))
        .collect()
}

fn deposit_of(view_tag: &[u8; 32], payload: &[u8], ring: Address) -> Option<RingDeposit> {
    let OutputDataEncoding::Encrypted(blob) = OutputDataEncoding::try_from_slice(payload).ok()?
    else {
        return None;
    };
    let (&scheme, body) = blob.split_first()?;
    if scheme != ENCRYPTED_RING_DEPOSIT_SCHEME {
        return None;
    }
    let output = EncryptedRingDepositOutput::try_from_slice(body).ok()?;
    let deposited = Address::new_from_array(output.ring_program_id);
    (deposited == ring).then(|| RingDeposit {
        depositor: *view_tag,
        asset: Address::new_from_array(output.asset),
        amount: output.amount,
    })
}
