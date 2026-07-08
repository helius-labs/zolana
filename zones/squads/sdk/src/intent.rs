//! Plain data types a wallet uses to express a private operation before proving.
//!
//! These carry no crypto or proving logic; they are the wallet's intermediate
//! representation that the construction modules ([`crate::proposal`],
//! [`crate::encrypted_utxo`]) and the prover witness builders consume. The zone
//! supports two operation shapes (`docs/squads_policy_program.md`, Zone Proof):
//! a transfer (recipient output + sender change) and a withdrawal (sender change
//! only, with a public withdrawn amount).

use zolana_keypair::P256Pubkey;
use zolana_squads_interface::types::Address;

/// The kind of private operation. A transfer moves value to another viewing key
/// account's owner (a private recipient output); a withdrawal exits value to a
/// public SPL/SOL account (a `public_amount`, no recipient UTXO).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionType {
    /// Private transfer to a recipient viewing key account.
    Transfer,
    /// Public withdrawal to an external account.
    Withdrawal,
}

/// The recipient of a transfer output: the recipient's account identity plus the
/// viewing key the recipient ciphertext is encrypted to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recipient {
    /// Recipient owner key hash (the `Owner` half of the output's owner hash).
    pub owner_key_hash: [u8; 32],
    /// Recipient nullifier pubkey bound into the output's owner hash.
    pub nullifier_pubkey: [u8; 32],
    /// Recipient's shared viewing public key; the recipient ciphertext target.
    pub viewing_pubkey: P256Pubkey,
}

/// An output UTXO the wallet intends to create.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputUtxo {
    /// `u64` token amount.
    pub amount: u64,
    /// 32-byte asset field element (e.g. `Poseidon(0, 0)` for SOL).
    pub asset: [u8; 32],
    /// Output owner. `None` marks the sender's own change output (its blinding is
    /// derived, not chosen); `Some` carries a transfer recipient.
    pub recipient: Option<Recipient>,
    /// Output blinding. For a recipient output the wallet chooses it (31-byte
    /// field element, right-aligned); for the sender change it is derived by the
    /// KDF chain and may be left zero here.
    pub blinding: [u8; 32],
}

impl OutputUtxo {
    /// A sender change output (no recipient; blinding derived downstream).
    pub fn change(amount: u64, asset: [u8; 32]) -> Self {
        Self {
            amount,
            asset,
            recipient: None,
            blinding: [0u8; 32],
        }
    }

    /// A recipient output for a transfer.
    pub fn to_recipient(
        amount: u64,
        asset: [u8; 32],
        recipient: Recipient,
        blinding: [u8; 32],
    ) -> Self {
        Self {
            amount,
            asset,
            recipient: Some(recipient),
            blinding,
        }
    }

    /// Whether this output is the sender's own change.
    pub fn is_change(&self) -> bool {
        self.recipient.is_none()
    }
}

/// A wallet's expression of a private transaction: the inputs it spends, the
/// outputs it creates, and the operation type. The witness builder turns this into
/// a zone proof; the proposal builder commits to it via `proposal_hash`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateTransactionIntent {
    /// Transfer or withdrawal.
    pub tx_type: TransactionType,
    /// UTXO hashes (or commitments) of the inputs being spent. The wallet resolves
    /// these to full witness UTXOs when building the proof.
    pub inputs: Vec<[u8; 32]>,
    /// Outputs to create (sender change first, then a recipient output for a
    /// transfer).
    pub outputs: Vec<OutputUtxo>,
    /// Asset mint. SOL is the default address.
    pub asset: Address,
    /// The public withdrawn amount (`0` for a transfer).
    pub public_amount: u64,
    /// External recipient (withdrawal SPL account / transfer recipient owner) as
    /// stored on the proposal; `None` for an in-place operation without one.
    pub external_recipient: Option<Address>,
}

impl PrivateTransactionIntent {
    /// A transfer intent.
    pub fn transfer(
        inputs: Vec<[u8; 32]>,
        outputs: Vec<OutputUtxo>,
        asset: Address,
        external_recipient: Address,
    ) -> Self {
        Self {
            tx_type: TransactionType::Transfer,
            inputs,
            outputs,
            asset,
            public_amount: 0,
            external_recipient: Some(external_recipient),
        }
    }

    /// A withdrawal intent (a single sender-change output, public amount exits).
    pub fn withdrawal(
        inputs: Vec<[u8; 32]>,
        change: OutputUtxo,
        asset: Address,
        public_amount: u64,
        spl_account: Address,
    ) -> Self {
        Self {
            tx_type: TransactionType::Withdrawal,
            inputs,
            outputs: vec![change],
            asset,
            public_amount,
            external_recipient: Some(spl_account),
        }
    }

    /// The recipient output of a transfer, if any (the first non-change output).
    pub fn recipient_output(&self) -> Option<&OutputUtxo> {
        self.outputs.iter().find(|o| !o.is_change())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{elliptic_curve::rand_core::OsRng, SecretKey};

    fn sample_recipient() -> Recipient {
        let sk = SecretKey::random(&mut OsRng);
        Recipient {
            owner_key_hash: [1u8; 32],
            nullifier_pubkey: [2u8; 32],
            viewing_pubkey: P256Pubkey::from_p256(&sk.public_key()),
        }
    }

    #[test]
    fn transfer_intent_shape() {
        let recipient = sample_recipient();
        let change = OutputUtxo::change(100, [0u8; 32]);
        let to = OutputUtxo::to_recipient(40, [0u8; 32], recipient, [9u8; 32]);
        let intent = PrivateTransactionIntent::transfer(
            vec![[7u8; 32]],
            vec![change, to],
            Address::default(),
            Address::new_from_array([5u8; 32]),
        );
        assert_eq!(intent.tx_type, TransactionType::Transfer);
        assert_eq!(intent.public_amount, 0);
        assert!(intent.outputs.first().expect("change output").is_change());
        let rec = intent.recipient_output().expect("recipient output");
        assert_eq!(rec.amount, 40);
        assert_eq!(rec.recipient, Some(recipient));
    }

    #[test]
    fn withdrawal_intent_shape() {
        let change = OutputUtxo::change(60, [0u8; 32]);
        let intent = PrivateTransactionIntent::withdrawal(
            vec![[7u8; 32]],
            change,
            Address::default(),
            40,
            Address::new_from_array([8u8; 32]),
        );
        assert_eq!(intent.tx_type, TransactionType::Withdrawal);
        assert_eq!(intent.public_amount, 40);
        assert_eq!(intent.outputs.len(), 1);
        assert!(intent.recipient_output().is_none());
    }
}
