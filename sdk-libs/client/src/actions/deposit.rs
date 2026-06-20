//! Proofless SOL shield action.

use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_interface::instruction::{Deposit as DepositInstruction, DepositIxData};
use zolana_keypair::{random_salt, ShieldedKeypair};
use zolana_transaction::{owner_utxo_hash, utxo_hash, SOL_MINT};

use crate::error::ClientError;
use crate::rpc::Rpc;

/// Prepared direct proofless SOL shield.
///
/// This owns the recipient-derived deposit material so callers do not need to
/// manually coordinate salt, blinding, owner commitment, and UTXO hash rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deposit {
    pub data: DepositIxData,
    pub utxo_hash: [u8; 32],
}

impl Deposit {
    pub fn sol(recipient: &ShieldedKeypair, lamports: u64) -> Result<Self, ClientError> {
        let salt = random_salt();
        let blinding = recipient.viewing_key.derive_proofless_blinding(&salt)?;
        let owner_hash = recipient.owner_hash()?;
        let owner_utxo_hash = owner_utxo_hash(&owner_hash, &blinding)?;
        let utxo_hash = utxo_hash(
            SOL_MINT,
            lamports,
            &[0u8; 32],
            &[0u8; 32],
            None,
            &owner_utxo_hash,
        )?;
        Ok(Self {
            data: DepositIxData {
                view_tag: recipient.recipient_bootstrap_view_tag(),
                owner_utxo_hash,
                salt,
                public_amount: Some(lamports),
                program_data_hash: None,
                program_data: None,
                cpi_signer: None,
            },
            utxo_hash,
        })
    }

    pub fn instruction(&self, tree: Pubkey, depositor: Pubkey) -> Instruction {
        deposit_instruction(tree, depositor, &self.data)
    }

    pub fn send<R: Rpc>(
        &self,
        rpc: &R,
        payer: &Keypair,
        tree: Pubkey,
        depositor: &Keypair,
    ) -> Result<Signature, ClientError> {
        deposit(rpc, payer, tree, depositor, &self.data)
    }

    pub fn view_tag(&self) -> [u8; 32] {
        self.data.view_tag
    }
}

/// Build and send a direct (non-zone) proofless SOL shield: a public deposit
/// that appends a recipient-hidden UTXO without a proof.
///
/// `payer` funds the transaction fee; `depositor` signs the deposit and is the
/// public funding source for the shielded amount (they may be the same key).
/// Returns the transaction signature; event indexing is the caller's concern.
pub fn deposit<R: Rpc>(
    rpc: &R,
    payer: &Keypair,
    tree: Pubkey,
    depositor: &Keypair,
    data: &DepositIxData,
) -> Result<Signature, ClientError> {
    let ix = deposit_instruction(tree, depositor.pubkey(), data);
    let mut signers: Vec<&Keypair> = vec![payer];
    if depositor.pubkey() != payer.pubkey() {
        signers.push(depositor);
    }
    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    rpc.create_and_send_transaction(&[ix], payer_address, &signers)
}

fn deposit_instruction(tree: Pubkey, depositor: Pubkey, data: &DepositIxData) -> Instruction {
    DepositInstruction {
        tree,
        depositor,
        spl: None,
        view_tag: data.view_tag,
        owner_utxo_hash: data.owner_utxo_hash,
        salt: data.salt,
        public_amount: data.public_amount,
        program_data_hash: data.program_data_hash,
        program_data: data.program_data.clone(),
        cpi_signer: data.cpi_signer,
    }
    .instruction()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    use solana_hash::Hash;
    use solana_transaction::Transaction;

    /// Minimal `Rpc` backend that records the transaction the action sends, so
    /// we can assert the action builds and submits the interface instruction
    /// without a live validator.
    #[derive(Default)]
    struct MockRpc {
        sent: RefCell<Option<Transaction>>,
    }

    impl Rpc for MockRpc {
        fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
            Ok((Hash::default(), 0))
        }

        fn send_transaction(&self, transaction: &Transaction) -> Result<Signature, ClientError> {
            *self.sent.borrow_mut() = Some(transaction.clone());
            Ok(Signature::default())
        }
    }

    #[test]
    fn deposit_sends_the_interface_instruction() {
        let rpc = MockRpc::default();
        let payer = Keypair::new();
        let depositor = Keypair::new();
        let tree = Pubkey::new_unique();
        let data = DepositIxData {
            view_tag: [1u8; 32],
            owner_utxo_hash: [2u8; 32],
            salt: [3u8; 16],
            public_amount: Some(1_000),
            program_data_hash: None,
            program_data: None,
            cpi_signer: None,
        };

        deposit(&rpc, &payer, tree, &depositor, &data).expect("action");

        let sent = rpc.sent.borrow().clone().expect("transaction recorded");
        let expected = DepositInstruction {
            tree,
            depositor: depositor.pubkey(),
            spl: None,
            view_tag: data.view_tag,
            owner_utxo_hash: data.owner_utxo_hash,
            salt: data.salt,
            public_amount: data.public_amount,
            program_data_hash: data.program_data_hash,
            program_data: data.program_data.clone(),
            cpi_signer: data.cpi_signer,
        }
        .instruction();
        assert_eq!(sent.message.instructions.len(), 1);
        assert_eq!(sent.message.instructions[0].data, expected.data);
        assert!(sent.message.account_keys.contains(&payer.pubkey()));
        assert!(sent.message.account_keys.contains(&depositor.pubkey()));
    }

    #[test]
    fn prepared_sol_deposit_derives_consistent_material() {
        let recipient = ShieldedKeypair::new().unwrap();
        let prepared = Deposit::sol(&recipient, 1_000).expect("prepared deposit");

        assert_eq!(
            prepared.data.view_tag,
            recipient.recipient_bootstrap_view_tag()
        );
        assert_eq!(prepared.data.public_amount, Some(1_000));
        assert_ne!(prepared.data.salt, [0u8; 16]);
        assert_ne!(prepared.data.owner_utxo_hash, [0u8; 32]);
        assert_ne!(prepared.utxo_hash, [0u8; 32]);
    }
}
