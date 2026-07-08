//! Idempotent associated-token-account creation action.

use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_interface::instruction::CreateAssociatedTokenAccount;

use crate::{error::ClientError, rpc::Rpc};

/// Build and send an idempotent SPL associated-token-account creation for
/// `(owner, mint)`, funded by `payer`.
///
/// Idempotent: it succeeds whether or not the ATA already exists, so callers
/// need no prior `get_account` existence check. Returns the transaction
/// signature and the created ATA address.
pub fn create_associated_token_account<R: Rpc>(
    rpc: &R,
    payer: &dyn Signer,
    owner: &Pubkey,
    mint: &Pubkey,
) -> Result<(Signature, Pubkey), ClientError> {
    let builder = CreateAssociatedTokenAccount {
        payer: payer.pubkey(),
        owner: *owner,
        mint: *mint,
    };
    let ata = builder.address();
    let ix = builder.instruction();
    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    let signature = rpc.create_and_send_transaction(&[ix], payer_address, &[payer])?;
    Ok((signature, ata))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use solana_hash::Hash;
    use solana_keypair::Keypair;
    use solana_transaction::Transaction;
    use zolana_interface::pda;

    use super::*;

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
    fn create_associated_token_account_sends_idempotent_instruction() {
        let rpc = MockRpc::default();
        let payer = Keypair::new();
        let owner = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        let (_sig, ata) =
            create_associated_token_account(&rpc, &payer, &owner, &mint).expect("action");

        assert_eq!(ata, pda::associated_token_address(&owner, &mint));

        let sent = rpc.sent.borrow().clone().expect("transaction recorded");
        assert_eq!(sent.message.instructions.len(), 1);
        // `1` is the SPL ATA `CreateIdempotent` discriminator.
        assert_eq!(sent.message.instructions[0].data, vec![1u8]);
        assert!(sent.message.account_keys.contains(&payer.pubkey()));
        assert!(sent.message.account_keys.contains(&ata));
    }
}
