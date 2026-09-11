//! Idempotent associated-token-account creation action.

use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_interface::instruction::CreateAssociatedTokenAccount;

use zolana_client::{
    error::ClientError,
    rpc::{ComputeBudgetConfig, Rpc},
};

/// Build and send an idempotent SPL associated-token-account creation for
/// `(owner, mint)`, funded by `payer`.
///
/// Idempotent: it succeeds whether or not the ATA already exists, so callers
/// need no prior `get_account` existence check. Returns the transaction
/// signature and the created ATA address.
pub fn create_associated_token_account<R: Rpc>(
    rpc: &R,
    payer: &Keypair,
    owner: &Pubkey,
    mint: &Pubkey,
) -> Result<(Signature, Pubkey), ClientError> {
    create_associated_token_account_with_program(
        rpc,
        payer,
        owner,
        mint,
        &zolana_interface::pda::spl_token_program_id(),
    )
}

pub fn create_associated_token_account_with_program<R: Rpc>(
    rpc: &R,
    payer: &Keypair,
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Result<(Signature, Pubkey), ClientError> {
    let builder = CreateAssociatedTokenAccount {
        payer: payer.pubkey(),
        owner: *owner,
        mint: *mint,
        token_program: *token_program,
    };
    let ata = builder.address();
    let ix = builder.instruction();
    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    let signature = rpc.create_and_send_transaction(
        core::slice::from_ref(&ix),
        payer_address,
        &[payer],
        ComputeBudgetConfig::for_instruction_count(1),
    )?;
    Ok((signature, ata))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use solana_hash::Hash;
    use solana_message::VersionedMessage;
    use solana_transaction::versioned::VersionedTransaction;
    use zolana_interface::pda;

    use super::*;

    /// Minimal `Rpc` backend that records the transaction the action sends, so
    /// we can assert the action builds and submits the interface instruction
    /// without a live validator.
    #[derive(Default)]
    struct MockRpc {
        sent: RefCell<Option<VersionedTransaction>>,
    }

    impl Rpc for MockRpc {
        fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
            Ok((Hash::default(), 0))
        }

        fn process_transaction(
            &self,
            transaction: VersionedTransaction,
        ) -> Result<Signature, ClientError> {
            *self.sent.borrow_mut() = Some(transaction);
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
        assert!(matches!(sent.message, VersionedMessage::V1(_)));
        let instructions = sent.message.instructions();
        assert_eq!(instructions.len(), 1);
        // `1` is the SPL ATA `CreateIdempotent` discriminator.
        assert_eq!(
            instructions.first().expect("the only instruction").data,
            vec![1u8]
        );
        let account_keys = sent.message.static_account_keys();
        assert!(account_keys.contains(&payer.pubkey()));
        assert!(account_keys.contains(&ata));
    }
}
