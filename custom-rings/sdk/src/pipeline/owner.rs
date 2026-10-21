//! The confidential rail.

use custom_ring_interface::{CustomRingError, RingMode};
use zolana_client::{AsyncRpc, SettlementAccountValidation};
use zolana_keypair::NullifierKey;
use zolana_program::instruction::TransactInterfaceTransferAccounts;
use zolana_ring_transaction::RingOutputRail;
use zolana_transaction::{instructions::transact::ConfidentialTransaction, ShieldedKeys};

use super::{
    packed_or_delivered, sealed, transaction_key, Rail, RailKind, RingTransfer, Spend, Staged,
    TransferAuthority,
};
use crate::{CustomRing, CustomRingConfig, RingError};

/// The sender's spends, it signs the assembled Solana transaction itself.
pub struct Owner<'a> {
    pub(super) sender: &'a (dyn ShieldedKeys + Send + Sync),
    pub(super) nullifier_key: Option<&'a NullifierKey>,
    pub(super) transaction: ConfidentialTransaction,
    pub(super) interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
}

pub struct CustomRingTransferInput<'a> {
    pub ring: CustomRing,
    /// Only transaction keys and the address are read, the signing key may live elsewhere.
    pub sender: &'a (dyn ShieldedKeys + Send + Sync),
    /// Completes the real inputs, `None` only for an all-padding transfer.
    pub nullifier_key: Option<&'a NullifierKey>,
    pub transaction: ConfidentialTransaction,
}

pub type CustomRingTransfer<'a> = RingTransfer<Owner<'a>>;

impl sealed::Sealed for Owner<'_> {}

impl Rail for Owner<'_> {
    fn kind(&self) -> RailKind<'_> {
        RailKind::Owner(self)
    }
}

impl<'a> RingTransfer<Owner<'a>> {
    pub fn new(input: CustomRingTransferInput<'a>) -> Self {
        Self {
            ring: input.ring,
            rail: Owner {
                sender: input.sender,
                nullifier_key: input.nullifier_key,
                transaction: input.transaction,
                interface_transfer_accounts: Vec::new(),
            },
        }
    }

    #[must_use = "use the updated transfer"]
    pub fn with_interface_transfer_accounts(
        mut self,
        accounts: Vec<TransactInterfaceTransferAccounts>,
    ) -> Self {
        self.rail.interface_transfer_accounts = accounts;
        self
    }
}

impl Owner<'_> {
    pub(super) fn check_settlement_accounts(&self) -> Result<(), RingError> {
        let transfers: Vec<_> = self
            .transaction
            .interface_transfers()?
            .into_iter()
            .map(|transfer| transfer.interface_transfer())
            .collect();
        SettlementAccountValidation {
            transfers: &transfers,
            accounts: &self.interface_transfer_accounts,
        }
        .validate()?;
        Ok(())
    }

    pub(super) async fn stage<R: AsyncRpc + ?Sized>(
        &self,
        _ring: CustomRing,
        _client: &R,
        config: &CustomRingConfig,
    ) -> Result<Staged<'_>, RingError> {
        if config.mode == RingMode::Anonymous {
            return Err(RingError::MissingAnonymousSigner);
        }
        let sender = self.sender.address()?;
        self.check_settlement_accounts()?;
        let mut transaction = self.transaction.clone();
        transaction.pad_to_canonical_shape(&sender)?;
        let delivery = packed_or_delivered(transaction.outputs().len(), "confidential")?;
        let first_nullifier = *transaction.first_nullifier();
        let rail = RingOutputRail::new(transaction_key(self.sender, first_nullifier)?, delivery);
        let proof_inputs = rail.encrypt(transaction, &sender)?;
        let owner_signers = proof_inputs.owner_signer_pubkeys()?;
        if config.has_policy && owner_signers.len() != 1 {
            return Err(CustomRingError::OwnerSignerCount.into());
        }
        Ok(Staged {
            owner_signers,
            proof_inputs,
            rail,
            sender,
            authority: TransferAuthority {
                owner: self.nullifier_key.cloned(),
            },
            interface_transfer_accounts: self.interface_transfer_accounts.clone(),
            spend: Spend::Owner,
        })
    }
}
