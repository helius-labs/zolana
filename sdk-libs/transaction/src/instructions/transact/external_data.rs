use solana_address::Address;
use zolana_event::MessageData;
use zolana_interface::instruction::{
    instruction_data::transact::{
        external_data_hash, InterfaceTransfer, OwnerTag, TransactIxBound, TransactOutput,
    },
    tag,
};
use zolana_interface::pda;
use zolana_interface::MAX_INTERFACE_TRANSFERS;

use crate::{error::TransactionError, SOL_MINT};

/// One ordered interface transfer, including the accounts committed by the
/// canonical external-data hash. SPL legs retain their mint so proof public
/// transfers can be derived without inspecting private inputs or outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementTransfer {
    Sol {
        is_deposit: bool,
        amount: u64,
        user_sol_account: Address,
    },
    Spl {
        mint: Address,
        is_deposit: bool,
        amount: u64,
        user_spl_token: Address,
        spl_token_interface: Address,
    },
}

impl SettlementTransfer {
    pub const fn amount(self) -> u64 {
        match self {
            Self::Sol { amount, .. } | Self::Spl { amount, .. } => amount,
        }
    }

    pub const fn is_deposit(self) -> bool {
        match self {
            Self::Sol { is_deposit, .. } | Self::Spl { is_deposit, .. } => is_deposit,
        }
    }

    pub const fn asset(self) -> Address {
        match self {
            Self::Sol { .. } => SOL_MINT,
            Self::Spl { mint, .. } => mint,
        }
    }

    pub fn interface_transfer(self) -> InterfaceTransfer {
        match self {
            Self::Sol {
                is_deposit, amount, ..
            } => {
                if is_deposit {
                    InterfaceTransfer::SolDeposit { amount }
                } else {
                    InterfaceTransfer::SolWithdrawal { amount }
                }
            }
            Self::Spl {
                mint,
                is_deposit,
                amount,
                ..
            } => {
                let spl_interface_bump = pda::spl_interface_bump(mint.as_array());
                if is_deposit {
                    InterfaceTransfer::SplDeposit {
                        amount,
                        spl_interface_bump,
                    }
                } else {
                    InterfaceTransfer::SplWithdrawal {
                        amount,
                        spl_interface_bump,
                    }
                }
            }
        }
    }
}

/// Transaction-level public data the proofs commit to via `external_data_hash`.
/// The hash is computed by the canonical `external_data_hash` from the interface
/// crate, so the client and the Solana program agree byte-for-byte. Each output
/// carries its commitment, wire `owner_tag`, and optional ciphertext; the
/// resolved 32-byte owner tags are paired at construction so [`Self::hash`]
/// needs no account context and cannot drift from the wire tags. The hash also
/// binds `tx_viewing_pk` and `salt`, which are required to decrypt those
/// ciphertexts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalData {
    pub instruction_discriminator: u8,
    pub expiry_unix_ts: u64,
    pub interface_transfers: Vec<SettlementTransfer>,
    /// Optional transaction-level UTXO- and ring-specific external data
    /// digests folded into `external_data_hash`; `None` for a default-ring
    /// `transact`.
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
    pub tx_viewing_pk: [u8; 33],
    pub salt: [u8; 16],
    /// All `M` outputs in tree-append order (SPL change, SOL change, recipients
    /// / dummies). A `None` `data` marks a slot covered by a preceding bundle.
    pub outputs: Vec<TransactOutput>,
    /// The resolved 32-byte owner tag of each output, paired 1:1 with `outputs`
    /// at construction. `hash()` covers these resolved bytes rather than the
    /// wire `OwnerTag`, matching the program's OWNER public input.
    pub resolved_owner_tags: Vec<[u8; 32]>,
    /// Ciphertexts bound to no output commitment; empty for all current flows.
    pub messages: Vec<MessageData>,
}

impl ExternalData {
    pub fn new(
        tx_viewing_pk: [u8; 33],
        salt: [u8; 16],
        outputs: Vec<TransactOutput>,
        resolved_owner_tags: Vec<[u8; 32]>,
        messages: Vec<MessageData>,
    ) -> Self {
        Self {
            instruction_discriminator: tag::TRANSACT,
            expiry_unix_ts: u64::MAX, // default no expiry, not necessary for confidential transfers
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            tx_viewing_pk,
            salt,
            outputs,
            resolved_owner_tags,
            messages,
        }
    }

    pub fn with_interface_transfer(
        mut self,
        transfer: SettlementTransfer,
    ) -> Result<Self, TransactionError> {
        validate_settlement_transfers(&self.interface_transfers)?;
        validate_settlement_transfer(transfer)?;
        let len = self.interface_transfers.len().checked_add(1).ok_or(
            TransactionError::TooManyInterfaceTransfers {
                got: usize::MAX,
                max: MAX_INTERFACE_TRANSFERS,
            },
        )?;
        if len > MAX_INTERFACE_TRANSFERS {
            return Err(TransactionError::TooManyInterfaceTransfers {
                got: len,
                max: MAX_INTERFACE_TRANSFERS,
            });
        }
        self.interface_transfers.push(transfer);
        Ok(self)
    }

    pub fn with_interface_transfers(
        mut self,
        interface_transfers: Vec<SettlementTransfer>,
    ) -> Result<Self, TransactionError> {
        validate_settlement_transfers(&interface_transfers)?;
        self.interface_transfers = interface_transfers;
        Ok(self)
    }

    pub fn with_ring_hashes(
        mut self,
        data_hash: [u8; 32],
        ring_data_hash: [u8; 32],
    ) -> Result<Self, TransactionError> {
        if self.data_hash.is_some() || self.ring_data_hash.is_some() {
            return Err(TransactionError::RingHashesAlreadySet);
        }
        self.data_hash = Some(data_hash);
        self.ring_data_hash = Some(ring_data_hash);
        Ok(self)
    }

    /// `external_data_hash` via the canonical interface function.
    /// Builds [`ResolvedOutput`]s from the outputs paired with their resolved
    /// owner tags, so the client and program hash the identical preimage.
    /// The proof-bound region, exactly as it appears in instruction data.
    ///
    /// `ExternalData` is almost the bound region already; the exceptions are
    /// `data_hash`, `ring_data_hash` and `instruction_discriminator`, which the
    /// proof binds elsewhere or not at all, and `resolved_owner_tags`, which is
    /// carried alongside the outputs rather than inside them.
    pub fn bound(&self) -> TransactIxBound {
        TransactIxBound {
            expiry_unix_ts: self.expiry_unix_ts,
            tx_viewing_pk: self.tx_viewing_pk,
            salt: self.salt,
            interface_transfers: self
                .interface_transfers
                .iter()
                .copied()
                .map(SettlementTransfer::interface_transfer)
                .collect(),
            outputs: self.outputs.clone(),
            messages: self.messages.clone(),
        }
    }

    /// Addresses `external_data_hash` appends, in protocol order: each leg's
    /// settlement accounts, then the resolved owner of every account-tagged
    /// output.
    fn bound_addresses(&self) -> Vec<[u8; 32]> {
        let mut addresses = Vec::new();
        for transfer in &self.interface_transfers {
            match transfer {
                SettlementTransfer::Sol {
                    user_sol_account, ..
                } => addresses.push(*user_sol_account.as_array()),
                SettlementTransfer::Spl {
                    user_spl_token,
                    spl_token_interface,
                    ..
                } => {
                    addresses.push(*user_spl_token.as_array());
                    addresses.push(*spl_token_interface.as_array());
                }
            }
        }
        for (output, owner_tag) in self.outputs.iter().zip(self.resolved_owner_tags.iter()) {
            if matches!(output.owner_tag, OwnerTag::Account(_)) {
                addresses.push(*owner_tag);
            }
        }
        addresses
    }

    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        validate_settlement_transfers(&self.interface_transfers)?;
        if self.outputs.len() != self.resolved_owner_tags.len() {
            return Err(TransactionError::Hash(
                "resolved owner tags do not pair 1:1 with outputs".to_string(),
            ));
        }
        // Serialize the bound half and hash exactly those bytes, so the client
        // commits to the same range the program reads out of the instruction.
        let bound = wincode::serialize(&self.bound())
            .map_err(|e| TransactionError::Hash(format!("{e:?}")))?;
        external_data_hash(
            self.instruction_discriminator,
            &bound,
            self.bound_addresses().iter(),
        )
        .map_err(|e| TransactionError::Hash(format!("{e:?}")))
    }
}

fn validate_settlement_transfers(transfers: &[SettlementTransfer]) -> Result<(), TransactionError> {
    if transfers.len() > MAX_INTERFACE_TRANSFERS {
        return Err(TransactionError::TooManyInterfaceTransfers {
            got: transfers.len(),
            max: MAX_INTERFACE_TRANSFERS,
        });
    }
    for transfer in transfers {
        validate_settlement_transfer(*transfer)?;
    }
    Ok(())
}

fn validate_settlement_transfer(transfer: SettlementTransfer) -> Result<(), TransactionError> {
    if transfer.amount() == 0 {
        return Err(TransactionError::ZeroInterfaceTransferAmount);
    }
    if matches!(transfer, SettlementTransfer::Spl { mint, .. } if mint == SOL_MINT) {
        return Err(TransactionError::SettlementTargetMismatch { asset: SOL_MINT });
    }
    Ok(())
}
