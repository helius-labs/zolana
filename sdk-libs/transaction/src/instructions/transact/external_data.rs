use solana_address::Address;
use zolana_event::MessageData;
use zolana_interface::instruction::{
    instruction_data::transact::{
        ExternalDataHash, InterfaceTransfer, ResolvedInterfaceTransfer, ResolvedOutput,
        TransactOutput,
    },
    tag,
};
use zolana_interface::pda;
use zolana_interface::MAX_INTERFACE_TRANSFERS;

use crate::{error::TransactionError, SOL_MINT};

/// One ordered interface transfer, including the accounts committed by the
/// canonical external-data hash. SPL legs retain their mint so proof public
/// movements can be derived without inspecting private inputs or outputs.
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
                let vault_bump = pda::spl_asset_vault_bump(mint.as_array());
                if is_deposit {
                    InterfaceTransfer::SplDeposit { amount, vault_bump }
                } else {
                    InterfaceTransfer::SplWithdrawal { amount, vault_bump }
                }
            }
        }
    }

    fn resolved(self) -> ResolvedInterfaceTransfer {
        match self {
            Self::Sol {
                is_deposit,
                amount,
                user_sol_account,
            } => {
                if is_deposit {
                    ResolvedInterfaceTransfer::SolDeposit {
                        amount,
                        recipient: *user_sol_account.as_array(),
                    }
                } else {
                    ResolvedInterfaceTransfer::SolWithdrawal {
                        amount,
                        recipient: *user_sol_account.as_array(),
                    }
                }
            }
            Self::Spl {
                is_deposit,
                amount,
                user_spl_token,
                spl_token_interface,
                ..
            } => {
                if is_deposit {
                    ResolvedInterfaceTransfer::SplDeposit {
                        amount,
                        user_token_account: *user_spl_token.as_array(),
                        vault: *spl_token_interface.as_array(),
                    }
                } else {
                    ResolvedInterfaceTransfer::SplWithdrawal {
                        amount,
                        user_token_account: *user_spl_token.as_array(),
                        vault: *spl_token_interface.as_array(),
                    }
                }
            }
        }
    }
}

/// Transaction-level public data the proofs commit to via `external_data_hash`.
/// The hash is computed by the canonical [`ExternalDataHash`] from the interface
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
    /// Optional transaction-level UTXO- and zone-specific external data
    /// digests folded into `external_data_hash`; `None` for a default-zone
    /// `transact`.
    pub data_hash: Option<[u8; 32]>,
    pub zone_data_hash: Option<[u8; 32]>,
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
            zone_data_hash: None,
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

    pub fn with_zone_hashes(
        mut self,
        data_hash: [u8; 32],
        zone_data_hash: [u8; 32],
    ) -> Result<Self, TransactionError> {
        if self.data_hash.is_some() || self.zone_data_hash.is_some() {
            return Err(TransactionError::ZoneHashesAlreadySet);
        }
        self.data_hash = Some(data_hash);
        self.zone_data_hash = Some(zone_data_hash);
        Ok(self)
    }

    /// `external_data_hash` via the canonical interface [`ExternalDataHash`].
    /// Builds [`ResolvedOutput`]s from the outputs paired with their resolved
    /// owner tags, so the client and program hash the identical preimage.
    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        validate_settlement_transfers(&self.interface_transfers)?;
        if self.outputs.len() != self.resolved_owner_tags.len() {
            return Err(TransactionError::Hash(
                "resolved owner tags do not pair 1:1 with outputs".to_string(),
            ));
        }
        let resolved: Vec<ResolvedOutput> = self
            .outputs
            .iter()
            .zip(self.resolved_owner_tags.iter())
            .map(|(output, owner_tag)| ResolvedOutput {
                utxo_hash: &output.utxo_hash,
                owner_tag: *owner_tag,
                data: output.data.as_deref(),
            })
            .collect();
        let interface_transfers: Vec<_> = self
            .interface_transfers
            .iter()
            .copied()
            .map(SettlementTransfer::resolved)
            .collect();
        ExternalDataHash {
            spp_instruction_discriminator: self.instruction_discriminator,
            expiry_unix_ts: self.expiry_unix_ts,
            interface_transfers: &interface_transfers,
            data_hash: self.data_hash,
            zone_data_hash: self.zone_data_hash,
            tx_viewing_pk: &self.tx_viewing_pk,
            salt: &self.salt,
            outputs: &resolved,
            messages: &self.messages,
        }
        .hash()
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
