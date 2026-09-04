use solana_address::Address;
use wincode::{containers, len::FixIntLen, SchemaWrite};
use zolana_interface::instruction::MessageData;
use zolana_interface::instruction::{
    instruction_data::transact::{hash_external_data, InterfaceTransfer, OwnerTag, TransactOutput},
    tag,
};
use zolana_interface::pda;
use zolana_interface::MAX_INTERFACE_TRANSFERS;

use crate::{error::TransactionError, SOL_MINT};

/// One ordered interface transfer, including the accounts committed by the
/// external-data hash. SPL legs retain their mint so proof public
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
///
/// This client implementation may allocate: it serializes the committed prefix
/// and collects the committed account addresses, then hashes them through the
/// same interface preimage the on-chain program uses. Agreement is pinned by
/// layout and digest vectors below.
///
/// Each output carries its commitment, encoded `owner_tag`, and optional
/// ciphertext; the resolved 32-byte owner tags are paired at construction so
/// [`Self::hash`] needs no account context and cannot drift from the encoded
/// tags. The hash also binds `tx_viewing_pk` and `salt`, which are required to
/// decrypt those ciphertexts.
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
    /// at construction. Inline tags are already present in the serialized
    /// prefix; `hash()` appends this resolved value only for an
    /// `OwnerTag::Account`, matching the program's account-address suffix.
    pub resolved_owner_tags: Vec<[u8; 32]>,
    /// Ciphertexts bound to no output commitment; empty for all current flows.
    pub messages: Vec<MessageData>,
}

/// Client-only encoder for the contiguous prefix of `TransactIxData` covered by
/// `external_data_hash`.
///
/// This deliberately lives in the SDK, not in the program interface. The
/// on-chain program never constructs this value: it hashes a borrowed slice of
/// the instruction buffer. Field order must match the first eight fields of
/// `TransactIxData`; the agreement test below compares these bytes with the
/// prefix measured by the program parser.
#[derive(SchemaWrite)]
struct ExternalDataPrefix {
    expiry_unix_ts: u64,
    tx_viewing_pk: [u8; 33],
    salt: [u8; 16],
    #[wincode(with = "containers::Vec<InterfaceTransfer, FixIntLen<u8>>")]
    interface_transfers: Vec<InterfaceTransfer>,
    data_hash: Option<[u8; 32]>,
    ring_data_hash: Option<[u8; 32]>,
    #[wincode(with = "containers::Vec<TransactOutput, FixIntLen<u8>>")]
    outputs: Vec<TransactOutput>,
    #[wincode(with = "containers::Vec<MessageData, FixIntLen<u8>>")]
    messages: Vec<MessageData>,
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

    /// Serialize the same prefix that the program borrows from instruction
    /// data. Copying is acceptable here: this is an off-chain SDK path.
    fn serialize_instruction_prefix(&self) -> Result<Vec<u8>, TransactionError> {
        let prefix = ExternalDataPrefix {
            expiry_unix_ts: self.expiry_unix_ts,
            tx_viewing_pk: self.tx_viewing_pk,
            salt: self.salt,
            interface_transfers: self
                .interface_transfers
                .iter()
                .copied()
                .map(SettlementTransfer::interface_transfer)
                .collect(),
            data_hash: self.data_hash,
            ring_data_hash: self.ring_data_hash,
            outputs: self.outputs.clone(),
            messages: self.messages.clone(),
        };
        wincode::serialize(&prefix).map_err(|error| TransactionError::Hash(format!("{error:?}")))
    }

    /// Addresses `external_data_hash` appends, in protocol order: each leg's
    /// settlement accounts, then the resolved owner of every account-tagged
    /// output.
    fn committed_addresses(&self) -> Vec<[u8; 32]> {
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
        let external_data_prefix = self.serialize_instruction_prefix()?;
        hash_external_data(
            self.instruction_discriminator,
            &external_data_prefix,
            self.committed_addresses().iter(),
        )
        .map_err(|error| TransactionError::Hash(format!("{error:?}")))
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

#[cfg(test)]
mod tests {
    use zolana_interface::instruction::{
        CircuitId, InputUtxo, TransactIxData, TransactIxDataRef, TransactProof,
    };

    use super::*;

    #[test]
    fn client_prefix_encoding_matches_program_parser_boundary() {
        let external = ExternalData {
            instruction_discriminator: tag::RING_TRANSACT,
            expiry_unix_ts: 42,
            interface_transfers: vec![
                SettlementTransfer::Sol {
                    is_deposit: true,
                    amount: 1,
                    user_sol_account: Address::new_from_array([20; 32]),
                },
                SettlementTransfer::Spl {
                    mint: Address::new_from_array([21; 32]),
                    is_deposit: false,
                    amount: 2,
                    user_spl_token: Address::new_from_array([22; 32]),
                    spl_token_interface: Address::new_from_array([23; 32]),
                },
            ],
            data_hash: Some([24; 32]),
            ring_data_hash: Some([25; 32]),
            tx_viewing_pk: [26; 33],
            salt: [27; 16],
            outputs: vec![
                TransactOutput {
                    utxo_hash: [28; 32],
                    owner_tag: OwnerTag::Inline([29; 32]),
                    data: Some(vec![30, 31]),
                },
                TransactOutput {
                    utxo_hash: [32; 32],
                    owner_tag: OwnerTag::Account(7),
                    data: None,
                },
            ],
            resolved_owner_tags: vec![[29; 32], [33; 32]],
            messages: vec![MessageData {
                view_tag: [34; 32],
                data: vec![35, 36],
            }],
        };
        let interface_transfers = external
            .interface_transfers
            .iter()
            .copied()
            .map(SettlementTransfer::interface_transfer)
            .collect();
        let instruction = TransactIxData {
            expiry_unix_ts: external.expiry_unix_ts,
            tx_viewing_pk: external.tx_viewing_pk,
            salt: external.salt,
            interface_transfers,
            outputs: external.outputs.clone(),
            messages: external.messages.clone(),
            data_hash: external.data_hash,
            ring_data_hash: external.ring_data_hash,
            circuit: CircuitId::RingEddsa(1, 2, 1),
            proof: TransactProof::zeroed(),
            private_tx_hash: [37; 32],
            inputs: vec![InputUtxo {
                nullifier_hash: [38; 32],
                nullifier_tree_root_index: 39,
                utxo_tree_root_index: 40,
            }],
        };

        let instruction_bytes = instruction.serialize().unwrap();
        let (_, program_prefix) =
            TransactIxDataRef::parse_with_external_data_prefix(&instruction_bytes).unwrap();
        assert_eq!(
            external.serialize_instruction_prefix().unwrap(),
            program_prefix
        );
        let expected_addresses = [[20u8; 32], [22u8; 32], [23u8; 32], [33u8; 32]];
        assert_eq!(external.committed_addresses(), expected_addresses);
        assert_eq!(
            external.hash().unwrap(),
            [
                0, 222, 47, 97, 173, 68, 253, 98, 205, 189, 27, 97, 10, 140, 198, 237, 212, 34,
                217, 98, 116, 208, 46, 158, 75, 101, 153, 36, 240, 42, 194, 155,
            ],
            "update this protocol-vector literal only for an intentional layout or hash change",
        );
    }
}
