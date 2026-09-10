use solana_address::Address;
use zolana_interface::instruction::MessageData;
use zolana_interface::instruction::{
    instruction_data::transact::{
        hash_external_data, InterfaceTransfer, OwnerTag, TransactExternalData, TransactOutput,
    },
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
        let prefix = TransactExternalData {
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
        prefix
            .serialize()
            .map_err(|error| TransactionError::Hash(format!("{error:?}")))
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
    use serde::{Deserialize, Serialize};
    use zolana_interface::instruction::{
        CircuitId, InputUtxo, TransactIxData, TransactIxDataRef, TransactProof,
    };

    use super::*;

    const VECTOR_JSON: &str = include_str!("../../../../../test-vectors/external_data_hash.json");

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        instruction_discriminator: u8,
        expiry_unix_ts: u64,
        tx_viewing_pk: String,
        salt: String,
        interface_transfers: Vec<VectorTransfer>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data_hash: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ring_data_hash: Option<String>,
        outputs: Vec<VectorOutput>,
        messages: Vec<VectorMessage>,
        committed_addresses: Vec<String>,
        external_data_prefix: String,
        external_data_hash: String,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct VectorTransfer {
        kind: String,
        amount: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        spl_interface_bump: Option<u8>,
        user_account: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        spl_interface_account: Option<String>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct VectorOutput {
        utxo_hash: String,
        owner_tag: VectorOwnerTag,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data: Option<String>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct VectorOwnerTag {
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        index: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address: Option<String>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct VectorMessage {
        view_tag: String,
        data: String,
    }

    fn bytes<const N: usize>(hex: &str) -> [u8; N] {
        hex::decode(hex)
            .expect("hex")
            .try_into()
            .expect("vector byte length")
    }

    fn address(hex: &str) -> Address {
        Address::new_from_array(bytes::<32>(hex))
    }

    fn external_data_from_vector(vector: &Vector) -> ExternalData {
        let interface_transfers = vector
            .interface_transfers
            .iter()
            .map(|transfer| match transfer.kind.as_str() {
                "solDeposit" | "solWithdrawal" => SettlementTransfer::Sol {
                    is_deposit: transfer.kind == "solDeposit",
                    amount: transfer.amount,
                    user_sol_account: address(&transfer.user_account),
                },
                "splDeposit" | "splWithdrawal" => SettlementTransfer::Spl {
                    mint: address(transfer.mint.as_deref().expect("spl transfer mint")),
                    is_deposit: transfer.kind == "splDeposit",
                    amount: transfer.amount,
                    user_spl_token: address(&transfer.user_account),
                    spl_token_interface: address(
                        transfer
                            .spl_interface_account
                            .as_deref()
                            .expect("spl interface account"),
                    ),
                },
                other => panic!("unknown transfer kind {other}"),
            })
            .collect();
        let (outputs, resolved_owner_tags) = vector
            .outputs
            .iter()
            .map(|output| {
                let (owner_tag, resolved) = match output.owner_tag.kind.as_str() {
                    "inline" => {
                        let value = bytes::<32>(output.owner_tag.value.as_deref().expect("inline"));
                        (OwnerTag::Inline(value), value)
                    }
                    "account" => (
                        OwnerTag::Account(output.owner_tag.index.expect("account index")),
                        bytes::<32>(
                            output
                                .owner_tag
                                .address
                                .as_deref()
                                .expect("account address"),
                        ),
                    ),
                    other => panic!("unknown owner tag kind {other}"),
                };
                (
                    TransactOutput {
                        utxo_hash: bytes::<32>(&output.utxo_hash),
                        owner_tag,
                        data: output
                            .data
                            .as_deref()
                            .map(|data| hex::decode(data).expect("output data hex")),
                    },
                    resolved,
                )
            })
            .unzip();
        ExternalData {
            instruction_discriminator: vector.instruction_discriminator,
            expiry_unix_ts: vector.expiry_unix_ts,
            interface_transfers,
            data_hash: vector.data_hash.as_deref().map(bytes::<32>),
            ring_data_hash: vector.ring_data_hash.as_deref().map(bytes::<32>),
            tx_viewing_pk: bytes::<33>(&vector.tx_viewing_pk),
            salt: bytes::<16>(&vector.salt),
            outputs,
            resolved_owner_tags,
            messages: vector
                .messages
                .iter()
                .map(|message| MessageData {
                    view_tag: bytes::<32>(&message.view_tag),
                    data: hex::decode(&message.data).expect("message data hex"),
                })
                .collect(),
        }
    }

    #[test]
    fn client_prefix_encoding_matches_program_parser_boundary_and_the_shared_vector() {
        let vector: Vector = serde_json::from_str(VECTOR_JSON).unwrap();
        let external = external_data_from_vector(&vector);
        let interface_transfers: Vec<InterfaceTransfer> = external
            .interface_transfers
            .iter()
            .copied()
            .map(SettlementTransfer::interface_transfer)
            .collect();
        for (transfer, expected) in interface_transfers.iter().zip(&vector.interface_transfers) {
            if let InterfaceTransfer::SplDeposit {
                spl_interface_bump, ..
            }
            | InterfaceTransfer::SplWithdrawal {
                spl_interface_bump, ..
            } = transfer
            {
                assert_eq!(Some(*spl_interface_bump), expected.spl_interface_bump);
            }
        }
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
        let client_prefix = external.serialize_instruction_prefix().unwrap();
        assert_eq!(client_prefix, program_prefix);
        assert_eq!(hex::encode(&client_prefix), vector.external_data_prefix);
        assert_eq!(
            external
                .committed_addresses()
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            vector.committed_addresses
        );
        assert_eq!(
            hex::encode(external.hash().unwrap()),
            vector.external_data_hash
        );
    }

    #[test]
    #[ignore = "regenerates test-vectors/external_data_hash.json; run with --nocapture and commit the output"]
    fn print_external_data_hash_vector() {
        let mut vector: Vector = serde_json::from_str(VECTOR_JSON).unwrap();
        let external = external_data_from_vector(&vector);
        vector.committed_addresses = external
            .committed_addresses()
            .iter()
            .map(hex::encode)
            .collect();
        vector.external_data_prefix = hex::encode(external.serialize_instruction_prefix().unwrap());
        vector.external_data_hash = hex::encode(external.hash().unwrap());
        println!("{}", serde_json::to_string_pretty(&vector).unwrap());
    }
}
