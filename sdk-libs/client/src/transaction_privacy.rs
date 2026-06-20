//! Classifies what a shielded-pool transaction exposes to a public chain observer.
//!
//! Every `*_private` field is `true` when that aspect is **not** visible on-chain
//! to someone without viewing keys (shielded / hidden). `false` means publicly
//! observable (identity, balance movement, amount, or asset).

use zolana_interface::{
    event::{tag, GeneralEvent, InstructionGroup, ParsedInstruction},
    instruction::TransactIxDataRef,
    PROGRAM_ID_PUBKEY,
};

use std::fmt;

use crate::actions::{CreatedTransfer, CreatedWithdrawal, Deposit, TransferRecipient};
use crate::error::ClientError;

/// High-level flow label derived from [`TransactionPrivacy`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionPrivacyKind {
    Deposit,
    ShieldedTransfer,
    Withdrawal,
}

/// Per-field privacy for a shielded-pool wallet action.
///
/// `true` on any field means that field is **private** (shielded from a public
/// observer). `false` means **public** on-chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionPrivacy {
    pub kind: TransactionPrivacyKind,
    pub sender_identity_private: bool,
    pub sender_balance_private: bool,
    pub recipient_identity_private: bool,
    pub recipient_balance_private: bool,
    pub amount_private: bool,
    pub asset_private: bool,
}

impl TransactionPrivacy {
    pub const fn deposit() -> Self {
        Self {
            kind: TransactionPrivacyKind::Deposit,
            sender_identity_private: false,
            sender_balance_private: false,
            recipient_identity_private: true,
            recipient_balance_private: true,
            amount_private: false,
            asset_private: false,
        }
    }

    pub const fn shielded_transfer() -> Self {
        Self {
            kind: TransactionPrivacyKind::ShieldedTransfer,
            sender_identity_private: true,
            sender_balance_private: true,
            recipient_identity_private: true,
            recipient_balance_private: true,
            amount_private: true,
            asset_private: true,
        }
    }

    pub const fn withdrawal() -> Self {
        Self {
            kind: TransactionPrivacyKind::Withdrawal,
            sender_identity_private: true,
            sender_balance_private: true,
            recipient_identity_private: false,
            recipient_balance_private: false,
            amount_private: false,
            asset_private: false,
        }
    }

    pub fn from_deposit(_deposit: &Deposit) -> Self {
        Self::deposit()
    }

    pub fn from_withdrawal(_withdrawal: &CreatedWithdrawal) -> Self {
        Self::withdrawal()
    }

    pub fn from_transfer(transfer: &CreatedTransfer) -> Self {
        match &transfer.recipient {
            TransferRecipient::Registered(_) => Self::shielded_transfer(),
            TransferRecipient::PublicWithdrawal { .. } => Self::withdrawal(),
        }
    }

    pub fn from_transact_ix(ix: &TransactIxDataRef<'_>) -> Self {
        if !ix.is_deposit_or_withdrawal() {
            return Self::shielded_transfer();
        }
        if ix.is_deposit() {
            Self::deposit()
        } else {
            Self::withdrawal()
        }
    }

    pub fn from_general_event(event: &GeneralEvent) -> Self {
        match event.deposit_withdraw.as_ref() {
            None => Self::shielded_transfer(),
            Some(deposit_withdraw) if deposit_withdraw.is_deposit => Self::deposit(),
            Some(_) => Self::withdrawal(),
        }
    }

    pub fn from_parsed_instruction(
        instruction: &ParsedInstruction,
    ) -> Result<Option<Self>, ClientError> {
        if instruction.program_id != PROGRAM_ID_PUBKEY {
            return Ok(None);
        }
        let Some(instruction_tag) = instruction.data.first() else {
            return Ok(None);
        };
        Ok(Some(match *instruction_tag {
            tag::DEPOSIT => Self::deposit(),
            tag::TRANSACT => {
                let ix = TransactIxDataRef::from_bytes(instruction.data.get(1..).unwrap_or_default())
                    .map_err(|err| {
                        ClientError::PrivacyClassification(format!(
                            "decode transact instruction data: {err}"
                        ))
                    })?;
                Self::from_transact_ix(&ix)
            }
            _ => return Ok(None),
        }))
    }

    pub fn from_instruction_groups(
        groups: &[InstructionGroup],
    ) -> Result<Option<Self>, ClientError> {
        for group in groups {
            if let Some(privacy) = Self::from_parsed_instruction(&group.outer)? {
                return Ok(Some(privacy));
            }
        }
        Ok(None)
    }

    pub fn flow_label(self) -> &'static str {
        match self.kind {
            TransactionPrivacyKind::Deposit => "public-to-private",
            TransactionPrivacyKind::ShieldedTransfer => "private-to-private",
            TransactionPrivacyKind::Withdrawal => "private-to-public",
        }
    }

    pub fn visibility_label(private: bool) -> &'static str {
        if private {
            "private"
        } else {
            "public"
        }
    }

    pub fn format_fields(self) -> String {
        format!(
            "flow={} sender_identity={} sender_balance={} recipient_identity={} recipient_balance={} amount={} asset={}",
            self.flow_label(),
            Self::visibility_label(self.sender_identity_private),
            Self::visibility_label(self.sender_balance_private),
            Self::visibility_label(self.recipient_identity_private),
            Self::visibility_label(self.recipient_balance_private),
            Self::visibility_label(self.amount_private),
            Self::visibility_label(self.asset_private),
        )
    }

    pub fn description(self) -> String {
        match self.kind {
            TransactionPrivacyKind::Deposit => {
                "Public-to-private: the depositor and funded amount are visible on-chain; \
                 the new shielded note owner, balance, and recipient-side details are private."
                    .to_string()
            }
            TransactionPrivacyKind::ShieldedTransfer => {
                "Private-to-private: sender, recipient, amount, and asset stay shielded; \
                 only nullifier and ciphertext metadata appear on-chain.".to_string()
            }
            TransactionPrivacyKind::Withdrawal => {
                let exposures = self.public_field_names();
                if exposures.is_empty() {
                    "Private-to-public: settlement fields become visible on-chain.".to_string()
                } else {
                    format!(
                        "Private-to-public: sender stays shielded; {} become visible on-chain.",
                        join_readable_list(&exposures)
                    )
                }
            }
        }
    }

    pub fn public_field_names(self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if !self.sender_identity_private {
            names.push("sender identity");
        }
        if !self.sender_balance_private {
            names.push("sender balance");
        }
        if !self.recipient_identity_private {
            names.push("recipient identity");
        }
        if !self.recipient_balance_private {
            names.push("recipient balance");
        }
        if !self.amount_private {
            names.push("amount");
        }
        if !self.asset_private {
            names.push("asset");
        }
        names
    }
}

impl fmt::Display for TransactionPrivacy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_fields())
    }
}

fn join_readable_list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => (*one).to_string(),
        [first, second] => format!("{first} and {second}"),
        all => {
            let (head, tail) = all.split_at(all.len() - 1);
            format!("{}, and {}", head.join(", "), tail[0])
        }
    }
}

#[cfg(test)]
mod tests {
    use borsh::to_vec;
    use solana_account::Account;
    use solana_pubkey::Pubkey;
    use zolana_interface::{
        event::{DepositWithdraw, GeneralEvent, Input, OutputUtxo},
        instruction::{tag, DepositIxData, TransactIxData},
    };
    use zolana_keypair::ShieldedKeypair;
    use zolana_transaction::{Address, AssetRegistry, Utxo, Wallet, WalletUtxo, SOL_MINT};
    use zolana_user_registry_interface::{user_record_pda, user_registry_program_id, UserRecord};

    use super::*;
    use crate::actions::deposit::{CreateDeposit, Deposit};
    use crate::actions::{
        create_transfer, create_withdrawal, CreateTransfer, CreateWithdrawal,
    };
    use crate::rpc::Rpc;

    struct MockRpc {
        account: Option<(Address, Account)>,
    }

    impl Rpc for MockRpc {
        fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            Ok(self
                .account
                .as_ref()
                .and_then(|(expected, account)| (*expected == address).then(|| account.clone())))
        }
    }

    fn wallet_with_asset(keypair: ShieldedKeypair, asset: Address, amount: u64) -> Wallet {
        let mut wallet = Wallet::new(keypair.clone()).expect("wallet");
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset,
            amount,
            blinding: [7u8; 31],
            zone_program_id: None,
            data: Default::default(),
        };
        let nullifier_pk = keypair.nullifier_key.pubkey().expect("nullifier pubkey");
        let hash = utxo
            .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
            .expect("utxo hash");
        let nullifier = utxo
            .nullifier(&hash, &keypair.nullifier_key)
            .expect("nullifier");
        wallet.utxos.push(WalletUtxo {
            utxo,
            hash,
            nullifier,
            spent: false,
        });
        wallet
    }

    #[test]
    fn deposit_privacy_is_public_to_private() {
        let privacy = TransactionPrivacy::deposit();
        assert_eq!(privacy.flow_label(), "public-to-private");
        assert!(!privacy.sender_identity_private);
        assert!(privacy.recipient_identity_private);
        assert!(!privacy.amount_private);
    }

    #[test]
    fn shielded_transfer_privacy_is_fully_private() {
        let privacy = TransactionPrivacy::shielded_transfer();
        assert_eq!(privacy.flow_label(), "private-to-private");
        assert!(privacy.sender_identity_private);
        assert!(privacy.recipient_identity_private);
        assert!(privacy.amount_private);
        assert!(privacy.asset_private);
    }

    #[test]
    fn withdrawal_privacy_exposes_recipient_amount_and_asset() {
        let privacy = TransactionPrivacy::withdrawal();
        assert_eq!(privacy.flow_label(), "private-to-public");
        assert!(privacy.sender_identity_private);
        assert!(!privacy.recipient_identity_private);
        assert!(!privacy.amount_private);
        assert!(!privacy.asset_private);
    }

    #[test]
    fn from_transfer_matches_recipient_registration() {
        let sender = ShieldedKeypair::new().unwrap();
        let recipient = ShieldedKeypair::new().unwrap();
        let owner = Pubkey::new_unique();
        let (record_pda, bump) = user_record_pda(&owner);
        let record = UserRecord {
            owner: owner.to_bytes(),
            bump,
            owner_p256: Some(*recipient.signing_pubkey().as_p256().unwrap().as_bytes()),
            nullifier_pubkey: recipient.nullifier_key.pubkey().unwrap(),
            viewing_pubkey: *recipient.viewing_pubkey().as_bytes(),
            sync_delegate: None,
            entries: Vec::new(),
        };
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(record_pda.to_bytes()),
                Account {
                    lamports: 1,
                    data: {
                        let mut data = vec![UserRecord::DISCRIMINATOR];
                        data.extend_from_slice(&to_vec(&record).expect("serialize"));
                        data
                    },
                    owner: user_registry_program_id(),
                    executable: false,
                    rent_epoch: 0,
                },
            )),
        };
        let wallet = wallet_with_asset(sender.clone(), SOL_MINT, 10);
        let registered = create_transfer(CreateTransfer {
            rpc: &rpc,
            wallet: &wallet,
            keypair: &sender,
            payer: Address::default(),
            recipient_owner: owner,
            asset: SOL_MINT,
            amount: 1,
            assets: &AssetRegistry::default(),
        })
        .expect("registered transfer");
        assert_eq!(
            TransactionPrivacy::from_transfer(&registered),
            TransactionPrivacy::shielded_transfer()
        );

        let unregistered = create_transfer(CreateTransfer {
            rpc: &MockRpc { account: None },
            wallet: &wallet,
            keypair: &sender,
            payer: Address::default(),
            recipient_owner: Pubkey::new_unique(),
            asset: SOL_MINT,
            amount: 1,
            assets: &AssetRegistry::default(),
        })
        .expect("public fallback");
        assert_eq!(
            TransactionPrivacy::from_transfer(&unregistered),
            TransactionPrivacy::withdrawal()
        );
    }

    #[test]
    fn from_deposit_and_withdrawal_helpers() {
        let sender = ShieldedKeypair::new().unwrap();
        let wallet = wallet_with_asset(sender.clone(), SOL_MINT, 10);
        let deposit = Deposit::new(CreateDeposit {
            recipient: &sender,
            asset: SOL_MINT,
            amount: 5,
            spl_token_account: None,
        })
        .expect("deposit");
        assert_eq!(
            TransactionPrivacy::from_deposit(&deposit),
            TransactionPrivacy::deposit()
        );

        let withdrawal = create_withdrawal(CreateWithdrawal {
            wallet: &wallet,
            keypair: &sender,
            payer: Address::default(),
            recipient: Pubkey::new_unique(),
            asset: SOL_MINT,
            amount: 1,
            assets: &AssetRegistry::default(),
        })
        .expect("withdrawal");
        assert_eq!(
            TransactionPrivacy::from_withdrawal(&withdrawal),
            TransactionPrivacy::withdrawal()
        );
    }

    #[test]
    fn from_general_event_classifies_flows() {
        let shielded = GeneralEvent {
            inputs: vec![Input {
                tree: [1u8; 32],
                input_queue_seq: 0,
                nullifier: [2u8; 32],
            }],
            outputs: vec![OutputUtxo {
                view_tag: [0u8; 32],
                utxo_hash: [0u8; 32],
                data: vec![],
            }],
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            first_output_leaf_index: 0,
            output_tree: [0u8; 32],
            relay_fee: None,
            deposit_withdraw: None,
        };
        assert_eq!(
            TransactionPrivacy::from_general_event(&shielded),
            TransactionPrivacy::shielded_transfer()
        );

        let deposit = GeneralEvent {
            deposit_withdraw: Some(DepositWithdraw {
                is_deposit: true,
                amount: 10,
                asset: None,
            }),
            ..shielded.clone()
        };
        assert_eq!(
            TransactionPrivacy::from_general_event(&deposit),
            TransactionPrivacy::deposit()
        );

        let withdrawal = GeneralEvent {
            deposit_withdraw: Some(DepositWithdraw {
                is_deposit: false,
                amount: 10,
                asset: None,
            }),
            ..shielded
        };
        assert_eq!(
            TransactionPrivacy::from_general_event(&withdrawal),
            TransactionPrivacy::withdrawal()
        );
    }

    #[test]
    fn from_parsed_instruction_decodes_deposit_and_transact() {
        let deposit_ix = ParsedInstruction::new(
            PROGRAM_ID_PUBKEY,
            vec![],
            {
                let data = DepositIxData {
                    view_tag: [0u8; 32],
                    owner_utxo_hash: [0u8; 32],
                    salt: [0u8; 16],
                    public_amount: Some(1),
                    program_data_hash: None,
                    program_data: None,
                    cpi_signer: None,
                };
                let mut bytes = vec![tag::DEPOSIT];
                bytes.extend_from_slice(&data.serialize().expect("serialize deposit"));
                bytes
            },
            Some(1),
        );
        assert_eq!(
            TransactionPrivacy::from_parsed_instruction(&deposit_ix)
                .expect("deposit ix")
                .expect("some"),
            TransactionPrivacy::deposit()
        );

        let shielded_ix = ParsedInstruction::new(
            PROGRAM_ID_PUBKEY,
            vec![],
            {
                let data = TransactIxData {
                    proof: [0u8; 192],
                    expiry_unix_ts: 0,
                    relayer_fee: 0,
                    private_tx_hash: [0u8; 32],
                    inputs: vec![],
                    public_sol_amount: None,
                    public_spl_amount: None,
                    cpi_signer: None,
                    tx_viewing_pk: [0u8; 33],
                    salt: [0u8; 16],
                    sender_utxo_data: OutputUtxo {
                        view_tag: [0u8; 32],
                        utxo_hash: [0u8; 32],
                        data: vec![],
                    },
                    recipient_utxo_data: vec![],
                };
                let mut bytes = vec![tag::TRANSACT];
                bytes.extend_from_slice(&data.serialize().expect("serialize transact"));
                bytes
            },
            Some(1),
        );
        assert_eq!(
            TransactionPrivacy::from_parsed_instruction(&shielded_ix)
                .expect("transact ix")
                .expect("some"),
            TransactionPrivacy::shielded_transfer()
        );
    }

    #[test]
    fn format_fields_and_description_are_stable() {
        let privacy = TransactionPrivacy::withdrawal();
        assert_eq!(
            privacy.format_fields(),
            "flow=private-to-public sender_identity=private sender_balance=private \
             recipient_identity=public recipient_balance=public amount=public asset=public"
        );
        assert!(privacy.description().contains("recipient identity"));
    }
}
