use solana_address::Address;
use zolana_event::OutputData;
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{
    constants::{BLINDING_LEN, SALT_LEN, VIEW_TAG_LEN},
    hash::sha256_be,
    shielded::ShieldedAddress,
    viewing_key::{random_blinding, ViewTag},
    P256Pubkey, PublicKey, ShieldedKeypairTrait, SignatureType, ViewingKey, ViewingKeyTrait,
};

use super::{
    signed_transaction::{asset_field, signed_to_field, PublicAmounts, SignedTransaction},
    ExternalData, OutputUtxo,
};
use crate::{
    data::Data,
    error::TransactionError,
    instructions::types::SpendUtxo,
    serialization::{
        confidential::{
            ConfidentialRecipient, ConfidentialRecipientEncode, ConfidentialSenderBundle,
            ConfidentialSenderEncode, TransferRecipientPlaintext, TransferSenderPlaintext,
        },
        confidential_unified::{ConfidentialUnified, ConfidentialUnifiedEncode},
        OwnerCx, UtxoSerialization,
    },
    utxo::{derive_blinding, Utxo},
    AssetRegistry, SOL_MINT,
};

const SPL_CHANGE_POSITION: u8 = 0;
const SOL_CHANGE_POSITION: u8 = 1;
const RECIPIENT_POSITION_BASE: u8 = 2;

/// Fixed number of leading sender-owned output slots in a transfer: SPL change at
/// slot 0 (and the sender bundle ciphertext), SOL change at slot 1. Recipients
/// always start at slot 2.
pub const SENDER_SLOT_COUNT: usize = 2;

/// Transfers always pad to this single shape so every transfer has the same
/// input/output count and its structure is not observable. The SPP prover
/// supports more shapes ([`SPP_SUPPORTED_SHAPES`]); this fixed shape is the
/// privacy-preserving subset used for padded transfers.
pub const SUPPORTED_SHAPES: [Shape; 1] = [Shape::new(2, 3)];

/// Shapes the SPP prover has keys for. Slot-signed transactions declare their
/// exact shape (they do not pad), so they validate against this full set rather
/// than [`SUPPORTED_SHAPES`]. Kept in sync with
/// `sdk-libs/client/src/prover/shape.rs`.
pub const SPP_SUPPORTED_SHAPES: [Shape; 10] = [
    Shape::new(1, 1),
    Shape::new(1, 2),
    Shape::new(2, 2),
    Shape::new(2, 3),
    Shape::new(3, 3),
    Shape::new(4, 3),
    Shape::new(4, 4),
    Shape::new(5, 3),
    Shape::new(5, 4),
    Shape::new(1, 8),
];

pub struct PreparedRecipient {
    pub view_tag: ViewTag,
    pub recipient_pubkey: P256Pubkey,
    pub plaintext: TransferRecipientPlaintext,
}

pub struct PreparedTransaction {
    pub inputs: Vec<SpendUtxo>,
    pub outputs: Vec<OutputUtxo>,
    pub sender_plaintext: TransferSenderPlaintext,
    pub recipients: Vec<PreparedRecipient>,
    pub first_nullifier: [u8; 32],
    pub public_amounts: PublicAmounts,
    pub shape: Shape,
    pub max_recipients: usize,
    pub payer_pubkey_hash: [u8; 32],
    pub expiry_unix_ts: u64,
    pub public_sol_amount: Option<i64>,
    pub public_spl_amount: Option<i64>,
    pub user_sol_account: Address,
    pub user_spl_token: Address,
    pub spl_token_interface: Address,
}

pub fn inputs_require_p256(inputs: &[SpendUtxo]) -> Result<bool, TransactionError> {
    for spend in inputs {
        // A dummy's zero owner reads as P256; skip it so it never forces the rail.
        if spend.is_dummy() {
            continue;
        }
        if spend.utxo.owner.signature_type()? == SignatureType::P256 {
            return Ok(true);
        }
    }
    Ok(false)
}

pub struct Recipient {
    pub address: ShieldedAddress,
    pub asset: Address,
    pub amount: u64,
}

pub enum WithdrawalTarget {
    Sol {
        user_sol_account: Address,
    },
    Spl {
        user_spl_token: Address,
        spl_token_interface: Address,
    },
}

pub struct Withdrawal {
    pub asset: Address,
    pub amount: u64,
    pub target: WithdrawalTarget,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Shape {
    pub n_inputs: usize,
    pub n_outputs: usize,
}

impl Shape {
    pub const fn new(n_inputs: usize, n_outputs: usize) -> Self {
        Self {
            n_inputs,
            n_outputs,
        }
    }
}

pub fn canonical_shape(n_in: usize, n_out: usize) -> Result<Shape, TransactionError> {
    SUPPORTED_SHAPES
        .iter()
        .copied()
        .find(|s| n_in <= s.n_inputs && n_out <= s.n_outputs)
        .ok_or(TransactionError::UnsupportedShape { n_in, n_out })
}

pub fn resolve_shape(
    declared: Option<Shape>,
    n_in: usize,
    n_out: usize,
) -> Result<Shape, TransactionError> {
    match declared {
        Some(shape) => {
            if !SUPPORTED_SHAPES.contains(&shape) {
                return Err(TransactionError::UnsupportedShape {
                    n_in: shape.n_inputs,
                    n_out: shape.n_outputs,
                });
            }
            if n_in > shape.n_inputs {
                return Err(TransactionError::TooManyInputs {
                    got: n_in,
                    max: shape.n_inputs,
                });
            }
            if n_out > shape.n_outputs {
                return Err(TransactionError::TooManyOutputsForShape {
                    got: n_out,
                    max: shape.n_outputs,
                });
            }
            Ok(shape)
        }
        None => canonical_shape(n_in, n_out),
    }
}

pub struct SlotCx<'a> {
    pub tx: &'a ViewingKey,
    pub self_pubkey: P256Pubkey,
    pub salt: [u8; SALT_LEN],
    /// AES ciphertext ordinal for this slot: the count of data-bearing outputs
    /// preceding it. Fed into the per-slot key/nonce derivation.
    pub slot_index: u32,
}

/// The encoded form of one output slot: its wire [`OwnerTag`], the resolved
/// 32-byte tag folded into the proof's owner-tag chain and republished as the
/// event `view_tag`, and the optional ciphertext (`None` when a preceding bundle
/// covers this slot).
pub struct EncodedSlot {
    pub owner_tag: OwnerTag,
    pub resolved_owner_tag: [u8; 32],
    pub data: Option<Vec<u8>>,
}

impl EncodedSlot {
    /// A self-contained data-bearing slot whose owner tag is embedded inline; the
    /// resolved tag is the same `view_tag` the ciphertext was sealed under.
    fn inline(ciphertext: OutputData) -> Self {
        Self {
            owner_tag: OwnerTag::Inline(ciphertext.view_tag),
            resolved_owner_tag: ciphertext.view_tag,
            data: Some(ciphertext.data),
        }
    }
}

pub trait EncodeOutputSlot {
    fn output(&self) -> &OutputUtxo;
    fn encode_slot(&self, cx: &SlotCx) -> Result<EncodedSlot, TransactionError>;
}

pub struct SenderSlot {
    pub output: OutputUtxo,
    pub plaintext: TransferSenderPlaintext,
}

impl EncodeOutputSlot for SenderSlot {
    fn output(&self) -> &OutputUtxo {
        &self.output
    }

    fn encode_slot(&self, cx: &SlotCx) -> Result<EncodedSlot, TransactionError> {
        Ok(EncodedSlot::inline(
            ConfidentialSenderBundle::encode_plaintext(
                &self.plaintext,
                self.plaintext.owner_pubkey.confidential_view_tag()?,
                &ConfidentialSenderEncode {
                    tx: cx.tx.clone(),
                    self_pubkey: cx.self_pubkey,
                    salt: cx.salt,
                    slot_index: cx.slot_index,
                    blinding_seed: self.plaintext.blinding_seed,
                    recipient_viewing_pks: self.plaintext.recipient_viewing_pks.clone(),
                },
            )?,
        ))
    }
}

pub struct RecipientSlot {
    output: OutputUtxo,
    asset_id: u64,
}

impl RecipientSlot {
    pub fn new(output: OutputUtxo, assets: &AssetRegistry) -> Result<Self, TransactionError> {
        if output.owner_address.is_none() {
            return Err(TransactionError::MissingOutput);
        }
        let asset_id = if output.asset == SOL_MINT {
            crate::SOL_ASSET_ID
        } else {
            assets.asset_id(&output.asset)?
        };
        Ok(Self { output, asset_id })
    }
}

impl EncodeOutputSlot for RecipientSlot {
    fn output(&self) -> &OutputUtxo {
        &self.output
    }

    fn encode_slot(&self, cx: &SlotCx) -> Result<EncodedSlot, TransactionError> {
        let address = self
            .output
            .owner_address
            .ok_or(TransactionError::MissingOutput)?;
        Ok(EncodedSlot::inline(
            ConfidentialRecipient::encode_plaintext(
                &TransferRecipientPlaintext {
                    asset_id: self.asset_id,
                    amount: self.output.amount,
                    blinding: self.output.blinding,
                    zone_program_id: self.output.zone_program_id,
                    data: self.output.data.clone(),
                },
                address.signing_pubkey.confidential_view_tag()?,
                &ConfidentialRecipientEncode {
                    tx: cx.tx.clone(),
                    recipient_pubkey: address.viewing_pubkey,
                    salt: cx.salt,
                    slot_index: cx.slot_index,
                },
            )?,
        ))
    }
}

pub struct ConfidentialSlot {
    output: OutputUtxo,
    asset_id: u64,
}

impl ConfidentialSlot {
    pub fn new(output: OutputUtxo, assets: &AssetRegistry) -> Result<Self, TransactionError> {
        if output.owner_address.is_none() {
            return Err(TransactionError::MissingOutput);
        }
        let asset_id = if output.asset == SOL_MINT {
            crate::SOL_ASSET_ID
        } else {
            assets.asset_id(&output.asset)?
        };
        Ok(Self { output, asset_id })
    }
}

impl EncodeOutputSlot for ConfidentialSlot {
    fn output(&self) -> &OutputUtxo {
        &self.output
    }

    fn encode_slot(&self, cx: &SlotCx) -> Result<EncodedSlot, TransactionError> {
        let address = self
            .output
            .owner_address
            .ok_or(TransactionError::MissingOutput)?;
        Ok(EncodedSlot::inline(ConfidentialUnified::encode_plaintext(
            &TransferRecipientPlaintext {
                asset_id: self.asset_id,
                amount: self.output.amount,
                blinding: self.output.blinding,
                zone_program_id: self.output.zone_program_id,
                data: self.output.data.clone(),
            },
            address.signing_pubkey.confidential_view_tag()?,
            &ConfidentialUnifiedEncode {
                tx: cx.tx.clone(),
                recipient_pubkey: address.viewing_pubkey,
                salt: cx.salt,
                slot_index: cx.slot_index,
            },
        )?))
    }
}

/// A slot whose ciphertext is already sealed (e.g. by a zone/swap SDK), carried
/// through verbatim. Its owner tag is embedded inline from the ciphertext's
/// `view_tag`.
pub struct PrebuiltSlot {
    pub output: OutputUtxo,
    pub ciphertext: OutputData,
}

impl EncodeOutputSlot for PrebuiltSlot {
    fn output(&self) -> &OutputUtxo {
        &self.output
    }

    fn encode_slot(&self, _cx: &SlotCx) -> Result<EncodedSlot, TransactionError> {
        Ok(EncodedSlot::inline(self.ciphertext.clone()))
    }
}
// TODO: we should separate this abstraction into a lowlevel ProofInputs and higher level Transfer that is specialized to perform transfers and is not intended to be used with custom utxos.
pub struct Transaction {
    pub owner: ShieldedAddress,
    pub inputs: Vec<SpendUtxo>,
    pub recipients: Vec<Recipient>,
    /// Fully specified recipient outputs that bind zone/program data. Unlike
    /// [`Recipient`] (which carries only address/asset/amount), these are minted
    /// verbatim, so the caller controls `data` and the zone/program ids.
    pub custom_outputs: Vec<OutputUtxo>,
    pub withdrawal: Option<Withdrawal>,
    pub payer_pubkey_hash: [u8; 32],
    pub blinding_seed: [u8; BLINDING_LEN],
    pub shape: Option<Shape>,
    pub expiry_unix_ts: u64,
}

impl Transaction {
    pub fn new(owner: ShieldedAddress, inputs: Vec<SpendUtxo>, payer: Address) -> Self {
        Self {
            owner,
            inputs,
            recipients: Vec::new(),
            custom_outputs: Vec::new(),
            withdrawal: None,
            payer_pubkey_hash: sha256_be(payer.as_array()),
            blinding_seed: random_blinding(),
            shape: None,
            // Never expires by default; the program rejects `current_ts > expiry`,
            // so callers that want a relayer deadline set it explicitly.
            expiry_unix_ts: u64::MAX,
        }
    }

    /// Push a fully specified custom recipient output. It counts toward the proof
    /// shape like a [`Self::send`] recipient and is encoded into its own
    /// ciphertext slot. The output must name its recipient via `owner_address`.
    pub fn add_output(&mut self, output: OutputUtxo) -> Result<&mut Self, TransactionError> {
        if output.owner_address.is_none() {
            return Err(TransactionError::MissingOutput);
        }
        self.custom_outputs.push(output);
        Ok(self)
    }

    pub fn with_shape(mut self, shape: Shape) -> Self {
        self.shape = Some(shape);
        self
    }

    pub fn with_expiry(mut self, expiry_unix_ts: u64) -> Self {
        self.expiry_unix_ts = expiry_unix_ts;
        self
    }

    pub fn requires_p256_owner(&self) -> Result<bool, TransactionError> {
        inputs_require_p256(&self.inputs)
    }

    pub fn send(
        &mut self,
        recipient: &ShieldedAddress,
        asset: Address,
        amount: u64,
    ) -> Result<&mut Self, TransactionError> {
        self.recipients.push(Recipient {
            address: *recipient,
            asset,
            amount,
        });
        Ok(self)
    }

    pub fn withdraw(
        &mut self,
        asset: Address,
        amount: u64,
        target: WithdrawalTarget,
    ) -> Result<&mut Self, TransactionError> {
        if self.withdrawal.is_some() {
            return Err(TransactionError::WithdrawalAlreadySet);
        }
        self.withdrawal = Some(Withdrawal {
            asset,
            amount,
            target,
        });
        Ok(self)
    }

    /// Keypair rail: assemble with the owner's own viewing key and sign in place,
    /// no separate authority. The authority rail is [`Self::prepare`] +
    /// [`PreparedTransaction::finalize`], with encryption/signing delegated to a
    /// `WalletAuthority`.
    pub fn sign<K: ShieldedKeypairTrait + ViewingKeyTrait>(
        self,
        keypair: &K,
        assets: &AssetRegistry,
    ) -> Result<SignedTransaction, TransactionError> {
        let mut signed = self.assemble(keypair, assets)?;
        if keypair.curve()? == SignatureType::P256 {
            let message_hash = signed.message_hash()?;
            signed.p256_owner = Some(keypair.sign(&message_hash));
        }
        Ok(signed)
    }

    pub fn sign_with_slots<K: ShieldedKeypairTrait + ViewingKeyTrait>(
        self,
        slots: &[&dyn EncodeOutputSlot],
        keypair: &K,
    ) -> Result<SignedTransaction, TransactionError> {
        let shape = Shape::new(self.inputs.len(), slots.len());
        if !SPP_SUPPORTED_SHAPES.contains(&shape) {
            return Err(TransactionError::UnsupportedShape {
                n_in: shape.n_inputs,
                n_out: shape.n_outputs,
            });
        }

        let first_nullifier = self.first_nullifier()?;
        let tx = keypair.get_transaction_viewing_key(&first_nullifier)?;
        let salt = zolana_keypair::random_salt();
        let tx_viewing_pk = tx.pubkey();
        let self_pubkey = keypair.viewing_pubkey();

        let mut output_utxos = Vec::with_capacity(slots.len());
        let mut transact_outputs = Vec::with_capacity(slots.len());
        let mut resolved_owner_tags = Vec::with_capacity(slots.len());
        // AES ordinal: only data-bearing slots consume an index. Every
        // sign_with_slots slot is data-bearing, so the ordinal equals the slot
        // position, matching the historical `i as u32`.
        let mut ordinal = 0u32;
        for slot in slots.iter() {
            let encoded = slot.encode_slot(&SlotCx {
                tx: &tx,
                self_pubkey,
                salt,
                slot_index: ordinal,
            })?;
            let output = slot.output().clone();
            let utxo_hash = output.hash()?;
            if encoded.data.is_some() {
                ordinal += 1;
            }
            transact_outputs.push(TransactOutput {
                utxo_hash,
                owner_tag: encoded.owner_tag,
                data: encoded.data,
            });
            resolved_owner_tags.push(encoded.resolved_owner_tag);
            output_utxos.push(output);
        }

        let external_data = ExternalData::new(
            *tx_viewing_pk.as_bytes(),
            salt,
            transact_outputs,
            resolved_owner_tags,
            vec![],
            self.expiry_unix_ts,
        );

        let mut signed = SignedTransaction {
            inputs: self.inputs,
            outputs: output_utxos,
            public_amounts: PublicAmounts {
                sol: signed_to_field(0),
                spl: signed_to_field(0),
                asset: [0u8; 32],
            },
            external_data,
            payer_pubkey_hash: self.payer_pubkey_hash,
            shape,
            p256_owner: None, // TODO: rename to p256 signature
        };
        if keypair.curve()? == SignatureType::P256 {
            let message_hash = signed.message_hash()?;
            signed.p256_owner = Some(keypair.sign(&message_hash));
        }
        Ok(signed)
    }

    fn assemble<K: ShieldedKeypairTrait + ViewingKeyTrait>(
        self,
        keypair: &K,
        assets: &AssetRegistry,
    ) -> Result<SignedTransaction, TransactionError> {
        let prepared = self.prepare(assets)?;
        let tx = keypair.get_transaction_viewing_key(&prepared.first_nullifier)?;
        let salt = zolana_keypair::random_salt();
        let tx_viewing_pk = tx.pubkey();

        let sender_view_tag = prepared
            .sender_plaintext
            .owner_pubkey
            .confidential_view_tag()?;
        let mut slots = Vec::with_capacity(1 + prepared.recipients.len());
        slots.push(ConfidentialSenderBundle::encode_plaintext(
            &prepared.sender_plaintext,
            sender_view_tag,
            &ConfidentialSenderEncode {
                tx: tx.clone(),
                self_pubkey: keypair.viewing_pubkey(),
                salt,
                slot_index: 0,
                blinding_seed: prepared.sender_plaintext.blinding_seed,
                recipient_viewing_pks: prepared.sender_plaintext.recipient_viewing_pks.clone(),
            },
        )?);
        for (i, recipient) in prepared.recipients.iter().enumerate() {
            slots.push(ConfidentialRecipient::encode_plaintext(
                &recipient.plaintext,
                recipient.view_tag,
                &ConfidentialRecipientEncode {
                    tx: tx.clone(),
                    recipient_pubkey: recipient.recipient_pubkey,
                    salt,
                    slot_index: (i + 1) as u32,
                },
            )?);
        }

        prepared.finalize(tx_viewing_pk, salt, slots, assets)
    }

    pub fn prepare(self, assets: &AssetRegistry) -> Result<PreparedTransaction, TransactionError> {
        let spl_asset = self.spl_asset()?;
        let (public_sol, public_spl) = self.public_amounts();
        let sol_change = self.change(&SOL_MINT, public_sol)?;
        let spl_change = match spl_asset {
            Some(asset) => self.change(&asset, public_spl)?,
            None => 0,
        };

        let mut outputs = Vec::new();
        outputs.push(match spl_asset {
            Some(asset) if spl_change > 0 => OutputUtxo {
                owner_address: Some(self.owner),
                asset,
                amount: spl_change,
                blinding: derive_blinding(&self.blinding_seed, SPL_CHANGE_POSITION),
                ..Default::default()
            },
            _ => OutputUtxo {
                blinding: derive_blinding(&self.blinding_seed, SPL_CHANGE_POSITION),
                owner_tag: Some(self.owner.signing_pubkey.confidential_view_tag()?),
                ..Default::default()
            },
        });
        outputs.push(if sol_change > 0 {
            OutputUtxo {
                owner_address: Some(self.owner),
                asset: SOL_MINT,
                amount: sol_change,
                blinding: derive_blinding(&self.blinding_seed, SOL_CHANGE_POSITION),
                ..Default::default()
            }
        } else {
            OutputUtxo {
                blinding: derive_blinding(&self.blinding_seed, SOL_CHANGE_POSITION),
                owner_tag: Some(self.owner.signing_pubkey.confidential_view_tag()?),
                ..Default::default()
            }
        });

        let mut recipients = Vec::with_capacity(self.recipients.len());
        let mut recipient_viewing_pks = Vec::with_capacity(self.recipients.len());
        for (i, recipient) in self.recipients.iter().enumerate() {
            let position = RECIPIENT_POSITION_BASE + i as u8;
            let blinding = derive_blinding(&self.blinding_seed, position);
            let asset_id = self.asset_id(assets, &recipient.asset)?;
            outputs.push(OutputUtxo {
                owner_address: Some(recipient.address),
                asset: recipient.asset,
                amount: recipient.amount,
                blinding,
                ..Default::default()
            });
            recipient_viewing_pks.push(recipient.address.viewing_pubkey);
            recipients.push(PreparedRecipient {
                view_tag: recipient.address.signing_pubkey.confidential_view_tag()?,
                recipient_pubkey: recipient.address.viewing_pubkey,
                plaintext: TransferRecipientPlaintext {
                    asset_id,
                    amount: recipient.amount,
                    blinding,
                    zone_program_id: None,
                    data: Data::default(),
                },
            });
        }

        for output in &self.custom_outputs {
            let address = output
                .owner_address
                .ok_or(TransactionError::MissingOutput)?;
            let asset_id = self.asset_id(assets, &output.asset)?;
            recipient_viewing_pks.push(address.viewing_pubkey);
            recipients.push(PreparedRecipient {
                view_tag: address.signing_pubkey.confidential_view_tag()?,
                recipient_pubkey: address.viewing_pubkey,
                plaintext: TransferRecipientPlaintext {
                    asset_id,
                    amount: output.amount,
                    blinding: output.blinding,
                    zone_program_id: output.zone_program_id,
                    data: output.data.clone(),
                },
            });
            outputs.push(output.clone());
        }

        let shape = resolve_shape(self.shape, self.inputs.len(), outputs.len())?;
        let max_recipients = shape
            .n_outputs
            .checked_sub(SENDER_SLOT_COUNT)
            .ok_or(TransactionError::MissingOutput)?;
        let sender_viewing_pubkey = self.owner.viewing_pubkey;
        while recipient_viewing_pks.len() < max_recipients {
            recipient_viewing_pks.push(sender_viewing_pubkey);
        }

        let spl_asset_id = match spl_asset {
            Some(asset) => self.asset_id(assets, &asset)?,
            None => 0,
        };
        let sender_plaintext = TransferSenderPlaintext {
            owner_pubkey: self.owner.signing_pubkey,
            spl_asset_id,
            spl_amount: spl_change,
            sol_amount: sol_change,
            blinding_seed: self.blinding_seed,
            recipient_viewing_pks,
            spl_data: Data::default(),
            sol_data: Data::default(),
        };

        let first_nullifier = self.first_nullifier()?;
        let (user_sol_account, user_spl_token, spl_token_interface) = self.external_accounts();
        let public_amounts = PublicAmounts {
            sol: signed_to_field(public_sol),
            spl: signed_to_field(public_spl),
            asset: match (public_spl != 0, spl_asset) {
                (true, Some(asset)) => asset_field(&asset)?,
                _ => [0u8; 32],
            },
        };

        Ok(PreparedTransaction {
            inputs: self.inputs,
            outputs,
            sender_plaintext,
            recipients,
            first_nullifier,
            public_amounts,
            shape,
            max_recipients,
            payer_pubkey_hash: self.payer_pubkey_hash,
            expiry_unix_ts: self.expiry_unix_ts,
            public_sol_amount: (public_sol != 0).then_some(public_sol as i64),
            public_spl_amount: (public_spl != 0).then_some(public_spl as i64),
            user_sol_account,
            user_spl_token,
            spl_token_interface,
        })
    }

    fn asset_id(&self, assets: &AssetRegistry, asset: &Address) -> Result<u64, TransactionError> {
        if asset == &SOL_MINT {
            Ok(crate::SOL_ASSET_ID)
        } else {
            Ok(assets.asset_id(asset)?)
        }
    }

    fn spl_asset(&self) -> Result<Option<Address>, TransactionError> {
        let mut found: Option<Address> = None;
        let assets = self
            .inputs
            .iter()
            .map(|spend| spend.utxo.asset)
            .chain(self.recipients.iter().map(|recipient| recipient.asset))
            .chain(self.custom_outputs.iter().map(|output| output.asset))
            .chain(self.withdrawal.iter().map(|withdrawal| withdrawal.asset));
        for asset in assets {
            if asset != SOL_MINT {
                match found {
                    Some(existing) if existing != asset => {
                        return Err(TransactionError::MultiplePublicSplAssets)
                    }
                    _ => found = Some(asset),
                }
            }
        }
        Ok(found)
    }

    fn public_amounts(&self) -> (i128, i128) {
        match &self.withdrawal {
            Some(withdrawal) if withdrawal.asset == SOL_MINT => (-i128::from(withdrawal.amount), 0),
            Some(withdrawal) => (0, -i128::from(withdrawal.amount)),
            None => (0, 0),
        }
    }

    fn input_sum(&self, asset: &Address) -> i128 {
        self.inputs
            .iter()
            .filter(|spend| &spend.utxo.asset == asset)
            .map(|spend| i128::from(spend.utxo.amount))
            .sum()
    }

    fn recipient_sum(&self, asset: &Address) -> i128 {
        self.recipients
            .iter()
            .filter(|recipient| &recipient.asset == asset)
            .map(|recipient| i128::from(recipient.amount))
            .sum()
    }

    fn custom_output_sum(&self, asset: &Address) -> i128 {
        self.custom_outputs
            .iter()
            .filter(|output| &output.asset == asset)
            .map(|output| i128::from(output.amount))
            .sum()
    }

    fn change(&self, asset: &Address, public: i128) -> Result<u64, TransactionError> {
        let leftover = self
            .input_sum(asset)
            .checked_add(public)
            .and_then(|v| v.checked_sub(self.recipient_sum(asset)))
            .and_then(|v| v.checked_sub(self.custom_output_sum(asset)))
            .ok_or(TransactionError::SelectedBalanceOverflow)?;
        if leftover < 0 {
            return Err(TransactionError::InsufficientBalance {
                requested: (-leftover) as u64,
                available: 0,
            });
        }
        Ok(leftover as u64)
    }

    fn first_nullifier(&self) -> Result<[u8; 32], TransactionError> {
        let spend = self.inputs.first().ok_or(TransactionError::NoInputs)?;
        let nullifier_pubkey = spend.nullifier_key.pubkey()?;
        let utxo_hash = spend.utxo.hash(
            &nullifier_pubkey,
            &spend.data_hash.unwrap_or([0u8; 32]),
            &spend.zone_data_hash.unwrap_or([0u8; 32]),
        )?;
        Ok(spend
            .nullifier_key
            .nullifier(&utxo_hash, &spend.utxo.blinding)?)
    }

    fn external_accounts(&self) -> (Address, Address, Address) {
        match self
            .withdrawal
            .as_ref()
            .map(|withdrawal| &withdrawal.target)
        {
            Some(WithdrawalTarget::Sol { user_sol_account }) => {
                (*user_sol_account, Address::default(), Address::default())
            }
            Some(WithdrawalTarget::Spl {
                user_spl_token,
                spl_token_interface,
            }) => (Address::default(), *user_spl_token, *spl_token_interface),
            None => (Address::default(), Address::default(), Address::default()),
        }
    }
}

impl PreparedTransaction {
    pub fn finalize(
        self,
        tx_viewing_pk: P256Pubkey,
        salt: [u8; zolana_keypair::constants::SALT_LEN],
        slots: Vec<OutputData>,
        assets: &AssetRegistry,
    ) -> Result<SignedTransaction, TransactionError> {
        let PreparedTransaction {
            mut inputs,
            mut outputs,
            sender_plaintext,
            public_amounts,
            shape,
            payer_pubkey_hash,
            expiry_unix_ts,
            public_sol_amount,
            public_spl_amount,
            user_sol_account,
            user_spl_token,
            spl_token_interface,
            ..
        } = self;

        // The sender owns every change position; its resolved tag is the owner
        // view tag folded into the proof's owner-tag chain. The wire tag is the
        // most compact form that resolves to it: `P256SigningKey` on the P256
        // rail, `Account(0)` when the owner is the fee payer, else `Inline`.
        let (sender_tag, sender_resolved) =
            sender_owner_tag(&sender_plaintext.owner_pubkey, &payer_pubkey_hash)?;

        // Each padded recipient slot gets one random view tag, shared between its
        // dummy output (folded into the confidential proof's owner-tag chain) and
        // its dummy ciphertext, so the dummy is indistinguishable from a real
        // recipient and the proof's tag equals the published tag.
        let dummy_recipient_count = shape.n_outputs.saturating_sub(outputs.len());
        let dummy_tags = (0..dummy_recipient_count)
            .map(|_| random_view_tag())
            .collect::<Result<Vec<_>, _>>()?;
        for tag in &dummy_tags {
            outputs.push(OutputUtxo {
                blinding: random_blinding(),
                owner_tag: Some(*tag),
                ..Default::default()
            });
        }
        while inputs.len() < shape.n_inputs {
            inputs.push(SpendUtxo::new_dummy());
        }

        // Random ciphertexts for the dummy recipient positions, byte-length
        // matched to a real recipient slot so dummies do not stand out.
        let mut dummy_ciphertexts = if dummy_recipient_count > 0 {
            let throwaway = zolana_keypair::ViewingKey::new();
            let dummy_len = dummy_ciphertext_len(&throwaway, throwaway.pubkey(), salt, assets)?;
            (0..dummy_recipient_count)
                .map(|_| random_dummy_ciphertext(dummy_len))
                .collect::<Vec<_>>()
                .into_iter()
        } else {
            Vec::new().into_iter()
        };

        // 1:1 output assembly. The sender bundle covers the leading
        // SENDER_SLOT_COUNT change positions: position 0 carries the bundle
        // ciphertext, the rest carry `None` (the sender's tag with empty data).
        // Recipient positions carry their own ciphertext inline; dummy positions
        // carry the aligned random ciphertext under the dummy output's tag.
        let (bundle, recipient_slots) = match slots.split_first() {
            Some((bundle, rest)) => (Some(bundle), rest),
            None => (None, &[][..]),
        };
        let mut transact_outputs = Vec::with_capacity(outputs.len());
        let mut resolved_owner_tags = Vec::with_capacity(outputs.len());
        for (position, output) in outputs.iter().enumerate() {
            let utxo_hash = output.hash()?;
            let (owner_tag, resolved, data) = if position == 0 {
                (sender_tag, sender_resolved, bundle.map(|b| b.data.clone()))
            } else if position < SENDER_SLOT_COUNT {
                (sender_tag, sender_resolved, None)
            } else {
                let recipient_index = position - SENDER_SLOT_COUNT;
                match recipient_slots.get(recipient_index) {
                    Some(slot) => (
                        OwnerTag::Inline(slot.view_tag),
                        slot.view_tag,
                        Some(slot.data.clone()),
                    ),
                    None => {
                        let tag = output.owner_tag.ok_or(TransactionError::MissingOutput)?;
                        let ciphertext = dummy_ciphertexts
                            .next()
                            .ok_or(TransactionError::MissingOutput)?;
                        (OwnerTag::Inline(tag), tag, Some(ciphertext))
                    }
                }
            };
            transact_outputs.push(TransactOutput {
                utxo_hash,
                owner_tag,
                data,
            });
            resolved_owner_tags.push(resolved);
        }

        let mut external_data = ExternalData::new(
            *tx_viewing_pk.as_bytes(),
            salt,
            transact_outputs,
            resolved_owner_tags,
            vec![],
            expiry_unix_ts,
        );
        if let Some(amount) = public_sol_amount {
            external_data = external_data.with_public_sol(amount, user_sol_account)?;
        }
        if let Some(amount) = public_spl_amount {
            external_data =
                external_data.with_public_spl(amount, user_spl_token, spl_token_interface)?;
        }

        Ok(SignedTransaction {
            inputs,
            outputs,
            public_amounts,
            external_data,
            payer_pubkey_hash,
            shape,
            p256_owner: None,
        })
    }
}

/// The sender's output owner tag and its resolved 32-byte value. The resolved
/// value is always `confidential_view_tag()` (the P256 x-coordinate or the full
/// ed25519 key); the wire tag is the most compact form that resolves to it:
/// `P256SigningKey` on the P256 rail, `Account(0)` when the ed25519 owner is the
/// fee payer at account index 0, else `Inline` (relayed transfer).
fn sender_owner_tag(
    owner_pubkey: &PublicKey,
    payer_pubkey_hash: &[u8; 32],
) -> Result<(OwnerTag, [u8; 32]), TransactionError> {
    let resolved = owner_pubkey.confidential_view_tag()?;
    let tag = match owner_pubkey.signature_type()? {
        SignatureType::P256 => OwnerTag::P256SigningKey,
        SignatureType::Ed25519 => {
            if sha256_be(&resolved) == *payer_pubkey_hash {
                OwnerTag::Account(0)
            } else {
                OwnerTag::Inline(resolved)
            }
        }
    };
    Ok((tag, resolved))
}

/// A view tag for a dummy output slot: the Poseidon hash of 31 random bytes. The
/// result is a 32-byte field element, indistinguishable from a real owner-pubkey
/// tag, so a dummy slot does not stand out and leak the recipient count. The 31
/// random bytes are left-padded to a 32-byte big-endian field element (leading byte
/// zero keeps it below the BN254 modulus).
fn random_view_tag() -> Result<[u8; VIEW_TAG_LEN], TransactionError> {
    let mut input = [0u8; 32];
    input[1..].copy_from_slice(&random_blinding());
    Ok(zolana_keypair::hash::poseidon(&[&input])?)
}

/// Random `len` bytes for a dummy output slot.
fn random_dummy_ciphertext(len: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(len);
    while data.len() < len {
        let chunk = random_blinding();
        let take = (len - data.len()).min(chunk.len());
        data.extend_from_slice(&chunk[..take]);
    }
    data
}

/// The exact ciphertext byte length of a real recipient slot, derived by
/// encoding a throwaway recipient through the same path. This keeps dummy slots
/// byte-length-indistinguishable from real ones without pinning a brittle constant.
fn dummy_ciphertext_len(
    tx: &zolana_keypair::ViewingKey,
    throwaway_pubkey: P256Pubkey,
    salt: [u8; zolana_keypair::constants::SALT_LEN],
    assets: &AssetRegistry,
) -> Result<usize, TransactionError> {
    let utxo = Utxo {
        owner: PublicKey::zeroed(),
        asset: SOL_MINT,
        amount: 0,
        blinding: random_blinding(),
        zone_program_id: None,
        data: Data::default(),
    };
    let owner_cx = OwnerCx {
        owner: utxo.owner,
        assets,
        zone_program_id: None,
    };
    let ciphertext = ConfidentialRecipient::encode(
        core::slice::from_ref(&utxo),
        &owner_cx,
        [0u8; VIEW_TAG_LEN],
        &ConfidentialRecipientEncode {
            tx: tx.clone(),
            recipient_pubkey: throwaway_pubkey,
            salt,
            slot_index: 0,
        },
    )?;
    Ok(ciphertext.data.len())
}

#[cfg(test)]
mod tests {
    use zolana_keypair::SigningKey;

    use super::*;

    /// An ed25519 owner who is also the fee payer at account index 0 is tagged
    /// `Account(0)`; the resolved value is the owner's view tag (the ed25519 key).
    #[test]
    fn sender_tag_is_account_zero_when_owner_is_payer() {
        let pk = SigningKey::from_ed25519(&[7u8; 32]).pubkey();
        let resolved = pk.confidential_view_tag().unwrap();
        let payer_hash = sha256_be(&resolved);
        let (tag, got_resolved) = sender_owner_tag(&pk, &payer_hash).unwrap();
        assert_eq!(tag, OwnerTag::Account(0));
        assert_eq!(got_resolved, resolved);
    }

    /// A relayed transfer whose ed25519 owner is not the fee payer falls back to
    /// an inline tag carrying the owner's view tag verbatim.
    #[test]
    fn sender_tag_is_inline_for_relayed_transfer() {
        let pk = SigningKey::from_ed25519(&[7u8; 32]).pubkey();
        let resolved = pk.confidential_view_tag().unwrap();
        let unrelated_payer_hash = [0u8; 32];
        let (tag, got_resolved) = sender_owner_tag(&pk, &unrelated_payer_hash).unwrap();
        assert_eq!(tag, OwnerTag::Inline(resolved));
        assert_eq!(got_resolved, resolved);
    }

    /// A P256 owner is tagged `P256SigningKey`, resolving to the shared signing
    /// key's x-coordinate regardless of the fee payer.
    #[test]
    fn sender_tag_is_p256_signing_key_for_p256_owner() {
        let pk = SigningKey::new().pubkey();
        let resolved = pk.confidential_view_tag().unwrap();
        let (tag, got_resolved) = sender_owner_tag(&pk, &[0u8; 32]).unwrap();
        assert_eq!(tag, OwnerTag::P256SigningKey);
        assert_eq!(got_resolved, resolved);
    }
}
