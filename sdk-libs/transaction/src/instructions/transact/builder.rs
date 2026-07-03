use solana_address::Address;
use zolana_interface::instruction::instruction_data::transact::OutputCiphertext;
use zolana_keypair::{
    constants::{BLINDING_LEN, VIEW_TAG_LEN},
    hash::sha256_be,
    shielded::ShieldedAddress,
    viewing_key::{random_blinding, ViewTag},
    P256Pubkey, PublicKey, ShieldedKeypairTrait, SignatureType, ViewingKeyTrait,
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
        split::{Split, SplitBundlePlaintext, SplitEncode},
        OwnerCx, UtxoSerialization,
    },
    utxo::{derive_blinding, Utxo},
    AssetRegistry, SOL_MINT,
};

const TRANSACT_DISCRIMINATOR: u8 = 0;
const SPL_CHANGE_POSITION: u8 = 0;
const SOL_CHANGE_POSITION: u8 = 1;
const RECIPIENT_POSITION_BASE: u8 = 2;

/// Fixed number of leading sender-owned output slots in a transfer: SPL change at
/// slot 0 (and the sender bundle ciphertext), SOL change at slot 1. Recipients
/// always start at slot 2.
pub const SENDER_SLOT_COUNT: usize = 2;

/// Proof shapes a confidential transfer may target. Every shape carries three
/// outputs (two sender change slots + one recipient), so they differ only in
/// input capacity: a transfer spends 1-5 notes into a single recipient.
/// [`canonical_shape`] picks the smallest-input shape that fits and pads the
/// unused inputs with dummies, so the ordering here must be ascending by
/// `n_inputs`.
///
/// Deliberately capped at three outputs. A fourth output (`{4,4}`/`{5,4}`, i.e.
/// multi-recipient) adds an output ciphertext that pushes the instruction past
/// Solana's 1232-byte transaction limit, so those shapes need Address Lookup
/// Tables first. A balance fragmented across more than five notes is consolidated
/// via `merge` (the `merge_8_1` circuit), not by a larger transfer shape.
pub const SUPPORTED_SHAPES: [Shape; 4] = [
    Shape::new(2, 3),
    Shape::new(3, 3),
    Shape::new(4, 3),
    Shape::new(5, 3),
];

/// Proof shapes a split may target: a single input fanned out into up to eight
/// self-owned notes. A split into more than eight outputs is an unsupported
/// shape. Kept separate from [`SUPPORTED_SHAPES`] because the split rides its own
/// 1xN circuit, not the 2x3 confidential-transfer shape.
pub const SUPPORTED_SPLIT_SHAPES: [Shape; 1] = [Shape::new(1, 8)];

/// Smallest supported split shape holding `n_out` self-owned outputs from a single
/// input. Errors with [`TransactionError::UnsupportedShape`] when no shape fits
/// (e.g. more than eight outputs).
pub fn canonical_split_shape(n_out: usize) -> Result<Shape, TransactionError> {
    SUPPORTED_SPLIT_SHAPES
        .iter()
        .copied()
        .find(|s| n_out <= s.n_outputs)
        .ok_or(TransactionError::UnsupportedShape { n_in: 1, n_out })
}

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

struct Recipient {
    address: ShieldedAddress,
    asset: Address,
    amount: u64,
}

/// A split: fan the single selected input out into `num_outputs` equal self-owned
/// notes of one asset. The notes are minted to the sender and encoded into one
/// [`Split`] bundle ciphertext (slot 0), not into per-recipient slots. The
/// [`Split`] bundle carries a single `asset_amount`, so every output note holds
/// exactly `per_output_amount`; uneven splits are not representable.
struct SplitIntent {
    asset: Address,
    num_outputs: u8,
    per_output_amount: u64,
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

struct Withdrawal {
    asset: Address,
    amount: u64,
    target: WithdrawalTarget,
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

pub struct Transaction {
    owner: ShieldedAddress,
    inputs: Vec<SpendUtxo>,
    recipients: Vec<Recipient>,
    /// Fully specified recipient outputs that bind zone/program data. Unlike
    /// [`Recipient`] (which carries only address/asset/amount), these are minted
    /// verbatim, so the caller controls `data` and the zone/program ids.
    custom_outputs: Vec<OutputUtxo>,
    withdrawal: Option<Withdrawal>,
    split: Option<SplitIntent>,
    payer_pubkey_hash: [u8; 32],
    blinding_seed: [u8; BLINDING_LEN],
    shape: Option<Shape>,
    expiry_unix_ts: u64,
}

impl Transaction {
    pub fn new(owner: ShieldedAddress, inputs: Vec<SpendUtxo>, payer: Address) -> Self {
        Self {
            owner,
            inputs,
            recipients: Vec::new(),
            custom_outputs: Vec::new(),
            withdrawal: None,
            split: None,
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

    /// Record a split of the single selected input into `num_outputs` equal
    /// self-owned notes of `asset`, each holding `per_output_amount`. A split
    /// conserves value and has no change output, so
    /// `num_outputs * per_output_amount` must equal the selected input's balance
    /// for that asset (checked in [`Self::prepare_split`]). The [`Split`] bundle
    /// only carries one amount, so parts are necessarily equal. Splitting is
    /// mutually exclusive with `send`/`withdraw`.
    pub fn split(
        &mut self,
        asset: Address,
        num_outputs: u8,
        per_output_amount: u64,
    ) -> Result<&mut Self, TransactionError> {
        if num_outputs == 0 {
            return Err(TransactionError::SplitWithoutOutputs);
        }
        self.split = Some(SplitIntent {
            asset,
            num_outputs,
            per_output_amount,
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
        if self.split.is_some() {
            return self.sign_split(keypair, assets);
        }
        let mut signed = self.assemble(keypair, assets)?;
        if keypair.curve()? == SignatureType::P256 {
            let message_hash = signed.message_hash()?;
            signed.p256_owner = Some(keypair.sign(&message_hash));
        }
        Ok(signed)
    }

    /// Keypair rail for a split: prepare the self-owned outputs, encode the single
    /// [`Split`] bundle with the owner's viewing key, and sign in place.
    fn sign_split<K: ShieldedKeypairTrait + ViewingKeyTrait>(
        self,
        keypair: &K,
        assets: &AssetRegistry,
    ) -> Result<SignedTransaction, TransactionError> {
        let prepared = self.prepare_split(assets)?;
        let tx = keypair.get_transaction_viewing_key(&prepared.first_nullifier)?;
        let salt = zolana_keypair::random_salt();
        let tx_viewing_pk = tx.pubkey();
        let slot = prepared.encode_bundle(assets, &tx, keypair.viewing_pubkey(), salt, 0)?;
        let mut signed = prepared.finalize(tx_viewing_pk, salt, slot, assets)?;
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

    /// Public authority-rail entry: prepare the split's self-owned outputs and the
    /// data a [`crate::serialization::split::Split`] bundle needs to encode. The
    /// caller encodes the bundle through a `WalletAuthority` (which owns the
    /// viewing key) and then calls [`PreparedSplit::finalize`].
    pub fn prepare_split(self, assets: &AssetRegistry) -> Result<PreparedSplit, TransactionError> {
        let intent = self
            .split
            .as_ref()
            .ok_or(TransactionError::SplitWithoutOutputs)?;
        if self.inputs.len() != 1 {
            return Err(TransactionError::SplitInputCount(self.inputs.len()));
        }
        let num_outputs = intent.num_outputs;
        let shape = canonical_split_shape(usize::from(num_outputs))?;

        let input = &self.inputs[0].utxo;
        let requested = u64::from(num_outputs)
            .checked_mul(intent.per_output_amount)
            .ok_or(TransactionError::SelectedBalanceOverflow)?;
        let available = self.input_sum(&intent.asset);
        if input.asset != intent.asset || i128::from(requested) != available {
            return Err(TransactionError::SplitAmountMismatch {
                requested,
                available: available.max(0) as u64,
            });
        }

        let asset_id = self.asset_id(assets, &intent.asset)?;
        let outputs = (0..num_outputs)
            .map(|position| OutputUtxo {
                owner_address: Some(self.owner),
                asset: intent.asset,
                amount: intent.per_output_amount,
                blinding: derive_blinding(&self.blinding_seed, position),
                ..Default::default()
            })
            .collect::<Vec<_>>();

        let first_nullifier = self.first_nullifier()?;
        Ok(PreparedSplit {
            inputs: self.inputs,
            outputs,
            owner: self.owner,
            asset_id,
            num_outputs,
            blinding_seed: self.blinding_seed,
            first_nullifier,
            shape,
            payer_pubkey_hash: self.payer_pubkey_hash,
            expiry_unix_ts: self.expiry_unix_ts,
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
    /// Committed hash of the first REAL output note this transaction appends to
    /// the state tree, in output order: a recipient output for a transfer, the
    /// change output for a withdrawal. Callers use it as an "is it indexed yet?"
    /// probe (a returned merkle proof for the hash means the tx is indexed),
    /// which is stable under a shared view tag that has more than a page of
    /// outputs. Falls back to the first output when every output is a dummy
    /// (e.g. a full-balance withdrawal with no change); every committed hash is
    /// appended to the tree, so it remains a valid indexing probe.
    pub fn wait_output_hash(&self) -> Result<[u8; 32], TransactionError> {
        let output = self
            .outputs
            .iter()
            .find(|o| !o.is_dummy())
            .or_else(|| self.outputs.first())
            .ok_or(TransactionError::MissingOutput)?;
        output.hash()
    }

    pub fn finalize(
        self,
        tx_viewing_pk: P256Pubkey,
        salt: [u8; zolana_keypair::constants::SALT_LEN],
        slots: Vec<OutputCiphertext>,
        assets: &AssetRegistry,
    ) -> Result<SignedTransaction, TransactionError> {
        let PreparedTransaction {
            mut inputs,
            mut outputs,
            public_amounts,
            shape,
            max_recipients,
            payer_pubkey_hash,
            expiry_unix_ts,
            public_sol_amount,
            public_spl_amount,
            user_sol_account,
            user_spl_token,
            spl_token_interface,
            ..
        } = self;

        // Each padded recipient slot gets one random view tag, shared between its
        // dummy output (folded into the confidential proof's owner-tag chain) and
        // its dummy ciphertext, so the dummy is indistinguishable from a real
        // recipient and the proof's tag equals the published tag. The dummy outputs
        // (positions >= RECIPIENT_POSITION_BASE) align 1:1 with the dummy
        // ciphertexts (indices >= 1 + real recipient count).
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

        let mut output_utxo_hashes = Vec::with_capacity(outputs.len());
        for output in &outputs {
            output_utxo_hashes.push(output.hash()?);
        }

        let mut output_ciphertexts = slots;
        if output_ciphertexts.len() < 1 + max_recipients {
            let throwaway = zolana_keypair::ViewingKey::new();
            let dummy_len = dummy_ciphertext_len(&throwaway, throwaway.pubkey(), salt, assets)?;
            let mut tags = dummy_tags.iter();
            while output_ciphertexts.len() < 1 + max_recipients {
                // Reuse the aligned dummy output's tag; fall back to a fresh one only
                // if the arrays ever diverge in length.
                let view_tag = match tags.next() {
                    Some(tag) => *tag,
                    None => random_view_tag()?,
                };
                output_ciphertexts.push(OutputCiphertext {
                    view_tag,
                    data: random_dummy_ciphertext(dummy_len),
                });
            }
        }

        let external_data = ExternalData {
            instruction_discriminator: TRANSACT_DISCRIMINATOR,
            expiry_unix_ts,
            relayer_fee: 0,
            public_sol_amount,
            public_spl_amount,
            user_sol_account,
            user_spl_token,
            spl_token_interface,
            data_hash: None,
            zone_data_hash: None,
            tx_viewing_pk: *tx_viewing_pk.as_bytes(),
            salt,
            output_utxo_hashes,
            output_ciphertexts,
        };

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

/// A split prepared for encoding: the single real input, the `num_outputs`
/// self-owned output notes (already blinded from `blinding_seed`), and the bundle
/// metadata a [`Split`] ciphertext needs. Unlike a transfer there are no dummy
/// ciphertexts: one bundle at slot 0 carries every output note, so
/// `output_ciphertexts.len() == 1` and the program's `sender_slot_count` maps every
/// output position to the sender's own view tag.
pub struct PreparedSplit {
    pub inputs: Vec<SpendUtxo>,
    pub outputs: Vec<OutputUtxo>,
    pub owner: ShieldedAddress,
    pub asset_id: u64,
    pub num_outputs: u8,
    pub blinding_seed: [u8; BLINDING_LEN],
    pub first_nullifier: [u8; 32],
    pub shape: Shape,
    pub payer_pubkey_hash: [u8; 32],
    pub expiry_unix_ts: u64,
}

impl PreparedSplit {
    /// The `SplitBundlePlaintext` describing every self-owned output note. Its
    /// `into_utxos` reconstructs exactly `outputs` (same owner, asset, amount, and
    /// per-index blinding), so what `sync` decodes matches what the proof commits.
    pub fn bundle_plaintext(&self) -> SplitBundlePlaintext {
        SplitBundlePlaintext {
            owner_pubkey: self.owner.signing_pubkey,
            num_outputs: self.num_outputs,
            asset_id: self.asset_id,
            asset_amount: self.outputs.first().map(|o| o.amount).unwrap_or(0),
            blinding_seed: self.blinding_seed,
            data: Data::default(),
        }
    }

    /// Committed hash of one real self-split output note this transaction appends
    /// to the state tree (before dummy padding). Used as the "is it indexed yet?"
    /// wait probe. A split always has at least one real output.
    pub fn wait_output_hash(&self) -> Result<[u8; 32], TransactionError> {
        self.outputs
            .first()
            .ok_or(TransactionError::MissingOutput)?
            .hash()
    }

    /// The view tag the bundle ciphertext must carry: the owner's confidential
    /// view tag. The program derives every output owner's `pk_field` from this tag
    /// (`sender_slot_count == n_outputs`), matching each self-owned output's
    /// `owner_pk_field`.
    pub fn view_tag(&self) -> Result<[u8; VIEW_TAG_LEN], TransactionError> {
        Ok(self.owner.signing_pubkey.confidential_view_tag()?)
    }

    /// Keypair-rail bundle encode: seal the split plaintext into slot 0 with the
    /// caller's transaction viewing key.
    fn encode_bundle(
        &self,
        assets: &AssetRegistry,
        tx: &zolana_keypair::ViewingKey,
        recipient_pubkey: P256Pubkey,
        salt: [u8; zolana_keypair::constants::SALT_LEN],
        slot_index: u32,
    ) -> Result<OutputCiphertext, TransactionError> {
        let owner_cx = OwnerCx {
            owner: self.owner.signing_pubkey,
            assets,
            zone_program_id: None,
        };
        Split::encode(
            &self.output_utxos(assets)?,
            &owner_cx,
            self.view_tag()?,
            &SplitEncode {
                tx: tx.clone(),
                recipient_pubkey,
                salt,
                slot_index,
                blinding_seed: self.blinding_seed,
            },
        )
    }

    fn output_utxos(&self, assets: &AssetRegistry) -> Result<Vec<Utxo>, TransactionError> {
        self.bundle_plaintext().into_utxos(assets, None)
    }

    /// Fold the encoded bundle (slot 0) into a [`SignedTransaction`], padding to
    /// the proof shape. The bundle at ciphertext position 0 covers every real
    /// self-owned output; the shape is then filled to `shape.n_outputs` with
    /// commitment-only dummy outputs so the on-chain verifier selects the
    /// `{1, n_outputs}` verifying key from the EMITTED counts
    /// (`output_utxo_hashes.len()`), not the real count `N`.
    ///
    /// Dummy outputs and their aligned dummy ciphertexts mirror the
    /// confidential-transfer padding: each dummy output carries a random
    /// `owner_tag`, and each dummy ciphertext reuses that same tag. With
    /// `n_ciphertexts = 1 + (n_outputs - N)` the program's
    /// `sender_slot_count(n_outputs, n_ciphertexts) == N`, so output positions
    /// `0..N` map to the bundle (owner's view tag) and positions `N..n_outputs`
    /// each map to their own aligned dummy ciphertext — keeping the proof's
    /// `output_owner_pk_hashes` consistent with the program's reconstruction.
    pub fn finalize(
        self,
        tx_viewing_pk: P256Pubkey,
        salt: [u8; zolana_keypair::constants::SALT_LEN],
        bundle: OutputCiphertext,
        assets: &AssetRegistry,
    ) -> Result<SignedTransaction, TransactionError> {
        let PreparedSplit {
            mut inputs,
            mut outputs,
            shape,
            payer_pubkey_hash,
            expiry_unix_ts,
            ..
        } = self;

        // Pad the real self-split outputs to the proof shape with commitment-only
        // dummies. Each dummy's random view tag is shared between its output (its
        // `owner_tag`) and its aligned ciphertext below, so the dummy is
        // indistinguishable from a real note and the proof's tag equals the
        // published tag.
        let dummy_count = shape.n_outputs.saturating_sub(outputs.len());
        let dummy_tags = (0..dummy_count)
            .map(|_| random_view_tag())
            .collect::<Result<Vec<_>, _>>()?;
        for tag in &dummy_tags {
            outputs.push(OutputUtxo {
                blinding: random_blinding(),
                owner_tag: Some(*tag),
                ..Default::default()
            });
        }
        // `{1, 8}` has one input, so no dummy inputs are pushed; kept for symmetry
        // with the shape if a wider split shape is ever added.
        while inputs.len() < shape.n_inputs {
            inputs.push(SpendUtxo::new_dummy());
        }

        let mut output_utxo_hashes = Vec::with_capacity(outputs.len());
        for output in &outputs {
            output_utxo_hashes.push(output.hash()?);
        }

        // One bundle ciphertext (slot 0) plus one aligned dummy ciphertext per
        // dummy output. This keeps `sender_slot_count == N`: the N real outputs
        // map to the bundle, each dummy output to its own tail ciphertext.
        let mut output_ciphertexts = Vec::with_capacity(1 + dummy_tags.len());
        output_ciphertexts.push(bundle);
        if !dummy_tags.is_empty() {
            let throwaway = zolana_keypair::ViewingKey::new();
            let dummy_len = dummy_ciphertext_len(&throwaway, throwaway.pubkey(), salt, assets)?;
            for tag in &dummy_tags {
                output_ciphertexts.push(OutputCiphertext {
                    view_tag: *tag,
                    data: random_dummy_ciphertext(dummy_len),
                });
            }
        }

        let external_data = ExternalData {
            instruction_discriminator: TRANSACT_DISCRIMINATOR,
            expiry_unix_ts,
            relayer_fee: 0,
            public_sol_amount: None,
            public_spl_amount: None,
            user_sol_account: Address::default(),
            user_spl_token: Address::default(),
            spl_token_interface: Address::default(),
            data_hash: None,
            zone_data_hash: None,
            tx_viewing_pk: *tx_viewing_pk.as_bytes(),
            salt,
            output_utxo_hashes,
            output_ciphertexts,
        };

        Ok(SignedTransaction {
            inputs,
            outputs,
            public_amounts: PublicAmounts {
                sol: [0u8; 32],
                spl: [0u8; 32],
                asset: [0u8; 32],
            },
            external_data,
            payer_pubkey_hash,
            shape,
            p256_owner: None,
        })
    }
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

/// The exact `OutputCiphertext::data` byte length of a real recipient slot, derived
/// by encoding a throwaway recipient through the same path. This keeps dummy slots
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
