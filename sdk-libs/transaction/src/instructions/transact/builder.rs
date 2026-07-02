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
    wallet::Wallet,
    serialization::{
        confidential::{
            ConfidentialRecipient, ConfidentialRecipientEncode, ConfidentialSenderBundle,
            ConfidentialSenderEncode, TransferRecipientPlaintext, TransferSenderPlaintext,
        },
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

pub const SUPPORTED_SHAPES: [Shape; 1] = [Shape::new(2, 3)];

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
            payer_pubkey_hash: sha256_be(payer.as_array()),
            blinding_seed: random_blinding(),
            shape: None,
            // Never expires by default; the program rejects `current_ts > expiry`,
            // so callers that want a relayer deadline set it explicitly.
            expiry_unix_ts: u64::MAX,
        }
    }

    /// Build a transaction spending `inputs` from `wallet`, paid by `payer`.
    ///
    /// Wraps [`Self::new`]: the spend inputs are derived from the wallet's
    /// nullifier key and the owner is the wallet's shielded address. Use this
    /// instead of hand-assembling `SpendUtxo`s when you already hold a `Wallet`.
    pub fn from_wallet(
        wallet: &Wallet,
        inputs: &[Utxo],
        payer: Address,
    ) -> Result<Self, TransactionError> {
        let spends = inputs
            .iter()
            .map(|utxo| SpendUtxo::from_keypair(utxo.clone(), &wallet.keypair))
            .collect();
        Ok(Self::new(wallet.keypair.shielded_address()?, spends, payer))
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

#[cfg(test)]
mod from_wallet_tests {
    use zolana_keypair::ShieldedKeypair;

    use super::*;
    use crate::{AssetRegistry, SOL_MINT};

    fn sample_utxo(keypair: &ShieldedKeypair, amount: u64) -> Utxo {
        Utxo {
            owner: keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount,
            blinding: [7u8; BLINDING_LEN],
            zone_program_id: None,
            data: Data::default(),
        }
    }

    #[test]
    fn from_wallet_builds_tx_over_wallet_inputs() {
        let wallet = Wallet::new(ShieldedKeypair::new().unwrap(), AssetRegistry::default()).unwrap();
        let payer = Address::new_from_array([9u8; 32]);
        let inputs = vec![sample_utxo(&wallet.keypair, 100), sample_utxo(&wallet.keypair, 50)];

        let tx = Transaction::from_wallet(&wallet, &inputs, payer).expect("from_wallet");

        assert_eq!(tx.inputs.len(), 2, "one spend per input");
        assert_eq!(tx.owner, wallet.keypair.shielded_address().unwrap());
        assert_eq!(tx.payer_pubkey_hash, sha256_be(payer.as_array()));
    }
}
