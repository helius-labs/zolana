use solana_address::Address;
use zolana_event::OutputData;
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{
    constants::{BLINDING_LEN, VIEW_TAG_LEN},
    hash::sha256_be,
    shielded::ShieldedAddress,
    viewing_key::{random_blinding, ViewTag},
    P256Pubkey, PublicKey, ShieldedKeypairTrait, SignatureType, ViewingKeyTrait,
};

use super::{
    shape::Shape,
    spp_proof_inputs::{first_nullifier, inputs_require_p256, SppProofInputs},
    ExternalData, OutputUtxo,
};
use crate::{
    data::Data,
    error::TransactionError,
    instructions::types::SppProofInputUtxo,
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

const SPL_CHANGE_POSITION: u8 = 0;
const SOL_CHANGE_POSITION: u8 = 1;
const RECIPIENT_POSITION_BASE: u8 = 2;

/// Fixed number of leading sender-owned output slots in a transfer: SPL change at
/// slot 0 (and the sender bundle ciphertext), SOL change at slot 1. Recipients
/// always start at slot 2.
pub const SENDER_SLOT_COUNT: usize = 2;

pub struct PreparedRecipient {
    pub view_tag: ViewTag,
    pub recipient_pubkey: P256Pubkey,
    pub plaintext: TransferRecipientPlaintext,
}

pub struct PreparedTransfer {
    pub inputs: Vec<SppProofInputUtxo>,
    pub outputs: Vec<OutputUtxo>,
    pub sender_plaintext: TransferSenderPlaintext,
    pub recipients: Vec<PreparedRecipient>,
    pub first_nullifier: [u8; 32],
    pub shape: Shape,
    pub max_recipients: usize,
    pub payer_pubkey_hash: [u8; 32],
    pub public_sol_amount: Option<i64>,
    pub public_spl_amount: Option<i64>,
    pub user_sol_account: Address,
    pub user_spl_token: Address,
    pub spl_token_interface: Address,
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

/// Transfers always pad to [`Shape::IN2_OUT3`] so every transfer has the same
/// input/output count and its structure is not observable. The SPP prover
/// supports more shapes ([`SPP_SUPPORTED_SHAPES`](super::shape::SPP_SUPPORTED_SHAPES));
/// this fixed shape is the privacy-preserving subset used for padded transfers.
pub fn canonical_shape(n_in: usize, n_out: usize) -> Result<Shape, TransactionError> {
    let shape = Shape::IN2_OUT3;
    if n_in <= shape.n_inputs() && n_out <= shape.n_outputs() {
        Ok(shape)
    } else {
        Err(TransactionError::UnsupportedShape { n_in, n_out })
    }
}

pub fn resolve_shape(
    declared: Option<Shape>,
    n_in: usize,
    n_out: usize,
) -> Result<Shape, TransactionError> {
    match declared {
        Some(shape) => {
            if shape != Shape::IN2_OUT3 {
                return Err(TransactionError::UnsupportedShape {
                    n_in: shape.n_inputs(),
                    n_out: shape.n_outputs(),
                });
            }
            if n_in > shape.n_inputs() {
                return Err(TransactionError::TooManyInputs {
                    got: n_in,
                    max: shape.n_inputs(),
                });
            }
            if n_out > shape.n_outputs() {
                return Err(TransactionError::TooManyOutputsForShape {
                    got: n_out,
                    max: shape.n_outputs(),
                });
            }
            Ok(shape)
        }
        None => canonical_shape(n_in, n_out),
    }
}

pub struct Transfer {
    pub owner: ShieldedAddress,
    pub inputs: Vec<SppProofInputUtxo>,
    pub recipients: Vec<Recipient>,
    pub withdrawal: Option<Withdrawal>,
    pub payer_pubkey_hash: [u8; 32],
    pub blinding_seed: [u8; BLINDING_LEN],
    pub shape: Option<Shape>,
}

impl Transfer {
    pub fn new(owner: ShieldedAddress, inputs: Vec<SppProofInputUtxo>, payer: Address) -> Self {
        Self {
            owner,
            inputs,
            recipients: Vec::new(),
            withdrawal: None,
            payer_pubkey_hash: sha256_be(payer.as_array()),
            blinding_seed: random_blinding(),
            shape: None,
        }
    }

    pub fn with_shape(mut self, shape: Shape) -> Self {
        self.shape = Some(shape);
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
    /// [`PreparedTransfer::finalize`], with encryption/signing delegated to a
    /// `WalletAuthority`.
    pub fn sign<K: ShieldedKeypairTrait + ViewingKeyTrait>(
        self,
        keypair: &K,
        assets: &AssetRegistry,
    ) -> Result<SppProofInputs, TransactionError> {
        let mut signed = self.assemble(keypair, assets)?;
        if keypair.curve()? == SignatureType::P256 {
            signed.sign_p256(keypair)?;
        }
        Ok(signed)
    }

    fn assemble<K: ShieldedKeypairTrait + ViewingKeyTrait>(
        self,
        keypair: &K,
        assets: &AssetRegistry,
    ) -> Result<SppProofInputs, TransactionError> {
        let prepared = self.prepare(assets)?;
        let transaction_viewing_key =
            keypair.get_transaction_viewing_key(&prepared.first_nullifier)?;
        let salt = zolana_keypair::random_salt();
        let tx_viewing_pk = transaction_viewing_key.pubkey();

        let sender_view_tag = prepared
            .sender_plaintext
            .owner_pubkey
            .confidential_view_tag()?;
        let mut slots = Vec::with_capacity(1 + prepared.recipients.len());
        slots.push(ConfidentialSenderBundle::encode_plaintext(
            &prepared.sender_plaintext,
            sender_view_tag,
            &ConfidentialSenderEncode {
                tx: transaction_viewing_key.clone(),
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
                    tx: transaction_viewing_key.clone(),
                    recipient_pubkey: recipient.recipient_pubkey,
                    salt,
                    slot_index: (i + 1) as u32,
                },
            )?);
        }

        prepared.finalize(tx_viewing_pk, salt, slots, assets)
    }

    pub fn prepare(self, assets: &AssetRegistry) -> Result<PreparedTransfer, TransactionError> {
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

        let shape = resolve_shape(self.shape, self.inputs.len(), outputs.len())?;
        let max_recipients = shape
            .n_outputs()
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

        let first_nullifier = first_nullifier(&self.inputs)?;
        let (user_sol_account, user_spl_token, spl_token_interface) = self.external_accounts();

        Ok(PreparedTransfer {
            inputs: self.inputs,
            outputs,
            sender_plaintext,
            recipients,
            first_nullifier,
            shape,
            max_recipients,
            payer_pubkey_hash: self.payer_pubkey_hash,
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

    fn change(&self, asset: &Address, public: i128) -> Result<u64, TransactionError> {
        let leftover = self
            .input_sum(asset)
            .checked_add(public)
            .and_then(|v| v.checked_sub(self.recipient_sum(asset)))
            .ok_or(TransactionError::SelectedBalanceOverflow)?;
        if leftover < 0 {
            return Err(TransactionError::InsufficientBalance {
                requested: (-leftover) as u64,
                available: 0,
            });
        }
        Ok(leftover as u64)
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

impl PreparedTransfer {
    pub fn finalize(
        self,
        tx_viewing_pk: P256Pubkey,
        salt: [u8; zolana_keypair::constants::SALT_LEN],
        slots: Vec<OutputData>,
        assets: &AssetRegistry,
    ) -> Result<SppProofInputs, TransactionError> {
        let PreparedTransfer {
            mut inputs,
            mut outputs,
            sender_plaintext,
            shape,
            payer_pubkey_hash,
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
        let dummy_recipient_count = shape.n_outputs().saturating_sub(outputs.len());
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
        while inputs.len() < shape.n_inputs() {
            inputs.push(SppProofInputUtxo::new_dummy());
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
        );
        if let Some(amount) = public_sol_amount {
            external_data = external_data.with_public_sol(amount, user_sol_account)?;
        }
        if let Some(amount) = public_spl_amount {
            external_data =
                external_data.with_public_spl(amount, user_spl_token, spl_token_interface)?;
        }

        Ok(SppProofInputs {
            input_utxos: inputs,
            output_utxos: outputs,
            external_data,
            payer_pubkey_hash,
            p256_signature: None,
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
