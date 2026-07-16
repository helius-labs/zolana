use solana_address::Address;
use zolana_event::MessageData;
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{
    constants::{BLINDING_LEN, SALT_LEN, VIEW_TAG_LEN},
    hash::sha256_be,
    random_salt,
    shielded::ShieldedAddress,
    viewing_key::random_blinding,
    P256Pubkey, PublicKey, ShieldedKeypairTrait, SignatureType, ViewingKey, ViewingKeyTrait,
};

use super::{
    shape::{resolve_shape, Shape},
    slots::encode_confidential_slots,
    spp_proof_inputs::{first_nullifier, inputs_require_p256, SppProofInputs},
    ExternalData, SppProofOutputUtxo,
};
use crate::{
    data::Data,
    error::TransactionError,
    instructions::types::SppProofInputUtxo,
    serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        UtxoSerialization,
    },
    utxo::derive_blinding,
    AssetRegistry, SOL_ASSET_ID, SOL_MINT,
};

const SPL_CHANGE_POSITION: u8 = 0;
const SOL_CHANGE_POSITION: u8 = 1;
const RECIPIENT_POSITION_BASE: u8 = 2;

/// Fixed number of leading sender-owned output slots in a transfer: SPL change at
/// slot 0, SOL change at slot 1. Recipients always start at slot 2.
pub const SENDER_SLOT_COUNT: usize = 2;

pub struct PreparedTransfer {
    pub owner: ShieldedAddress,
    pub inputs: Vec<SppProofInputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    pub first_nullifier: [u8; 32],
    pub shape: Shape,
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

#[derive(Clone)]
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

pub struct ConfidentialTransfer {
    pub owner: ShieldedAddress,
    pub inputs: Vec<SppProofInputUtxo>,
    pub recipients: Vec<Recipient>,
    pub withdrawal: Option<Withdrawal>,
    pub payer_pubkey_hash: [u8; 32],
    pub blinding_seed: [u8; BLINDING_LEN],
    pub shape: Option<Shape>,
}

impl ConfidentialTransfer {
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
        let prepared = self.prepare()?;
        let transaction_viewing_key =
            keypair.get_transaction_viewing_key(&prepared.first_nullifier)?;
        let salt = random_salt();
        let tx_viewing_pk = transaction_viewing_key.pubkey();
        let slots =
            encode_confidential_slots(&prepared.outputs, assets, &transaction_viewing_key, salt)?;
        prepared.finalize(tx_viewing_pk, salt, slots)
    }

    pub fn prepare(self) -> Result<PreparedTransfer, TransactionError> {
        let spl_asset = self.spl_asset()?;
        let (public_sol, public_spl) = self.public_amounts();
        let sol_change = self.change(&SOL_MINT, public_sol)?;
        let spl_change = match spl_asset {
            Some(asset) => self.change(&asset, public_spl)?,
            None => 0,
        };

        let mut outputs = Vec::new();
        outputs.push(match spl_asset {
            Some(asset) if spl_change > 0 => SppProofOutputUtxo {
                owner_address: Some(self.owner),
                asset,
                amount: spl_change,
                blinding: derive_blinding(&self.blinding_seed, SPL_CHANGE_POSITION),
                ..Default::default()
            },
            _ => SppProofOutputUtxo {
                blinding: derive_blinding(&self.blinding_seed, SPL_CHANGE_POSITION),
                owner_tag: Some(self.owner.signing_pubkey.confidential_view_tag()?),
                ..Default::default()
            },
        });
        outputs.push(if sol_change > 0 {
            SppProofOutputUtxo {
                owner_address: Some(self.owner),
                asset: SOL_MINT,
                amount: sol_change,
                blinding: derive_blinding(&self.blinding_seed, SOL_CHANGE_POSITION),
                ..Default::default()
            }
        } else {
            SppProofOutputUtxo {
                blinding: derive_blinding(&self.blinding_seed, SOL_CHANGE_POSITION),
                owner_tag: Some(self.owner.signing_pubkey.confidential_view_tag()?),
                ..Default::default()
            }
        });

        for (i, recipient) in self.recipients.iter().enumerate() {
            let position = RECIPIENT_POSITION_BASE + i as u8;
            outputs.push(SppProofOutputUtxo {
                owner_address: Some(recipient.address),
                asset: recipient.asset,
                amount: recipient.amount,
                blinding: derive_blinding(&self.blinding_seed, position),
                ..Default::default()
            });
        }

        let shape = resolve_shape(self.shape, self.inputs.len(), outputs.len())?;
        let first_nullifier = first_nullifier(&self.inputs)?;
        let (user_sol_account, user_spl_token, spl_token_interface) = self.external_accounts();

        Ok(PreparedTransfer {
            owner: self.owner,
            inputs: self.inputs,
            outputs,
            first_nullifier,
            shape,
            payer_pubkey_hash: self.payer_pubkey_hash,
            public_sol_amount: (public_sol != 0).then_some(public_sol as i64),
            public_spl_amount: (public_spl != 0).then_some(public_spl as i64),
            user_sol_account,
            user_spl_token,
            spl_token_interface,
        })
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
        salt: [u8; SALT_LEN],
        slots: Vec<Option<MessageData>>,
    ) -> Result<SppProofInputs, TransactionError> {
        let PreparedTransfer {
            owner,
            mut inputs,
            mut outputs,
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
            sender_owner_tag(&owner.signing_pubkey, &payer_pubkey_hash)?;

        // Each padded slot gets one random view tag, shared between its dummy
        // output (folded into the proof's owner-tag chain) and its dummy
        // ciphertext, so the dummy is indistinguishable from a real recipient.
        let dummy_recipient_count = shape.n_outputs().saturating_sub(outputs.len());
        let dummy_tags = (0..dummy_recipient_count)
            .map(|_| random_view_tag())
            .collect::<Result<Vec<_>, _>>()?;
        for tag in &dummy_tags {
            outputs.push(SppProofOutputUtxo {
                blinding: random_blinding(),
                owner_tag: Some(*tag),
                ..Default::default()
            });
        }
        while inputs.len() < shape.n_inputs() {
            inputs.push(SppProofInputUtxo::new_dummy());
        }

        // Length-matched random ciphertext for every position without a real
        // encoding: padded slots and zero-value change slots.
        let dummy_len = if slots.iter().any(|slot| slot.is_none()) || dummy_recipient_count > 0 {
            let throwaway = ViewingKey::new();
            dummy_ciphertext_len(&throwaway, throwaway.pubkey(), salt)?
        } else {
            0
        };

        // 1:1 output assembly. Every published slot carries its own ciphertext.
        // Change positions keep the compact sender tag; recipient positions take
        // the inline tag of their ciphertext; padded/zero positions carry a
        // length-matched random ciphertext under their padded tag.
        let mut transact_outputs = Vec::with_capacity(outputs.len());
        let mut resolved_owner_tags = Vec::with_capacity(outputs.len());
        for (position, output) in outputs.iter().enumerate() {
            let utxo_hash = output.hash()?;
            let slot = slots.get(position).and_then(|slot| slot.as_ref());
            let (owner_tag, resolved, data) = if position < SENDER_SLOT_COUNT {
                let data = match slot {
                    Some(output_data) => output_data.data.clone(),
                    None => random_dummy_ciphertext(dummy_len),
                };
                (sender_tag, sender_resolved, data)
            } else {
                match slot {
                    Some(output_data) => (
                        OwnerTag::Inline(output_data.view_tag),
                        output_data.view_tag,
                        output_data.data.clone(),
                    ),
                    None => {
                        let tag = output.owner_tag.ok_or(TransactionError::MissingOutput)?;
                        (
                            OwnerTag::Inline(tag),
                            tag,
                            random_dummy_ciphertext(dummy_len),
                        )
                    }
                }
            };
            transact_outputs.push(TransactOutput {
                utxo_hash,
                owner_tag,
                data: Some(data),
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

/// The exact ciphertext byte length of a real confidential slot, derived by
/// encoding a throwaway output through the same path. This keeps dummy slots
/// byte-length-indistinguishable from real ones without pinning a brittle constant.
fn dummy_ciphertext_len(
    tx: &ViewingKey,
    throwaway_pubkey: P256Pubkey,
    salt: [u8; SALT_LEN],
) -> Result<usize, TransactionError> {
    let output_data = Confidential::encode_plaintext(
        &ConfidentialOutputPlaintext {
            asset_id: SOL_ASSET_ID,
            amount: 0,
            blinding: random_blinding(),
            zone_program_id: None,
            data: Data::default(),
        },
        [0u8; VIEW_TAG_LEN],
        &ConfidentialEncode {
            tx: tx.clone(),
            recipient_pubkey: throwaway_pubkey,
            salt,
            slot_index: 0,
        },
    )?;
    Ok(output_data.data.len())
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
