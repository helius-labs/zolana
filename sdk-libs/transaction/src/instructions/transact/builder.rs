use solana_address::Address;
use zolana_interface::instruction::instruction_data::transact::OutputCiphertext;
use zolana_keypair::constants::{BLINDING_LEN, VIEW_TAG_LEN};
use zolana_keypair::hash::sha256_be;
use zolana_keypair::shielded::ShieldedAddress;
use zolana_keypair::viewing_key::{random_blinding, ViewTag};
use zolana_keypair::{P256Pubkey, PublicKey, ShieldedKeypairTrait, SignatureType, ViewingKeyTrait};

use crate::data::Data;
use crate::error::TransactionError;
use crate::instructions::types::SpendUtxo;
use crate::serialization::confidential::{
    ConfidentialRecipient, ConfidentialRecipientEncode, ConfidentialSenderBundle,
    ConfidentialSenderEncode,
};
use crate::serialization::{OwnerCx, UtxoSerialization};
use crate::utxo::{derive_blinding, Utxo};
use crate::{AssetRegistry, SOL_MINT};

use super::signed_transaction::{asset_field, signed_to_field, PublicAmounts, SignedTransaction};
use super::{ExternalData, OutputUtxo};

const TRANSACT_DISCRIMINATOR: u8 = 0;
const SPL_CHANGE_POSITION: u8 = 0;
const SOL_CHANGE_POSITION: u8 = 1;
const RECIPIENT_POSITION_BASE: u8 = 2;

/// Fixed number of leading sender-owned output slots in a transfer: SPL change at
/// slot 0 (and the sender bundle ciphertext), SOL change at slot 1. Recipients
/// always start at slot 2.
const SENDER_SLOT_COUNT: usize = 2;

pub const SUPPORTED_SHAPES: [Shape; 1] = [Shape::new(2, 3)];

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
    view_tag: ViewTag,
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
            withdrawal: None,
            payer_pubkey_hash: sha256_be(payer.as_array()),
            blinding_seed: random_blinding(),
            shape: None,
            // Never expires by default; the program rejects `current_ts > expiry`,
            // so callers that want a relayer deadline set it explicitly.
            expiry_unix_ts: u64::MAX,
        }
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
        view_tag: ViewTag,
    ) -> Result<&mut Self, TransactionError> {
        self.recipients.push(Recipient {
            address: *recipient,
            asset,
            amount,
            view_tag,
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

    pub fn sign<K>(
        self,
        keypair: &K,
        assets: &AssetRegistry,
        sender_view_tag: ViewTag,
    ) -> Result<SignedTransaction, TransactionError>
    where
        K: ShieldedKeypairTrait + ViewingKeyTrait,
    {
        let mut assembled_transaction = self.assemble(keypair, assets, sender_view_tag)?;
        if keypair.curve()? == SignatureType::P256 {
            let message_hash = assembled_transaction.message_hash()?;
            let signature = keypair.sign(&message_hash);
            assembled_transaction.p256_owner = Some(signature);
        }
        Ok(assembled_transaction)
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
        let leftover = self.input_sum(asset) + public - self.recipient_sum(asset);
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
            &spend.program_data_hash.unwrap_or([0u8; 32]),
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

    fn assemble<K>(
        self,
        keypair: &K,
        assets: &AssetRegistry,
        sender_view_tag: ViewTag,
    ) -> Result<SignedTransaction, TransactionError>
    where
        K: ShieldedKeypairTrait + ViewingKeyTrait,
    {
        let owner_hash = self.owner.owner_hash()?;
        let spl_asset = self.spl_asset()?;
        let (public_sol, public_spl) = self.public_amounts();
        let sol_change = self.change(&SOL_MINT, public_sol)?;
        let spl_change = match spl_asset {
            Some(asset) => self.change(&asset, public_spl)?,
            None => 0,
        };

        // Output positions are fixed so every party can locate slots without
        // decrypting the sender bundle: slot 0 is the sender's SPL change, slot 1
        // the SOL change, and recipients follow at slot 2+. Absent change is an
        // empty (owner = 0) UTXO whose blinding still derives from its position, so
        // the sender bundle ciphertext on slot 0 stays fixed-size.
        let mut outputs = Vec::new();
        outputs.push(match spl_asset {
            Some(asset) if spl_change > 0 => OutputUtxo {
                owner_hash,
                asset,
                amount: spl_change,
                blinding: derive_blinding(&self.blinding_seed, SPL_CHANGE_POSITION),
                ..Default::default()
            },
            _ => OutputUtxo {
                blinding: derive_blinding(&self.blinding_seed, SPL_CHANGE_POSITION),
                ..Default::default()
            },
        });
        outputs.push(if sol_change > 0 {
            OutputUtxo {
                owner_hash,
                asset: SOL_MINT,
                amount: sol_change,
                blinding: derive_blinding(&self.blinding_seed, SOL_CHANGE_POSITION),
                ..Default::default()
            }
        } else {
            OutputUtxo {
                blinding: derive_blinding(&self.blinding_seed, SOL_CHANGE_POSITION),
                ..Default::default()
            }
        });

        let sender_viewing_pubkey = keypair.viewing_pubkey();
        let signing_pubkey = keypair.signing_pubkey();
        let zone_program_id: Option<Address> = None;

        let mut recipient_outputs: Vec<(ViewTag, Utxo, P256Pubkey, u8)> =
            Vec::with_capacity(self.recipients.len());
        let mut recipient_viewing_pks = Vec::with_capacity(self.recipients.len());
        for (i, recipient) in self.recipients.iter().enumerate() {
            let position = RECIPIENT_POSITION_BASE + i as u8;
            let blinding = derive_blinding(&self.blinding_seed, position);
            outputs.push(OutputUtxo {
                owner_hash: recipient.address.owner_hash()?,
                asset: recipient.asset,
                amount: recipient.amount,
                blinding,
                ..Default::default()
            });
            recipient_viewing_pks.push(recipient.address.viewing_pubkey);
            recipient_outputs.push((
                recipient.view_tag,
                Utxo {
                    owner: recipient.address.signing_pubkey,
                    asset: recipient.asset,
                    amount: recipient.amount,
                    blinding,
                    zone_program_id: None,
                    data: Data::default(),
                },
                recipient.address.viewing_pubkey,
                position,
            ));
        }

        let shape = resolve_shape(self.shape, self.inputs.len(), outputs.len())?;
        let max_recipients = shape
            .n_outputs
            .checked_sub(SENDER_SLOT_COUNT)
            .ok_or(TransactionError::MissingOutput)?;
        // Pad recipient_viewing_pks to MAX_RECIPIENTS with a throwaway pubkey (the
        // sender's own viewing key) so the encrypted sender bundle is fixed-size and
        // does not reveal the real recipient count. A dummy slot's trial-decrypt
        // fails on its random bytes regardless of this pubkey.
        while recipient_viewing_pks.len() < max_recipients {
            recipient_viewing_pks.push(sender_viewing_pubkey);
        }

        let first_nullifier = self.first_nullifier()?;
        let salt = zolana_keypair::random_salt();
        let tx = keypair.get_transaction_viewing_key(&first_nullifier)?;
        let tx_viewing_pk = tx.pubkey();

        // Sender change bundle: the SPL and SOL change UTXOs owned by the sender, at
        // ciphertext slot 0. Empty change is conveyed by a zero-amount UTXO.
        let mut change_utxos = Vec::with_capacity(SENDER_SLOT_COUNT);
        if let Some(asset) = spl_asset {
            change_utxos.push(Utxo {
                owner: signing_pubkey,
                asset,
                amount: spl_change,
                blinding: derive_blinding(&self.blinding_seed, SPL_CHANGE_POSITION),
                zone_program_id: None,
                data: Data::default(),
            });
        }
        change_utxos.push(Utxo {
            owner: signing_pubkey,
            asset: SOL_MINT,
            amount: sol_change,
            blinding: derive_blinding(&self.blinding_seed, SOL_CHANGE_POSITION),
            zone_program_id: None,
            data: Data::default(),
        });

        let sender_owner_cx = OwnerCx {
            owner: signing_pubkey,
            assets,
            zone_program_id,
        };
        let sender_ciphertext = ConfidentialSenderBundle::encode(
            &change_utxos,
            &sender_owner_cx,
            sender_view_tag,
            &ConfidentialSenderEncode {
                tx: tx.clone(),
                self_pubkey: sender_viewing_pubkey,
                salt,
                slot_index: 0,
                blinding_seed: self.blinding_seed,
                recipient_viewing_pks,
            },
        )?;

        let mut output_ciphertexts = Vec::with_capacity(1 + max_recipients);
        output_ciphertexts.push(sender_ciphertext);

        for (view_tag, utxo, recipient_pubkey, position) in &recipient_outputs {
            let slot_index = u32::from(*position) - SENDER_SLOT_COUNT as u32 + 1;
            let recipient_owner_cx = OwnerCx {
                owner: utxo.owner,
                assets,
                zone_program_id,
            };
            let ciphertext = ConfidentialRecipient::encode(
                core::slice::from_ref(utxo),
                &recipient_owner_cx,
                *view_tag,
                &ConfidentialRecipientEncode {
                    tx: tx.clone(),
                    recipient_pubkey: *recipient_pubkey,
                    salt,
                    slot_index,
                },
            )?;
            output_ciphertexts.push(ciphertext);
        }

        // Fill the remaining slots with random L-byte dummies under same-distribution
        // view tags so the recipient count is hidden. A real recipient ciphertext is
        // indistinguishable from random to an observer, so a same-length random filler
        // hides whether the slot holds a real recipient. The filler length is derived
        // from the real recipient ciphertext layout by encoding a throwaway recipient.
        let dummy_len = dummy_ciphertext_len(&tx, sender_viewing_pubkey, salt, assets)?;
        while output_ciphertexts.len() < 1 + max_recipients {
            output_ciphertexts.push(OutputCiphertext {
                view_tag: random_view_tag(),
                data: random_dummy_ciphertext(dummy_len),
            });
        }

        let (user_sol_account, user_spl_token, spl_token_interface) = self.external_accounts();

        // Pad to the fixed proof shape here, before signing, so the dummy output
        // hashes are part of the signed external data. A dummy output has
        // `owner_hash = 0` (random blinding) and is never a recipient; empty SOL/SPL
        // change slots are dummies in the same sense (owner = 0, no value).
        while outputs.len() < shape.n_outputs {
            outputs.push(OutputUtxo {
                blinding: random_blinding(),
                ..Default::default()
            });
        }

        let mut inputs = self.inputs;
        while inputs.len() < shape.n_inputs {
            inputs.push(SpendUtxo::new_dummy());
        }

        // All output commitments in tree-append order.
        let mut output_utxo_hashes = Vec::with_capacity(outputs.len());
        for output in &outputs {
            output_utxo_hashes.push(output.hash()?);
        }

        let external_data = ExternalData {
            instruction_discriminator: TRANSACT_DISCRIMINATOR,
            expiry_unix_ts: self.expiry_unix_ts,
            relayer_fee: 0,
            public_sol_amount: (public_sol != 0).then_some(public_sol as i64),
            public_spl_amount: (public_spl != 0).then_some(public_spl as i64),
            user_sol_account,
            user_spl_token,
            spl_token_interface,
            cpi_signer: None,
            tx_viewing_pk: *tx_viewing_pk.as_bytes(),
            salt,
            output_utxo_hashes,
            output_ciphertexts,
        };

        let public_amounts = PublicAmounts {
            sol: signed_to_field(public_sol),
            spl: signed_to_field(public_spl),
            asset: match (public_spl != 0, spl_asset) {
                (true, Some(asset)) => asset_field(&asset)?,
                _ => [0u8; 32],
            },
        };

        Ok(SignedTransaction {
            inputs,
            outputs,
            public_amounts,
            external_data,
            payer_pubkey_hash: self.payer_pubkey_hash,
            shape,
            p256_owner: None,
        })
    }
}

/// A view tag for a dummy output slot, drawn from the same byte distribution as a
/// derived one: byte 0 is `0` (derived tags right-align a 31-byte value into 32
/// bytes), bytes `1..32` random. A uniformly random tag would have a nonzero
/// leading byte 255/256 of the time and mark the slot as a dummy, leaking the
/// recipient count.
fn random_view_tag() -> [u8; VIEW_TAG_LEN] {
    let mut tag = [0u8; VIEW_TAG_LEN];
    tag[1..].copy_from_slice(&random_blinding());
    tag
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
