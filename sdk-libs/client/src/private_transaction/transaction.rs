use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey as EcdsaSigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use solana_address::Address;
use zolana_interface::event::OutputUtxo as OutputSlot;
use zolana_keypair::constants::{BLINDING_LEN, P256_PUBKEY_LEN};
use zolana_keypair::hash::sha256_be;
use zolana_keypair::shielded::{ShieldedAddress, ShieldedKeypair};
use zolana_keypair::viewing_key::ViewTag;
use zolana_keypair::{NullifierKey, P256Pubkey, SignatureType};
use zolana_transaction::asset::{AssetRegistry, SOL_ASSET_ID};
use zolana_transaction::transfer::{
    RecipientOutput, TransferRecipientPlaintext, TransferSenderPlaintext, SENDER_SLOT_COUNT,
};
use zolana_transaction::utxo::derive_blinding;
use zolana_transaction::{Data, ExternalData, OutputUtxo, TransactionEncryption, Utxo, SOL_MINT};

use crate::error::ClientError;
use crate::private_transaction::field::{asset_field, signed_to_field};
use crate::private_transaction::signed_transaction::SignedTransaction;
use crate::prover::shape::{resolve_shape, Shape};
use crate::prover::transfer::TransferProver;
use crate::prover::transfer_p256::{P256Owner, PublicAmounts, TransferP256Prover};
use crate::rpc::{NullifierNonInclusionProof, StateInclusionProof};

const TRANSACT_DISCRIMINATOR: u8 = 0;
const SPL_CHANGE_POSITION: u8 = 0;
const SOL_CHANGE_POSITION: u8 = 1;
const RECIPIENT_POSITION_BASE: u8 = 2;

pub struct SpendUtxo {
    pub utxo: Utxo,
    pub nullifier_key: NullifierKey,
    pub zone_data_hash: Option<[u8; 32]>,
    pub program_data_hash: Option<[u8; 32]>,
}

impl From<(Utxo, &ShieldedKeypair)> for SpendUtxo {
    fn from((utxo, keypair): (Utxo, &ShieldedKeypair)) -> Self {
        Self {
            utxo,
            nullifier_key: NullifierKey::from_secret(*keypair.nullifier_key.secret()),
            zone_data_hash: None,
            program_data_hash: None,
        }
    }
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

pub struct InputCommitment {
    pub index: usize,
    pub utxo_hash: [u8; 32],
    pub nullifier: [u8; 32],
}

pub struct SpendProof {
    pub state: StateInclusionProof,
    pub nullifier: NullifierNonInclusionProof,
}

pub enum CircuitType {
    P256(TransferP256Prover),
    Eddsa(TransferProver),
}

pub(crate) fn inputs_require_p256(inputs: &[SpendUtxo]) -> Result<bool, ClientError> {
    for spend in inputs {
        if spend.utxo.owner.signature_type()? == SignatureType::P256 {
            return Ok(true);
        }
    }
    Ok(false)
}

pub struct Transaction {
    owner: ShieldedAddress,
    inputs: Vec<SpendUtxo>,
    recipients: Vec<Recipient>,
    withdrawal: Option<Withdrawal>,
    payer_pubkey_hash: [u8; 32],
    blinding_seed: [u8; BLINDING_LEN],
    shape: Option<Shape>,
}

impl Transaction {
    pub fn new(owner: ShieldedAddress, inputs: Vec<SpendUtxo>, payer: Address) -> Self {
        let mut blinding_seed = [0u8; BLINDING_LEN];
        OsRng.fill_bytes(&mut blinding_seed);
        Self {
            owner,
            inputs,
            recipients: Vec::new(),
            withdrawal: None,
            payer_pubkey_hash: sha256_be(payer.as_array()),
            blinding_seed,
            shape: None,
        }
    }

    pub fn with_shape(mut self, shape: Shape) -> Self {
        self.shape = Some(shape);
        self
    }

    pub fn requires_p256_owner(&self) -> Result<bool, ClientError> {
        inputs_require_p256(&self.inputs)
    }

    pub fn send(
        &mut self,
        recipient: &ShieldedAddress,
        asset: Address,
        amount: u64,
        view_tag: ViewTag,
    ) -> Result<&mut Self, ClientError> {
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
    ) -> Result<&mut Self, ClientError> {
        if self.withdrawal.is_some() {
            return Err(ClientError::WithdrawalAlreadySet);
        }
        self.withdrawal = Some(Withdrawal {
            asset,
            amount,
            target,
        });
        Ok(self)
    }

    pub fn sign(
        self,
        keypair: &ShieldedKeypair,
        assets: &AssetRegistry,
        sender_view_tag: ViewTag,
    ) -> Result<SignedTransaction, ClientError> {
        let mut sealed = self.assemble(keypair, assets, sender_view_tag)?;
        let message_hash = sealed.message_hash()?;
        let ecdsa = EcdsaSigningKey::from_slice(keypair.signing_key.secret_bytes().as_slice())
            .map_err(|e| ClientError::P256Signature(e.to_string()))?;
        sealed.p256_owner = Some(precompute_p256(&ecdsa, &message_hash)?);
        Ok(sealed)
    }

    pub fn finalize(
        self,
        keypair: &ShieldedKeypair,
        assets: &AssetRegistry,
        sender_view_tag: ViewTag,
    ) -> Result<SignedTransaction, ClientError> {
        self.assemble(keypair, assets, sender_view_tag)
    }

    fn spl_asset(&self) -> Result<Option<Address>, ClientError> {
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
                        return Err(ClientError::MultiplePublicSplAssets)
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

    fn change(&self, asset: &Address, public: i128) -> Result<u64, ClientError> {
        let leftover = self.input_sum(asset) + public - self.recipient_sum(asset);
        if leftover < 0 {
            return Err(ClientError::InsufficientBalance {
                requested: (-leftover) as u64,
                available: 0,
            });
        }
        Ok(leftover as u64)
    }

    fn first_nullifier(&self) -> Result<[u8; 32], ClientError> {
        let spend = self.inputs.first().ok_or(ClientError::NoInputs)?;
        let utxo_hash = spend
            .utxo
            .hash(&spend.nullifier_key.pubkey()?, &[0u8; 32], &[0u8; 32])?;
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

    fn assemble(
        self,
        keypair: &ShieldedKeypair,
        assets: &AssetRegistry,
        sender_view_tag: ViewTag,
    ) -> Result<SignedTransaction, ClientError> {
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

        let sender_pubkey = keypair.viewing_pubkey();
        let mut recipient_outputs = Vec::with_capacity(self.recipients.len());
        let mut recipient_viewing_pks = Vec::with_capacity(self.recipients.len());
        for (i, recipient) in self.recipients.iter().enumerate() {
            let position = RECIPIENT_POSITION_BASE + i as u8;
            let blinding = derive_blinding(&self.blinding_seed, position);
            let asset_id = self.asset_id(assets, &recipient.asset)?;
            outputs.push(OutputUtxo {
                owner_hash: recipient.address.owner_hash()?,
                asset: recipient.asset,
                amount: recipient.amount,
                blinding,
                ..Default::default()
            });
            recipient_viewing_pks.push(recipient.address.viewing_pubkey);
            recipient_outputs.push(RecipientOutput {
                view_tag: recipient.view_tag,
                plaintext: TransferRecipientPlaintext {
                    owner_pubkey: recipient.address.signing_pubkey,
                    sender_pubkey,
                    asset_id,
                    amount: recipient.amount,
                    blinding,
                    data: Data::default(),
                },
            });
        }

        let spl_asset_id = match spl_asset {
            Some(asset) => self.asset_id(assets, &asset)?,
            None => 0,
        };
        let sender = TransferSenderPlaintext {
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
        let encrypted =
            keypair
                .viewing_key
                .encrypt_transfer(&first_nullifier, &sender, &recipient_outputs)?;

        let (user_sol_account, user_spl_token, spl_token_interface) = self.external_accounts();

        let shape = resolve_shape(self.shape, self.inputs.len(), outputs.len())?;

        let ciphertexts =
            encrypted.to_output_ciphertexts(sender_view_tag, SENDER_SLOT_COUNT, shape.n_outputs)?;
        let mut output_slots = Vec::with_capacity(shape.n_outputs);
        for (index, ciphertext) in ciphertexts.into_iter().enumerate() {
            let utxo_hash = match outputs.get(index) {
                Some(output) => output.hash()?,
                None => [0u8; 32],
            };
            output_slots.push(OutputSlot {
                view_tag: ciphertext.view_tag,
                utxo_hash,
                data: ciphertext.data,
            });
        }

        let external_data = ExternalData {
            instruction_discriminator: TRANSACT_DISCRIMINATOR,
            expiry_unix_ts: 0,
            relayer_fee: 0,
            public_sol_amount: (public_sol != 0).then_some(public_sol as i64),
            public_spl_amount: (public_spl != 0).then_some(public_spl as i64),
            user_sol_account,
            user_spl_token,
            spl_token_interface,
            cpi_signer: None,
            tx_viewing_pk: *encrypted.tx_viewing_pk.as_bytes(),
            salt: encrypted.salt,
            output_slots,
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
            inputs: self.inputs,
            outputs,
            public_amounts,
            external_data,
            payer_pubkey_hash: self.payer_pubkey_hash,
            shape,
            p256_owner: None,
        })
    }

    fn asset_id(&self, assets: &AssetRegistry, asset: &Address) -> Result<u64, ClientError> {
        if asset == &SOL_MINT {
            Ok(SOL_ASSET_ID)
        } else {
            Ok(assets.asset_id(asset)?)
        }
    }
}

fn precompute_p256(
    signer: &EcdsaSigningKey,
    message_hash: &[u8; 32],
) -> Result<P256Owner, ClientError> {
    let signature: Signature = signer
        .sign_prehash(message_hash)
        .map_err(|e| ClientError::P256Signature(e.to_string()))?;
    let bytes = signature.to_bytes();
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    sig_r.copy_from_slice(&bytes[..32]);
    sig_s.copy_from_slice(&bytes[32..]);

    let encoded = signer.verifying_key().to_encoded_point(true);
    let mut pubkey_bytes = [0u8; P256_PUBKEY_LEN];
    pubkey_bytes.copy_from_slice(encoded.as_bytes());
    let pubkey = P256Pubkey::from_bytes(pubkey_bytes)?;

    Ok(P256Owner::Precomputed {
        pubkey,
        sig_r,
        sig_s,
    })
}
