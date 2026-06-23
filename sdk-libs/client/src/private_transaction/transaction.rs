use rand::rngs::OsRng;
use rand::RngCore;
use solana_address::Address;
use solana_pubkey::Pubkey;
use zolana_interface::instruction::instruction_data::transact::OutputCiphertext;
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::hash::sha256_be;
use zolana_keypair::shielded::{ShieldedAddress, ShieldedKeypair};
use zolana_keypair::viewing_key::{random_blinding, ViewTag};
use zolana_keypair::{NullifierKey, PublicKey, SignatureType};
use zolana_transaction::asset::{AssetRegistry, SOL_ASSET_ID};
use zolana_transaction::transfer::{
    RecipientOutput, TransferRecipientPlaintext, TransferSenderPlaintext, RECIPIENT_CIPHERTEXT_LEN,
    SENDER_SLOT_COUNT,
};
use zolana_transaction::utxo::derive_blinding;
use zolana_transaction::{Data, ExternalData, OutputUtxo, Utxo, SOL_MINT};

use crate::error::ClientError;
use crate::private_transaction::field::{asset_field, signed_to_field};
use crate::private_transaction::signed_transaction::SignedTransaction;
use crate::prover::shape::{resolve_shape, Shape};
use crate::prover::transfer::TransferProver;
use crate::prover::transfer_p256::{PublicAmounts, TransferP256Prover};
use crate::rpc::{MerkleProof, NonInclusionProof};
use crate::wallet_authority::{
    ApprovalRequest, ScopedSpendWitness, SpendWitnessRequest, WalletAuthority,
};

const TRANSACT_DISCRIMINATOR: u8 = 0;
const SPL_CHANGE_POSITION: u8 = 0;
const SOL_CHANGE_POSITION: u8 = 1;
const RECIPIENT_POSITION_BASE: u8 = 2;

#[derive(Clone)]
pub struct SpendUtxo {
    pub utxo: Utxo,
    pub witness: ScopedSpendWitness,
    /// Program data hash committed by this input UTXO. Current transfer assembly
    /// only supports clean/default inputs, but the field belongs with the selected
    /// input so future program-data spends can plumb it into the proof witness.
    pub program_data_hash: Option<[u8; 32]>,
    /// Zone data hash committed by this input UTXO. See `program_data_hash`.
    pub zone_data_hash: Option<[u8; 32]>,
}

impl SpendUtxo {
    /// Padding input that fills a fixed proof shape. `owner = 0` makes it
    /// unspendable and marks it as a dummy ([`Self::is_dummy`]); the random blinding
    /// is the sole source of unpredictability for its nullifier, which is
    /// indistinguishable from a real one. The circuit skips the ownership,
    /// inclusion, and nullifier checks for it.
    pub fn new_dummy() -> Self {
        let utxo = Utxo {
            owner: PublicKey::zeroed(),
            asset: Address::default(),
            amount: 0,
            blinding: random_blinding(),
            zone_program_id: None,
            data: Data::default(),
        };
        // Dummy slots never use witness data (they are filtered before commitment
        // lookup and handled via `proof: None`), so a zero witness is sufficient.
        let witness = ScopedSpendWitness {
            nullifier_pubkey: [0u8; 32],
            nullifier: [0u8; 32],
            nullifier_secret: [0u8; BLINDING_LEN],
        };
        Self {
            utxo,
            witness,
            program_data_hash: None,
            zone_data_hash: None,
        }
    }

    pub fn is_dummy(&self) -> bool {
        self.utxo.owner.is_zero()
    }

    pub fn from_keypair(utxo: Utxo, keypair: &ShieldedKeypair) -> Result<Self, ClientError> {
        Self::from_nullifier_key(utxo, &keypair.nullifier_key)
    }

    pub fn from_nullifier_key(
        utxo: Utxo,
        nullifier_key: &NullifierKey,
    ) -> Result<Self, ClientError> {
        let request = SpendWitnessRequest::new(utxo.clone());
        Ok(Self {
            utxo,
            witness: ScopedSpendWitness::from_nullifier_key(&request, nullifier_key)?,
            program_data_hash: None,
            zone_data_hash: None,
        })
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

#[derive(Clone)]
pub struct SpendProof {
    pub state: MerkleProof,
    pub nullifier: NonInclusionProof,
}

pub enum CircuitType {
    P256(TransferP256Prover),
    Eddsa(TransferProver),
}

pub(crate) fn inputs_require_p256(inputs: &[SpendUtxo]) -> Result<bool, ClientError> {
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

    pub fn sign<A: WalletAuthority>(
        self,
        owner_pubkey: Pubkey,
        authority: &A,
        assets: &AssetRegistry,
        sender_view_tag: ViewTag,
    ) -> Result<SignedTransaction, ClientError> {
        authority.request_user_approval(ApprovalRequest {
            owner_pubkey,
            summary: format!(
                "private transaction with {} input(s), {} recipient(s)",
                self.inputs.len(),
                self.recipients.len()
            ),
        })?;
        let mut sealed = self.assemble(owner_pubkey, authority, assets, sender_view_tag)?;
        if authority
            .shielded_address(owner_pubkey)?
            .signing_pubkey
            .signature_type()?
            == SignatureType::P256
        {
            let message_hash = sealed.message_hash()?;
            let signature = authority.sign_p256(owner_pubkey, &message_hash)?;
            sealed.p256_owner = Some(signature.into());
        }
        Ok(sealed)
    }

    pub fn finalize<A: WalletAuthority>(
        self,
        owner_pubkey: Pubkey,
        authority: &A,
        assets: &AssetRegistry,
        sender_view_tag: ViewTag,
    ) -> Result<SignedTransaction, ClientError> {
        self.assemble(owner_pubkey, authority, assets, sender_view_tag)
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
        Ok(spend.witness.nullifier)
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

    fn assemble<A: WalletAuthority>(
        self,
        owner_pubkey: Pubkey,
        authority: &A,
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

        let sender_pubkey = authority.shielded_address(owner_pubkey)?.viewing_pubkey;
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

        let shape = resolve_shape(self.shape, self.inputs.len(), outputs.len())?;
        let max_recipients = shape
            .n_outputs
            .checked_sub(SENDER_SLOT_COUNT)
            .ok_or(ClientError::MissingOutput)?;
        // Pad recipient_viewing_pks to MAX_RECIPIENTS with a throwaway pubkey (the
        // sender's own viewing key) so the encrypted sender bundle is fixed-size and
        // does not reveal the real recipient count. A dummy slot's trial-decrypt
        // fails on its random bytes regardless of this pubkey.
        while recipient_viewing_pks.len() < max_recipients {
            recipient_viewing_pks.push(sender_pubkey);
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
        let encrypted = authority.encrypt_transfer(
            owner_pubkey,
            &first_nullifier,
            &sender,
            &recipient_outputs,
        )?;

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

        // Fixed-length ciphertext vector: the sender bundle, the real recipient
        // ciphertexts, then random L-byte dummies under same-distribution view tags
        // so the recipient count is hidden.
        let mut output_ciphertexts = Vec::with_capacity(1 + max_recipients);
        output_ciphertexts.push(OutputCiphertext {
            view_tag: sender_view_tag,
            data: encrypted.sender_ciphertext.clone(),
        });
        for recipient in &encrypted.recipient_slots {
            output_ciphertexts.push(OutputCiphertext {
                view_tag: recipient.view_tag,
                data: recipient.ciphertext.clone(),
            });
        }
        while output_ciphertexts.len() < 1 + max_recipients {
            output_ciphertexts.push(OutputCiphertext {
                view_tag: random_view_tag(),
                data: random_dummy_ciphertext(),
            });
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
            tx_viewing_pk: *encrypted.tx_viewing_pk.as_bytes(),
            salt: encrypted.salt,
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

    fn asset_id(&self, assets: &AssetRegistry, asset: &Address) -> Result<u64, ClientError> {
        if asset == &SOL_MINT {
            Ok(SOL_ASSET_ID)
        } else {
            Ok(assets.asset_id(asset)?)
        }
    }
}

/// A view tag for a dummy output slot, drawn from the same byte distribution as a
/// derived one: byte 0 is `0` (derived tags right-align a 31-byte value into 32
/// bytes), bytes `1..32` random. A uniformly random tag would have a nonzero
/// leading byte 255/256 of the time and mark the slot as a dummy, leaking the
/// recipient count.
fn random_view_tag() -> [u8; 32] {
    let mut tag = [0u8; 32];
    OsRng.fill_bytes(&mut tag[1..]);
    tag
}

/// Random `RECIPIENT_CIPHERTEXT_LEN` bytes for a dummy output slot. A real GCM
/// ciphertext is indistinguishable from random to an observer, so a same-length
/// random filler hides whether the slot holds a real recipient.
fn random_dummy_ciphertext() -> Vec<u8> {
    let mut data = vec![0u8; RECIPIENT_CIPHERTEXT_LEN];
    OsRng.fill_bytes(&mut data);
    data
}
