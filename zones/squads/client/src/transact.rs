//! `requestTransact`: build the paired zone + SPP proofs and the `transact`
//! instruction for a transfer or withdrawal.
//!
//! The backend proves on the account's behalf using the shared viewing key and
//! nullifier secret it recovered with the auditor key (the smart-account,
//! signatureless rail). The P256 keypair rail needs the owner signing key the
//! backend does not hold and is reported unsupported here. All Solana settlement
//! accounts are assembled internally: the fee payer / co-signer is the backend's
//! relayer (`zone_authority`), the zone authority and pool PDAs are derived, and
//! the withdrawal rail is built from the request plus those derivations.

use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use solana_pubkey::Pubkey;
use zolana_client::{Rpc, SpendProof};
use zolana_interface::{
    pda, SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::{
    hash::{hash_field, sha256, sha256_be},
    NullifierKey, P256Pubkey,
};
use zolana_squads_interface::{
    instruction::{
        builders::{Transact, TransactWithdrawal},
        instruction_data::{EncryptedUtxos, InputContext, TransactIxData},
    },
    state::ViewingKeyAccount,
    PROGRAM_ID_PUBKEY, ZONE_AUTH_PDA_SEED,
};
use zolana_squads_sdk::prover::{
    probe_squads_transfer, probe_squads_withdrawal, prove_squads_smart_account_transfer,
    prove_squads_smart_account_withdrawal, ProbedTransfer, ProbedWithdrawal,
    SquadsSmartAccountIdentity, SquadsSmartAccountTransferRequest,
    SquadsSmartAccountWithdrawalRequest, SquadsTransferInput, SquadsTransferProbe,
    SquadsTransferProof, SquadsTransferRecipient, SquadsWithdrawalInput, SquadsWithdrawalProbe,
    SquadsWithdrawalProof,
};
use zolana_transaction::Address;

use crate::{
    backend::{SquadsBackend, SOL_ASSET_ID},
    error::{Result, SquadsBackendError},
    tags::{account_view_tag, view_tag_from_shared_viewing_key},
    types::{
        DecryptedUtxo, PrivateTransactionIntent, RequestTransactRequest, RequestTransactResponse,
        TransactionType,
    },
};

/// Byte offset of the owner field in an SPL token account (`mint(32) || owner(32)`).
const SPL_TOKEN_OWNER_OFFSET: usize = 32;

fn to_pubkey(address: Address) -> Pubkey {
    Pubkey::new_from_array(address.to_bytes())
}

/// A fresh per-transaction AES salt forwarded to SPP (not bound by
/// `external_data_hash`); generated once per request and shared by the proof and
/// the instruction.
fn random_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// A per-transaction salt derived deterministically from the request, so the P256
/// rail's probe (which the client signs) and finalize rebuild the identical
/// `private_tx_hash`. The salt is not bound by `external_data_hash`, so any stable
/// value works; deriving it from the stable request fields keeps the two calls in
/// sync without carrying probe state across the API boundary.
fn deterministic_salt(request: &RequestTransactRequest) -> [u8; 16] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(
        request
            .intent
            .sender_viewing_key_account
            .to_bytes()
            .as_ref(),
    );
    preimage.extend_from_slice(&request.intent.expiry.to_be_bytes());
    for input in &request.intent.inputs {
        preimage.extend_from_slice(&input.utxo_hash);
        preimage.extend_from_slice(&input.blinding);
    }
    for output in &request.intent.outputs {
        preimage.extend_from_slice(output.owner.to_bytes().as_ref());
        preimage.extend_from_slice(&output.amount.to_be_bytes());
        preimage.extend_from_slice(&output.blinding);
    }
    if let Some(pubkey) = request.sender_owner_pubkey {
        preimage.extend_from_slice(&pubkey);
    }
    let digest = sha256(&preimage);
    let mut salt = [0u8; 16];
    if let Some(prefix) = digest.get(..16) {
        salt.copy_from_slice(prefix);
    }
    salt
}

/// Split a 64-byte P256 signature into its `(r, s)` halves.
fn split_signature(signature: &[u8; 64]) -> Result<([u8; 32], [u8; 32])> {
    let r: [u8; 32] = signature
        .get(..32)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| SquadsBackendError::Unsupported("owner signature r".into()))?;
    let s: [u8; 32] = signature
        .get(32..)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| SquadsBackendError::Unsupported("owner signature s".into()))?;
    Ok((r, s))
}

/// The withdrawal settlement rail plus the fields the proof and instruction need.
struct WithdrawalRail {
    asset: Address,
    is_spl: bool,
    withdrawal: TransactWithdrawal,
    user_sol_account: Address,
    user_spl_token: Address,
    spl_token_interface: Address,
}

impl<I: Rpc, R: Rpc> SquadsBackend<I, R> {
    /// Build the proof and `transact` instruction.
    ///
    /// `sender_owner_pubkey == None` selects the smart-account (signatureless)
    /// rail and returns the instruction for a smart account to wrap, partial-sign,
    /// and submit with the co-signer. `Some` selects the P256 keypair rail, which
    /// requires the client's `owner_signature` over `sha256(private_tx_hash)`
    /// (obtained via [`Self::request_transact_probe`]); the backend finalizes the
    /// paired proofs and returns the assembled instruction.
    pub fn request_transact(
        &self,
        request: RequestTransactRequest,
    ) -> Result<RequestTransactResponse> {
        match request.sender_owner_pubkey {
            None => self.request_transact_smart_account(&request),
            Some(_) => {
                let signature = request.owner_signature.ok_or_else(|| {
                    SquadsBackendError::Unsupported(
                        "P256 keypair rail requires owner_signature over sha256(private_tx_hash); obtain it via request_transact_probe".into(),
                    )
                })?;
                let (sig_r, sig_s) = split_signature(&signature)?;
                self.request_transact_p256(&request, sig_r, sig_s)
            }
        }
    }

    /// The P256 keypair rail: probe (server-free) to get `private_tx_hash` the
    /// client signs, then call [`Self::request_transact`] with the signature. The
    /// probe uses a deterministic salt so the `private_tx_hash` the client signs
    /// matches the one the finalize step rebuilds.
    pub fn request_transact_probe(&self, request: &RequestTransactRequest) -> Result<[u8; 32]> {
        let owner_pubkey = self.p256_owner_pubkey(request)?;
        let sender = self.resolve_shared_key(request.intent.sender_viewing_key_account)?;
        let salt = deterministic_salt(request);
        match request.transaction_type {
            TransactionType::Transfer {
                recipient_viewing_key_account,
            } => Ok(self
                .build_transfer_probe(
                    request,
                    &sender,
                    owner_pubkey,
                    recipient_viewing_key_account,
                    salt,
                )?
                .private_tx_hash),
            TransactionType::Withdraw {
                public_amount,
                recipient_account,
            } => Ok(self
                .build_withdrawal_probe(
                    request,
                    &sender,
                    owner_pubkey,
                    public_amount,
                    recipient_account,
                    salt,
                )?
                .0
                .private_tx_hash),
        }
    }

    /// The smart-account (signatureless) rail (unchanged behaviour).
    fn request_transact_smart_account(
        &self,
        request: &RequestTransactRequest,
    ) -> Result<RequestTransactResponse> {
        let sender = self.resolve_shared_key(request.intent.sender_viewing_key_account)?;
        // The spend proof reconstructs the input owner as `hash_field(vault)`; the
        // viewing key account stores only that hash, so the raw vault is supplied by
        // the client. Using `sender.account.owner` (already `hash_field(vault)`)
        // here would hash it a second time and break the input owner binding.
        let owner_vault = request.sender_vault.ok_or_else(|| {
            SquadsBackendError::Unsupported(
                "smart-account rail requires sender_vault (the raw Squads vault)".into(),
            )
        })?;
        let vault_field = hash_field(&owner_vault.to_bytes())
            .map_err(|e| SquadsBackendError::Crypto(format!("vault owner field: {e:?}")))?;
        if vault_field != sender.account.owner.to_bytes() {
            return Err(SquadsBackendError::Unsupported(
                "sender_vault does not hash to the viewing key account owner field".into(),
            ));
        }
        let identity = SquadsSmartAccountIdentity {
            owner_vault,
            nullifier_secret: sender.nullifier_secret,
            viewing_secret: sender.shared_viewing_sk.clone(),
        };
        let sender_view_tag = account_view_tag(&sender.account);
        let nullifier_key = NullifierKey::from_secret(sender.nullifier_secret);
        let salt = random_salt();

        match request.transaction_type {
            TransactionType::Transfer {
                recipient_viewing_key_account,
            } => {
                let proof = self.prove_transfer(
                    &request.intent,
                    identity,
                    recipient_viewing_key_account,
                    &nullifier_key,
                    sender_view_tag,
                    salt,
                )?;
                let instruction = self.build_transfer_instruction(
                    &request.intent,
                    &proof,
                    recipient_viewing_key_account,
                    sender_view_tag,
                    salt,
                )?;
                Ok(RequestTransactResponse::Instruction(instruction))
            }
            TransactionType::Withdraw {
                public_amount,
                recipient_account,
            } => {
                let input = request.intent.inputs.first().ok_or_else(|| {
                    SquadsBackendError::Unsupported("withdrawal needs one input".into())
                })?;
                let rail = self.build_withdrawal_rail(input.asset_id, recipient_account)?;
                let proof =
                    prove_squads_smart_account_withdrawal(SquadsSmartAccountWithdrawalRequest {
                        identity,
                        input: SquadsWithdrawalInput {
                            asset: rail.asset,
                            amount: input.amount,
                            blinding: input.blinding,
                            spend_proof: self.spend_proof(input, &nullifier_key)?,
                        },
                        withdrawn: public_amount,
                        is_spl: rail.is_spl,
                        user_sol_account: rail.user_sol_account,
                        user_spl_token: rail.user_spl_token,
                        spl_token_interface: rail.spl_token_interface,
                        payer_pubkey_hash: self.payer_pubkey_hash(),
                        expiry_unix_ts: request.intent.expiry as u64,
                        salt,
                        sender_view_tag,
                        proposal: None,
                        prover_url: self.prover_url().to_string(),
                    })?;

                let instruction = self.build_withdrawal_instruction(
                    request.intent.sender_viewing_key_account,
                    rail.withdrawal,
                    public_amount,
                    &proof,
                    sender_view_tag,
                    salt,
                    request.intent.expiry,
                );
                Ok(RequestTransactResponse::Instruction(instruction))
            }
        }
    }

    /// The P256 keypair rail: rebuild the probe (deterministic salt), finalize with
    /// the client-supplied `(sig_r, sig_s)` over `sha256(private_tx_hash)`, and
    /// assemble the instruction. The owner signature is verified in-circuit by the
    /// SPP proof; the Solana transaction is still co-signed by the relayer.
    fn request_transact_p256(
        &self,
        request: &RequestTransactRequest,
        sig_r: [u8; 32],
        sig_s: [u8; 32],
    ) -> Result<RequestTransactResponse> {
        let owner_pubkey = self.p256_owner_pubkey(request)?;
        let sender = self.resolve_shared_key(request.intent.sender_viewing_key_account)?;
        let sender_view_tag = account_view_tag(&sender.account);
        let salt = deterministic_salt(request);

        match request.transaction_type {
            TransactionType::Transfer {
                recipient_viewing_key_account,
            } => {
                let probe = self.build_transfer_probe(
                    request,
                    &sender,
                    owner_pubkey,
                    recipient_viewing_key_account,
                    salt,
                )?;
                let proof = probe.finalize(sig_r, sig_s)?;
                let instruction = self.build_transfer_instruction(
                    &request.intent,
                    &proof,
                    recipient_viewing_key_account,
                    sender_view_tag,
                    salt,
                )?;
                Ok(RequestTransactResponse::Instruction(instruction))
            }
            TransactionType::Withdraw {
                public_amount,
                recipient_account,
            } => {
                let (probe, rail) = self.build_withdrawal_probe(
                    request,
                    &sender,
                    owner_pubkey,
                    public_amount,
                    recipient_account,
                    salt,
                )?;
                let proof = probe.finalize(sig_r, sig_s)?;
                let instruction = self.build_withdrawal_instruction(
                    request.intent.sender_viewing_key_account,
                    rail.withdrawal,
                    public_amount,
                    &proof,
                    sender_view_tag,
                    salt,
                    request.intent.expiry,
                );
                Ok(RequestTransactResponse::Instruction(instruction))
            }
        }
    }

    /// Decode the request's P256 owner public key (the keypair rail selector).
    fn p256_owner_pubkey(&self, request: &RequestTransactRequest) -> Result<P256Pubkey> {
        let bytes = request.sender_owner_pubkey.ok_or_else(|| {
            SquadsBackendError::Unsupported(
                "the P256 keypair rail requires sender_owner_pubkey".into(),
            )
        })?;
        P256Pubkey::from_bytes(bytes).map_err(|e| SquadsBackendError::Keypair(format!("{e:?}")))
    }

    /// Build a `(2, 2)` P256 transfer probe (server- and signature-free) from the
    /// request; its `private_tx_hash` is what the sender signs.
    fn build_transfer_probe(
        &self,
        request: &RequestTransactRequest,
        sender: &crate::backend::ResolvedAccount,
        owner_pubkey: P256Pubkey,
        recipient_vka: Address,
        salt: [u8; 16],
    ) -> Result<ProbedTransfer> {
        if !(1..=2).contains(&request.intent.inputs.len()) {
            return Err(SquadsBackendError::Unsupported(
                "P256 transfer spends one or two inputs".into(),
            ));
        }
        let recipient_account = self.load_viewing_key_account(recipient_vka)?;
        let recipient = self.transfer_recipient(&recipient_account)?;
        let recipient_output = request
            .intent
            .outputs
            .iter()
            .find(|o| {
                self.mint_for_asset_id(o.asset_id).is_some() && o.owner == recipient_account.owner
            })
            .ok_or_else(|| {
                SquadsBackendError::Unsupported("intent has no recipient output".into())
            })?;

        let nullifier_key = NullifierKey::from_secret(sender.nullifier_secret);
        let mut inputs = Vec::with_capacity(2);
        for input in &request.intent.inputs {
            let input_asset = self.mint_for_asset_id(input.asset_id).ok_or_else(|| {
                SquadsBackendError::Unsupported(format!("unknown asset_id {}", input.asset_id))
            })?;
            inputs.push(SquadsTransferInput {
                asset: input_asset,
                amount: input.amount,
                blinding: input.blinding,
                spend_proof: self.spend_proof(input, &nullifier_key)?,
            });
        }

        Ok(probe_squads_transfer(SquadsTransferProbe {
            owner_pubkey,
            nullifier_secret: sender.nullifier_secret,
            viewing_secret: sender.shared_viewing_sk.clone(),
            inputs,
            recipient,
            transferred: recipient_output.amount,
            recipient_blinding: recipient_output.blinding,
            payer_pubkey_hash: self.payer_pubkey_hash(),
            expiry_unix_ts: request.intent.expiry as u64,
            salt,
            sender_view_tag: account_view_tag(&sender.account),
            recipient_view_tag: view_tag_from_shared_viewing_key(
                &recipient_account.shared_viewing_key,
            ),
            proposal: None,
            prover_url: self.prover_url().to_string(),
        })?)
    }

    /// Build a `(1, 1)` P256 withdrawal probe plus its settlement rail.
    fn build_withdrawal_probe(
        &self,
        request: &RequestTransactRequest,
        sender: &crate::backend::ResolvedAccount,
        owner_pubkey: P256Pubkey,
        public_amount: u64,
        recipient_account: Address,
        salt: [u8; 16],
    ) -> Result<(ProbedWithdrawal, WithdrawalRail)> {
        let input =
            request.intent.inputs.first().ok_or_else(|| {
                SquadsBackendError::Unsupported("withdrawal needs one input".into())
            })?;
        let rail = self.build_withdrawal_rail(input.asset_id, recipient_account)?;
        let nullifier_key = NullifierKey::from_secret(sender.nullifier_secret);
        let probe = probe_squads_withdrawal(SquadsWithdrawalProbe {
            owner_pubkey,
            nullifier_secret: sender.nullifier_secret,
            viewing_secret: sender.shared_viewing_sk.clone(),
            input: SquadsWithdrawalInput {
                asset: rail.asset,
                amount: input.amount,
                blinding: input.blinding,
                spend_proof: self.spend_proof(input, &nullifier_key)?,
            },
            withdrawn: public_amount,
            is_spl: rail.is_spl,
            user_sol_account: rail.user_sol_account,
            user_spl_token: rail.user_spl_token,
            spl_token_interface: rail.spl_token_interface,
            payer_pubkey_hash: self.payer_pubkey_hash(),
            expiry_unix_ts: request.intent.expiry as u64,
            salt,
            sender_view_tag: account_view_tag(&sender.account),
            proposal: None,
            prover_url: self.prover_url().to_string(),
        })?;
        Ok((probe, rail))
    }

    /// The withdrawal settlement rail, chosen by the spent asset: SOL settles
    /// through the SOL interface, every other asset through its per-mint SPL vault.
    fn build_withdrawal_rail(
        &self,
        asset_id: u64,
        recipient_account: Address,
    ) -> Result<WithdrawalRail> {
        let asset = self.mint_for_asset_id(asset_id).ok_or_else(|| {
            SquadsBackendError::Unsupported(format!("unknown asset_id {asset_id}"))
        })?;
        let is_spl = asset_id != SOL_ASSET_ID;
        if is_spl {
            let vault = pda::spl_asset_vault(&to_pubkey(asset));
            let withdrawal = TransactWithdrawal::Spl {
                cpi_authority: Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY),
                vault,
                recipient: self.spl_token_account_owner(recipient_account)?,
                user_token_account: to_pubkey(recipient_account),
                token_program: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
            };
            Ok(WithdrawalRail {
                asset,
                is_spl,
                withdrawal,
                user_sol_account: Address::default(),
                user_spl_token: recipient_account,
                spl_token_interface: Address::new_from_array(vault.to_bytes()),
            })
        } else {
            let withdrawal = TransactWithdrawal::Sol {
                sol_interface: pda::sol_interface(),
                recipient: to_pubkey(recipient_account),
            };
            Ok(WithdrawalRail {
                asset,
                is_spl,
                withdrawal,
                user_sol_account: recipient_account,
                user_spl_token: Address::default(),
                spl_token_interface: Address::default(),
            })
        }
    }

    /// Assemble the withdrawal `transact` instruction from a proof.
    #[allow(clippy::too_many_arguments)]
    fn build_withdrawal_instruction(
        &self,
        sender_viewing_key_account: Address,
        withdrawal_rail: TransactWithdrawal,
        public_amount: u64,
        proof: &SquadsWithdrawalProof,
        sender_view_tag: [u8; 32],
        salt: [u8; 16],
        expiry: i64,
    ) -> solana_instruction::Instruction {
        let ix_data = TransactIxData {
            zone_proof: proof.zone_proof,
            spp_proof: proof.spp_proof,
            public_amount: Some(public_amount),
            private_tx_hash: proof.private_tx_hash,
            expiry,
            salt,
            output_view_tags: vec![sender_view_tag],
            output_utxo_hashes: vec![proof.change_utxo_hash],
            input_contexts: vec![InputContext {
                nullifier: proof.nullifier,
                tree_index: 0,
                utxo_root_index: proof.utxo_root_index,
                nullifier_root_index: proof.nullifier_root_index,
            }],
            encrypted_utxos: EncryptedUtxos {
                tx_viewing_pk: [0u8; 33],
                sender_ciphertext: proof.sender_ciphertext,
                recipient_ciphertexts: vec![],
            },
        };
        self.transact_instruction(
            sender_viewing_key_account,
            None,
            Some(withdrawal_rail),
            ix_data,
        )
    }

    /// The relayer that pays and co-signs zone transactions (the backend's
    /// `zone_authority`).
    pub(crate) fn relayer_pubkey(&self) -> Pubkey {
        self.zone_authority_pubkey()
    }

    /// Sha256-BE of the SPP payer address SPP sees (the relayer).
    pub(crate) fn payer_pubkey_hash(&self) -> [u8; 32] {
        sha256_be(&self.relayer_pubkey().to_bytes())
    }

    /// The zone authority PDA (SPP's `ZoneConfig` for this zone).
    pub(crate) fn zone_auth_pubkey(&self) -> Pubkey {
        Pubkey::find_program_address(&[ZONE_AUTH_PDA_SEED], &PROGRAM_ID_PUBKEY).0
    }

    /// Read the owner of an SPL token account from its on-chain data.
    fn spl_token_account_owner(&self, token_account: Address) -> Result<Pubkey> {
        let account = self
            .rpc()
            .get_account(token_account)?
            .ok_or_else(|| SquadsBackendError::AccountNotFound(token_account.to_string()))?;
        let owner: [u8; 32] = account
            .data
            .get(SPL_TOKEN_OWNER_OFFSET..SPL_TOKEN_OWNER_OFFSET + 32)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| {
                SquadsBackendError::Unsupported(format!(
                    "{token_account} is not an SPL token account"
                ))
            })?;
        Ok(Pubkey::new_from_array(owner))
    }

    /// State-inclusion + nullifier-non-inclusion proofs for one input.
    pub(crate) fn spend_proof(
        &self,
        input: &DecryptedUtxo,
        nullifier_key: &NullifierKey,
    ) -> Result<SpendProof> {
        let nullifier = nullifier_key
            .nullifier(&input.utxo_hash, &input.blinding)
            .map_err(|e| SquadsBackendError::Crypto(format!("nullifier: {e:?}")))?;
        let state = self
            .indexer()
            .get_merkle_proofs(self.tree(), vec![input.utxo_hash])?
            .proofs
            .into_iter()
            .next()
            .ok_or_else(|| {
                SquadsBackendError::Unsupported("missing state inclusion proof".into())
            })?;
        let non_inclusion = self
            .indexer()
            .get_non_inclusion_proofs(self.tree(), vec![nullifier])?
            .proofs
            .into_iter()
            .next()
            .ok_or_else(|| {
                SquadsBackendError::Unsupported("missing nullifier non-inclusion proof".into())
            })?;
        Ok(SpendProof {
            state,
            nullifier: non_inclusion,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn prove_transfer(
        &self,
        intent: &PrivateTransactionIntent,
        identity: SquadsSmartAccountIdentity,
        recipient_vka: Address,
        nullifier_key: &NullifierKey,
        sender_view_tag: [u8; 32],
        salt: [u8; 16],
    ) -> Result<SquadsTransferProof> {
        if intent.inputs.is_empty() || intent.inputs.len() > 2 {
            return Err(SquadsBackendError::Unsupported(
                "smart-account transfer spends one or two inputs".into(),
            ));
        }
        let recipient_account = self.load_viewing_key_account(recipient_vka)?;
        let recipient = self.transfer_recipient(&recipient_account)?;

        // The recipient output is the one owned by the recipient account.
        let recipient_output = intent
            .outputs
            .iter()
            .find(|o| {
                self.mint_for_asset_id(o.asset_id).is_some() && o.owner == recipient_account.owner
            })
            .ok_or_else(|| {
                SquadsBackendError::Unsupported("intent has no recipient output".into())
            })?;

        // Input selection is the caller's job: every listed input is spent verbatim
        // (a single input is padded with a prover-synthesized dummy so the circuit
        // shape stays (2, 2)).
        let mut inputs = Vec::with_capacity(intent.inputs.len());
        for input in &intent.inputs {
            let input_asset = self.mint_for_asset_id(input.asset_id).ok_or_else(|| {
                SquadsBackendError::Unsupported(format!("unknown asset_id {}", input.asset_id))
            })?;
            inputs.push(SquadsTransferInput {
                asset: input_asset,
                amount: input.amount,
                blinding: input.blinding,
                spend_proof: self.spend_proof(input, nullifier_key)?,
            });
        }

        Ok(prove_squads_smart_account_transfer(
            SquadsSmartAccountTransferRequest {
                identity,
                inputs,
                recipient,
                transferred: recipient_output.amount,
                recipient_blinding: recipient_output.blinding,
                payer_pubkey_hash: self.payer_pubkey_hash(),
                expiry_unix_ts: intent.expiry as u64,
                salt,
                sender_view_tag,
                recipient_view_tag: view_tag_from_shared_viewing_key(
                    &recipient_account.shared_viewing_key,
                ),
                proposal: None,
                prover_url: self.prover_url().to_string(),
            },
        )?)
    }

    /// Build the transfer recipient descriptor from a recipient viewing key
    /// account. The recipient output hash needs only the recipient's
    /// `owner_pk_field` (the VKA `owner`), its `nullifier_pubkey`, and its viewing
    /// pubkey, so this works for both smart-account and P256-keypair recipients
    /// without the raw recipient signing key.
    pub(crate) fn transfer_recipient(
        &self,
        account: &ViewingKeyAccount,
    ) -> Result<SquadsTransferRecipient> {
        let viewing_pubkey = P256Pubkey::from_bytes(account.shared_viewing_key)
            .map_err(|e| SquadsBackendError::Keypair(format!("{e:?}")))?;
        Ok(SquadsTransferRecipient {
            owner_pk_field: account.owner.to_bytes(),
            nullifier_pubkey: account.nullifier_pubkey,
            viewing_pubkey,
        })
    }

    fn build_transfer_instruction(
        &self,
        intent: &PrivateTransactionIntent,
        proof: &SquadsTransferProof,
        recipient_vka: Address,
        sender_view_tag: [u8; 32],
        salt: [u8; 16],
    ) -> Result<solana_instruction::Instruction> {
        let recipient_account = self.load_viewing_key_account(recipient_vka)?;
        let recipient_view_tag =
            view_tag_from_shared_viewing_key(&recipient_account.shared_viewing_key);

        let ix_data = TransactIxData {
            zone_proof: proof.zone_proof,
            spp_proof: proof.spp_proof,
            public_amount: None,
            private_tx_hash: proof.private_tx_hash,
            expiry: intent.expiry,
            salt,
            output_view_tags: vec![sender_view_tag, recipient_view_tag],
            output_utxo_hashes: vec![proof.change_utxo_hash, proof.recipient_utxo_hash],
            input_contexts: proof
                .nullifiers
                .iter()
                .zip(proof.input_root_indices.iter())
                .map(
                    |(nullifier, (utxo_root_index, nullifier_root_index))| InputContext {
                        nullifier: *nullifier,
                        tree_index: 0,
                        utxo_root_index: *utxo_root_index,
                        nullifier_root_index: *nullifier_root_index,
                    },
                )
                .collect(),
            encrypted_utxos: EncryptedUtxos {
                tx_viewing_pk: proof.tx_viewing_pk,
                sender_ciphertext: proof.sender_ciphertext,
                recipient_ciphertexts: vec![proof.recipient_ciphertext],
            },
        };

        Ok(self.transact_instruction(
            intent.sender_viewing_key_account,
            Some(recipient_vka),
            None,
            ix_data,
        ))
    }

    /// Assemble the `transact` instruction with the backend's relayer as payer and
    /// co-signer and the derived zone authority / tree accounts.
    fn transact_instruction(
        &self,
        sender_viewing_key_account: Address,
        recipient_viewing_key_account: Option<Address>,
        withdrawal: Option<TransactWithdrawal>,
        data: TransactIxData,
    ) -> solana_instruction::Instruction {
        let relayer = self.relayer_pubkey();
        Transact {
            payer: relayer,
            co_signer: relayer,
            zone_config: to_pubkey(self.zone_config()),
            sender_viewing_key_account: to_pubkey(sender_viewing_key_account),
            recipient_viewing_key_account: recipient_viewing_key_account.map(to_pubkey),
            withdrawal,
            zone_auth: self.zone_auth_pubkey(),
            spp_program: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            tree_accounts: vec![to_pubkey(self.tree())],
            data,
        }
        .instruction()
    }
}
