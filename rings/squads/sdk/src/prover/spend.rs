//! Paired ring + SPP spend builder (gated under the `prover` feature).
//!
//! A squads spend is a `(2, 2)` transfer (sender change + one recipient output,
//! no public leg) or a `(1, 1)` withdrawal (sender change + one SOL/SPL
//! withdrawal leg). It forwards two proofs over one shared `private_tx_hash`:
//! 1. the squads ring proof ([`RingWitness`]), verified by the squads program;
//! 2. the SPP proof, verified by SPP after the `ring_auth`-signed CPI: the
//!    `AnonymousRingEddsa` rail ([`RingTransferProver`]) for a keypair owner, who signs
//!    `sha256(private_tx_hash || external_data_hash)`, or the `RingAuthority` rail
//!    ([`RingAuthorityProver`]) for a smart-account owner, whose spend the ring
//!    authorizes.
//!
//! Both proofs are built from the same UTXOs, external data and blinding seed,
//! so they agree by construction; [`ProbedSpend::finalize`] cross-checks the
//! shared hash. A spend is probed first ([`probe_squads_spend`]) so the Ed25519
//! owner can sign the returned message hash off-box.

use solana_instruction::AccountMeta;
use solana_pubkey::Pubkey;
use zolana_client::{
    input_utxos_from_nullifiers, NonInclusionProof, ProofAuthority, ProofCompressed, Prover,
    ProverClient, ProverExt, RingAuthorityProver, RingTransferProver, Shape, SpendProof,
    TransferInputUtxo,
};
use zolana_interface::{
    instruction::{
        tag::{RING_AUTHORITY_TRANSACT, RING_TRANSACT},
        CircuitId, OwnerTag, TransactIxData as SppTransactIxData, TransactOutput,
    },
    pda,
    verifying_keys::AnonymousRingEddsaProofData,
    N_PUBLIC_SLOTS, SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::{
    NullifierKey, PublicKey, ShieldedAddress, SigningKey, X25519Keypair, X25519Pubkey,
};
use zolana_program::instruction::{
    RingAuthorityTransact, RingTransact, TransactInterfaceTransferAccounts,
    TransactSolTransferAccounts, TransactSplWithdrawalAccounts,
};
use zolana_squads_interface::SQUADS_RING_PROGRAM_ID;
use zolana_transaction::{
    instructions::transact::{asset_field, CacheAccounts, SettlementTransfer, SppProofInputs},
    utxo::SppProofInputUtxo,
    Address, Data, ExternalData, Mint, SppProofOutputUtxo, Utxo, SOL_MINT,
};

use crate::prover::{
    error::SquadsProverError,
    ring::{
        right_align_u64, RingProofResult, RingProposal, RingRecipient, RingUtxo, RingWitness,
        UTXO_DOMAIN,
    },
};

/// How a squads UTXO owner authorizes its spends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SquadsOwner {
    /// Keypair owner: the SPP `AnonymousRingEddsa` rail; the owner signs
    /// `sha256(private_tx_hash || external_data_hash)` with this key.
    Ed25519([u8; 32]),
    /// Smart-account owner (a Squads vault): the SPP `RingAuthority` rail. The
    /// owner is known by its owner identity only.
    SmartAccount,
}

/// The spending account: its owner, its spend secrets and the tag its change
/// output is published under.
pub struct SquadsSender {
    pub owner: SquadsOwner,
    /// SPP owner identity, the viewing key account's `owner`.
    pub owner_identity: [u8; 32],
    pub nullifier_key: NullifierKey,
    /// The shared viewing secret; drives the change blinding and ciphertexts.
    pub viewing_secret: X25519Keypair,
    /// Owner tag of the change output.
    pub view_tag: [u8; 32],
}

impl SquadsSender {
    /// The owner as an SPP [`PublicKey`]: the Ed25519 key, or the precomputed
    /// identity of a smart-account owner.
    fn owner_key(&self) -> Result<PublicKey, SquadsProverError> {
        let key = match self.owner {
            SquadsOwner::Ed25519(pubkey) => PublicKey::from_ed25519(&pubkey),
            SquadsOwner::SmartAccount => PublicKey::from_owner_identity(self.owner_identity),
        };
        if key
            .owner_proof_input_hash()
            .map_err(|_| SquadsProverError::Poseidon)?
            != self.owner_identity
        {
            return Err(SquadsProverError::OwnerIdentityMismatch);
        }
        Ok(key)
    }
}

/// A deposited ring UTXO the sender spends, with its inclusion and nullifier
/// non-inclusion proofs.
pub struct SquadsSpendInput {
    pub asset: Address,
    pub amount: u64,
    pub blinding: [u8; 32],
    pub tree_id: u16,
    pub leaf_index: u64,
    pub spend_proof: SpendProof,
}

/// The padding slot of a single-input transfer: its blinding and the
/// non-inclusion proof of the dummy nullifier [`dummy_input`] derives from it,
/// under the real input's tree.
pub struct SquadsDummyInput {
    pub blinding: [u8; 32],
    pub nullifier_proof: NonInclusionProof,
}

/// The SPP dummy input for `blinding` in `tree_id`; its `nullifier` is what the
/// caller fetches a non-inclusion proof for.
pub fn dummy_input(
    blinding: [u8; 32],
    tree_id: u16,
) -> Result<SppProofInputUtxo, SquadsProverError> {
    SppProofInputUtxo::dummy_with_blinding(blinding, tree_id)
        .map_err(|_| SquadsProverError::Poseidon)
}

/// A transfer recipient, addressed by the public fields of its viewing key
/// account.
#[derive(Clone, Debug)]
pub struct SquadsRecipient {
    pub owner_identity: [u8; 32],
    pub nullifier_pubkey: [u8; 32],
    pub viewing_pubkey: X25519Pubkey,
    /// Owner tag of the recipient output.
    pub view_tag: [u8; 32],
}

/// Where a withdrawal settles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithdrawalSettlement {
    Sol {
        recipient: Address,
    },
    Spl {
        mint: Address,
        user_token_account: Address,
    },
}

impl WithdrawalSettlement {
    fn mint(self) -> Address {
        match self {
            Self::Sol { .. } => SOL_MINT,
            Self::Spl { mint, .. } => mint,
        }
    }

    fn transfer(self, amount: u64) -> SettlementTransfer {
        match self {
            Self::Sol { recipient } => SettlementTransfer::Sol {
                is_deposit: false,
                amount,
                user_sol_account: recipient,
            },
            Self::Spl {
                mint,
                user_token_account,
            } => SettlementTransfer::Spl {
                mint,
                is_deposit: false,
                amount,
                user_spl_token: user_token_account,
            },
        }
    }

    fn accounts(self) -> TransactInterfaceTransferAccounts {
        match self {
            Self::Sol { recipient } => {
                TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                    recipient: to_pubkey(&recipient),
                })
            }
            Self::Spl {
                mint,
                user_token_account,
            } => TransactInterfaceTransferAccounts::SplWithdrawal(TransactSplWithdrawalAccounts {
                mint: to_pubkey(&mint),
                spl_interface: pda::spl_interface(&to_pubkey(&mint)),
                user_token_account: to_pubkey(&user_token_account),
                token_program: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
            }),
        }
    }
}

/// The operation a spend performs.
#[derive(Clone, Debug)]
pub enum SquadsSpendOperation {
    Transfer {
        recipient: SquadsRecipient,
        amount: u64,
    },
    Withdrawal {
        amount: u64,
        settlement: WithdrawalSettlement,
    },
}

/// Everything a spend needs besides the Ed25519 authorization.
pub struct SquadsSpendRequest {
    pub sender: SquadsSender,
    /// One real input for a withdrawal; one or two for a transfer.
    pub inputs: Vec<SquadsSpendInput>,
    /// Required iff a transfer spends a single real input.
    pub dummy: Option<SquadsDummyInput>,
    pub operation: SquadsSpendOperation,
    /// The SPP fee payer (the relayer / backend).
    pub payer: Address,
    pub output_tree_id: u16,
    pub expiry_unix_ts: u64,
    /// A bound proposal for `execute_proposal`; `None` for a sync `transact`.
    pub proposal: Option<RingProposal>,
    pub prover_url: String,
}

/// A spend with every signature-independent step done. A Ed25519 owner signs
/// [`Self::message_hash`] and passes the signature to [`Self::finalize`].
pub struct ProbedSpend {
    /// `sha256(private_tx_hash || external_data_hash)`, the digest a Ed25519 owner signs.
    pub message_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    sender: SquadsSender,
    spp_inputs: SppProofInputs,
    spend_proofs: Vec<SpendProof>,
    dummy_nullifier_proof: Option<NonInclusionProof>,
    ring: RingWitness,
    shape: Shape,
    tag: u8,
    input_tree_ids: Vec<u16>,
    settlement: Option<WithdrawalSettlement>,
    prover_url: String,
}

/// The paired proofs and the forwarded SPP payload of a spend.
pub struct SquadsSpendProof {
    pub ring_proof: [u8; 192],
    /// The complete SPP `ring_transact` / `ring_authority_transact` payload.
    pub spp: SppTransactIxData,
    /// The SPP account list for [`Self::spp`], as the squads builders forward it.
    pub spp_accounts: Vec<AccountMeta>,
    pub private_tx_hash: [u8; 32],
    pub proposal_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub change: SpentOutput,
    /// The recipient output of a transfer.
    pub recipient: Option<SpentOutput>,
}

/// A created output of a spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpentOutput {
    pub utxo_hash: [u8; 32],
    pub amount: u64,
    pub blinding: [u8; 32],
}

fn squads_program() -> Address {
    Address::new_from_array(SQUADS_RING_PROGRAM_ID)
}

fn to_pubkey(address: &Address) -> Pubkey {
    Pubkey::new_from_array(address.to_bytes())
}

fn mint_of(asset: Address) -> Mint {
    if asset == SOL_MINT {
        Mint::SOL
    } else {
        Mint::new(asset, 0)
    }
}

fn tx_err<E>(_: E) -> SquadsProverError {
    SquadsProverError::Poseidon
}

/// Build every signature-independent part of a spend.
pub fn probe_squads_spend(request: SquadsSpendRequest) -> Result<ProbedSpend, SquadsProverError> {
    let SquadsSpendRequest {
        sender,
        inputs,
        dummy,
        operation,
        payer,
        output_tree_id,
        expiry_unix_ts,
        proposal,
        prover_url,
    } = request;

    let is_transfer = matches!(operation, SquadsSpendOperation::Transfer { .. });
    let real_count = inputs.len();
    let shape_inputs = real_count + usize::from(dummy.is_some());
    let valid = if is_transfer {
        (real_count == 2 && dummy.is_none()) || (real_count == 1 && dummy.is_some())
    } else {
        real_count == 1 && dummy.is_some() == matches!(sender.owner, SquadsOwner::SmartAccount)
    };
    if !valid {
        return Err(SquadsProverError::UnsupportedShape(
            shape_inputs,
            if is_transfer { 2 } else { 1 },
        ));
    }

    let owner = sender.owner_key()?;
    let nullifier_pubkey = sender.nullifier_key.pubkey().map_err(tx_err)?;
    let asset = inputs
        .first()
        .ok_or(SquadsProverError::UnsupportedShape(0, 0))?
        .asset;
    if inputs.iter().any(|input| input.asset != asset) {
        return Err(SquadsProverError::InputAssetMismatch);
    }
    if let SquadsSpendOperation::Withdrawal { settlement, .. } = &operation {
        if settlement.mint() != asset {
            return Err(SquadsProverError::InputAssetMismatch);
        }
    }
    let mint = mint_of(asset);
    let asset_fe = asset_field(&asset).map_err(tx_err)?;
    let ring_program_id = squads_program();
    let ring_program_fe =
        zolana_hasher::primitives::hash_bytes(ring_program_id.as_array()).map_err(tx_err)?;

    let total_in = inputs
        .iter()
        .try_fold(0u64, |acc, input| acc.checked_add(input.amount))
        .ok_or(SquadsProverError::InvalidAmount)?;
    let spent = match &operation {
        SquadsSpendOperation::Transfer { amount, .. }
        | SquadsSpendOperation::Withdrawal { amount, .. } => *amount,
    };
    let change_amount = total_in
        .checked_sub(spent)
        .ok_or(SquadsProverError::InvalidAmount)?;

    // --- inputs, SPP and ring representations ---
    let mut spp_inputs = Vec::with_capacity(2);
    let mut ring_inputs = Vec::with_capacity(2);
    let mut spend_proofs = Vec::with_capacity(2);
    let mut input_tree_ids: Vec<u16> = Vec::with_capacity(2);
    for input in inputs {
        let utxo = Utxo {
            owner,
            asset: mint,
            amount: input.amount,
            blinding: input.blinding,
            ring_program_id: Some(ring_program_id),
            data: Data::default(),
        };
        let utxo_hash = utxo
            .hash(&nullifier_pubkey, &[0u8; 32], &[0u8; 32], input.tree_id)
            .map_err(tx_err)?;
        let nullifier = sender
            .nullifier_key
            .nullifier(&utxo_hash, &input.blinding)
            .map_err(tx_err)?;
        spp_inputs.push(SppProofInputUtxo {
            utxo,
            nullifier_pubkey,
            utxo_hash,
            nullifier,
            data_hash: None,
            ring_data_hash: None,
            tree_id: input.tree_id,
            leaf_index: input.leaf_index,
            cache_slot: None,
            compact: false,
            address: false,
        });
        ring_inputs.push(RingUtxo {
            domain: UTXO_DOMAIN,
            tree_id: input.tree_id,
            owner_key_hash: sender.owner_identity,
            nullifier_pubkey,
            asset: asset_fe,
            amount: input.amount,
            blinding: input.blinding,
            program_data_hash: [0u8; 32],
            ring_data_hash: [0u8; 32],
            ring_program_id: ring_program_fe,
        });
        if !input_tree_ids.contains(&input.tree_id) {
            input_tree_ids.push(input.tree_id);
        }
        spend_proofs.push(input.spend_proof);
    }
    let dummy_nullifier_proof = match dummy {
        Some(dummy) => {
            let tree_id = *input_tree_ids
                .last()
                .ok_or(SquadsProverError::UnsupportedShape(0, 0))?;
            spp_inputs.push(dummy_input(dummy.blinding, tree_id)?);
            if is_transfer {
                ring_inputs.push(RingUtxo::dummy(tree_id, dummy.blinding));
            }
            Some(dummy.nullifier_proof)
        }
        None => None,
    };

    let first_nullifier = spp_inputs
        .first()
        .ok_or(SquadsProverError::UnsupportedShape(0, 0))?
        .nullifier;
    let secrets =
        crate::prover::ring::derive_spend_secrets(&sender.viewing_secret, &first_nullifier)?;

    // --- outputs: change first, then the transfer recipient ---
    let sender_viewing_pubkey = sender.viewing_secret.pubkey();
    let change_spp = SppProofOutputUtxo {
        asset: mint,
        amount: change_amount,
        blinding: secrets.change_blinding,
        ring_program_id: Some(ring_program_id),
        ring_data_hash: None,
        data_hash: None,
        owner_address: Some(ShieldedAddress {
            signing_pubkey: owner,
            nullifier_pubkey,
            viewing_pubkey: sender_viewing_pubkey,
        }),
        owner_tag: Some(sender.view_tag),
        data: Data::default(),
        cache_slot: None,
        compact: false,
    };
    let change_ring = RingUtxo {
        domain: UTXO_DOMAIN,
        tree_id: output_tree_id,
        owner_key_hash: sender.owner_identity,
        nullifier_pubkey,
        asset: asset_fe,
        amount: change_amount,
        blinding: secrets.change_blinding,
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: ring_program_fe,
    };
    let mut spp_outputs = vec![change_spp];
    let mut ring_outputs = vec![change_ring];
    let mut output_tags = vec![sender.view_tag];

    let (ring_recipient, settlement, public_amount, interface_transfers) = match &operation {
        SquadsSpendOperation::Transfer { recipient, amount } => {
            spp_outputs.push(SppProofOutputUtxo {
                asset: mint,
                amount: *amount,
                blinding: secrets.recipient_blinding,
                ring_program_id: Some(ring_program_id),
                ring_data_hash: None,
                data_hash: None,
                owner_address: Some(ShieldedAddress {
                    signing_pubkey: PublicKey::from_owner_identity(recipient.owner_identity),
                    nullifier_pubkey: recipient.nullifier_pubkey,
                    viewing_pubkey: recipient.viewing_pubkey,
                }),
                owner_tag: Some(recipient.view_tag),
                data: Data::default(),
                cache_slot: None,
                compact: false,
            });
            ring_outputs.push(RingUtxo {
                domain: UTXO_DOMAIN,
                tree_id: output_tree_id,
                owner_key_hash: recipient.owner_identity,
                nullifier_pubkey: recipient.nullifier_pubkey,
                asset: asset_fe,
                amount: *amount,
                blinding: secrets.recipient_blinding,
                program_data_hash: [0u8; 32],
                ring_data_hash: [0u8; 32],
                ring_program_id: ring_program_fe,
            });
            output_tags.push(recipient.view_tag);
            let ring_recipient = RingRecipient {
                owner_key_hash: recipient.owner_identity,
                nullifier_pubkey: recipient.nullifier_pubkey,
                viewing_pubkey: recipient.viewing_pubkey,
            };
            (Some(ring_recipient), None, [0u8; 32], Vec::new())
        }
        SquadsSpendOperation::Withdrawal { amount, settlement } => (
            None,
            Some(*settlement),
            right_align_u64(*amount),
            vec![settlement.transfer(*amount)],
        ),
    };

    let ciphertexts = crate::prover::ring::encrypt_spend_outputs(
        &secrets,
        ring_outputs.first().ok_or(SquadsProverError::Poseidon)?,
        match (&ring_recipient, ring_outputs.get(1)) {
            (Some(recipient), Some(output)) => Some((recipient, output)),
            _ => None,
        },
    )?;
    let mut output_data = vec![ciphertexts.sender.clone()];
    if let Some(recipient_ciphertext) = &ciphertexts.recipient {
        output_data.push(recipient_ciphertext.clone());
    }
    let outputs = spp_outputs
        .iter()
        .zip(output_tags.iter())
        .zip(output_data)
        .map(|((output, tag), data)| {
            Ok(TransactOutput {
                utxo_hash: output.hash(output_tree_id).map_err(tx_err)?,
                owner_tag: OwnerTag::Inline(*tag),
                data: Some(data),
            })
        })
        .collect::<Result<Vec<_>, SquadsProverError>>()?;

    let tag = match sender.owner {
        SquadsOwner::Ed25519(_) => RING_TRANSACT,
        SquadsOwner::SmartAccount => RING_AUTHORITY_TRANSACT,
    };
    let external_data = ExternalData {
        instruction_discriminator: tag,
        expiry_unix_ts,
        interface_transfers,
        data_hash: None,
        ring_data_hash: None,
        tx_viewing_pk: secrets.tx_viewing_pk,
        salt: [0u8; 16],
        outputs,
        resolved_owner_tags: output_tags,
        messages: Vec::new(),
    };
    let external_data_hash = external_data.hash().map_err(tx_err)?;

    let ring = RingWitness {
        viewing_secret_key: sender.viewing_secret.clone(),
        nullifier_secret: nullifier_secret_field(&sender.nullifier_key),
        inputs: ring_inputs,
        outputs: ring_outputs,
        external_data_hash,
        recipient: ring_recipient,
        proposal,
        public_amount,
    };
    let private_tx_hash = ring.private_tx_hash()?;

    let spp_inputs = SppProofInputs {
        input_utxos: spp_inputs,
        output_utxos: spp_outputs,
        blinding_seed: secrets.blinding_seed,
        output_tree_id,
        external_data,
        payer,
        cache_accounts: CacheAccounts::default(),
    };
    let message_hash = spp_inputs.message_hash().map_err(tx_err)?;
    if message_hash
        != zolana_transaction::instructions::transact::transact_message_hash(
            &private_tx_hash,
            &external_data_hash,
        )
    {
        return Err(SquadsProverError::PrivateTxHashMismatch);
    }
    let mut spp_inputs = spp_inputs;
    if !is_transfer {
        spp_inputs.output_utxos.push(SppProofOutputUtxo {
            blinding: secrets.recipient_blinding,
            compact: true,
            ..Default::default()
        });
    }
    let shape = Shape::new(shape_inputs, spp_inputs.output_utxos.len());

    Ok(ProbedSpend {
        message_hash,
        private_tx_hash,
        sender,
        spp_inputs,
        spend_proofs,
        dummy_nullifier_proof,
        ring,
        shape,
        tag,
        input_tree_ids,
        settlement,
        prover_url,
    })
}

/// The nullifier secret as the 32-byte field element the circuits witness.
fn nullifier_secret_field(nullifier_key: &NullifierKey) -> [u8; 32] {
    let secret = nullifier_key.secret();
    let mut field = [0u8; 32];
    if let Some(dst) = field.get_mut(1..) {
        dst.copy_from_slice(secret.as_slice());
    }
    field
}

/// Sign a probed spend's message hash with the owner's Ed25519 key.
pub fn sign_spend(
    signing_key: &SigningKey,
    message_hash: &[u8; 32],
) -> Result<[u8; 64], SquadsProverError> {
    signing_key
        .sign_message(message_hash)
        .map_err(|_| SquadsProverError::InvalidProofEncoding)
}

impl ProbedSpend {
    /// Prove both legs. `authorization` is the Ed25519 owner's signature over
    /// [`Self::message_hash`]; a smart-account spend takes `None`.
    pub fn finalize(
        self,
        authorization: Option<[u8; 64]>,
    ) -> Result<SquadsSpendProof, SquadsProverError> {
        let prover = ProverClient::new(self.prover_url.clone());
        let transfer_inputs: Vec<TransferInputUtxo> = zolana_client::attach_input_proofs(
            self.spp_inputs.input_utxos.clone(),
            &self.spend_proofs,
            self.dummy_nullifier_proof.as_slice(),
        )
        .map_err(spp_err)?;
        let public_transfers = self.spp_inputs.public_transfers().map_err(tx_err)?;
        // SPP publishes the dummy-input flag from the input trees' headroom,
        // whether or not this spend pads with a dummy.
        let allow_dummy_inputs = true;
        let ring_program_id = Some(squads_program());
        let (n_inputs, n_outputs) = (self.shape.n_inputs(), self.shape.n_outputs());
        let n_inputs = u8::try_from(n_inputs).map_err(tx_err)?;
        let n_outputs = u8::try_from(n_outputs).map_err(tx_err)?;

        let (proof, circuit, private_tx_hash, nullifiers, tree_contexts, input_tree_indexes) =
            match (self.sender.owner, authorization) {
                (SquadsOwner::Ed25519(owner_public_key), Some(authorization)) => {
                    let mut result = RingTransferProver {
                        inputs: transfer_inputs,
                        outputs: self.spp_inputs.output_utxos.clone(),
                        blinding_seed: self.spp_inputs.blinding_seed,
                        output_tree_id: self.spp_inputs.output_tree_id,
                        external_data: self.spp_inputs.external_data.clone(),
                        public_transfers,
                        signer_pk_hashes: zolana_client::prover::transact::anonymous_ring_eddsa::anonymous_signer_pk_hashes(
                            &self.spp_inputs, &self.sender.owner_key()?,
                        )
                            .map_err(tx_err)?,
                        allow_dummy_inputs,
                        ring_program_id,
                        shape: self.shape,
                    }
                    .build_anonymous(owner_public_key, authorization)
                    .map_err(spp_err)?;
                    self.sender
                        .nullifier_key
                        .complete_inputs(&mut result.inputs.transfer.inputs)
                        .map_err(spp_err)?;
                    let proof = prover.prove(&result.inputs).map_err(spp_err)?;
                    let (proof, bsb22_commitment) = ProofCompressed::try_from(proof)
                        .map_err(spp_err)?
                        .into_committed_transact_parts()
                        .map_err(spp_err)?;
                    let circuit = CircuitId::AnonymousRingEddsa(
                        n_inputs,
                        n_outputs,
                        N_PUBLIC_SLOTS as u8,
                        AnonymousRingEddsaProofData {
                            bsb22_commitment,
                            default_owner_tag: result.default_owner_tag,
                        },
                    );
                    (
                        proof,
                        circuit,
                        result.private_tx_hash,
                        result.nullifiers,
                        result.tree_contexts,
                        result.input_tree_indexes,
                    )
                }
                (SquadsOwner::SmartAccount, None) => {
                    let mut result = RingAuthorityProver {
                        inputs: transfer_inputs,
                        outputs: self.spp_inputs.output_utxos.clone(),
                        blinding_seed: self.spp_inputs.blinding_seed,
                        output_tree_id: self.spp_inputs.output_tree_id,
                        external_data: self.spp_inputs.external_data.clone(),
                        public_transfers,
                        payer: self.spp_inputs.payer,
                        allow_dummy_inputs,
                        ring_program_id,
                        shape: self.shape,
                    }
                    .build()
                    .map_err(spp_err)?;
                    self.sender
                        .nullifier_key
                        .complete_inputs(&mut result.inputs.inputs)
                        .map_err(spp_err)?;
                    let proof = prover
                        .prove_ring_authority(&result.inputs)
                        .map_err(spp_err)?;
                    let proof = ProofCompressed::try_from(proof)
                        .map_err(spp_err)?
                        .to_transact_proof();
                    let circuit =
                        CircuitId::RingAuthority(n_inputs, n_outputs, N_PUBLIC_SLOTS as u8);
                    (
                        proof,
                        circuit,
                        result.private_tx_hash,
                        result.nullifiers,
                        result.tree_contexts,
                        result.input_tree_indexes,
                    )
                }
                _ => return Err(SquadsProverError::AuthorizationMismatch),
            };
        if private_tx_hash != self.private_tx_hash {
            return Err(SquadsProverError::PrivateTxHashMismatch);
        }

        let ring: RingProofResult = self.ring.prove()?;
        if ring.private_tx_hash != private_tx_hash {
            return Err(SquadsProverError::PrivateTxHashMismatch);
        }

        let external_data = &self.spp_inputs.external_data;
        let spp = SppTransactIxData {
            expiry_unix_ts: external_data.expiry_unix_ts,
            tx_viewing_pk: external_data.tx_viewing_pk,
            salt: external_data.salt,
            interface_transfers: external_data
                .interface_transfers
                .iter()
                .map(|transfer| transfer.interface_transfer())
                .collect(),
            data_hash: external_data.data_hash,
            ring_data_hash: external_data.ring_data_hash,
            outputs: external_data.outputs.clone(),
            messages: external_data.messages.clone(),
            private_tx_hash,
            circuit,
            proof,
            inputs: input_utxos_from_nullifiers(&nullifiers, &input_tree_indexes)
                .map_err(spp_err)?,
            tree_contexts,
        };
        let spp_accounts = spp_accounts(
            self.tag,
            &self.spp_inputs.payer,
            &self.input_tree_ids,
            self.spp_inputs.output_tree_id,
            self.settlement,
            &spp,
        );

        let output = |index: usize| -> Option<SpentOutput> {
            let utxo = self.spp_inputs.output_utxos.get(index)?;
            let utxo_hash = spp.outputs.get(index)?.utxo_hash;
            Some(SpentOutput {
                utxo_hash,
                amount: utxo.amount,
                blinding: utxo.blinding,
            })
        };
        let change = output(0).ok_or(SquadsProverError::Poseidon)?;
        let recipient = output(1);
        Ok(SquadsSpendProof {
            ring_proof: ring.proof,
            spp_accounts,
            private_tx_hash,
            proposal_hash: ring.proposal_hash,
            nullifiers,
            change,
            recipient,
            spp,
        })
    }
}

/// The SPP account list of a squads spend: the `zolana_program` ring builder's
/// ring-program-targeted account list, which the squads program forwards to SPP
/// unchanged.
fn spp_accounts(
    tag: u8,
    payer: &Address,
    input_tree_ids: &[u16],
    output_tree_id: u16,
    settlement: Option<WithdrawalSettlement>,
    data: &SppTransactIxData,
) -> Vec<AccountMeta> {
    let payer = to_pubkey(payer);
    let input_trees: Vec<Pubkey> = input_tree_ids.iter().map(|id| pda::tree(*id)).collect();
    let output_tree = pda::tree(output_tree_id);
    let ring_program_id = Pubkey::new_from_array(SQUADS_RING_PROGRAM_ID);
    let interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts> = settlement
        .map(WithdrawalSettlement::accounts)
        .into_iter()
        .collect();
    let instruction = if tag == RING_TRANSACT {
        RingTransact {
            payer,
            input_trees,
            output_tree,
            ring_program_id,
            owner_signers: Vec::new(),
            interface_transfer_accounts,
            data: data.clone(),
        }
        .instruction()
    } else {
        RingAuthorityTransact {
            payer,
            input_trees,
            output_tree,
            ring_program_id,
            interface_transfer_accounts,
            data: data.clone(),
        }
        .instruction()
    };
    instruction.accounts
}

pub(crate) fn spp_err(e: zolana_client::ClientError) -> SquadsProverError {
    SquadsProverError::Prover(format!("spp prover: {e}"))
}

#[cfg(test)]
#[path = "spend_tests.rs"]
mod tests;
