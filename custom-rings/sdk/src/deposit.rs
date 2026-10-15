use custom_ring_interface::{
    tag, AuditedDepositPrefix, CustomRingProof, DepositContext, DepositPublicInput,
    RingDepositAuditCapsule, MAX_RING_DEPOSIT_AUDIT_SLOTS,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_signature::Signature;
use solana_signer::Signer;
use zeroize::Zeroizing;
use zolana_client::{
    fetch_asset_id_async,
    prover::indexed::{IndexedDepositRequest, IndexedRegistry},
    AsyncIndexer, AsyncRpc, AsyncZolanaClient, ComputeBudgetConfig,
};
use zolana_keypair::{random_blinding, P256Pubkey, ShieldedKeypair};
use zolana_program::instruction::{DepositAsset, DepositBuildError, RingAssetDeposit};
use zolana_ring_client::{seal_deposits, DepositEncryption, DepositOpening};
use zolana_transaction::{owner_utxo_hash, Data, Mint, RingDepositPlaintext, Utxo};

use crate::{
    escrow::{EscrowedKeys, KeyRegistry, OutputKey},
    projection::retry_projection_lag,
    prover::{RingCircuit, RingRequest},
    request::DepositBody,
    submission::BoundRoot,
    to_instruction_proof,
    transact_ix::{ring_prefix, window_metas},
    CustomRing, EscrowBinding, RingError, RingSubmission, SettledSubmission,
};

#[must_use]
pub struct RingDeposit<'a> {
    pub ring: CustomRing,
    /// Lamport source for Sol, the user token's authority for Spl.
    pub payer: &'a (dyn Signer + Sync),
    pub recipient: &'a ShieldedKeypair,
    pub tree: Address,
    pub asset: DepositAsset,
    pub amount: u64,
    /// The ring's co-signer when its scope covers deposits.
    pub cosigner: Option<&'a (dyn Signer + Sync)>,
}

pub struct RingDepositReceipt {
    pub signature: Signature,
    pub utxo: Utxo,
}

/// A deposit whose note and auditor ciphertext are fixed, the proof is not.
pub struct PreparedRingDeposit {
    ring: CustomRing,
    tree: Address,
    depositor: Address,
    cosigner: Option<Address>,
    deposit: RingAssetDeposit,
    utxo: Utxo,
    /// `None` for an undisclosed deposit.
    disclosure: Option<DepositDisclosure>,
}

struct DepositDisclosure {
    context_hash: [u8; 32],
    owner_utxo_hash: [u8; 32],
    key: OutputKey,
    blinding: Zeroizing<[u8; 32]>,
    encryption: DepositEncryption,
    auditor: P256Pubkey,
    key_registry: Option<KeyRegistry>,
}

/// An enabled deposit audit requires a proof bound to the exact SPP payload.
#[must_use]
pub struct Deposit {
    pub ring: CustomRing,
    pub tree: Address,
    /// Funds the deposit, writable and a signer for SOL.
    pub depositor: Address,
    pub deposits: Vec<RingAssetDeposit>,
    pub proof: Option<CustomRingProof>,
    pub escrow: EscrowBinding,
    pub cosigner: Option<Address>,
}

impl RingDeposit<'_> {
    /// Fixes the note, every proving attempt deposits the same one.
    pub async fn prepare(
        &self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<PreparedRingDeposit, RingError> {
        let mint = self.asset.mint();
        let mint = Mint::new(mint, fetch_asset_id_async(rpc, mint).await?);
        let config = self
            .ring
            .config(rpc)
            .await?
            .ok_or(RingError::MissingRingConfig)?;
        let blinding = random_blinding();
        let owner_hash = self.recipient.owner_hash()?;
        let mut deposit = RingAssetDeposit {
            asset: self.asset,
            view_tag: self.recipient.recipient_bootstrap_view_tag(),
            owner_utxo_hash: owner_utxo_hash(&owner_hash, &blinding)?,
            amount: self.amount,
            ring_data_hash: [0; 32],
            encrypted: RingDepositPlaintext {
                blinding,
                utxo_data: None,
                memo: None,
                ring_data: Vec::new(),
            }
            .encrypt(&self.recipient.viewing_pubkey())?,
        };
        let key_registry = KeyRegistry::of(self.ring, &config);
        let disclosure = if key_registry.is_some() || self.ring.deposit_audit(rpc).await? {
            let opening = DepositOpening {
                owner_hash,
                blinding: Zeroizing::new(blinding),
            };
            let encryption = seal_deposits(&[opening], &config.auditor_pubkey)?;
            deposit.encrypted.ciphertext = RingDepositAuditCapsule {
                slot_index: 0,
                eph_pk: encryption.ephemeral_pk.as_bytes(),
                ciphertext: &encryption.ciphertexts[0],
                recipient_ciphertext: &deposit.encrypted.ciphertext,
            }
            .encode();
            // The proof binds the ring, the tree and the exact forwarded SPP bytes.
            let spp = zolana_program::instruction::RingDeposit {
                tree: self.tree,
                depositor: self.payer.pubkey(),
                ring_program_id: self.ring.program_id(),
                deposits: vec![deposit.clone()],
            }
            .instruction()?;
            let address = self.recipient.shielded_address()?;
            Some(DepositDisclosure {
                context_hash: DepositContext {
                    program_id: self.ring.program_id().as_array(),
                    tree: self.tree.as_array(),
                    spp_data: &spp.data,
                }
                .hash()?,
                owner_utxo_hash: deposit.owner_utxo_hash,
                key: OutputKey {
                    owner_pk_hash: address.signing_pubkey.owner_proof_input_hash()?,
                    nullifier_pk: address.nullifier_pubkey,
                },
                blinding: Zeroizing::new(blinding),
                encryption,
                auditor: config.auditor_pubkey,
                key_registry,
            })
        } else {
            None
        };
        Ok(PreparedRingDeposit {
            ring: self.ring,
            tree: self.tree,
            depositor: self.payer.pubkey(),
            cosigner: self.cosigner.map(|cosigner| cosigner.pubkey()),
            deposit,
            utxo: Utxo {
                owner: self.recipient.signing_pubkey(),
                asset: mint,
                amount: self.amount,
                blinding,
                ring_program_id: Some(self.ring.program_id()),
                data: Data::default(),
            },
            disclosure,
        })
    }

    /// Prepares, proves, signs and settles the deposit.
    pub async fn send<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<RingDepositReceipt, RingError> {
        let prepared = self.prepare(client).await?;
        let utxo = prepared.utxo.clone();
        let signers: Vec<_> = self.cosigner.into_iter().collect();
        match RingSubmission::new(prepared)
            .send_until_settled(client, self.payer, &signers)
            .await?
        {
            SettledSubmission::Confirmed { signature, .. } => {
                Ok(RingDepositReceipt { signature, utxo })
            }
            SettledSubmission::Failed { signature, error } => {
                Err(RingError::Rejected { signature, error })
            }
        }
    }
}

impl PreparedRingDeposit {
    pub fn utxo(&self) -> &Utxo {
        &self.utxo
    }

    pub fn budget(&self) -> ComputeBudgetConfig {
        match self.disclosure {
            Some(_) => ComputeBudgetConfig::new(custom_ring_interface::compute_unit_limit(
                custom_ring_interface::InstructionTag::AuditedDeposit,
            )),
            None => ComputeBudgetConfig::for_instruction_count(1),
        }
    }

    /// A stale key-registry root re-proves the prepared note under a fresh root.
    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<Instruction, RingError> {
        Ok(self.prove_bound(client).await?.0)
    }

    /// The instruction and the registry root its proof binds.
    pub(crate) async fn prove_bound<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<(Instruction, Option<BoundRoot>), RingError> {
        let Some(disclosure) = &self.disclosure else {
            return self.instruction(None, None);
        };
        retry_projection_lag(|| async {
            let indexed = client.indexed_prover();
            // An escrowed ring proves the recipient's key is enrolled.
            let escrow = match disclosure.key_registry {
                Some(registry) if indexed.is_some() => Some(registry.pending(client).await?),
                Some(registry) => Some(registry.openings(client, &[Some(disclosure.key)]).await?),
                None => None,
            };
            let body = disclosure.body(escrow.as_ref())?;
            let proof = match (indexed, &escrow) {
                (Some(prover), Some(escrow)) => {
                    let registry = IndexedRegistry {
                        ring_program_id: self.ring.program_id(),
                        root: escrow.root.root,
                        next_index: escrow.root.next_index,
                    };
                    let request = IndexedDepositRequest::new(&RingRequest(&*body), registry)?;
                    let proof = prover.prove_indexed(&request).await?;
                    RingCircuit::Deposit.verify(&proof, body.public_input_hash)?;
                    proof
                }
                _ => client.prove_request(&RingRequest(&*body)).await?,
            };
            self.instruction(Some(to_instruction_proof(proof)?), escrow)
        })
        .await
    }

    fn instruction(
        &self,
        proof: Option<CustomRingProof>,
        escrow: Option<EscrowedKeys>,
    ) -> Result<(Instruction, Option<BoundRoot>), RingError> {
        let escrow = EscrowBinding::of(escrow.map(|escrow| escrow.root));
        let instruction = Deposit {
            ring: self.ring,
            tree: self.tree,
            depositor: self.depositor,
            deposits: vec![self.deposit.clone()],
            proof,
            escrow,
            cosigner: self.cosigner,
        }
        .instruction()?;
        Ok((instruction, BoundRoot::of(self.ring, escrow)))
    }
}

impl DepositDisclosure {
    fn body(&self, escrow: Option<&EscrowedKeys>) -> Result<Box<DepositBody>, RingError> {
        let root = escrow.map(|escrow| escrow.root.root);
        let public_input_hash = DepositPublicInput {
            context_hash: &self.context_hash,
            owner_utxo_hashes: &[self.owner_utxo_hash],
            ciphertexts: &self.encryption.ciphertexts,
            auditor_pk: self.auditor.as_bytes(),
            eph_pk: self.encryption.ephemeral_pk.as_bytes(),
            key_registry_root: root.as_ref(),
        }
        .hash()?;
        let mut keys = [None; MAX_RING_DEPOSIT_AUDIT_SLOTS];
        if let Some(escrow) = escrow {
            keys[..escrow.keys.len()].copy_from_slice(&escrow.keys);
        }
        let first = |value: [u8; 32]| {
            let mut slots = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
            slots[0] = value;
            slots
        };
        Ok(Box::new(DepositBody {
            circuit_type: RingCircuit::Deposit,
            public_input_hash,
            context_hash: self.context_hash,
            count: 1,
            owner_pk_hashes: first(self.key.owner_pk_hash),
            nullifier_pks: first(self.key.nullifier_pk),
            blindings: Zeroizing::new(first(*self.blinding)),
            keys,
            ephemeral_sk: self.encryption.ephemeral_sk.clone(),
            auditor_pk: self.auditor,
            key_escrow: root.is_some(),
            key_registry_root: root.unwrap_or_default(),
        }))
    }
}

impl Deposit {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        if self.proof.is_none() && self.escrow != EscrowBinding::Off {
            return Err(RingError::AuditRequired);
        }
        if self.proof.is_some() && self.deposits.len() > MAX_RING_DEPOSIT_AUDIT_SLOTS {
            return Err(DepositBuildError::TooManyEntries {
                count: self.deposits.len(),
                max: MAX_RING_DEPOSIT_AUDIT_SLOTS,
            }
            .into());
        }
        let windows = window_metas(self.ring, settled_mints(&self.deposits));
        let mut instruction = zolana_program::instruction::RingDeposit {
            tree: self.tree,
            depositor: self.depositor,
            ring_program_id: self.ring.program_id(),
            deposits: self.deposits,
        }
        .instruction()?;
        if let Some(proof) = self.proof {
            let prefix = AuditedDepositPrefix {
                tag: tag::AUDITED_DEPOSIT,
                proof,
                key_registry_root_index: self.escrow.root_index(),
            };
            instruction.data = [bytemuck::bytes_of(&prefix), &instruction.data].concat();
        }
        let mut prefix = ring_prefix(self.ring, self.cosigner).to_vec();
        prefix.push(AccountMeta::new_readonly(
            self.ring.deposit_audit_pda(),
            false,
        ));
        prefix.extend(self.escrow.meta(self.ring));
        prefix.extend(windows);
        instruction.accounts.splice(0..0, prefix);
        Ok(instruction)
    }
}

/// SPP settles SOL first, then each SPL mint in first appearance, the windows follow that order.
fn settled_mints(deposits: &[RingAssetDeposit]) -> Vec<Address> {
    let mut mints = Vec::new();
    if deposits
        .iter()
        .any(|deposit| matches!(deposit.asset, DepositAsset::Sol))
    {
        mints.push(Address::default());
    }
    for deposit in deposits {
        if let DepositAsset::Spl(accounts) = deposit.asset {
            if !mints.contains(&accounts.mint) {
                mints.push(accounts.mint);
            }
        }
    }
    mints
}
