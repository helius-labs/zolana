use custom_ring_interface::{
    tag, AuditedDepositPrefix, CustomRingProof, DepositContext, DepositPublicInput, EscrowKey,
    RingDepositAuditCapsule, RingMode, MAX_RING_DEPOSIT_AUDIT_SLOTS,
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
use zolana_interface::merge_utils::ciphertext_hash;
use zolana_keypair::{random_blinding, Curve, ShieldedKeypair, X25519Pubkey};
use zolana_program::instruction::{DepositAsset, DepositBuildError, RingAssetDeposit};
use zolana_ring_client::{seal_deposits, DepositEncryption, DepositOpening};
use zolana_ring_policy::Member;
use zolana_transaction::{owner_utxo_hash, Data, Mint, RingDepositPlaintext, Utxo};

use crate::{
    member_registry::{ReadMemberRecord, RecordOpening},
    projection::retry_projection_lag,
    prover::{RingCircuit, RingRequest},
    request::{DepositBody, RecordWitness},
    submission::BoundRoot,
    to_instruction_proof,
    transact_ix::ring_prefix,
    CurrentRegistryRoot, CustomRing, EscrowBinding, RingError, RingSubmission, SettledSubmission,
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
    /// Every ring deposit carries a proof-bound auditor disclosure.
    disclosure: DepositDisclosure,
}

struct DepositDisclosure {
    /// The Ed25519 owner key an anonymous ring discloses, the proof binds it to the owner hash.
    owner_key: Option<[u8; 32]>,
    context_hash: [u8; 32],
    owner_utxo_hash: [u8; 32],
    key: OutputKey,
    blinding: Zeroizing<[u8; 32]>,
    encryption: DepositEncryption,
    auditor: X25519Pubkey,
    /// The recipient's record must escrow the key the note uses.
    escrow: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OutputKey {
    owner_pk_hash: [u8; 32],
    nullifier_pk: [u8; 32],
}

/// The recipient's record as the deposit circuit opens it.
struct EscrowedRecord {
    witness: RecordWitness,
    ct_hash: [u8; 32],
}

/// A ring deposit requires a proof bound to the exact SPP payload.
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
        let anonymous = config.mode == RingMode::Anonymous;
        // An anonymous ring spends only through the hidden Ed25519 proof.
        if anonymous && self.recipient.signing_pubkey().curve()? != Curve::Ed25519 {
            return Err(RingError::AnonymousRecipient);
        }
        if anonymous {
            let owner = self.recipient.pubkey();
            if self.payer.pubkey() == owner
                || self.cosigner.is_some_and(|signer| signer.pubkey() == owner)
            {
                return Err(RingError::AnonymousPublicSignerLinksOwner);
            }
        }
        let blinding = random_blinding();
        let owner_hash = self.recipient.owner_hash()?;
        let mut deposit = RingAssetDeposit {
            asset: self.asset,
            view_tag: match anonymous {
                true => [0; 32],
                false => self.recipient.recipient_bootstrap_view_tag(),
            },
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
        let escrow = config.mode == RingMode::Registry;
        let address = self.recipient.shielded_address()?;
        let owner_key = anonymous
            .then(|| address.signing_pubkey.as_ed25519())
            .transpose()?;
        let opening = DepositOpening {
            owner_hash,
            blinding: Zeroizing::new(blinding),
            owner_key,
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
        let disclosure = DepositDisclosure {
            owner_key,
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
            escrow,
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
        self.send_with_fee_payer(client, self.payer).await
    }

    /// Sponsors transaction fees while the deposit source still authorizes its funds.
    pub async fn send_with_fee_payer<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
        fee_payer: &(dyn Signer + Sync),
    ) -> Result<RingDepositReceipt, RingError> {
        let prepared = self.prepare(client).await?;
        let utxo = prepared.utxo.clone();
        let signers: Vec<_> = core::iter::once(self.payer).chain(self.cosigner).collect();
        match RingSubmission::new(prepared)
            .send_until_settled(client, fee_payer, &signers)
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
    pub(crate) fn check_public_signers(
        &self,
        signers: impl IntoIterator<Item = Address>,
    ) -> Result<(), RingError> {
        if let Some(owner) = self.disclosure.owner_key {
            if signers.into_iter().any(|signer| signer.to_bytes() == owner) {
                return Err(RingError::AnonymousPublicSignerLinksOwner);
            }
        }
        Ok(())
    }

    pub fn utxo(&self) -> &Utxo {
        &self.utxo
    }

    pub fn budget(&self) -> ComputeBudgetConfig {
        ComputeBudgetConfig::new(custom_ring_interface::compute_unit_limit(
            custom_ring_interface::InstructionTag::AuditedDeposit,
        ))
    }

    /// A stale registry root re-proves the prepared note under a fresh root.
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
        let disclosure = &self.disclosure;
        retry_projection_lag(|| async {
            let indexed = client.indexed_prover();
            // An escrowed ring proves the recipient's record escrows the note's key.
            let root = match disclosure.escrow {
                true => Some(
                    self.ring
                        .member_registry_root(client)
                        .await?
                        .ok_or(RingError::MissingMemberRegistry)?,
                ),
                false => None,
            };
            let record = match (root, indexed.is_some()) {
                (Some(root), false) => Some(disclosure.record(client, self.ring, root).await?),
                _ => None,
            };
            let body = disclosure.body(root, record.as_ref())?;
            let proof = match (indexed, root) {
                (Some(prover), Some(root)) => {
                    let registry = IndexedRegistry {
                        ring_program_id: self.ring.program_id(),
                        root: root.root,
                        next_index: root.next_index,
                    };
                    let request = IndexedDepositRequest::new(&RingRequest(&*body), registry)?;
                    let proof = prover.prove_indexed(&request).await?;
                    RingCircuit::Deposit.verify(&proof, body.public_input_hash)?;
                    proof
                }
                _ => client.prove_request(&RingRequest(&*body)).await?,
            };
            self.instruction(Some(to_instruction_proof(proof)?), root)
        })
        .await
    }

    fn instruction(
        &self,
        proof: Option<CustomRingProof>,
        root: Option<CurrentRegistryRoot>,
    ) -> Result<(Instruction, Option<BoundRoot>), RingError> {
        let escrow = EscrowBinding::of(root);
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
    /// The recipient's record under `root`, which must escrow the deposited key.
    async fn record(
        &self,
        rpc: &(impl AsyncRpc + ?Sized),
        ring: CustomRing,
        root: CurrentRegistryRoot,
    ) -> Result<EscrowedRecord, RingError> {
        let owner = Member::from_bytes(self.key.owner_pk_hash)?;
        let read = ReadMemberRecord {
            ring,
            member: owner,
        }
        .read_at(rpc, root)
        .await?;
        let RecordOpening::Present {
            record,
            index,
            path,
            sealed: Some(sealed),
        } = read.opening
        else {
            return Err(RingError::UnregisteredOutputKey { owner });
        };
        let escrow_key = EscrowKey {
            nullifier_pk: &self.key.nullifier_pk,
            ciphertext: &sealed.ciphertext,
        }
        .hash()?;
        if escrow_key != record.escrow_key {
            return Err(RingError::UnregisteredOutputKey { owner });
        }
        Ok(EscrowedRecord {
            witness: RecordWitness::present(&record, index, path),
            ct_hash: ciphertext_hash(&sealed.ciphertext)?,
        })
    }

    fn body(
        &self,
        root: Option<CurrentRegistryRoot>,
        record: Option<&EscrowedRecord>,
    ) -> Result<Box<DepositBody>, RingError> {
        let root = root.map(|root| root.root);
        let public_input_hash = DepositPublicInput {
            context_hash: &self.context_hash,
            anonymous: self.owner_key.is_some(),
            owner_utxo_hashes: &[self.owner_utxo_hash],
            ciphertexts: &self.encryption.ciphertexts,
            auditor_pk: self.auditor.as_bytes(),
            eph_pk: self.encryption.ephemeral_pk.as_bytes(),
            member_registry_root: root.as_ref(),
        }
        .hash()?;
        let mut members: [Option<RecordWitness>; MAX_RING_DEPOSIT_AUDIT_SLOTS] = Default::default();
        let mut ct_hashes = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
        if let Some(record) = record {
            members[0] = Some(record.witness.clone());
            ct_hashes[0] = record.ct_hash;
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
            anonymous: self.owner_key.is_some(),
            owner_pk_hashes: first(self.key.owner_pk_hash),
            owner_keys: self.owner_key.map(first),
            nullifier_pks: first(self.key.nullifier_pk),
            blindings: Zeroizing::new(first(*self.blinding)),
            ct_hashes,
            members,
            ephemeral_sk: self.encryption.ephemeral_sk.clone(),
            auditor_pk: self.auditor,
            key_escrow: root.is_some(),
            member_registry_root: root.unwrap_or_default(),
        }))
    }
}

impl Deposit {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        if self.proof.is_none() {
            return Err(RingError::AuditRequired);
        }
        if self.proof.is_some() && self.deposits.len() > MAX_RING_DEPOSIT_AUDIT_SLOTS {
            return Err(DepositBuildError::TooManyEntries {
                count: self.deposits.len(),
                max: MAX_RING_DEPOSIT_AUDIT_SLOTS,
            }
            .into());
        }
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
                registry_root_index: self.escrow.root_index(),
            };
            instruction.data = [bytemuck::bytes_of(&prefix), &instruction.data].concat();
        }
        let mut prefix = ring_prefix(self.ring, self.cosigner).to_vec();
        prefix.push(AccountMeta::new_readonly(
            self.ring.deposit_audit_pda(),
            false,
        ));
        prefix.extend(self.escrow.meta(self.ring));
        instruction.accounts.splice(0..0, prefix);
        Ok(instruction)
    }
}
