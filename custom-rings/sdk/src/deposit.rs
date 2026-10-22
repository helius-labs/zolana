//! Deposits whose proof binds the SPP deposit bytes and, under key escrow, the recipient's record.

use custom_ring_interface::{
    domain::deposit_blinding, key_catalog::RingCircuit, tag, AuditedDepositPrefix, CoSignScope,
    CustomRingError, CustomRingProof, DepositContext, DepositPublicInput, RingDepositAuditCapsule,
    RingMode, MAX_RING_DEPOSIT_AUDIT_SLOTS,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_signature::Signature;
use solana_signer::Signer;
use zeroize::Zeroizing;
use zolana_client::{
    fetch_asset_id_async, AnonymousRingState, AsyncIndexer, AsyncRpc, AsyncZolanaClient,
};
use zolana_keypair::{random_blinding, Curve, ShieldedAddress, X25519Pubkey};
use zolana_program::instruction::{DepositAsset, RingAssetDeposit};
use zolana_ring_client::{seal_deposits, DepositEncryption, DepositOpening};
use zolana_transaction::{
    exactly_one, owner_utxo_hash, Data, Mint, RingDepositPlaintext, ShieldedKeys, Utxo,
};

use crate::{
    pipeline::HiddenOwner,
    projection::retry_projection_lag,
    prover::{to_instruction_proof, RingRequest},
    records::{MemberRead, OwnerRead},
    request::{DepositRequest, RecordOpeningRequest},
    submission::BoundRoot,
    CustomRing, RingError, RingSubmission, SettledSubmission,
};

#[derive(Clone, Copy)]
pub enum DepositRecipient<'a> {
    /// The member finds the note under its viewing key's tag.
    Confidential(ShieldedAddress),
    /// The depositor's own hidden identity on an anonymous ring, found on its deposit stream.
    Anonymous {
        keys: &'a (dyn ShieldedKeys + Send + Sync),
        /// Its `deposit_next` is the deposit's stream counter.
        state: &'a AnonymousRingState,
    },
}

#[must_use]
pub struct RingDeposit<'a> {
    pub ring: CustomRing,
    /// Lamport source for Sol, the user token's authority for Spl.
    pub payer: &'a (dyn Signer + Sync),
    pub recipient: DepositRecipient<'a>,
    pub tree: Address,
    pub asset: DepositAsset,
    pub amount: u64,
    /// Signs when the config's scope covers deposits.
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
    disclosure: DepositDisclosure,
}

pub(crate) struct BoundDeposit {
    pub instruction: Instruction,
    /// `None` without key escrow.
    pub root: Option<BoundRoot>,
}

struct DepositDisclosure {
    /// The Ed25519 owner key an anonymous ring discloses, the proof binds it to the owner hash.
    owner_key: Option<[u8; 32]>,
    context_hash: [u8; 32],
    owner_utxo_hash: [u8; 32],
    owner_pk_hash: [u8; 32],
    nullifier_pk: [u8; 32],
    blinding_secret: Zeroizing<[u8; 32]>,
    encryption: DepositEncryption,
    auditor: X25519Pubkey,
    /// The recipient's record must escrow the key the note uses.
    escrow: bool,
}

struct EscrowedRecord {
    opening: RecordOpeningRequest,
    ct_hash: [u8; 32],
}

impl RingDeposit<'_> {
    /// Fixes the note, every proving attempt deposits the same one.
    pub async fn prepare(
        &self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<PreparedRingDeposit, RingError> {
        let mint = self.asset.mint();
        let mint = Mint::new(mint, fetch_asset_id_async(rpc, mint).await?);
        let config = self.ring.require_config(rpc).await?;
        self.ring.require_active(rpc).await?;
        let anonymous = config.mode == RingMode::Anonymous;
        let (address, view_tag) = match self.recipient {
            DepositRecipient::Confidential(address) if !anonymous => {
                (address, address.viewing_pubkey.u())
            }
            DepositRecipient::Anonymous { keys, state } if anonymous => {
                if state.ring() != self.ring.program_id() {
                    return Err(RingError::ForeignRingState {
                        state: state.ring(),
                        ring: self.ring.program_id(),
                    });
                }
                (
                    keys.address()?,
                    exactly_one(keys.sender_view_tags(&[state.deposit_next()])?)?,
                )
            }
            DepositRecipient::Confidential(_) => {
                return Err(CustomRingError::AnonymousRingRefused.into())
            }
            DepositRecipient::Anonymous { .. } => return Err(RingError::NotAnonymousRing),
        };
        let owner_key = match anonymous {
            // An anonymous ring spends only through the hidden Ed25519 proof.
            true if address.signing_pubkey.curve()? != Curve::Ed25519 => {
                return Err(RingError::AnonymousRecipient)
            }
            true => Some(address.signing_pubkey.as_ed25519()?),
            false => None,
        };
        if let Some(owner) = owner_key {
            HiddenOwner(Address::new_from_array(owner)).check_signers(
                core::iter::once(self.payer.pubkey())
                    .chain(self.cosigner.map(|signer| signer.pubkey())),
            )?;
        }
        let blinding_secret = Zeroizing::new(random_blinding());
        let blinding = deposit_blinding(&blinding_secret)?;
        let owner_hash = address.owner_hash()?;
        let mut deposit = RingAssetDeposit {
            asset: self.asset,
            view_tag,
            owner_utxo_hash: owner_utxo_hash(&owner_hash, &blinding)?,
            amount: self.amount,
            ring_data_hash: [0; 32],
            encrypted: RingDepositPlaintext {
                blinding,
                utxo_data: None,
                memo: None,
                ring_data: Vec::new(),
            }
            .encrypt(&address.viewing_pubkey)?,
        };
        let encryption = seal_deposits(
            &[DepositOpening {
                owner_hash,
                blinding: Zeroizing::new(blinding),
                owner_key,
            }],
            &config.auditor_pubkey,
        )?;
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
        let cosigner = custom_ring_interface::cosign::CoSignDemand {
            approval_required: false,
            classes: CoSignScope::DEPOSITS,
            withdrawals: Vec::new(),
        }
        .signer(config.account())?;
        if cosigner.is_some() && cosigner != self.cosigner.map(|signer| signer.pubkey()) {
            return Err(CustomRingError::MissingCoSigner.into());
        }
        Ok(PreparedRingDeposit {
            ring: self.ring,
            tree: self.tree,
            depositor: self.payer.pubkey(),
            cosigner,
            utxo: Utxo {
                owner: address.signing_pubkey,
                asset: mint,
                amount: self.amount,
                blinding,
                ring_program_id: Some(self.ring.program_id()),
                data: Data::default(),
            },
            disclosure: DepositDisclosure {
                owner_key,
                context_hash: DepositContext {
                    program_id: self.ring.program_id().as_array(),
                    tree: self.tree.as_array(),
                    spp_data: &spp.data,
                }
                .hash()?,
                owner_utxo_hash: deposit.owner_utxo_hash,
                owner_pk_hash: address.signing_pubkey.owner_proof_input_hash()?,
                nullifier_pk: address.nullifier_pubkey,
                blinding_secret,
                encryption,
                auditor: config.auditor_pubkey,
                escrow: config.mode == RingMode::Registry,
            },
            deposit,
        })
    }

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
        let signers = self.signers(&prepared);
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

    /// A co-signer the config does not demand is no account of the deposit and cannot sign it.
    pub(crate) fn signers(&self, prepared: &PreparedRingDeposit) -> Vec<&(dyn Signer + Sync)> {
        core::iter::once(self.payer)
            .chain(self.cosigner.filter(|_| prepared.cosigner.is_some()))
            .collect()
    }
}

impl PreparedRingDeposit {
    pub(crate) fn check_public_signers(
        &self,
        signers: impl IntoIterator<Item = Address>,
    ) -> Result<(), RingError> {
        match self.disclosure.owner_key {
            Some(owner) => HiddenOwner(Address::new_from_array(owner)).check_signers(signers),
            None => Ok(()),
        }
    }

    pub fn utxo(&self) -> &Utxo {
        &self.utxo
    }

    /// Each call binds the newest root, a raised floor needs only a new proof.
    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<Instruction, RingError> {
        Ok(self.prove_bound(client).await?.instruction)
    }

    pub(crate) async fn prove_bound<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<BoundDeposit, RingError> {
        let disclosure = &self.disclosure;
        retry_projection_lag(|| async {
            let root = match disclosure.escrow {
                true => Some(BoundRoot::newest(self.ring, client).await?),
                false => None,
            };
            let record = match root {
                Some(root) => Some(disclosure.record(client, root).await?),
                None => None,
            };
            let body = disclosure.body(root.map(|root| root.root), record.as_ref())?;
            let proof = RingRequest::new(RingCircuit::Deposit, &*body)?
                .prove(client, body.public_input_hash)
                .await?;
            Ok(BoundDeposit {
                instruction: self.instruction(to_instruction_proof(proof)?, root)?,
                root,
            })
        })
        .await
    }

    /// `[config, registry?, co-signer?]`, then SPP's deposit list.
    fn instruction(
        &self,
        proof: CustomRingProof,
        root: Option<BoundRoot>,
    ) -> Result<Instruction, RingError> {
        let mut instruction = zolana_program::instruction::RingDeposit {
            tree: self.tree,
            depositor: self.depositor,
            ring_program_id: self.ring.program_id(),
            deposits: vec![self.deposit.clone()],
        }
        .instruction()?;
        let prefix = AuditedDepositPrefix {
            tag: tag::AUDITED_DEPOSIT,
            proof,
            registry_root_index: root.map_or(0, |root| root.index),
        };
        instruction.data = [bytemuck::bytes_of(&prefix), &instruction.data].concat();
        let mut accounts = vec![AccountMeta::new_readonly(self.ring.config_pda(), false)];
        if root.is_some() {
            accounts.push(AccountMeta::new_readonly(self.ring.registry_pda(), false));
        }
        accounts.extend(
            self.cosigner
                .map(|cosigner| AccountMeta::new_readonly(cosigner, true)),
        );
        instruction.accounts.splice(0..0, accounts);
        Ok(instruction)
    }
}

impl DepositDisclosure {
    /// The recipient's record under `root`, it must escrow the deposited key.
    async fn record(
        &self,
        rpc: &(impl AsyncRpc + ?Sized),
        root: BoundRoot,
    ) -> Result<EscrowedRecord, RingError> {
        let read = MemberRead {
            root,
            member: self.owner_pk_hash,
        }
        .read(rpc)
        .await?;
        let escrowed = OwnerRead {
            owner: self.owner_pk_hash,
            read: &read,
        }
        .escrowed(&self.nullifier_pk)?;
        Ok(EscrowedRecord {
            opening: RecordOpeningRequest::present(escrowed.record, escrowed.path),
            ct_hash: escrowed.ct_hash()?,
        })
    }

    fn body(
        &self,
        root: Option<[u8; 32]>,
        record: Option<&EscrowedRecord>,
    ) -> Result<Box<DepositRequest>, RingError> {
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
        let first = |value: [u8; 32]| {
            let mut slots = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
            slots[0] = value;
            slots
        };
        let mut members: [Option<RecordOpeningRequest>; MAX_RING_DEPOSIT_AUDIT_SLOTS] =
            Default::default();
        members[0] = record.map(|record| record.opening.clone());
        Ok(Box::new(DepositRequest {
            public_input_hash,
            context_hash: self.context_hash,
            count: 1,
            anonymous: self.owner_key.is_some(),
            owner_pk_hashes: first(self.owner_pk_hash),
            owner_keys: self.owner_key.map(first),
            nullifier_pks: first(self.nullifier_pk),
            blinding_secrets: Zeroizing::new(first(*self.blinding_secret)),
            ct_hashes: first(record.map_or([0; 32], |record| record.ct_hash)),
            members,
            eph_sk: self.encryption.ephemeral_sk.clone(),
            auditor_pk: self.auditor,
            key_escrow: root.is_some(),
            member_registry_root: root.unwrap_or_default(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use solana_signature::Signature;
    use zolana_client::{OutputContext, OutputSlot, ShieldedTransaction};
    use zolana_interface::pda;

    use super::*;
    use crate::tests::support::{keypair, ring, Chain, RingSettings, TREE_ID};

    /// An indexer that shows every counter of the first window taken moves no deposit tag.
    #[tokio::test]
    async fn a_deposit_takes_the_stored_counter_whatever_the_indexer_shows() {
        let member = keypair(1);
        let payer = keypair(9);
        let first_window: Vec<u64> = (0..64).collect();
        let chain = member
            .sender_view_tags(&first_window)
            .unwrap()
            .into_iter()
            .zip(0u8..)
            .fold(
                Chain::ring(RingSettings::new(RingMode::Anonymous)),
                |chain, (view_tag, seed)| {
                    chain.with_transaction(ShieldedTransaction {
                        slot: 1,
                        tx_signature: Signature::from([seed; 64]),
                        event_index: Some(0),
                        tx_viewing_pk: None,
                        salt: None,
                        output_slots: vec![OutputSlot {
                            view_tag,
                            output_context: OutputContext {
                                hash: [seed; 32],
                                tree_id: TREE_ID,
                                leaf_index: u64::from(seed),
                            },
                            payload: Vec::new(),
                        }],
                        messages: Vec::new(),
                        nullifiers: Vec::new(),
                        proofless: true,
                        ring_config: None,
                        ring_program_id: None,
                    })
                },
            );
        let state = AnonymousRingState::new(ring().program_id(), 0);
        let prepared = RingDeposit {
            ring: ring(),
            payer: &payer,
            recipient: DepositRecipient::Anonymous {
                keys: &member,
                state: &state,
            },
            tree: pda::tree(TREE_ID),
            asset: DepositAsset::Sol,
            amount: 5,
            cosigner: None,
        }
        .prepare(&chain)
        .await
        .unwrap();
        assert_eq!(
            prepared.deposit.view_tag,
            member.sender_view_tags(&[state.deposit_next()]).unwrap()[0]
        );
    }

    #[tokio::test]
    async fn a_deposit_refuses_the_state_of_another_ring() {
        let member = keypair(1);
        let payer = keypair(9);
        let chain = Chain::ring(RingSettings::new(RingMode::Anonymous));
        let other = Address::new_from_array([0x47; 32]);
        let state = AnonymousRingState::new(other, 0);
        let refused = RingDeposit {
            ring: ring(),
            payer: &payer,
            recipient: DepositRecipient::Anonymous {
                keys: &member,
                state: &state,
            },
            tree: pda::tree(TREE_ID),
            asset: DepositAsset::Sol,
            amount: 5,
            cosigner: None,
        }
        .prepare(&chain)
        .await;
        assert!(matches!(
            refused,
            Err(RingError::ForeignRingState { state, ring: paid })
                if state == other && paid == ring().program_id()
        ));
    }
}
