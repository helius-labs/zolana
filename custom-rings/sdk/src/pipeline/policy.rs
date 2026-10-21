//! The policy half of a ring transfer, every record read under a root the statement binds.

use std::collections::BTreeSet;

use custom_ring_interface::{
    key_catalog::RingCircuit, MemberRegistry, PolicyKey, PolicyStatement, RingAccount, RingMode,
    RingRail,
};
use solana_address::Address;
use zolana_client::{AsyncIndexer, AsyncRpc, AsyncZolanaClient};
use zolana_hasher::hash_chain::create_nonzero_hash_chain_from_slice;
use zolana_interface::N_PUBLIC_SLOTS;
use zolana_ring_client::records::MemberOpeningRead;
use zolana_ring_policy::{
    EncodedRuleTable, Member, OutputSubjects, RecordLists, SourceMap, Subject, TransferSubjects,
};
use zolana_transaction::instructions::transact::SppProofInputs;

use crate::{
    limits::Outflows,
    prover::{to_instruction_proof, RingRequest},
    records::{OpeningsByMember, OwnerRead, RecordReads},
    request::{
        DelegatePolicy, Entry, MemberOpening, MemberPolicy, Opening, OutputOpening, PolicyParams,
        PolicyTable,
    },
    submission::BoundRoot,
    CustomRing, CustomRingConfig, PinnedPolicy, RingError,
};

#[derive(Clone, Copy)]
struct OutputOwner {
    member: [u8; 32],
    nullifier_pk: [u8; 32],
}

pub(super) struct PolicyInputs {
    rules: EncodedRuleTable,
    sources: SourceMap,
    pub policy_hash: [u8; 32],
    pub own: BoundRoot,
    pub curator: Option<BoundCurator>,
    sender_entry: Entry,
    owner_entries: Vec<Entry>,
    asset_entries: Vec<Entry>,
    /// The escrowed key ciphertext hash of every UTXO output's owner, under key escrow.
    ct_hashes: Vec<Option<[u8; 32]>>,
    pub approval_required: bool,
    pub key_escrow: bool,
}

#[derive(Clone, Copy)]
pub(super) struct BoundCurator {
    pub address: Address,
    pub root: BoundRoot,
}

pub(super) struct PolicyRead<'a> {
    pub ring: CustomRing,
    pub config: &'a CustomRingConfig,
    pub rail: RingRail,
    pub inputs: &'a SppProofInputs,
    /// The owner identity the rules read as the sender.
    pub sender: [u8; 32],
    pub public_assets: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    pub public_amounts: &'a [i128; N_PUBLIC_SLOTS],
}

impl PolicyRead<'_> {
    pub async fn read<R: AsyncRpc + ?Sized>(self, client: &R) -> Result<PolicyInputs, RingError> {
        let registry = self.ring.require_registry(client).await?;
        let pinned = PinnedPolicy::of(&registry)?;
        let own = BoundRoot::current(self.ring, &registry);
        let curator = match pinned.curator {
            Some(address) => Some(BoundCurator::read(client, address).await?),
            None => None,
        };
        let outputs = &self.inputs.output_utxos;
        let asset_rules = pinned
            .table
            .rules()
            .iter()
            .any(|rule| rule.subject == Subject::Asset);
        let owners = outputs
            .iter()
            .map(|output| {
                output
                    .owner_address
                    .map(|owner| {
                        Ok::<_, RingError>(OutputOwner {
                            member: owner.signing_pubkey.owner_proof_input_hash()?,
                            nullifier_pk: owner.nullifier_pubkey,
                        })
                    })
                    .transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let assets = outputs
            .iter()
            .map(|output| match (asset_rules, output.is_dummy()) {
                (true, false) => Ok(Some(*Member::asset(&output.asset.asset)?.as_bytes())),
                _ => Ok(None),
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        let members: BTreeSet<[u8; 32]> = core::iter::once(self.sender)
            .chain(owners.iter().flatten().map(|owner| owner.member))
            .chain(assets.iter().flatten().copied())
            .collect();
        let members: Vec<[u8; 32]> = members.into_iter().collect();
        let own_reads = RecordReads {
            root: own,
            members: &members,
        }
        .read_keyed(client)
        .await?;
        let curator_reads = match curator {
            Some(curator) => Some(
                RecordReads {
                    root: curator.root,
                    members: &members,
                }
                .read_keyed(client)
                .await?,
            ),
            None => None,
        };
        let lists = |member: [u8; 32]| {
            let on = |reads: &OpeningsByMember| {
                reads
                    .get(&member)
                    .and_then(MemberOpeningRead::record)
                    .map_or(0, |record| record.lists)
            };
            RecordLists {
                own: on(&own_reads),
                curator: curator_reads.as_ref().map_or(0, on),
            }
        };
        let subjects = outputs
            .iter()
            .zip(&owners)
            .filter_map(|(output, owner)| owner.map(|owner| (output, owner)))
            .map(|(output, owner)| {
                let asset = *Member::asset(&output.asset.asset)?.as_bytes();
                Ok(OutputSubjects {
                    owner: owner.member,
                    asset,
                    amount: output.amount,
                    owner_lists: lists(owner.member),
                    asset_lists: lists(asset),
                })
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        pinned.table.admit(
            &pinned.sources,
            &TransferSubjects {
                sender: lists(self.sender),
                outputs: &subjects,
            },
        )?;
        let entry = |member: Option<[u8; 32]>| -> Entry {
            let Some(member) = member else {
                return Entry::default();
            };
            let find = |reads: &OpeningsByMember| {
                reads
                    .get(&member)
                    .map(|read| MemberOpening::from(&read.opening))
            };
            Entry {
                own: find(&own_reads),
                curator: curator_reads.as_ref().and_then(find),
            }
        };
        let key_escrow = self.config.mode == RingMode::Registry;
        let ct_hashes = owners
            .iter()
            .map(|owner| {
                owner
                    .filter(|_| key_escrow)
                    .map(|owner| -> Result<[u8; 32], RingError> {
                        let read = own_reads
                            .get(&owner.member)
                            .ok_or(RingError::InvalidRecordOpening)?;
                        let read = OwnerRead {
                            owner: owner.member,
                            read,
                        };
                        Ok(read.escrowed(&owner.nullifier_pk)?.ct_hash()?)
                    })
                    .transpose()
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        let approval_required = match self.rail {
            RingRail::Delegate => false,
            RingRail::Confidential | RingRail::Anonymous => Outflows {
                sender: self.sender,
                ring: self.ring.program_id(),
                outputs,
                public_assets: self.public_assets,
                public_amounts: self.public_amounts,
            }
            .approval_required(pinned.table.limits())?,
        };
        Ok(PolicyInputs {
            rules: registry.rules,
            sources: pinned.sources,
            policy_hash: pinned.policy_hash,
            own,
            curator,
            sender_entry: entry(Some(self.sender)),
            owner_entries: owners
                .iter()
                .map(|owner| entry(owner.map(|owner| owner.member)))
                .collect(),
            asset_entries: assets.iter().map(|asset| entry(*asset)).collect(),
            ct_hashes,
            approval_required,
            key_escrow,
        })
    }
}

pub(super) struct PolicyProving<'a> {
    pub ring_id: [u8; 32],
    pub rail: RingRail,
    pub inputs: &'a SppProofInputs,
    pub private_tx_hash: [u8; 32],
    pub private_tx_blinding: [u8; 32],
    /// The owner identity, the anonymous rail's sender commitment, zero on the delegate rail.
    pub sender: [u8; 32],
    pub sender_pk_hash: [u8; 32],
    pub public_assets: [[u8; 32]; N_PUBLIC_SLOTS],
    pub public_amount_fields: [[u8; 32]; N_PUBLIC_SLOTS],
}

impl PolicyInputs {
    pub fn curator_root(&self) -> [u8; 32] {
        self.curator.map_or([0; 32], |curator| curator.root.root)
    }

    pub fn statement(&self, proving: &PolicyProving<'_>) -> Result<[u8; 32], RingError> {
        let key = proving.rail.policy_key();
        let delegate = key == PolicyKey::Delegate;
        Ok(PolicyStatement {
            key,
            private_tx_hash: &proving.private_tx_hash,
            policy_hash: &self.policy_hash,
            ring_id: &proving.ring_id,
            approval_required: self.approval_required,
            key_escrow: delegate || self.key_escrow,
            own_root: &self.own.root,
            curator_root: &self.curator_root(),
            sender: &proving.sender,
            public_assets: &proving.public_assets,
            public_amounts: &proving.public_amount_fields,
        }
        .hash()?)
    }

    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
        proving: &PolicyProving<'_>,
    ) -> Result<custom_ring_interface::CustomRingProof, RingError> {
        let inputs = proving.inputs;
        let shape = inputs.check_shape()?;
        let circuit = RingCircuit::policy(
            proving.rail,
            u8::try_from(shape.n_inputs())
                .map_err(|_| RingError::ShapeUnkeyed { rail: "policy" })?,
            u8::try_from(shape.n_outputs())
                .map_err(|_| RingError::ShapeUnkeyed { rail: "policy" })?,
        );
        let public_input_hash = self.statement(proving)?;
        let outputs = inputs
            .output_utxos
            .iter()
            .zip(&self.ct_hashes)
            .map(|(output, ct_hash)| {
                Ok(OutputOpening {
                    opening: Opening::output(output, inputs.output_tree_id)?,
                    ct_hash: *ct_hash,
                })
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        let address_nullifiers: Vec<[u8; 32]> = inputs
            .input_utxos
            .iter()
            .map(|input| input.private_tx_address_nullifier())
            .collect();
        let params = PolicyParams {
            private_tx_hash: proving.private_tx_hash,
            policy_hash: self.policy_hash,
            ring_id: proving.ring_id,
            own_root: self.own.root,
            curator_root: self.curator_root(),
            public_assets: proving.public_assets.to_vec(),
            public_amounts: proving.public_amount_fields.to_vec(),
            table: PolicyTable {
                rules: &self.rules,
                sources: &self.sources,
            },
            address_chain: create_nonzero_hash_chain_from_slice(&address_nullifiers)?,
            private_tx_blinding: proving.private_tx_blinding,
            outputs,
            sender_pk_hash: proving.sender_pk_hash,
            sender_entry: self.sender_entry.clone(),
            owner_entries: self.owner_entries.clone(),
            asset_entries: self.asset_entries.clone(),
        };
        let proof = match proving.rail {
            RingRail::Delegate => {
                let body = DelegatePolicy {
                    public_input_hash,
                    inputs: inputs
                        .input_utxos
                        .iter()
                        .map(Opening::input)
                        .collect::<Result<_, _>>()?,
                    policy: params,
                };
                RingRequest::new(circuit, &body)?
                    .prove(client, public_input_hash)
                    .await?
            }
            RingRail::Confidential | RingRail::Anonymous => {
                let input_hashes: Vec<[u8; 32]> = inputs
                    .input_utxos
                    .iter()
                    .map(|input| input.private_tx_input_hash())
                    .collect();
                let body = MemberPolicy {
                    public_input_hash,
                    anonymous: proving.rail == RingRail::Anonymous,
                    approval_required: self.approval_required,
                    key_escrow: self.key_escrow,
                    sender: proving.sender,
                    input_chain: create_nonzero_hash_chain_from_slice(&input_hashes)?,
                    policy: params,
                };
                RingRequest::new(circuit, &body)?
                    .prove(client, public_input_hash)
                    .await?
            }
        };
        to_instruction_proof(proof)
    }
}

impl BoundCurator {
    async fn read<R: AsyncRpc + ?Sized>(client: &R, address: Address) -> Result<Self, RingError> {
        let account = client
            .get_account(address)
            .await?
            .ok_or(RingError::InvalidCuratorRegistry { address })?;
        let registry = MemberRegistry::from_data(&account.data)
            .ok_or(RingError::InvalidCuratorRegistry { address })?;
        Ok(Self {
            address,
            root: BoundRoot::current(CustomRing::new(account.owner), registry),
        })
    }
}
