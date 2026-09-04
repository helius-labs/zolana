//! Both entry transitions are a 1-in 1-out `ConfidentialEddsa` transfer signed by
//! the namespace PDA. Create fills the address slot, update fills the input slot with
//! the live version.

use num_bigint::BigUint;
use solana_address::Address;
use thiserror::Error;
use zolana_client::{
    prover::{field::be, ProofCompressed},
    ClientError, MerkleProof, NonInclusionProof, ProverClient, PublicInputs, PublicTransfers, Rpc,
    TransferInput, TransferInputs, TransferOutput, STATE_TREE_HEIGHT,
};
use zolana_hasher::primitives::{hash_bytes, right_align};
use zolana_interface::{
    instruction::instruction_data::transact::{OwnerTag, TransactOutput, TransactProof},
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    ADDRESS_DOMAIN, SHIELDED_POOL_PROGRAM_ID, SOL_ASSET_FIELD, UTXO_DOMAIN,
};
use zolana_ring_policy::{entry_nullifier, entry_seed, ListEntry, ListId, ListNamespace, Member};
use zolana_transaction::{
    instructions::transact::{ExternalData, PrivateTxHash},
    ProofInputUtxo,
};
use zolana_tree::TreeAccount;

/// The mutation witness failed to assemble or prove.
#[derive(Debug, Error)]
pub enum EntryProofError {
    #[error(transparent)]
    Client(#[from] Box<ClientError>),
    #[error("hashing failed")]
    Hashing,
    #[error("entries tree account {address} is missing")]
    MissingTree { address: Address },
    #[error("entries tree account {address} is not a shielded pool tree")]
    InvalidTree { address: Address },
    #[error("indexer returned no proof for the entry")]
    MissingProof,
    #[error("the spend of the {list_id:?} entry published no version {version}")]
    BrokenLineage {
        list_id: ListId,
        member: [u8; 32],
        version: u64,
    },
    #[error("proof is not a transact proof")]
    InvalidProof,
}

impl From<ClientError> for EntryProofError {
    fn from(error: ClientError) -> Self {
        Self::Client(Box::new(error))
    }
}

/// A one-in one-out SPP transfer proof carrying one entry transition.
pub struct EntryProof {
    pub proof: TransactProof,
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    /// The public input nullifier whose writable queue PDA SPP requires.
    pub nullifier: [u8; 32],
}

pub(super) struct EntryWitness<'a> {
    pub owner: &'a ListNamespace,
    pub namespace: Address,
    pub entries_tree: Address,
    pub payer: Address,
    pub entry: ListEntry,
    pub spent: Option<ListEntry>,
}

impl EntryWitness<'_> {
    pub(super) fn prove<I: Rpc, R: Rpc>(
        self,
        indexer: &I,
        rpc: &R,
        prover: &ProverClient,
    ) -> Result<EntryProof, EntryProofError> {
        let address = self
            .owner
            .address(self.entry.list_id, &self.entry.member)
            .map_err(|_| EntryProofError::Hashing)?;
        let slot = match self.spent {
            None => InputSlot::claim(self.owner, self.entry.list_id, &self.entry.member, address)?,
            Some(spent) => {
                InputSlot::spend(indexer, self.entries_tree, self.owner, &spent, address)?
            }
        };

        let non_inclusion = non_inclusion_proof(indexer, self.entries_tree, slot.nullifier)?;
        let owner_pk_hash =
            hash_bytes(self.namespace.as_array()).map_err(|_| EntryProofError::Hashing)?;
        let payer_hash = hash_bytes(self.payer.as_array()).map_err(|_| EntryProofError::Hashing)?;

        let output_hash = self
            .entry
            .utxo_hash(self.owner, &address)
            .map_err(|_| EntryProofError::Hashing)?;
        let output_data_hash = self
            .entry
            .data_hash(&address)
            .map_err(|_| EntryProofError::Hashing)?;
        let content = self.entry.to_output_data();
        let external = ExternalData::new(
            [0u8; 33],
            [0u8; 16],
            vec![TransactOutput {
                utxo_hash: output_hash,
                owner_tag: OwnerTag::Inline(self.namespace.to_bytes()),
                data: Some(content.to_vec()),
            }],
            vec![self.namespace.to_bytes()],
            Vec::new(),
        );
        let external_hash = external.hash().map_err(|_| EntryProofError::Hashing)?;
        let private_tx = PrivateTxHash {
            input_hashes: &[slot.input_hash],
            output_hashes: &[output_hash],
            address_hashes: slot.address_hash.as_ref().map(core::slice::from_ref),
            external_data_hash: &external_hash,
        }
        .hash()
        .map_err(|_| EntryProofError::Hashing)?;

        // An address slot proves no inclusion, its path is zero and any live root serves.
        let (utxo_root, utxo_root_index, state_path, state_index) = match &slot.state {
            Some(state) => (
                state.root,
                state.root_index,
                state.path.iter().map(be).collect(),
                BigUint::from(state.leaf_index),
            ),
            None => {
                let live = read_state_root(rpc, self.entries_tree)?;
                (
                    live.value,
                    live.index,
                    vec![BigUint::ZERO; STATE_TREE_HEIGHT],
                    BigUint::ZERO,
                )
            }
        };

        let signer_hashes = [payer_hash, owner_pk_hash];
        let output_owner_hashes = [owner_pk_hash];
        let public_transfers = PublicTransfers::default();
        let allow_dummy_inputs = right_align(&1u64.to_be_bytes());
        let public_hash = PublicInputs {
            nullifiers: &[slot.nullifier],
            output_hashes: &[output_hash],
            utxo_roots: &[utxo_root],
            nullifier_tree_roots: &[non_inclusion.root],
            private_tx: &private_tx,
            external_data_hash: &external_hash,
            public_transfers: &public_transfers,
            ring_program_id: &[0u8; 32],
            allow_dummy_inputs: &allow_dummy_inputs,
            signer_pk_hashes: &signer_hashes,
            output_owner_pk_hashes: Some(&output_owner_hashes),
        }
        .hash()
        .map_err(|_| EntryProofError::Hashing)?;

        let transfer_input = TransferInput {
            utxo: slot.utxo,
            is_dummy: BigUint::ZERO,
            state_path_elements: state_path,
            state_path_index: state_index,
            nullifier_low_value: be(&non_inclusion.low_element),
            nullifier_next_value: be(&non_inclusion.high_element),
            nullifier_low_path_elements: non_inclusion.path.iter().map(be).collect(),
            nullifier_low_path_index: BigUint::from(non_inclusion.low_element_index),
            utxo_tree_root: be(&utxo_root),
            nullifier_tree_root: be(&non_inclusion.root),
            nullifier: be(&slot.nullifier),
            owner_pk_hash: be(&owner_pk_hash),
            nullifier_secret: BigUint::ZERO,
        };
        let transfer_output = TransferOutput {
            utxo: ProofInputUtxo {
                domain: right_align(&UTXO_DOMAIN.to_be_bytes()),
                owner_hash: self.owner.owner_hash,
                asset: SOL_ASSET_FIELD,
                amount: [0u8; 32],
                blinding: self.entry.blinding(),
                data_hash: output_data_hash,
                ..ProofInputUtxo::default()
            },
            is_dummy: BigUint::ZERO,
            hash: be(&output_hash),
            owner_pk_hash: be(&owner_pk_hash),
            nullifier_pk: be(&zero_nullifier_pubkey()?),
        };

        let inputs = TransferInputs {
            inputs: vec![transfer_input],
            outputs: vec![transfer_output],
            external_data_hash: be(&external_hash),
            private_tx_hash: be(&private_tx),
            public_assets: core::array::from_fn(|_| BigUint::ZERO),
            public_amounts: core::array::from_fn(|_| BigUint::ZERO),
            ring_program_id: BigUint::ZERO,
            signer_pk_hashes: signer_hashes.iter().map(be).collect(),
            allow_dummy_inputs: BigUint::from(1u8),
            published_output_owner_pk_hashes: output_owner_hashes.iter().map(be).collect(),
            public_input_hash: be(&public_hash),
        };
        let proof = prover.prove_transfer(&inputs)?;
        Ok(EntryProof {
            proof: ProofCompressed::try_from(proof)
                .map_err(|_| EntryProofError::InvalidProof)?
                .to_transact_proof(),
            nullifier_tree_root_index: non_inclusion.root_index,
            utxo_tree_root_index: utxo_root_index,
            nullifier: slot.nullifier,
        })
    }
}

/// The input the transfer spends. A claim carries an address slot and no state
/// path, a spend carries the live version's leaf.
struct InputSlot {
    utxo: ProofInputUtxo,
    input_hash: [u8; 32],
    address_hash: Option<[u8; 32]>,
    nullifier: [u8; 32],
    state: Option<MerkleProof>,
}

impl InputSlot {
    fn claim(
        owner: &ListNamespace,
        list_id: ListId,
        member: &Member,
        address: [u8; 32],
    ) -> Result<Self, EntryProofError> {
        let seed = entry_seed(list_id, member).map_err(|_| EntryProofError::Hashing)?;
        let utxo = ProofInputUtxo {
            domain: right_align(&ADDRESS_DOMAIN.to_be_bytes()),
            owner_hash: owner.owner_hash,
            blinding: seed,
            ..ProofInputUtxo::default()
        };
        let address_hash = utxo.hash().map_err(|_| EntryProofError::Hashing)?;
        Ok(Self {
            utxo,
            input_hash: [0u8; 32],
            address_hash: Some(address_hash),
            nullifier: address,
            state: None,
        })
    }

    fn spend<I: Rpc>(
        indexer: &I,
        tree: Address,
        owner: &ListNamespace,
        spent: &ListEntry,
        address: [u8; 32],
    ) -> Result<Self, EntryProofError> {
        let input_hash = spent
            .utxo_hash(owner, &address)
            .map_err(|_| EntryProofError::Hashing)?;
        let nullifier = entry_nullifier(&input_hash, &spent.blinding())
            .map_err(|_| EntryProofError::Hashing)?;
        let data_hash = spent
            .data_hash(&address)
            .map_err(|_| EntryProofError::Hashing)?;
        let utxo = ProofInputUtxo {
            domain: right_align(&UTXO_DOMAIN.to_be_bytes()),
            owner_hash: owner.owner_hash,
            asset: SOL_ASSET_FIELD,
            amount: [0u8; 32],
            blinding: spent.blinding(),
            data_hash,
            ..ProofInputUtxo::default()
        };
        Ok(Self {
            utxo,
            input_hash,
            address_hash: None,
            nullifier,
            state: Some(merkle_proof(indexer, tree, input_hash)?),
        })
    }
}

/// A root and the history index the program resolves it by.
struct StateRoot {
    value: [u8; 32],
    index: u16,
}

fn zero_nullifier_pubkey() -> Result<[u8; 32], EntryProofError> {
    zolana_keypair::NullifierKey::from_secret([0u8; 31])
        .pubkey()
        .map_err(|_| EntryProofError::Hashing)
}

fn merkle_proof<I: Rpc>(
    indexer: &I,
    tree: Address,
    leaf: [u8; 32],
) -> Result<MerkleProof, EntryProofError> {
    indexer
        .get_merkle_proofs(tree, vec![leaf], None)?
        .proofs
        .into_iter()
        .next()
        .ok_or(EntryProofError::MissingProof)
}

fn non_inclusion_proof<I: Rpc>(
    indexer: &I,
    tree: Address,
    leaf: [u8; 32],
) -> Result<NonInclusionProof, EntryProofError> {
    indexer
        .get_non_inclusion_proofs(tree, vec![leaf], None)?
        .proofs
        .into_iter()
        .next()
        .ok_or(EntryProofError::MissingProof)
}

fn read_state_root<R: Rpc>(rpc: &R, tree: Address) -> Result<StateRoot, EntryProofError> {
    let mut account = rpc
        .get_account(tree)?
        .ok_or(EntryProofError::MissingTree { address: tree })?;
    if account.owner.to_bytes() != SHIELDED_POOL_PROGRAM_ID
        || account.data.first() != Some(&TREE_ACCOUNT_DISCRIMINATOR)
    {
        return Err(EntryProofError::InvalidTree { address: tree });
    }
    let mut tree_account = TreeAccount::from_bytes(&mut account.data, tree.to_bytes())
        .map_err(|_| EntryProofError::InvalidTree { address: tree })?;
    let index = tree_account.utxo_tree().current_root_index();
    let value = tree_account
        .get_utxo_tree_root(index)
        .map_err(|_| EntryProofError::InvalidTree { address: tree })?;
    Ok(StateRoot { value, index })
}
