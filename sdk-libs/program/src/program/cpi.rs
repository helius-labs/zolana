use alloc::vec::Vec;

use borsh::BorshSerialize;
use pinocchio::{cpi::Signer, ProgramResult};
use zolana_instruction::{
    cpi::SppTransactAccounts,
    derivation::{
        derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
    },
    PrivateTxHash, TransactExternalData, TransactInputs,
};
use zolana_interface::{
    event::OutputDataEncoding,
    instruction::instruction_data::transact::{
        CircuitId, InputUtxo, OwnerTag, TransactIxData, TransactOutput, TransactProof, TreeContext,
    },
    shape::{Shape, SPP_SUPPORTED_SHAPES},
    N_PUBLIC_SLOTS,
};

use crate::hasher::DataHasher;

use super::{
    load_tree_id, unique::UtxoInput, utxo::DataUtxo, CompressedAccountError, PdaOwner,
    UniqueDataUtxo,
};

/// The blinding seed of every transaction [`SppTransactCpi`] builds; a client
/// proving one uses it too. The state is public, so the seed hides nothing,
/// and a fixed seed keeps the blindings unique: each derivation folds in the
/// transaction's first nullifier, which enters the nullifier tree once. The
/// prover rejects a zero seed.
pub const ACCOUNT_BLINDING_SEED: [u8; 32] = {
    let mut seed = [0u8; 32];
    seed[31] = 1;
    seed
};

/// One shielded-pool transaction that writes compressed accounts: one input
/// and one output per account, in the order they are added. The program builds
/// everything but the proof on chain: every blinding, the output UTXO hashes,
/// the external data hash and the private transaction hash.
///
/// Inputs may interleave trees; every input of one tree shares its root indexes.
pub struct SppTransactCpi {
    proof: TransactProof,
    output_blinding_seed: Option<[u8; 32]>,
    writes: Vec<UtxoWrite>,
}

/// A write with its new state hashed and serialized, so one transaction can
/// write accounts of different state types.
struct UtxoWrite {
    owner: PdaOwner,
    input: UtxoInput,
    tree_id: u16,
    tree_context: TreeContext,
    blinding: [u8; 32],
    data_hash: [u8; 32],
    data: Vec<u8>,
}

impl SppTransactCpi {
    pub fn new(proof: TransactProof) -> Self {
        Self {
            proof,
            output_blinding_seed: None,
            writes: Vec::new(),
        }
    }

    /// Adds a write of `account`. Its output gets the transaction-derived blinding;
    /// the address and Borsh-encoded state are published as plaintext.
    /// Each write takes one input and one output; the transaction is
    /// proved at the smallest square shape the pool supports that holds every
    /// write, and compact padding fills the slots the writes leave.
    pub fn with_unique_data_utxo<S: DataHasher + BorshSerialize>(
        mut self,
        account: UniqueDataUtxo<'_, S>,
    ) -> Result<Self, CompressedAccountError> {
        square_width(self.writes.len() + 1)?;
        let data_hash = account.data_hash()?;
        let UniqueDataUtxo {
            owner,
            input,
            tree_id,
            tree_context,
            state,
            address,
        } = account;
        let first_nullifier = match self.writes.first() {
            Some(first) => *first.input.nullifier(),
            None => *input.nullifier(),
        };
        let slot = u32::try_from(self.writes.len())
            .map_err(|_| CompressedAccountError::TooManyAccounts)?;
        let seed = match self.output_blinding_seed {
            Some(seed) => seed,
            None => {
                let seed = derive_output_blinding_seed(&first_nullifier, &ACCOUNT_BLINDING_SEED)?;
                self.output_blinding_seed = Some(seed);
                seed
            }
        };
        let blinding = derive_transact_output_blinding(&first_nullifier, &seed, slot)?;
        let data = plaintext_output_data(&address, &state)?;
        self.writes.push(UtxoWrite {
            owner: *owner,
            input,
            tree_id,
            tree_context,
            blinding,
            data_hash,
            data,
        });
        Ok(self)
    }

    /// Builds the transaction and invokes transact through `accounts`, whose
    /// output tree receives every output. Every account's owner must be one of
    /// `accounts`' signer PDAs.
    pub fn invoke<const MAX_ACCOUNTS: usize>(
        self,
        accounts: &SppTransactAccounts,
        signers: &[Signer],
    ) -> ProgramResult {
        if self
            .writes
            .iter()
            .any(|write| !accounts.signs_for(write.owner.pda()))
        {
            return Err(CompressedAccountError::OwnerNotSigner.into());
        }
        let output_tree_id = load_tree_id(accounts.output_tree()?)?;
        let transact_bytes = self
            .into_ix_data(output_tree_id)?
            .serialize()
            .map_err(|_| CompressedAccountError::SerializationFailed)?;
        accounts.invoke::<MAX_ACCOUNTS>(&transact_bytes, signers)
    }

    /// The transact instruction data, with every output appended to the tree
    /// with the raw id `output_tree_id`. [`Self::invoke`] builds it on chain;
    /// a client builds the same data to prove the transaction.
    pub fn into_ix_data(
        self,
        output_tree_id: u16,
    ) -> Result<TransactIxData, CompressedAccountError> {
        let first_nullifier = *self
            .writes
            .first()
            .ok_or(CompressedAccountError::NoAccounts)?
            .input
            .nullifier();
        let width = square_width(self.writes.len())?;

        let mut inputs = Vec::with_capacity(self.writes.len());
        let mut input_hashes = Vec::with_capacity(self.writes.len());
        let mut address_nullifiers = Vec::with_capacity(self.writes.len());
        let mut tree_contexts: Vec<(u16, TreeContext)> = Vec::new();
        let mut outputs = Vec::with_capacity(self.writes.len());
        let mut output_hashes = Vec::with_capacity(self.writes.len());

        for write in self.writes {
            let tree_index = tree_index(&mut tree_contexts, write.tree_id, write.tree_context)?;
            inputs.push(InputUtxo {
                nullifier_hash: *write.input.nullifier(),
                tree_index,
            });
            let (input_hash, address_nullifier) = match &write.input {
                UtxoInput::Address(address) => ([0u8; 32], *address.address()),
                UtxoInput::Current(key) => (*key.hash(), [0u8; 32]),
            };
            input_hashes.push(input_hash);
            address_nullifiers.push(address_nullifier);

            let output_hash = DataUtxo {
                owner: &write.owner,
                data_hash: write.data_hash,
                blinding: write.blinding,
            }
            .hash(output_tree_id)?;
            let pda = write.owner.pda().to_bytes();
            outputs.push(TransactOutput {
                utxo_hash: output_hash,
                owner_tag: OwnerTag::Inline(pda),
                data: Some(write.data),
            });
            output_hashes.push(output_hash);
        }

        let external = TransactExternalData::from_outputs(outputs);
        let private_tx_blinding =
            derive_private_tx_blinding(&first_nullifier, &ACCOUNT_BLINDING_SEED)?;
        let private_tx_hash = PrivateTxHash {
            input_hashes: &input_hashes,
            output_hashes: &output_hashes,
            address_nullifiers: Some(&address_nullifiers),
            blinding: &private_tx_blinding,
        }
        .hash()?;
        Ok(external.into_ix_data(
            private_tx_hash,
            CircuitId::ConfidentialEddsa(width, width, N_PUBLIC_SLOTS as u8),
            self.proof,
            TransactInputs {
                inputs,
                tree_contexts: tree_contexts
                    .into_iter()
                    .map(|(_, context)| context)
                    .collect(),
            },
        ))
    }
}

/// The width of the smallest supported square shape holding `count` writes.
/// The instruction data carries only the writes: SPP fills the remaining
/// slots with compact padding.
fn square_width(count: usize) -> Result<u8, CompressedAccountError> {
    SPP_SUPPORTED_SHAPES
        .iter()
        .filter(|shape| shape.n_inputs() == shape.n_outputs() && shape.n_inputs() >= count)
        .map(Shape::n_inputs)
        .min()
        .and_then(|width| u8::try_from(width).ok())
        .ok_or(CompressedAccountError::TooManyAccounts)
}

/// The unique UTXO payload is `address || Borsh(state)`, inside the protocol's
/// plaintext tag and u32 length prefix. The blinding is transaction metadata:
/// derive it from the first nullifier, `ACCOUNT_BLINDING_SEED` and output index.
fn plaintext_output_data<T: BorshSerialize>(
    address: &[u8; 32],
    state: &T,
) -> Result<Vec<u8>, CompressedAccountError> {
    let mut data = alloc::vec![OutputDataEncoding::PLAINTEXT_TAG, 0, 0, 0, 0];
    data.extend_from_slice(address);
    state
        .serialize(&mut data)
        .map_err(|_| CompressedAccountError::SerializationFailed)?;
    let length =
        u32::try_from(data.len() - 5).map_err(|_| CompressedAccountError::SerializationFailed)?;
    data[1..5].copy_from_slice(&length.to_le_bytes());
    Ok(data)
}

/// Reuse a tree's context wherever it occurs in the input order.
fn tree_index(
    tree_contexts: &mut Vec<(u16, TreeContext)>,
    tree_id: u16,
    tree_context: TreeContext,
) -> Result<u8, CompressedAccountError> {
    if let Some((index, (_, context))) = tree_contexts
        .iter()
        .enumerate()
        .find(|(_, (id, _))| *id == tree_id)
    {
        if *context != tree_context {
            return Err(CompressedAccountError::ConflictingTreeContexts);
        }
        return u8::try_from(index).map_err(|_| CompressedAccountError::TooManyAccounts);
    }
    let index =
        u8::try_from(tree_contexts.len()).map_err(|_| CompressedAccountError::TooManyAccounts)?;
    tree_contexts.push((tree_id, tree_context));
    Ok(index)
}
