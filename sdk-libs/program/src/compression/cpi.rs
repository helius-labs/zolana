use alloc::vec::Vec;

use borsh::BorshSerialize;
use pinocchio::{cpi::Signer, error::ProgramError, ProgramResult};
use zolana_interface::{
    event::OutputDataEncoding,
    instruction::{
        instruction_data::transact::{
            CircuitId, InputUtxo, OwnerTag, TransactIxData, TransactOutput, TransactProof,
            TreeContext,
        },
        tag::TRANSACT,
    },
    N_PUBLIC_SLOTS,
};

use super::{
    account::AccountInput, load_tree_id, CompressedAccount, CompressedAccountData,
    CompressedAccountError, DataUtxo, PdaOwner,
};
use crate::{
    cpi::SppTransactAccounts,
    derivation::{
        derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
    },
    PrivateTxHash, TransactExternalData, TransactInputs,
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
/// The inputs of one tree must be added one after another, and share that
/// tree's root indexes.
pub struct SppTransactCpi<'a> {
    proof: TransactProof,
    writes: Vec<AccountWrite<'a>>,
}

/// A write with its new state hashed and serialized, so one transaction can
/// write accounts of different state types.
struct AccountWrite<'a> {
    owner: &'a PdaOwner,
    input: AccountInput,
    tree_id: u16,
    tree_context: TreeContext,
    blinding: [u8; 32],
    data_hash: [u8; 32],
    data: Vec<u8>,
}

impl<'a> SppTransactCpi<'a> {
    pub fn new(proof: TransactProof) -> Self {
        Self {
            proof,
            writes: Vec::new(),
        }
    }

    /// Adds a write of `account`. Its state gets the blinding the circuit
    /// derives for its output slot, and is then hashed and published as it
    /// stands.
    pub fn with_compressed_account<A: CompressedAccountData>(
        mut self,
        account: CompressedAccount<'a, A>,
    ) -> Result<Self, ProgramError> {
        let CompressedAccount {
            owner,
            input,
            tree_id,
            tree_context,
            account: mut state,
        } = account;
        let first_nullifier = match self.writes.first() {
            Some(first) => *first.input.nullifier(),
            None => *input.nullifier(),
        };
        let slot = u32::try_from(self.writes.len())
            .map_err(|_| CompressedAccountError::TooManyAccounts)?;
        let blinding = output_blinding(&first_nullifier, slot)?;
        *state.blinding_mut() = blinding;
        let data_hash = state.data_hash()?;
        let data = plaintext_output_data(&state)?;
        self.writes.push(AccountWrite {
            owner,
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
        let count =
            u8::try_from(self.writes.len()).map_err(|_| CompressedAccountError::TooManyAccounts)?;

        let mut inputs = Vec::with_capacity(self.writes.len());
        let mut input_hashes = Vec::with_capacity(self.writes.len());
        let mut address_nullifiers = Vec::with_capacity(self.writes.len());
        let mut tree_contexts: Vec<(u16, TreeContext)> = Vec::new();
        let mut outputs = Vec::with_capacity(self.writes.len());
        let mut output_hashes = Vec::with_capacity(self.writes.len());
        let mut owner_tags = Vec::with_capacity(self.writes.len());

        for write in self.writes {
            let tree_index = tree_index(&mut tree_contexts, write.tree_id, write.tree_context)?;
            inputs.push(InputUtxo {
                nullifier_hash: *write.input.nullifier(),
                tree_index,
            });
            let (input_hash, address_nullifier) = match &write.input {
                AccountInput::Address(address) => ([0u8; 32], *address.address()),
                AccountInput::Current(key) => (*key.hash(), [0u8; 32]),
            };
            input_hashes.push(input_hash);
            address_nullifiers.push(address_nullifier);

            let output_hash = DataUtxo {
                owner: write.owner,
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
            owner_tags.push(pda);
        }

        let external = TransactExternalData::from_outputs(outputs);
        let external_data_hash = external.hash(TRANSACT, &[], &owner_tags)?;
        let private_tx_blinding =
            derive_private_tx_blinding(&first_nullifier, &ACCOUNT_BLINDING_SEED)?;
        let private_tx_hash = PrivateTxHash {
            input_hashes: &input_hashes,
            output_hashes: &output_hashes,
            address_nullifiers: Some(&address_nullifiers),
            external_data_hash: &external_data_hash,
            blinding: &private_tx_blinding,
        }
        .hash()?;
        Ok(external.into_ix_data(
            private_tx_hash,
            CircuitId::ConfidentialEddsa(count, count, N_PUBLIC_SLOTS as u8),
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

/// The blinding the circuit derives for output `slot` of a transaction with
/// `first_nullifier` and [`ACCOUNT_BLINDING_SEED`].
fn output_blinding(
    first_nullifier: &[u8; 32],
    slot: u32,
) -> Result<[u8; 32], CompressedAccountError> {
    let seed = derive_output_blinding_seed(first_nullifier, &ACCOUNT_BLINDING_SEED)?;
    Ok(derive_transact_output_blinding(
        first_nullifier,
        &seed,
        slot,
    )?)
}

/// `state` as `OutputDataEncoding::Plaintext` output data: the plaintext tag,
/// the borsh length as a little-endian `u32`, then the borsh bytes.
fn plaintext_output_data(state: &impl BorshSerialize) -> Result<Vec<u8>, CompressedAccountError> {
    let state_len =
        borsh::object_length(state).map_err(|_| CompressedAccountError::SerializationFailed)?;
    let state_len_prefix =
        u32::try_from(state_len).map_err(|_| CompressedAccountError::SerializationFailed)?;
    let mut data = Vec::with_capacity(1 + 4 + state_len);
    data.push(OutputDataEncoding::PLAINTEXT_TAG);
    data.extend_from_slice(&state_len_prefix.to_le_bytes());
    state
        .serialize(&mut data)
        .map_err(|_| CompressedAccountError::SerializationFailed)?;
    Ok(data)
}

/// The index of `tree_id`'s context, adding it when the tree starts a new run
/// of inputs. Transact takes one context per tree and needs the inputs of a
/// tree to be contiguous.
fn tree_index(
    tree_contexts: &mut Vec<(u16, TreeContext)>,
    tree_id: u16,
    tree_context: TreeContext,
) -> Result<u8, CompressedAccountError> {
    match tree_contexts.last() {
        Some((last_tree_id, last_context)) if *last_tree_id == tree_id => {
            if *last_context != tree_context {
                return Err(CompressedAccountError::ConflictingTreeContexts);
            }
        }
        _ => {
            if tree_contexts.iter().any(|(id, _)| *id == tree_id) {
                return Err(CompressedAccountError::InputTreesNotContiguous);
            }
            tree_contexts.push((tree_id, tree_context));
        }
    }
    u8::try_from(tree_contexts.len().saturating_sub(1))
        .map_err(|_| CompressedAccountError::TooManyAccounts)
}
