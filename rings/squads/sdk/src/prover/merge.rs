//! Policy-ring merge proof builder for a squads account (gated under the
//! `prover` feature).
//!
//! A merge consolidates up to 51 of one owner's same-asset ring UTXOs into a
//! single output of the same owner and total value. There is no ring proof and
//! no signature: the squads program's `merge_transact` checks only its
//! merge-authority access control and forwards the SPP `merge_ring` payload,
//! whose proof SPP verifies. The merged output carries SPP's merge ciphertext; its
//! blinding is `merge_output_blinding(nullifier_key, first_nullifier)`, so the
//! holder of the account's nullifier secret rebuilds it from the event.
//!
//! The owner is addressed by its owner identity (the viewing key account's
//! `owner`), wrapped in a precomputed-identity [`PublicKey`] so the merge circuit
//! takes its pass-through owner rail.

use solana_instruction::AccountMeta;
use solana_pubkey::Pubkey;
use zolana_client::{
    MergeProver, NonInclusionProof, ProofCompressed, ProverClient, ProverExt, SpendProof,
};
use zolana_interface::{instruction::instruction_data::merge_ring::MergeRingIxData, pda};
use zolana_keypair::{NullifierKey, PublicKey, ShieldedAddress, X25519Pubkey};
use zolana_program::instruction::MergeRing;
use zolana_squads_interface::SQUADS_RING_PROGRAM_ID;
use zolana_transaction::{
    instructions::merge::{
        merge_circuit_width, merge_dummy_nullifier, merge_output_blinding, merge_output_key,
        MergeOutputPlaintext, MergeProofInputs,
    },
    utxo::SppProofInputUtxo,
    Address, Data, Mint, SppProofOutputUtxo, Utxo, SOL_MINT,
};

use crate::prover::{error::SquadsProverError, spend::spp_err};

/// One ring UTXO the owner consolidates, with its inclusion and nullifier
/// non-inclusion proofs.
pub use crate::prover::spend::SquadsSpendInput as SquadsMergeInput;

/// Everything a merge needs.
pub struct SquadsMergeRequest {
    /// The owner identity, the viewing key account's `owner`.
    pub owner_identity: [u8; 32],
    pub nullifier_key: NullifierKey,
    /// The account's shared viewing key, carried on the merged output's owner
    /// address.
    pub viewing_pubkey: X25519Pubkey,
    /// 1..=51 same-asset inputs from one tree; input 0 seeds the blindings.
    pub inputs: Vec<SquadsMergeInput>,
    /// Non-inclusion proofs of [`merge_dummy_nullifiers`] for the padding slots,
    /// in slot order.
    pub dummy_nullifier_proofs: Vec<NonInclusionProof>,
    pub expiry_unix_ts: u64,
    pub output_tree_id: u16,
    /// The merge authority, SPP's `merge_ring` payer.
    pub payer: Address,
    pub prover_url: String,
}

/// The forwarded SPP payload of a merge and its accounts.
pub struct SquadsMergeProof {
    pub spp: MergeRingIxData,
    /// The SPP `merge_ring` account list the squads builder forwards.
    pub spp_accounts: Vec<AccountMeta>,
    pub output_utxo_hash: [u8; 32],
    pub output_amount: u64,
    pub output_blinding: [u8; 32],
    /// Every slot's nullifier, real inputs first.
    pub nullifiers: Vec<[u8; 32]>,
}

/// The deterministic nullifiers of a merge's padding slots, which the caller
/// fetches non-inclusion proofs for.
pub fn merge_dummy_nullifiers(
    nullifier_key: &NullifierKey,
    first_nullifier: &[u8; 32],
    real_inputs: usize,
) -> Result<Vec<[u8; 32]>, SquadsProverError> {
    let padded = merge_circuit_width(real_inputs)
        .ok_or(SquadsProverError::UnsupportedShape(real_inputs, 1))?;
    (real_inputs..padded)
        .map(|slot| {
            let slot = u8::try_from(slot)
                .map_err(|_| SquadsProverError::UnsupportedShape(real_inputs, 1))?;
            merge_dummy_nullifier(nullifier_key, first_nullifier, slot)
                .map_err(|_| SquadsProverError::Poseidon)
        })
        .collect()
}

/// The nullifier the merge's first input publishes; it seeds the dummy
/// nullifiers and the output blinding.
pub fn merge_first_nullifier(
    owner_identity: [u8; 32],
    nullifier_key: &NullifierKey,
    first: &SquadsMergeInput,
) -> Result<[u8; 32], SquadsProverError> {
    Ok(merge_input(owner_identity, nullifier_key, first)?.nullifier)
}

fn mint_of(asset: Address) -> Mint {
    if asset == SOL_MINT {
        Mint::SOL
    } else {
        Mint::new(asset, 0)
    }
}

fn merge_input(
    owner_identity: [u8; 32],
    nullifier_key: &NullifierKey,
    input: &SquadsMergeInput,
) -> Result<SppProofInputUtxo, SquadsProverError> {
    let nullifier_pubkey = nullifier_key
        .pubkey()
        .map_err(|_| SquadsProverError::Poseidon)?;
    let utxo = Utxo {
        owner: PublicKey::from_owner_identity(owner_identity),
        asset: mint_of(input.asset),
        amount: input.amount,
        blinding: input.blinding,
        ring_program_id: Some(Address::new_from_array(SQUADS_RING_PROGRAM_ID)),
        data: Data::default(),
    };
    let utxo_hash = utxo
        .hash(&nullifier_pubkey, &[0u8; 32], &[0u8; 32], input.tree_id)
        .map_err(|_| SquadsProverError::Poseidon)?;
    let nullifier = nullifier_key
        .nullifier(&utxo_hash, &input.blinding)
        .map_err(|_| SquadsProverError::Poseidon)?;
    Ok(SppProofInputUtxo {
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
    })
}

/// Build and prove the SPP `merge_ring` payload for `request`.
pub fn prove_squads_merge(
    request: SquadsMergeRequest,
) -> Result<SquadsMergeProof, SquadsProverError> {
    let SquadsMergeRequest {
        owner_identity,
        nullifier_key,
        viewing_pubkey,
        inputs,
        dummy_nullifier_proofs,
        expiry_unix_ts,
        output_tree_id,
        payer,
        prover_url,
    } = request;

    let first = inputs
        .first()
        .ok_or(SquadsProverError::UnsupportedShape(0, 1))?;
    let asset = first.asset;
    let tree_id = first.tree_id;
    if inputs.iter().any(|input| input.asset != asset) {
        return Err(SquadsProverError::InputAssetMismatch);
    }
    if inputs.iter().any(|input| input.tree_id != tree_id) {
        return Err(SquadsProverError::UnsupportedShape(inputs.len(), 1));
    }
    let total = inputs
        .iter()
        .try_fold(0u64, |acc, input| acc.checked_add(input.amount))
        .ok_or(SquadsProverError::InvalidAmount)?;

    let mut input_utxos = inputs
        .iter()
        .map(|input| merge_input(owner_identity, &nullifier_key, input))
        .collect::<Result<Vec<_>, _>>()?;
    let first_nullifier = input_utxos
        .first()
        .ok_or(SquadsProverError::UnsupportedShape(0, 1))?
        .nullifier;
    for nullifier in merge_dummy_nullifiers(&nullifier_key, &first_nullifier, inputs.len())? {
        let mut dummy =
            SppProofInputUtxo::compact(tree_id).map_err(|_| SquadsProverError::Poseidon)?;
        dummy.nullifier = nullifier;
        input_utxos.push(dummy);
    }
    let spend_proofs: Vec<SpendProof> = inputs.into_iter().map(|input| input.spend_proof).collect();

    let owner = PublicKey::from_owner_identity(owner_identity);
    let nullifier_pubkey = nullifier_key
        .pubkey()
        .map_err(|_| SquadsProverError::Poseidon)?;
    let output_blinding = merge_output_blinding(&nullifier_key, &first_nullifier)
        .map_err(|_| SquadsProverError::Poseidon)?;
    let ring_program_id = Address::new_from_array(SQUADS_RING_PROGRAM_ID);
    let output_utxo = SppProofOutputUtxo {
        asset: mint_of(asset),
        amount: total,
        blinding: output_blinding,
        ring_program_id: Some(ring_program_id),
        ring_data_hash: None,
        data_hash: None,
        owner_address: Some(ShieldedAddress {
            signing_pubkey: owner,
            nullifier_pubkey,
            viewing_pubkey,
        }),
        owner_tag: None,
        data: Data::default(),
        cache_slot: None,
        compact: false,
    };

    let output_ciphertext_salt = zolana_keypair::random_salt();
    let output_ciphertext = MergeOutputPlaintext {
        amount: total,
        mint: asset,
    }
    .encrypt(
        &merge_output_key(&nullifier_key, &first_nullifier)
            .map_err(|_| SquadsProverError::Poseidon)?,
        &output_ciphertext_salt,
    )
    .map_err(|_| SquadsProverError::Poseidon)?;
    let result = MergeProver {
        transaction: MergeProofInputs {
            input_utxos,
            output_utxo,
            expiry_unix_ts,
            signing_pubkey: owner,
            output_tree_id,
            ring_program_id: Some(ring_program_id),
            output_ciphertext_salt,
            output_ciphertext,
        },
        nullifier_key,
        proofs: spend_proofs,
        dummy_nullifier_proofs,
        cache: None,
    }
    .build()
    .map_err(spp_err)?;
    let proof = ProverClient::new(prover_url)
        .prove_merge_ring(&result.inputs)
        .map_err(spp_err)?;
    let proof = ProofCompressed::try_from(proof)
        .map_err(spp_err)?
        .to_merge_proof()
        .map_err(spp_err)?;
    let spp = result.ring_instruction_data(proof);

    let spp_accounts = MergeRing {
        input_tree: pda::tree(tree_id),
        output_tree: pda::tree(output_tree_id),
        ring_program_id: Pubkey::new_from_array(SQUADS_RING_PROGRAM_ID),
        payer: Pubkey::new_from_array(payer.to_bytes()),
        data: spp.merge.clone(),
        output_ring_data_hash: spp.output_ring_data_hash,
        cache: None,
    }
    .instruction()
    .accounts;

    Ok(SquadsMergeProof {
        output_utxo_hash: result.output_hash,
        output_amount: total,
        output_blinding,
        nullifiers: result.nullifiers,
        spp,
        spp_accounts,
    })
}
