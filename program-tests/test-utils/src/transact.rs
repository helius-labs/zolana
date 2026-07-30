//! Shared `transact` proof-wiring helpers: witness construction, prover
//! round-trips used by the shielded-pool proof tests and the validator
//! lifecycle harnesses. The public-input hash is NOT re-assembled here: callers
//! use the canonical `zolana_client::PublicInputs::hash()`.

use anyhow::{anyhow, Context, Result};
use groth16_solana::groth16::Groth16Verifier;
use num_bigint::BigUint;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    prover::field::{be, right_align_slice},
    spawn_prover, Proof, ProofCompressed, ProofInputUtxo, ProverClient, PublicInputs,
    PublicMovements, TransferInput, TransferInputs, TransferOutput, NULLIFIER_TREE_HEIGHT,
    STATE_TREE_HEIGHT,
};
use zolana_hasher::primitives::hash_bytes;
use zolana_hasher::{sha256::Sha256BE, Hasher, Poseidon};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{
            CircuitId, ExternalDataHash, InputUtxo, InterfaceTransfer, OwnerTag,
            ResolvedInterfaceTransfer, ResolvedOutput, TransactIxData, TransactOutput,
            TransactProof,
        },
        tag, Transact, TransactInterfaceTransferAccounts, TransactSplWithdrawalAccounts,
    },
    pda,
    verifying_keys::transfer_confidential_2_3,
    N_PUBLIC_SLOTS, SOL_ASSET_FIELD,
};
use zolana_keypair::{
    hash::owner_hash, NullifierKey, P256Pubkey, PublicKey, ShieldedAddress, ViewingKey,
};
use zolana_merkle_tree::indexed::{IndexedMerkleTree, NonInclusionProof};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::ZolanaProgramTest;
use zolana_transaction::{
    instructions::transact::spp_proof_inputs::{signed_to_field, BN254_MODULUS_DEC},
    instructions::transact::PrivateTxHash,
    instructions::types::SppProofInputUtxo,
    Data, SppProofOutputUtxo, Utxo,
};
use zolana_tree::TreeAccount;

pub fn start_prover() -> Result<()> {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        std::env::set_var(
            "ZOLANA_PROVER_KEYS_DIR",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../prover/server/proving-keys"
            ),
        );
    });
    spawn_prover()?;
    Ok(())
}

/// A field element holding `value` in its low 8 bytes (big-endian).
pub fn fe(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

/// Build the compressed proof carried by a `transact` instruction.
pub fn pack_transact_proof(proof: &Proof) -> Result<TransactProof> {
    Ok(ProofCompressed::try_from(*proof)?.to_transact_proof())
}

pub type PublicSlots = ([[u8; 32]; N_PUBLIC_SLOTS], [[u8; 32]; N_PUBLIC_SLOTS]);

pub fn sol_public_slots(amount: [u8; 32]) -> PublicSlots {
    let zero = [0u8; 32];
    let mut assets = [zero; N_PUBLIC_SLOTS];
    let mut amounts = [zero; N_PUBLIC_SLOTS];
    if amount != zero {
        *assets.first_mut().expect("public slot exists") = SOL_ASSET_FIELD;
        *amounts.first_mut().expect("public slot exists") = amount;
    }
    (assets, amounts)
}

pub fn spl_public_slots(amount: [u8; 32], mint: &[u8; 32]) -> Result<PublicSlots> {
    let zero = [0u8; 32];
    let mut assets = [zero; N_PUBLIC_SLOTS];
    let mut amounts = [zero; N_PUBLIC_SLOTS];
    if amount != zero {
        *assets.first_mut().expect("public slot exists") =
            hash_bytes(mint).map_err(|e| anyhow!("public SPL asset field: {e:?}"))?;
        *amounts.first_mut().expect("public slot exists") = amount;
    }
    Ok((assets, amounts))
}

/// Per-output owner `pk_field` the program reconstructs as
/// `hash_bytes(resolved_owner_tag)`, one per output position. Mirrors the
/// program's `resolve_outputs`: each output carries its own inline or
/// account-based owner tag.
pub fn output_owner_pk_hashes(outputs: &[TransactOutput]) -> Result<Vec<[u8; 32]>> {
    outputs
        .iter()
        .map(|output| {
            let resolved = output
                .into_resolved(|_| None)
                .map_err(|e| anyhow!("resolve owner tag: {e:?}"))?;
            hash_bytes(&resolved.owner_tag).map_err(|e| anyhow!("owner pk field: {e:?}"))
        })
        .collect()
}

/// Build the `transact` output slots from parallel utxo-hash and owner-view-tag
/// vectors: each output carries an `Inline` owner tag equal to its view tag and
/// no ciphertext, so `hash_bytes(view_tag)` is the OWNER public input the circuit
/// binds that output to. The two slices must have equal length; extra entries in
/// either are dropped.
pub fn inline_outputs(
    output_utxo_hashes: &[[u8; 32]],
    view_tags: &[[u8; 32]],
) -> Vec<TransactOutput> {
    output_utxo_hashes
        .iter()
        .zip(view_tags.iter())
        .map(|(utxo_hash, view_tag)| inline_output(*utxo_hash, *view_tag))
        .collect()
}

/// One inline, plaintext-free output slot.
pub fn inline_output(utxo_hash: [u8; 32], view_tag: [u8; 32]) -> TransactOutput {
    TransactOutput {
        utxo_hash,
        owner_tag: OwnerTag::Inline(view_tag),
        data: None,
    }
}

/// Resolve every output's owner tag against the transaction context (`Inline`
/// tags resolve to themselves), producing the `ResolvedOutput` slice
/// [`ExternalDataHash`] hashes. Mirrors the program's per-output resolution so
/// the client and program agree on the hash preimage.
pub fn resolve_outputs(ix: &TransactIxData) -> Result<Vec<ResolvedOutput<'_>>> {
    ix.outputs
        .iter()
        .map(|output| {
            output
                .into_resolved(|_| None)
                .map_err(|e| anyhow!("resolve owner tag: {e:?}"))
        })
        .collect()
}

/// Stamp the confidential owner tag onto each witness output. `owner_pk_hashes[i]`
/// is the program's `hash_bytes(view_tag[i])` (so the public output-owner chain
/// matches), and `nullifier_pks[i]` is the real output's nullifier pubkey from
/// which the circuit recomputes `owner_hash` (zero for a dummy, whose owner the
/// circuit leaves unconstrained).
///
/// Two rules every caller relies on: a real output's owner tag is its owner's
/// `confidential_view_tag` (so the program's `hash_bytes(resolved_owner_tag)`
/// equals that owner's `owner_pk_field`), and PR164's `AssertDummyTags` gate
/// requires every DUMMY output to name a transaction participant, so dummy
/// slots reuse a real participant's tag rather than a fresh key's.
pub fn set_output_owner_tags(
    outputs: &mut [TransferOutput],
    owner_pk_hashes: &[[u8; 32]],
    nullifier_pks: &[[u8; 32]],
) {
    for ((output, owner), nullifier_pk) in outputs
        .iter_mut()
        .zip(owner_pk_hashes.iter())
        .zip(nullifier_pks.iter())
    {
        output.owner_pk_hash = be(owner);
        output.nullifier_pk = be(nullifier_pk);
    }
}

pub fn eddsa_input_utxo(nullifier_hash: [u8; 32], utxo_tree_root_index: u16) -> InputUtxo {
    InputUtxo {
        nullifier_hash,
        nullifier_tree_root_index: 0,
        utxo_tree_root_index,
        eddsa_signer_index: 0,
    }
}

pub fn new_transact_ix_data(
    inputs: Vec<InputUtxo>,
    interface_transfers: Vec<InterfaceTransfer>,
    outputs: Vec<TransactOutput>,
) -> TransactIxData {
    let circuit = CircuitId::ConfidentialEddsa(
        inputs.len() as u8,
        outputs.len() as u8,
        N_PUBLIC_SLOTS as u8,
    );
    TransactIxData {
        proof: TransactProof::zeroed(),
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0u8; 32],
        circuit,
        inputs,
        interface_transfers,
        data_hash: None,
        zone_data_hash: None,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        outputs,
        messages: Vec::new(),
    }
}

/// The single hand-maintained `ExternalDataHash` assembly; both settlement
/// rails feed it with their own bound accounts (mirroring the program's
/// `settlement_accounts`).
pub fn external_data_hash(
    transact_ix_data: &TransactIxData,
    interface_transfers: &[ResolvedInterfaceTransfer],
) -> Result<[u8; 32]> {
    let outputs = resolve_outputs(transact_ix_data)?;
    Ok(ExternalDataHash {
        spp_instruction_discriminator: tag::TRANSACT,
        expiry_unix_ts: transact_ix_data.expiry_unix_ts,
        interface_transfers,
        data_hash: None,
        zone_data_hash: None,
        tx_viewing_pk: &transact_ix_data.tx_viewing_pk,
        salt: &transact_ix_data.salt,
        outputs: &outputs,
        messages: &transact_ix_data.messages,
    }
    .hash()?)
}

/// `external_data_hash` for an SPL settlement: binds the user's SPL token
/// account and the pool's SPL interface vault as a resolved SPL interface
/// transfer, exactly as the program's `settlement_accounts` does for the SPL
/// rail.
pub fn external_data_hash_spl(
    transact_ix_data: &TransactIxData,
    user_spl_token_account: &[u8; 32],
    spl_token_interface: &[u8; 32],
) -> Result<[u8; 32]> {
    let transfer = transact_ix_data
        .interface_transfers
        .first()
        .context("external_data_hash_spl requires one SPL interface transfer")?;
    let resolved = if transfer.is_deposit() {
        ResolvedInterfaceTransfer::SplDeposit {
            amount: transfer.amount(),
            user_token_account: *user_spl_token_account,
            vault: *spl_token_interface,
        }
    } else {
        ResolvedInterfaceTransfer::SplWithdrawal {
            amount: transfer.amount(),
            user_token_account: *user_spl_token_account,
            vault: *spl_token_interface,
        }
    };
    external_data_hash(transact_ix_data, &[resolved])
}

/// A dummy output (`owner_hash = 0`) over a chosen `blinding`, assembled exactly as
/// the production prover does (`assemble_outputs`): it gets a real `utxo_hash` that
/// the program appends to the tree and the proof commits via the public output
/// chain, while contributing `0` to `private_tx_hash`. Returns the witness output
/// and that hash so callers can wire both consistently.
pub fn dummy_transfer_output(blinding: &[u8; 31]) -> Result<(TransferOutput, [u8; 32])> {
    let mut field_blinding = [0u8; 32];
    field_blinding[1..].copy_from_slice(blinding);
    let output = SppProofOutputUtxo {
        blinding: field_blinding,
        ..Default::default()
    };
    let hash = output
        .hash()
        .map_err(|e| anyhow!("dummy output hash: {e:?}"))?;
    let utxo =
        ProofInputUtxo::try_from(&output).map_err(|e| anyhow!("dummy output utxo: {e:?}"))?;
    let zero = [0u8; 32];
    Ok((
        TransferOutput {
            utxo,
            is_dummy: be(&fe(1)),
            hash: be(&hash),
            // Patched by `set_output_owner_tags` once the per-output view_tag
            // mapping is known; a dummy's nullifier_pk stays 0 (unconstrained).
            owner_pk_hash: be(&zero),
            nullifier_pk: be(&zero),
        },
        hash,
    ))
}

pub struct TransferProverInputsArgs {
    pub inputs: Vec<TransferInput>,
    pub outputs: Vec<TransferOutput>,
    pub external_data_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub public_slot_assets: [[u8; 32]; N_PUBLIC_SLOTS],
    pub public_slot_amounts: [[u8; 32]; N_PUBLIC_SLOTS],
    pub payer_pubkey_hash: [u8; 32],
    pub public_input_hash: [u8; 32],
}

pub fn build_transfer_prover_inputs(args: TransferProverInputsArgs) -> TransferInputs {
    let zero = [0u8; 32];
    TransferInputs {
        inputs: args.inputs,
        outputs: args.outputs,
        external_data_hash: be(&args.external_data_hash),
        private_tx_hash: be(&args.private_tx_hash),
        public_assets: args.public_slot_assets.map(|asset| be(&asset)),
        public_amounts: args.public_slot_amounts.map(|amount| be(&amount)),
        zone_program_id: be(&zero),
        payer_pubkey_hash: be(&args.payer_pubkey_hash),
        allow_dummy_inputs: be(&fe(1)),
        public_input_hash: be(&args.public_input_hash),
    }
}

/// Prove and locally verify a transfer on the fixed (2 inputs, 3 outputs)
/// confidential eddsa shape every current caller uses; the verifying key is
/// pinned to that shape.
pub fn prove_and_verify_transfer(
    prover_inputs: &TransferInputs,
    public_input_hash: [u8; 32],
    label: &str,
) -> Result<TransactProof> {
    let proof = ProverClient::local().prove_transfer(prover_inputs)?;
    let public_inputs = [public_input_hash];
    let mut verifier = Groth16Verifier::new(
        &proof.a,
        &proof.b,
        &proof.c,
        &public_inputs,
        &transfer_confidential_2_3::VERIFYINGKEY,
    )
    .map_err(|err| anyhow!("construct {label} verifier: {err:?}"))?;
    verifier
        .verify()
        .map_err(|err| anyhow!("verify {label} proof: {err:?}"))?;
    pack_transact_proof(&proof)
}

/// A fixed dummy viewing pubkey for real test outputs: the proof math
/// (`owner_hash` / `owner_pk_field`) never reads the viewing key, so any valid
/// P256 point works and a constant keeps the run deterministic.
fn test_viewing_pubkey() -> P256Pubkey {
    ViewingKey::from_bytes(&[5u8; 32])
        .expect("viewing key")
        .pubkey()
}

fn expand_blinding(blinding: &[u8; 31]) -> [u8; 32] {
    let mut field = [0u8; 32];
    field[1..].copy_from_slice(blinding);
    field
}

/// A real (non-dummy) output owned by `signing_pubkey`/`nullifier_pubkey`. The
/// resulting `owner_hash` is `Poseidon(signing_pubkey.owner_pk_field, nullifier)`,
/// which the circuit recomputes from the witness `owner_pk_hash` + `nullifier_pk`
/// stamped by [`set_output_owner_tags`].
pub fn real_output(
    signing_pubkey: PublicKey,
    nullifier_pubkey: [u8; 32],
    asset: Address,
    amount: u64,
    blinding: [u8; 31],
) -> SppProofOutputUtxo {
    SppProofOutputUtxo {
        asset,
        amount,
        blinding: expand_blinding(&blinding),
        owner_address: Some(ShieldedAddress {
            signing_pubkey,
            nullifier_pubkey,
            viewing_pubkey: test_viewing_pubkey(),
        }),
        ..Default::default()
    }
}

/// One circuit-dummy input over `blinding`: domain-tagged dummy utxo fields, the
/// nullifier derived over the dummified utxo hash with secret 0, and a real
/// non-inclusion witness for that nullifier from `nf_tree` (the circuit checks
/// non-inclusion for every slot). Returns the input and its nullifier — SPP
/// inserts dummy nullifiers exactly like real ones.
pub fn dummy_input(
    blinding: &[u8; 31],
    nf_tree: &IndexedMerkleTree<Poseidon, usize>,
    roots: ([u8; 32], [u8; 32]),
    owner_pk_hash: &[u8; 32],
) -> Result<(TransferInput, [u8; 32])> {
    let mut spend = SppProofInputUtxo::new_dummy();
    spend.utxo.blinding = expand_blinding(blinding);
    let nullifier = spend.nullifier()?;
    let non_inclusion = nf_tree.get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))?;
    let (utxo_root, nullifier_root) = roots;
    let zero = [0u8; 32];
    let input = TransferInput {
        utxo: ProofInputUtxo::try_from(&spend)?,
        is_dummy: be(&fe(1)),
        state_path_elements: vec![be(&zero); STATE_TREE_HEIGHT],
        state_path_index: be(&zero),
        nullifier_low_value: be(&non_inclusion.leaf_lower_range_value),
        nullifier_next_value: be(&non_inclusion.leaf_higher_range_value),
        nullifier_low_path_elements: non_inclusion.merkle_proof.iter().map(be).collect(),
        nullifier_low_path_index: be(&fe(non_inclusion.leaf_index as u64)),
        utxo_tree_root: be(&utxo_root),
        nullifier_tree_root: be(&nullifier_root),
        nullifier: be(&nullifier),
        owner_pk_hash: be(owner_pk_hash),
        nullifier_secret: be(&zero),
    };
    Ok((input, nullifier))
}

/// The nullifier a dummy input over `blinding` derives (over the dummified utxo
/// hash with secret 0). Callers fetch this value's non-inclusion proof before
/// building the input with [`dummy_input_with_proof`].
pub fn dummy_nullifier(blinding: &[u8; 31]) -> Result<[u8; 32]> {
    let mut spend = SppProofInputUtxo::new_dummy();
    spend.utxo.blinding = expand_blinding(blinding);
    Ok(spend.nullifier()?)
}

/// [`dummy_input`] over an indexer-fetched non-inclusion proof for the dummy's
/// own nullifier (see [`dummy_nullifier`]).
pub fn dummy_input_with_proof(
    blinding: &[u8; 31],
    non_inclusion: &zolana_client::NonInclusionProof,
    roots: ([u8; 32], [u8; 32]),
    owner_pk_hash: &[u8; 32],
) -> Result<TransferInput> {
    let mut spend = SppProofInputUtxo::new_dummy();
    spend.utxo.blinding = expand_blinding(blinding);
    let nullifier = spend.nullifier()?;
    let (utxo_root, nullifier_root) = roots;
    let zero = [0u8; 32];
    Ok(TransferInput {
        utxo: ProofInputUtxo::try_from(&spend)?,
        is_dummy: be(&fe(1)),
        state_path_elements: vec![be(&zero); STATE_TREE_HEIGHT],
        state_path_index: be(&zero),
        nullifier_low_value: be(&non_inclusion.low_element),
        nullifier_next_value: be(&non_inclusion.high_element),
        nullifier_low_path_elements: non_inclusion.path.iter().map(be).collect(),
        nullifier_low_path_index: be(&fe(non_inclusion.low_element_index)),
        utxo_tree_root: be(&utxo_root),
        nullifier_tree_root: be(&nullifier_root),
        nullifier: be(&nullifier),
        owner_pk_hash: be(owner_pk_hash),
        nullifier_secret: be(&zero),
    })
}

pub fn nullifier_tree() -> Result<IndexedMerkleTree<Poseidon, usize>> {
    let modulus_minus_one = BigUint::parse_bytes(BN254_MODULUS_DEC.as_bytes(), 10)
        .context("parse bn254 modulus")?
        - 1u32;
    Ok(IndexedMerkleTree::<Poseidon, usize>::new_with_next_value(
        NULLIFIER_TREE_HEIGHT,
        0,
        modulus_minus_one,
    )?)
}

pub struct SpendInputArgs<'a> {
    pub utxo: &'a Utxo,
    pub owner_field: &'a [u8; 32],
    pub state_path: &'a [[u8; 32]],
    pub state_path_index: u64,
    pub non_inclusion: &'a NonInclusionProof,
    pub roots: ([u8; 32], [u8; 32]),
    pub nullifier: &'a [u8; 32],
    pub owner_pk_hash: &'a [u8; 32],
    pub nullifier_key: &'a NullifierKey,
}

pub fn spend_input(args: SpendInputArgs<'_>) -> Result<TransferInput> {
    let (utxo_root, nullifier_root) = args.roots;
    Ok(TransferInput {
        utxo: ProofInputUtxo::new(
            *args.owner_field,
            &args.utxo.asset,
            args.utxo.amount,
            &args.utxo.blinding,
        )?
        .with_zone([0u8; 32], &args.utxo.zone_program_id)?,
        is_dummy: be(&fe(0)),
        state_path_elements: args.state_path.iter().map(be).collect(),
        state_path_index: be(&fe(args.state_path_index)),
        nullifier_low_value: be(&args.non_inclusion.leaf_lower_range_value),
        nullifier_next_value: be(&args.non_inclusion.leaf_higher_range_value),
        nullifier_low_path_elements: args.non_inclusion.merkle_proof.iter().map(be).collect(),
        nullifier_low_path_index: be(&fe(args.non_inclusion.leaf_index as u64)),
        utxo_tree_root: be(&utxo_root),
        nullifier_tree_root: be(&nullifier_root),
        nullifier: be(args.nullifier),
        owner_pk_hash: be(args.owner_pk_hash),
        nullifier_secret: be(&right_align_slice(args.nullifier_key.secret())?),
    })
}

/// A real (non-dummy) witness output. The confidential owner tag
/// (`owner_pk_hash`) and `nullifier_pk` are left zero here and stamped by
/// [`set_output_owner_tags`] once the per-output view_tag mapping is known.
pub fn transfer_output(output: &SppProofOutputUtxo) -> Result<TransferOutput> {
    let hash = output.hash()?;
    let zero = [0u8; 32];
    Ok(TransferOutput {
        utxo: ProofInputUtxo::try_from(output)?,
        is_dummy: be(&fe(0)),
        hash: be(&hash),
        owner_pk_hash: be(&zero),
        nullifier_pk: be(&zero),
    })
}

pub fn public_sol_field(amount: Option<i64>) -> [u8; 32] {
    amount.map(signed_to_field).unwrap_or_default()
}

/// Everything a caller needs to drive and assert an SPL-withdrawal `transact`:
/// the bound settlement accounts, the spent UTXO's hash and nullifier, the
/// proven instruction data (cloneable for negative variants), and the
/// ready-to-send instruction.
pub struct SplWithdrawal {
    pub mint: Pubkey,
    pub vault: Pubkey,
    pub user_token: Pubkey,
    pub utxo_hash: [u8; 32],
    pub nullifier: [u8; 32],
    pub data: TransactIxData,
    pub instruction: Instruction,
}

/// Shared SPL-withdrawal pipeline: shield one real SPL UTXO of `amount` owned
/// by the payer's Ed25519 key via the proofless SPL deposit, then spend it in a
/// (2,3) eddsa `transact` (one real input, one dummy input, three dummy
/// outputs) carrying a real Groth16 proof, withdrawing the full token amount
/// from the vault back to the payer's token account. The input carries a real
/// state-inclusion proof against the on-chain UTXO tree root and a real
/// nullifier non-inclusion proof against the on-chain nullifier tree root, both
/// built from reference trees and gated against the on-chain roots. Fixed
/// blinding / nullifier secrets keep the run deterministic.
pub fn build_spl_withdrawal(
    pt: &mut ZolanaProgramTest,
    authority: &Keypair,
    tree: &Pubkey,
    amount: u64,
    blinding: [u8; 32],
) -> Result<SplWithdrawal> {
    let mint = pt.create_mint().context("create mint")?;
    pt.ensure_asset_counter(authority)
        .context("create asset counter")?;
    pt.create_spl_interface(authority, &mint)
        .context("create SPL interface")?;

    let payer = pt.payer.insecure_clone();
    let payer_bytes = payer.pubkey().to_bytes();
    let zero = [0u8; 32];

    let user_token = pt
        .create_token_account(&mint, &payer.pubkey())
        .context("create user token account")?;
    pt.mint_to(&mint, &user_token, amount).context("mint SPL")?;
    let vault = pda::spl_asset_vault(&mint);

    let nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let utxo = Utxo {
        owner: PublicKey::from_ed25519(&payer_bytes),
        asset: Address::new_from_array(mint.to_bytes()),
        amount,
        blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let owner_pk_hash = utxo.owner.owner_proof_input_hash().expect("owner hash");
    let owner_field = owner_hash(&utxo.owner, &nullifier_pk).expect("owner field");
    let shield =
        ZolanaProgramTest::spl_shield_data(amount, owner_field, blinding, &mint, &user_token);
    let event = pt.deposit(tree, &payer, &shield).context("SPL deposit")?;
    let utxo_hash = utxo.hash(&nullifier_pk, &zero, &zero).expect("UTXO hash");
    assert_eq!(event.utxo_hash, utxo_hash);

    // The UTXO is leaf 0; its inclusion proof binds the post-shield root
    // (history index 1, as in transact/withdrawal.rs).
    let mut tree_data = pt.account_data(tree).expect("tree account");
    let tree_account = TreeAccount::from_bytes(&mut tree_data, tree.to_bytes()).expect("load tree");
    let utxo_root = tree_account.get_utxo_tree_root(1).expect("utxo root");
    let nullifier_root = tree_account
        .get_nullifier_tree_root(0)
        .expect("nullifier root");

    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    state_tree.append(&utxo_hash).expect("append state leaf");
    assert_eq!(state_tree.root(), utxo_root);
    let state_path: Vec<[u8; 32]> = state_tree
        .get_proof_of_leaf(0, true)
        .expect("state proof")
        .to_vec();
    let nf_tree = nullifier_tree().expect("nullifier tree");
    assert_eq!(nf_tree.root(), nullifier_root);
    let nullifier = nullifier_key
        .nullifier(&utxo_hash, &blinding)
        .expect("nullifier");
    let non_inclusion = nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
        .expect("non-inclusion proof");
    let roots = (utxo_root, nullifier_root);
    let (withdraw_dummy_input, dummy_nullifier) =
        dummy_input(&[2u8; 31], &nf_tree, roots, &owner_pk_hash).expect("dummy input");
    let spend = spend_input(SpendInputArgs {
        utxo: &utxo,
        owner_field: &owner_field,
        state_path: &state_path,
        state_path_index: 0,
        non_inclusion: &non_inclusion,
        roots,
        nullifier: &nullifier,
        owner_pk_hash: &owner_pk_hash,
        nullifier_key: &nullifier_key,
    })
    .expect("spend input");

    let dummy_outputs: Vec<(TransferOutput, [u8; 32])> = [[1u8; 31], [2u8; 31], [3u8; 31]]
        .iter()
        .map(|blinding| dummy_transfer_output(blinding).expect("dummy output"))
        .collect();
    let output_hashes: Vec<[u8; 32]> = dummy_outputs.iter().map(|(_, hash)| *hash).collect();
    let mut outputs: Vec<TransferOutput> = dummy_outputs.into_iter().map(|(out, _)| out).collect();
    // Dummy slots carry the payer's tag (the AssertDummyTags rule; see
    // `set_output_owner_tags`).
    let mut data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(nullifier, 1),
            eddsa_input_utxo(dummy_nullifier, 1),
        ],
        vec![InterfaceTransfer::SplWithdrawal {
            amount,
            vault_bump: pda::spl_asset_vault_with_bump(&mint).1,
        }],
        inline_outputs(&output_hashes, &[payer_bytes; 3]),
    );
    let output_owner_hashes = output_owner_pk_hashes(&data.outputs).expect("output owner hashes");
    set_output_owner_tags(&mut outputs, &output_owner_hashes, &[zero, zero, zero]);
    let external_hash = external_data_hash_spl(&data, &user_token.to_bytes(), &vault.to_bytes())
        .expect("external data hash");
    let private_tx = PrivateTxHash::new(&[utxo_hash, zero], &[zero, zero, zero], &external_hash)
        .hash()
        .expect("private transaction hash");
    let public_spl_field = public_sol_field(Some(-(amount as i64)));
    let payer_hash = Sha256BE::hash(&payer_bytes).expect("payer hash");
    let mint_bytes = mint.to_bytes();
    let input_owner_hashes = [owner_pk_hash, owner_pk_hash];
    let (public_slot_assets, public_slot_amounts) =
        spl_public_slots(public_spl_field, &mint_bytes).expect("public SPL slots");
    let public_hash = PublicInputs {
        nullifiers: &[nullifier, dummy_nullifier],
        output_hashes: &output_hashes,
        utxo_roots: &[utxo_root, utxo_root],
        nullifier_tree_roots: &[nullifier_root, nullifier_root],
        private_tx: &private_tx,
        external_data_hash: &external_hash,
        public_movements: &PublicMovements {
            assets: public_slot_assets,
            amounts: public_slot_amounts,
        },
        zone_program_id: &zero,
        payer_pubkey_hash: &payer_hash,
        allow_dummy_inputs: &fe(1),
        input_owner_pk_hashes: &input_owner_hashes,
        output_owner_pk_hashes: &output_owner_hashes,
    }
    .hash()
    .expect("public input hash");
    let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![spend, withdraw_dummy_input],
        outputs,
        external_data_hash: external_hash,
        private_tx_hash: private_tx,
        public_slot_assets,
        public_slot_amounts,
        payer_pubkey_hash: payer_hash,
        public_input_hash: public_hash,
    });
    data.proof = prove_and_verify_transfer(&prover_inputs, public_hash, "SPL withdrawal")
        .expect("prove SPL withdrawal");
    data.private_tx_hash = private_tx;

    let instruction = Transact {
        payer: payer.pubkey(),
        input_tree: *tree,
        output_tree: *tree,
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::SplWithdrawal(
            TransactSplWithdrawalAccounts {
                mint,
                vault,
                user_token_account: user_token,
                token_program: ZolanaProgramTest::token_program_id(),
            },
        )],
        data: data.clone(),
    }
    .instruction();

    Ok(SplWithdrawal {
        mint,
        vault,
        user_token,
        utxo_hash,
        nullifier,
        data,
        instruction,
    })
}
