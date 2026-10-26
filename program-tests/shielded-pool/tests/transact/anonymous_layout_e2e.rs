//! An anonymous ring transfer publishes enough for its sender and recipient to
//! rebuild their outputs from their own keys.

use anyhow::{anyhow, ensure, Context, Result};
use shielded_pool_tests::support::transact::proof_env;
use solana_address::Address;
use solana_signer::Signer;
use zolana_client::{
    input_utxos_from_nullifiers,
    prover::transact::anonymous_ring_eddsa::anonymous_signer_pk_hashes, AnonymousRingEddsaProver,
    ComputeBudgetConfig, ProofAuthority, ProofCompressed, Prover, ProverClient, Rpc, SpendProof,
    TransferInputUtxo,
};
use zolana_hasher::{
    primitives::{pack_be, right_align},
    Hasher, Poseidon,
};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{CircuitId, OwnerTag, TransactIxData, TransactOutput},
        tag,
    },
    verifying_keys::AnonymousRingEddsaProofData,
    N_PUBLIC_SLOTS,
};
use zolana_keypair::{
    random_blinding, random_salt, viewing_key::Salt, PublicKey, ShieldedKeypair, SigningKey,
    ViewingKey, X25519Pubkey,
};
use zolana_program::instruction::RingTransact;
use zolana_program_test::{ProgramTestHandle, ZolanaProgramTest, RING_TEST_PROGRAM_ID};
use zolana_test_utils::{
    test_validator_asserts::{wait_for_merkle_proof, wait_for_non_inclusion_proof},
    utxo::wallet,
};
use zolana_transaction::{
    derive_output_blinding_seed,
    instructions::transact::SppProofInputs,
    utxo::{derive_transact_output_blinding, SppProofInputUtxo},
    Blinding, Data, ExternalData, Mint, ShieldedTransaction, SppProofOutputUtxo, Utxo,
};

const SENDER_SEED: [u8; 32] = [0x11; 32];
const RECIPIENT_SEED: [u8; 32] = [0x21; 32];
/// Custom rings `domain::BLINDING_SEED`.
const CRBS: u32 = 0x4352_4253;
const INPUT: u64 = 2_000_000;
const SENT: u64 = 1_500_000;
const RING: Address = Address::new_from_array(RING_TEST_PROGRAM_ID);

#[test]
fn sender_and_recipient_decrypt_their_outputs_from_the_indexer() -> Result<()> {
    let handle = send_transfer()?;
    let (sender, recipient) = (keypair(&SENDER_SEED)?, keypair(&RECIPIENT_SEED)?);
    let recipient_owner = recipient.signing_pubkey();

    let tx = fetch(&handle, recipient.recipient_bootstrap_view_tag())?;
    let paid = RecipientBody::decode(&open(&tx, &recipient, 1)?)?;
    assert_eq!(paid.sender, sender.viewing_pubkey());
    assert_eq!((paid.owner, paid.amount), (recipient_owner, SENT));
    let rebuilt = note(&recipient, paid.amount, paid.blinding)?;
    assert_eq!(mint(&tx, 1, rebuilt)?, Mint::SOL);

    let tx = fetch(&handle, sender.get_sender_view_tag(0)?)?;
    let salt = tx.salt.context("no salt")?;
    let secrets = TxSecrets::derive(&sender, tx.nullifiers[0], salt)?;
    assert_eq!(Some(secrets.viewing_key.pubkey()), tx.tx_viewing_pk);
    let change = ChangeBody::decode(&open(&tx, &sender, 0)?)?;
    assert_eq!(change.amount, INPUT - SENT);
    let rebuilt = note(&sender, change.amount, secrets.blindings[0])?;
    assert_eq!(mint(&tx, 0, rebuilt)?, Mint::SOL);
    assert_eq!(change.recipient_viewing_pks, [recipient.viewing_pubkey()]);
    let to = &change.recipient_viewing_pks[0];
    let payload = &tx.output_slots[1].payload;
    let sent = ViewingKey::decrypt_slot_ephemeral(&secrets.viewing_key, to, payload, salt, 1)?;
    let sent = RecipientBody::decode(&sent)?;
    assert_eq!((sent.owner, sent.amount), (recipient_owner, SENT));
    Ok(())
}

/// Readers start from seeds and the indexer alone.
fn send_transfer() -> Result<ProgramTestHandle> {
    let (sender, recipient) = (keypair(&SENDER_SEED)?, keypair(&RECIPIENT_SEED)?);
    let pool = proof_env();
    let (mut rpc, authority, tree, tree_id) = (pool.rpc, pool.authority, pool.tree, pool.tree_id);
    rpc.load_ring_test_program()?;
    rpc.create_activated_ring_config(&authority, &authority.pubkey(), &authority, false)?;
    let payer = rpc.payer.insecure_clone();
    let blinding = random_blinding();
    let address = sender.shielded_address()?;
    let shield = ZolanaProgramTest::wallet_ring_sol_shield_data(INPUT, &address, blinding)?;
    let leaf_index = rpc.ring_deposit(&tree, &payer, &shield)?.leaf_index;
    let utxo = Utxo {
        owner: sender.signing_pubkey(),
        asset: Mint::SOL,
        amount: INPUT,
        blinding,
        ring_program_id: Some(RING),
        data: Data::default(),
    };
    let note_in = wallet(utxo, &sender.nullifier_key, tree_id, leaf_index, None, None)?;
    let handle = rpc.into_handle();

    let salt = random_salt();
    let secrets = TxSecrets::derive(&sender, note_in.nullifier, salt)?;
    let (sender_vpk, recipient_vpk) = (sender.viewing_pubkey(), recipient.viewing_pubkey());
    let mut change = (INPUT - SENT).to_be_bytes().to_vec();
    change.extend([0, 1].iter().chain(recipient_vpk.as_bytes()));
    let mut paid = recipient.signing_pubkey().as_bytes().to_vec();
    paid.extend_from_slice(sender_vpk.as_bytes());
    paid.extend_from_slice(&SENT.to_be_bytes());
    paid.extend_from_slice(&secrets.blindings[1]);
    paid.push(0);
    let change_tag = sender.get_sender_view_tag(0)?;
    let tags = [change_tag, recipient.recipient_bootstrap_view_tag()];
    let bodies = [(&sender, INPUT - SENT, change), (&recipient, SENT, paid)];
    let mut outputs = Vec::new();
    let mut published = Vec::new();
    for (slot, ((owner, amount, body), tag)) in (0u32..).zip(bodies.into_iter().zip(tags)) {
        let mut output = note(owner, amount, secrets.blindings[slot as usize])?;
        output.owner_tag = Some(tag);
        let to = owner.viewing_pubkey();
        let data = Some(secrets.viewing_key.encrypt_slot(&to, &body, salt, slot)?);
        let (utxo_hash, owner_tag) = (output.hash(tree_id)?, OwnerTag::Inline(tag));
        published.push(TransactOutput {
            utxo_hash,
            owner_tag,
            data,
        });
        outputs.push(output);
    }
    let tx_viewing_pk = *secrets.viewing_key.pubkey().as_bytes();
    let mut external_data = ExternalData::new(tx_viewing_pk, salt, published, tags.into(), vec![]);
    external_data.instruction_discriminator = tag::RING_TRANSACT;
    let proof_inputs = SppProofInputs {
        input_utxos: vec![SppProofInputUtxo::from(&note_in)],
        output_utxos: outputs,
        blinding_seed: secrets.blinding_seed,
        output_tree_id: tree_id,
        external_data,
        payer: payer.pubkey(),
        cache_accounts: Default::default(),
    };

    let spend = SpendProof {
        state: wait_for_merkle_proof(&handle, tree, note_in.utxo_hash),
        nullifier: wait_for_non_inclusion_proof(&handle, tree, note_in.nullifier),
    };
    let mut result = AnonymousRingEddsaProver {
        inputs: vec![TransferInputUtxo {
            utxo: SppProofInputUtxo::from(&note_in),
            proof: Some(spend),
            nullifier_proof: None,
        }],
        outputs: proof_inputs.output_utxos.clone(),
        blinding_seed: proof_inputs.blinding_seed,
        output_tree_id: tree_id,
        external_data: proof_inputs.external_data.clone(),
        public_transfers: proof_inputs.public_transfers()?,
        signer_pk_hashes: anonymous_signer_pk_hashes(&proof_inputs, &sender.signing_pubkey())?,
        allow_dummy_inputs: true,
        owner: &sender.signing_key,
        ring_program_id: Some(RING),
        shape: proof_inputs.check_shape()?,
    }
    .build()?;
    sender.complete_inputs(&mut result.inputs.transfer.inputs)?;
    let proof = ProofCompressed::try_from(ProverClient::local().prove(&result.inputs)?)?;
    let (proof, bsb22_commitment) = proof.into_committed_transact_parts()?;
    let proof_data = AnonymousRingEddsaProofData {
        bsb22_commitment,
        default_owner_tag: None,
    };
    let external = proof_inputs.external_data;
    let data = TransactIxData {
        proof,
        expiry_unix_ts: external.expiry_unix_ts,
        private_tx_hash: result.private_tx_hash,
        circuit: CircuitId::AnonymousRingEddsa(1, 2, N_PUBLIC_SLOTS as u8, proof_data),
        inputs: input_utxos_from_nullifiers(&result.nullifiers, &result.input_tree_indexes)?,
        tree_contexts: result.tree_contexts,
        interface_transfers: Vec::new(),
        data_hash: external.data_hash,
        ring_data_hash: external.ring_data_hash,
        tx_viewing_pk: external.tx_viewing_pk,
        salt: external.salt,
        outputs: external.outputs,
        messages: external.messages,
    };
    let transfer = RingTransact {
        payer: payer.pubkey(),
        input_trees: vec![tree],
        output_tree: tree,
        ring_program_id: RING,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data,
    };
    let (ix, budget) = (transfer.instruction(), ComputeBudgetConfig::new(1_400_000));
    handle
        .lock()
        .create_and_send_default_payer_transaction_with_budget(&[ix], &[], budget)?;
    Ok(handle)
}

struct TxSecrets {
    viewing_key: ViewingKey,
    blinding_seed: [u8; 32],
    blindings: [Blinding; 2],
}

impl TxSecrets {
    /// Custom rings `ring_blinding_seed`, then SPP's TXOS and TXOB.
    fn derive(sender: &ShieldedKeypair, first_nullifier: [u8; 32], salt: Salt) -> Result<Self> {
        let viewing_key = sender.get_transaction_viewing_key(&first_nullifier)?;
        let [key0, key1] = pack_be(&viewing_key.secret_bytes());
        let domain = right_align(&CRBS.to_be_bytes());
        let blinding_seed = Poseidon::hashv(&[&domain, &key0, &key1, &right_align(&salt)])?;
        let output_seed = derive_output_blinding_seed(&first_nullifier, &blinding_seed)?;
        let blinding = |slot| derive_transact_output_blinding(&first_nullifier, &output_seed, slot);
        let blindings = [blinding(0)?, blinding(1)?];
        Ok(Self {
            viewing_key,
            blinding_seed,
            blindings,
        })
    }
}

struct ChangeBody {
    amount: u64,
    recipient_viewing_pks: Vec<X25519Pubkey>,
}

impl ChangeBody {
    fn decode(mut bytes: &[u8]) -> Result<Self> {
        let amount = u64::from_be_bytes(take(&mut bytes)?);
        let [data, count] = take(&mut bytes)?;
        let (keys, rest) = bytes.as_chunks();
        ensure!(data == 0 && rest.is_empty() && keys.len() == usize::from(count));
        let keys = keys.iter().map(|key| X25519Pubkey::from_bytes(*key));
        let recipient_viewing_pks = keys.collect::<Result<_, _>>()?;
        Ok(Self {
            amount,
            recipient_viewing_pks,
        })
    }
}

struct RecipientBody {
    owner: PublicKey,
    sender: X25519Pubkey,
    amount: u64,
    blinding: Blinding,
}

impl RecipientBody {
    fn decode(mut bytes: &[u8]) -> Result<Self> {
        let owner = PublicKey::from_bytes(take(&mut bytes)?)?;
        let sender = X25519Pubkey::from_bytes(take(&mut bytes)?)?;
        let amount = u64::from_be_bytes(take(&mut bytes)?);
        let blinding = take(&mut bytes)?;
        ensure!(bytes == [0]);
        Ok(Self {
            owner,
            sender,
            amount,
            blinding,
        })
    }
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N]> {
    let (head, rest) = bytes.split_first_chunk().context("body is truncated")?;
    *bytes = rest;
    Ok(*head)
}

fn fetch(handle: &ProgramTestHandle, view_tag: [u8; 32]) -> Result<ShieldedTransaction> {
    let found = handle.get_shielded_transactions_by_tags(vec![view_tag], None, None, None)?;
    let [tx] = <[_; 1]>::try_from(found.transactions).map_err(|_| anyhow!("one match"))?;
    Ok(tx)
}

fn open(tx: &ShieldedTransaction, reader: &ShieldedKeypair, slot: u32) -> Result<Vec<u8>> {
    let tx_viewing_pk = tx.tx_viewing_pk.context("no tx viewing key")?;
    let payload = &tx.output_slots[slot as usize].payload;
    Ok(reader.decrypt_utxo(payload, &tx_viewing_pk, tx.salt.context("no salt")?, slot)?)
}

/// The body carries no mint, a decoy ahead of SOL makes the trial real.
fn mint(tx: &ShieldedTransaction, slot: usize, mut rebuilt: SppProofOutputUtxo) -> Result<Mint> {
    let context = &tx.output_slots[slot].output_context;
    let candidates = [Mint::new(Address::new_from_array([0xa1; 32]), 2), Mint::SOL];
    for asset in candidates {
        rebuilt.asset = asset;
        if rebuilt.hash(context.tree_id)? == context.hash {
            return Ok(asset);
        }
    }
    Err(anyhow!("no ring mint rebuilds output {slot}"))
}

fn note(owner: &ShieldedKeypair, amount: u64, blinding: Blinding) -> Result<SppProofOutputUtxo> {
    Ok(SppProofOutputUtxo {
        asset: Mint::SOL,
        amount,
        blinding,
        ring_program_id: Some(RING),
        owner_address: Some(owner.shielded_address()?),
        ..Default::default()
    })
}

fn keypair(seed: &[u8; 32]) -> Result<ShieldedKeypair> {
    let signing_key = SigningKey::from_ed25519_bytes(seed);
    Ok(ShieldedKeypair::from_keypair(signing_key)?)
}
