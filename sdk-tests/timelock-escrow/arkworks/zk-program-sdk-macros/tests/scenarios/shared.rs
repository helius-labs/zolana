use borsh::{BorshDeserialize, BorshSerialize};
use solana_address::Address;
use solana_signature::Signature;
use zk_program_sdk::{
    circuit,
    circuit::{poseidon, CircuitVar, DataHash},
    conversion::{to_bytes, Allocator, ProofInput},
    RelationError,
};
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::{random_blinding, P256Pubkey, ShieldedAddress, ShieldedKeypair, SigningKey};
use zolana_transaction::{
    decrypt,
    instructions::transact::SppProofInputs,
    utxo::{SppProofInputUtxo, Utxo},
    AssetRegistry, Data, DataRecord, Mint, OutputContext, OutputSlot, ShieldedTransaction,
    SppProofOutputUtxo, WalletUtxo,
};

pub const TREE_ID: u16 = 3;
pub const USDC: Mint = Mint::new(Address::new_from_array([4u8; 32]), 4);
pub const BONK: Mint = Mint::new(Address::new_from_array([6u8; 32]), 6);

pub fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).expect("keypair")
}

pub fn token_input(
    owner: &ShieldedKeypair,
    mint: Mint,
    amount: u64,
    leaf_index: u64,
) -> WalletUtxo {
    token_input_in(owner, mint, amount, TREE_ID, leaf_index)
}

pub fn token_input_in(
    owner: &ShieldedKeypair,
    mint: Mint,
    amount: u64,
    tree_id: u16,
    leaf_index: u64,
) -> WalletUtxo {
    wallet_utxo(owner, mint, amount, None, tree_id, leaf_index)
}

pub fn data_input<S>(owner: &ShieldedKeypair, amount: u64, state: &S, leaf_index: u64) -> WalletUtxo
where
    S: ProofInput<Circuit: DataHash> + BorshSerialize,
{
    let data = borsh::to_vec(state).expect("state bytes");
    wallet_utxo(
        owner,
        Mint::SOL,
        amount,
        Some((data, data_hash(state))),
        TREE_ID,
        leaf_index,
    )
}

fn wallet_utxo(
    owner: &ShieldedKeypair,
    mint: Mint,
    amount: u64,
    state: Option<(Vec<u8>, [u8; 32])>,
    tree_id: u16,
    leaf_index: u64,
) -> WalletUtxo {
    let address = owner.shielded_address().expect("owner address");
    let data_hash = state.as_ref().map(|(_, data_hash)| *data_hash);
    let utxo = Utxo {
        owner: owner.signing_pubkey(),
        asset: mint,
        amount,
        blinding: random_blinding(),
        ring_program_id: None,
        data: state.map_or_else(Data::default, |(data, _)| {
            Data::new(vec![DataRecord::UtxoData(data)])
        }),
    };
    let utxo_hash = utxo
        .hash(
            &address.nullifier_pubkey,
            &data_hash.unwrap_or_default(),
            &[0u8; 32],
            tree_id,
        )
        .expect("utxo hash");
    WalletUtxo {
        nullifier: owner
            .nullifier(&utxo_hash, &utxo.blinding)
            .expect("nullifier"),
        utxo,
        nullifier_pubkey: address.nullifier_pubkey,
        utxo_hash,
        data_hash,
        ring_data_hash: None,
        tree_id,
        leaf_index,
        latest_tree_id: None,
        slot: 0,
        tx_signature: Signature::default(),
        slot_index: 0,
    }
}

pub fn dummy() -> WalletUtxo {
    WalletUtxo::dummy(TREE_ID).expect("dummy")
}

pub fn data_hash<S: ProofInput<Circuit: DataHash>>(state: &S) -> [u8; 32] {
    let circuit = state
        .instantiate(&Allocator::native())
        .expect("native state");
    to_bytes(&circuit.hash().expect("state hash")).expect("state hash bytes")
}

pub fn on_large_stack(run: impl FnOnce() + Send + 'static) {
    let builder = std::thread::Builder::new().stack_size(64 * 1024 * 1024);
    let builder = match std::thread::current().name() {
        Some(name) => builder.name(name.to_string()),
        None => builder,
    };
    builder
        .spawn(run)
        .expect("large stack thread")
        .join()
        .expect("large stack thread result");
}

pub fn poseidon_bytes(inputs: &[[u8; 32]]) -> [u8; 32] {
    let slices: Vec<&[u8]> = inputs.iter().map(<[u8; 32]>::as_slice).collect();
    Poseidon::hashv(&slices).expect("poseidon")
}

pub fn decrypt_data_output<S>(
    keys: &ShieldedKeypair,
    spp_proof_inputs: &SppProofInputs,
    slot: usize,
    first_leaf_index: u64,
) -> (WalletUtxo, S)
where
    S: ProofInput<Circuit: DataHash> + BorshDeserialize,
{
    let utxo = decrypted(keys, spp_proof_inputs, slot, first_leaf_index);
    let state = S::try_from_slice(utxo.utxo.data.utxo_data().expect("the output carries data"))
        .expect("the data decodes to the state");
    let data_hash = data_hash(&state);
    (placed(keys, utxo, data_hash), state)
}

fn decrypted(
    keys: &ShieldedKeypair,
    spp_proof_inputs: &SppProofInputs,
    slot: usize,
    first_leaf_index: u64,
) -> WalletUtxo {
    let mut assets = AssetRegistry::default();
    for output in &spp_proof_inputs.output_utxos {
        if output.asset != Mint::SOL && assets.mint(&output.asset.asset).is_err() {
            assets
                .insert(output.asset.asset_id, output.asset.asset)
                .expect("asset registry");
        }
    }
    let external_data = &spp_proof_inputs.external_data;
    let output_slots = external_data
        .outputs
        .iter()
        .zip(&external_data.resolved_owner_tags)
        .zip(first_leaf_index..)
        .map(|((output, view_tag), leaf_index)| OutputSlot {
            view_tag: *view_tag,
            output_context: OutputContext {
                hash: output.utxo_hash,
                tree_id: spp_proof_inputs.output_tree_id,
                leaf_index,
            },
            payload: output.data.clone().unwrap_or_default(),
        })
        .collect();
    let transaction = ShieldedTransaction {
        slot: 0,
        tx_signature: Signature::default(),
        event_index: None,
        tx_viewing_pk: Some(
            P256Pubkey::from_bytes(external_data.tx_viewing_pk).expect("tx viewing key"),
        ),
        salt: Some(external_data.salt),
        output_slots,
        messages: vec![],
        nullifiers: spp_proof_inputs
            .input_utxos
            .iter()
            .filter(|input| !input.is_dummy())
            .map(SppProofInputUtxo::nullifier)
            .collect(),
        proofless: false,
        ring_config: None,
        ring_program_id: None,
    };
    let slot_index = u32::try_from(slot).expect("slot index");
    decrypt(keys, &[transaction], &assets)
        .expect("decryption")
        .utxos
        .into_iter()
        .find(|utxo| utxo.slot_index == slot_index)
        .expect("the keys decrypt the output")
}

fn placed(keys: &ShieldedKeypair, mut utxo: WalletUtxo, data_hash: [u8; 32]) -> WalletUtxo {
    let address = keys.shielded_address().expect("owner address");
    utxo.data_hash = Some(data_hash);
    let utxo_hash = utxo
        .utxo
        .hash(
            &address.nullifier_pubkey,
            &data_hash,
            &[0u8; 32],
            utxo.tree_id,
        )
        .expect("utxo hash");
    assert_eq!(utxo_hash, utxo.utxo_hash, "the decrypted output hashes");
    utxo.nullifier = keys
        .nullifier(&utxo.utxo_hash, &utxo.utxo.blinding)
        .expect("nullifier");
    utxo
}

#[derive(Clone, Copy, Debug)]
pub struct ProgramOwner(zk_program_sdk::ProgramOwner);

impl ProgramOwner {
    pub fn new(seed: u8) -> Self {
        Self(zk_program_sdk::ProgramOwner::new(Address::new_from_array(
            [seed; 32],
        )))
    }

    pub fn address(&self, viewer: &ShieldedAddress) -> ShieldedAddress {
        self.0
            .address(viewer.viewing_pubkey)
            .expect("program address")
    }

    pub fn data_input<S>(
        &self,
        viewer: &ShieldedAddress,
        mint: Mint,
        amount: u64,
        state: &S,
        leaf_index: u64,
    ) -> WalletUtxo
    where
        S: ProofInput<Circuit: DataHash> + BorshSerialize,
    {
        let output = SppProofOutputUtxo::new(mint, amount, self.address(viewer))
            .expect("program output")
            .with_utxo_data(borsh::to_vec(state).expect("state bytes"), data_hash(state));
        self.input(&output, TREE_ID, leaf_index)
    }

    pub fn input(&self, output: &SppProofOutputUtxo, tree_id: u16, leaf_index: u64) -> WalletUtxo {
        self.0
            .input(output, tree_id, leaf_index)
            .expect("the output is owned by the program")
    }
}

pub const MERKLE_DEPTH: usize = 4;

pub struct MerkleTree {
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    pub fn new(leaves: &[[u8; 32]]) -> Self {
        let mut level: Vec<[u8; 32]> = (0..1usize << MERKLE_DEPTH)
            .map(|index| leaves.get(index).copied().unwrap_or_default())
            .collect();
        let mut levels = vec![level.clone()];
        while level.len() > 1 {
            level = level.chunks(2).map(poseidon_bytes).collect();
            levels.push(level.clone());
        }
        Self { levels }
    }

    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .expect("root")
    }

    pub fn path(&self, index: usize) -> MerklePath {
        let mut siblings = [[0u8; 32]; MERKLE_DEPTH];
        let mut bits = [false; MERKLE_DEPTH];
        for (depth, (sibling, bit)) in siblings.iter_mut().zip(bits.iter_mut()).enumerate() {
            let position = index >> depth;
            *bit = position & 1 == 1;
            *sibling = self
                .levels
                .get(depth)
                .and_then(|level| level.get(position ^ 1))
                .copied()
                .expect("sibling");
        }
        MerklePath { siblings, bits }
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct MerklePath {
    pub siblings: [[u8; 32]; MERKLE_DEPTH],
    pub bits: [bool; MERKLE_DEPTH],
}

#[circuit]
impl MerklePath {
    pub fn root(&self, leaf: &CircuitVar) -> Result<CircuitVar, RelationError> {
        self.siblings
            .iter()
            .zip(&self.bits)
            .try_fold(leaf.clone(), |node, (sibling, bit)| {
                poseidon(&[bit.select(sibling, &node), bit.select(&node, sibling)])
            })
    }
}
