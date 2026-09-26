use solana_address::Address;
use zolana_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, Poseidon,
};
use zolana_interface::tree_slot::tree_id_field;
use zolana_transaction::{
    utxo::SppProofInputUtxo,
    utxo::{program_id_proof_input_hash, DUMMY_DOMAIN, UTXO_DOMAIN},
    Blinding, SppProofOutputUtxo, TransactionError,
};

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ProofInputUtxo {
    pub domain: [u8; 32],
    /// The raw `u16` id of the tree holding this UTXO, right-aligned. This is
    /// transaction context rather than a UTXO body field: an input is hashed
    /// under the id of the tree it is spent from, an output under the id of the
    /// tree it is appended to.
    pub tree_id: [u8; 32],
    pub owner_hash: [u8; 32],
    pub asset: [u8; 32],
    pub amount: [u8; 32],
    pub blinding: [u8; 32],
    pub data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
    pub ring_program_id: [u8; 32],
}

impl ProofInputUtxo {
    pub fn new(
        owner_hash: [u8; 32],
        asset: &Address,
        amount: u64,
        blinding: &Blinding,
        tree_id: u16,
    ) -> Result<Self, TransactionError> {
        Ok(Self {
            domain: right_align(&UTXO_DOMAIN.to_be_bytes()),
            tree_id: tree_id_field(tree_id),
            owner_hash,
            asset: hash_bytes(asset.as_array())?,
            amount: right_align(&amount.to_be_bytes()),
            blinding: right_align(blinding),
            data_hash: [0u8; 32],
            ring_data_hash: [0u8; 32],
            ring_program_id: [0u8; 32],
        })
    }

    /// Padding (dummy) slot: the circuit requires every field except the domain
    /// tag and blinding to be zero, so dummy hashes are indistinguishable from
    /// real ones while the slot provably carries nothing. The tree id is not a
    /// UTXO field, so a dummy is hashed under its slot's tree id like any other.
    fn dummy_fields(blinding: &Blinding, tree_id: u16) -> Self {
        Self {
            domain: right_align(&DUMMY_DOMAIN.to_be_bytes()),
            tree_id: tree_id_field(tree_id),
            blinding: right_align(blinding),
            ..Default::default()
        }
    }

    pub fn with_data_hash(mut self, data_hash: [u8; 32]) -> Self {
        self.data_hash = data_hash;
        self
    }

    pub fn with_ring(
        mut self,
        ring_data_hash: [u8; 32],
        ring_program_id: &Option<Address>,
    ) -> Result<Self, TransactionError> {
        self.ring_data_hash = ring_data_hash;
        self.ring_program_id = program_id_proof_input_hash(ring_program_id)?;
        Ok(self)
    }

    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        let ring_hash = Poseidon::hashv(&[&self.ring_data_hash, &self.ring_program_id])?;
        let owner_utxo_hash = Poseidon::hashv(&[&self.owner_hash, &self.blinding])?;
        Ok(Poseidon::hashv(&[
            &self.domain,
            &self.tree_id,
            &self.asset,
            &self.amount,
            &self.data_hash,
            &ring_hash,
            &owner_utxo_hash,
        ])?)
    }
}

impl TryFrom<&SppProofInputUtxo> for ProofInputUtxo {
    type Error = TransactionError;

    // A dummy carries only its domain tag and blinding: the circuit classifies
    // slots by domain and requires every other dummy field to be zero.
    fn try_from(input_utxo: &SppProofInputUtxo) -> Result<Self, Self::Error> {
        if input_utxo.is_dummy() {
            return Ok(ProofInputUtxo::dummy_fields(
                &input_utxo.utxo.blinding,
                input_utxo.tree_id,
            ));
        }
        let owner_hash =
            zolana_keypair::hash::owner_hash(&input_utxo.utxo.owner, &input_utxo.nullifier_pubkey)?;
        ProofInputUtxo::new(
            owner_hash,
            &input_utxo.utxo.asset.asset,
            input_utxo.utxo.amount,
            &input_utxo.utxo.blinding,
            input_utxo.tree_id,
        )?
        .with_data_hash(input_utxo.data_hash.unwrap_or_default())
        .with_ring(
            input_utxo.ring_data_hash.unwrap_or_default(),
            &input_utxo.utxo.ring_program_id,
        )
    }
}

impl TryFrom<(&SppProofOutputUtxo, u16)> for ProofInputUtxo {
    type Error = TransactionError;

    fn try_from((output, tree_id): (&SppProofOutputUtxo, u16)) -> Result<Self, TransactionError> {
        if output.is_dummy() {
            return Ok(ProofInputUtxo::dummy_fields(&output.blinding, tree_id));
        }
        ProofInputUtxo::new(
            output.owner_hash()?,
            &output.asset.asset,
            output.amount,
            &output.blinding,
            tree_id,
        )?
        .with_data_hash(output.data_hash.unwrap_or_default())
        .with_ring(
            output.ring_data_hash.unwrap_or_default(),
            &output.ring_program_id,
        )
    }
}
