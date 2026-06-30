use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
pub use zolana_event::OutputUtxo;
use zolana_hasher::{sha256::Sha256BE, Hasher, HasherError};

/// The Groth16 proof carried by a `transact` instruction. The two proving rails
/// have different proof sizes, so the proof is a tagged enum instead of a padded
/// fixed-width blob: the Solana-only eddsa rail omits the 64-byte BSB22 commitment
/// the P256 rail requires. The components are the compressed wire-format points
/// (G1 -> 32 bytes, G2 -> 64 bytes); the program decompresses them only at the
/// `groth16-solana` verifier boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u8")]
pub enum TransactProof {
    /// Solana-only eddsa rail: vanilla Groth16, no BSB22 commitment (128 bytes).
    Eddsa {
        a: [u8; 32],
        b: [u8; 64],
        c: [u8; 32],
    },
    /// P256 rail: BSB22-committed Groth16 (192 bytes).
    P256 {
        a: [u8; 32],
        b: [u8; 64],
        c: [u8; 32],
        commitment: [u8; 32],
        commitment_pok: [u8; 32],
    },
}

impl TransactProof {
    /// A zeroed eddsa-rail proof, used as a placeholder before the real proof is
    /// attached and as a dummy in tests.
    pub const fn zeroed_eddsa() -> Self {
        TransactProof::Eddsa {
            a: [0u8; 32],
            b: [0u8; 64],
            c: [0u8; 32],
        }
    }
}

/// One spent input UTXO (spec: `transact` `InputUtxo`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct InputUtxo {
    pub nullifier_hash: [u8; 32],
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    pub tree_index: u8,
    pub eddsa_signer_index: u8,
}

/// One output ciphertext slot in `transact` instruction data (spec: `transact`
/// `OutputCiphertext`): a `view_tag` and the encrypted (or plaintext) payload. The
/// program does not parse `data`. The matching output commitment is carried
/// separately in `output_utxo_hashes`.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct OutputCiphertext {
    pub view_tag: [u8; 32],
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub data: Vec<u8>,
}

/// `transact` instruction data (spec: SPP `transact`).
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactIxData {
    pub expiry_unix_ts: u64,
    pub relayer_fee: u16,
    pub private_tx_hash: [u8; 32],
    /// Confidential variant: the shared P256 signing key's owner `pk_field`
    /// (`owner_pk_field` of the P256 owner), exposed as a public input so the
    /// circuit routes P256-owned inputs by equality. `None` on the eddsa rail
    /// (folded as `0` into the public-input hash).
    pub p256_signing_pk_field: Option<[u8; 32]>,
    /// SEC1-compressed P256 viewing key shared by every output ciphertext in
    /// this transaction; copied verbatim into the logged `GeneralEvent` so an
    /// indexer need not parse the per-output `data`.
    pub tx_viewing_pk: [u8; 33],
    /// Per-transaction encryption salt shared by every output ciphertext;
    /// copied into the logged `GeneralEvent` so wallets can derive the AES
    /// key/nonce without parsing the per-output `data`.
    pub salt: [u8; 16],
    pub proof: TransactProof,
    #[wincode(with = "containers::Vec<InputUtxo, FixIntLen<u8>>")]
    pub inputs: Vec<InputUtxo>,
    /// Signed public amount: positive deposits into the pool, negative
    /// withdraws. `None` for a pure shielded transfer.
    pub public_sol_amount: Option<i64>,
    pub public_spl_amount: Option<i64>,
    /// Optional transaction-level application- and zone-specific external data
    /// digests folded into `external_data_hash`; `None` (`[0; 32]`) for a
    /// default-zone `transact`. Distinct from the per-UTXO `data_hash` /
    /// `zone_data_hash` in the UTXO body.
    pub data_hash: Option<[u8; 32]>,
    pub zone_data_hash: Option<[u8; 32]>,
    /// All `M` output UTXO commitments in tree-append order (SPL change, SOL
    /// change, then recipients / dummies). Appended to the UTXO tree and folded
    /// into the proof's output hash chain. Dummy outputs carry real-looking
    /// hashes, so the vector does not reveal the recipient count.
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub output_utxo_hashes: Vec<[u8; 32]>,
    /// Fixed length `1 + (M - SENDER_SLOT_COUNT)`. `[0]` is the sender bundle
    /// (covers the change positions); `[1..]` are recipient slots, each a real
    /// ciphertext or a same-length dummy, so the real recipient count is hidden.
    #[wincode(with = "containers::Vec<OutputCiphertext, FixIntLen<u8>>")]
    pub output_ciphertexts: Vec<OutputCiphertext>,
}

impl TransactIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Read config for the borrowed views: identical to the default config used by
/// [`TransactIxData::serialize`], except sequences without an explicit
/// `FixIntLen` carry a `u16` length prefix. This matches the byte vectors
/// (`OutputCiphertext::data`) the owned struct writes with `FixIntLen<u16>`, while
/// the element vectors keep their explicit `FixIntLen<u8>` override.
type RefConfig = wincode::config::Configuration<
    true,
    { wincode::config::DEFAULT_PREALLOCATION_SIZE_LIMIT },
    FixIntLen<u16>,
>;

/// Borrowed view of an [`OutputCiphertext`]; `data` aliases the instruction buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct OutputCiphertextRef<'a> {
    pub view_tag: &'a [u8; 32],
    pub data: &'a [u8],
}

/// Zero-copy view of [`TransactIxData`]. The large payloads (`proof` and the
/// output ciphertexts) alias the instruction buffer; only the small element
/// vectors are read owned.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead)]
pub struct TransactIxDataRef<'a> {
    pub expiry_unix_ts: u64,
    pub relayer_fee: u16,
    pub private_tx_hash: &'a [u8; 32],
    pub p256_signing_pk_field: Option<[u8; 32]>,
    pub tx_viewing_pk: &'a [u8; 33],
    pub salt: &'a [u8; 16],
    pub proof: TransactProof,
    #[wincode(with = "containers::Vec<InputUtxo, FixIntLen<u8>>")]
    pub inputs: Vec<InputUtxo>,
    pub public_sol_amount: Option<i64>,
    pub public_spl_amount: Option<i64>,
    pub data_hash: Option<[u8; 32]>,
    pub zone_data_hash: Option<[u8; 32]>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub output_utxo_hashes: Vec<[u8; 32]>,
    #[wincode(with = "containers::Vec<OutputCiphertextRef<'a>, FixIntLen<u8>>")]
    pub output_ciphertexts: Vec<OutputCiphertextRef<'a>>,
}

impl<'a> TransactIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, wincode::ReadError> {
        wincode::config::deserialize(data, RefConfig::new())
    }

    /// True when the public amount is an SPL token amount; false for SOL or a
    /// pure shielded transfer (no public amount).
    pub fn is_spl(&self) -> bool {
        self.public_spl_amount.is_some()
    }

    /// True for a shield or unshield (a public amount is present); false for a
    /// pure shielded transfer.
    pub fn is_deposit_or_withdrawal(&self) -> bool {
        self.public_sol_amount.is_some() || self.public_spl_amount.is_some()
    }

    /// Direction of the public amount: `true` deposits into the pool (positive
    /// amount), `false` withdraws (negative amount). Meaningless for a pure
    /// shielded transfer, where no public amount is present.
    pub fn is_deposit(&self) -> bool {
        self.public_spl_amount
            .or(self.public_sol_amount)
            .unwrap_or(0)
            > 0
    }
}

/// Output-ciphertext byte accessors shared by the owned [`OutputCiphertext`] and
/// the borrowed [`OutputCiphertextRef`], so [`ExternalDataHash`] hashes either.
pub trait OutputCiphertextBytes {
    fn view_tag(&self) -> &[u8; 32];
    fn data(&self) -> &[u8];
}

impl OutputCiphertextBytes for OutputCiphertext {
    fn view_tag(&self) -> &[u8; 32] {
        &self.view_tag
    }
    fn data(&self) -> &[u8] {
        &self.data
    }
}

impl OutputCiphertextBytes for OutputCiphertextRef<'_> {
    fn view_tag(&self) -> &[u8; 32] {
        self.view_tag
    }
    fn data(&self) -> &[u8] {
        self.data
    }
}

/// `external_data_hash` public input (spec: `transact` external_data_hash). The
/// program recomputes it from the instruction and the committed Solana accounts;
/// the client computes the identical value when building the proof. It covers the
/// instruction's external fields, the output UTXO hashes, and the output
/// ciphertexts, but never `private_tx_hash` (which already commits this hash) or
/// the input UTXOs (bound through `private_tx_hash`). Used in both the program and
/// the client.
pub struct ExternalDataHash<'a, O: OutputCiphertextBytes> {
    pub spp_instruction_discriminator: u8,
    pub expiry_unix_ts: u64,
    pub relayer_fee: u16,
    pub public_sol_amount: Option<i64>,
    pub public_spl_amount: Option<i64>,
    pub user_sol_account: &'a [u8; 32],
    pub user_spl_token_account: &'a [u8; 32],
    pub spl_token_interface: &'a [u8; 32],
    pub data_hash: Option<[u8; 32]>,
    pub zone_data_hash: Option<[u8; 32]>,
    pub output_utxo_hashes: &'a [[u8; 32]],
    pub output_ciphertexts: &'a [O],
}

impl<O: OutputCiphertextBytes> ExternalDataHash<'_, O> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let mut preimage = Vec::new();
        preimage.push(self.spp_instruction_discriminator);
        preimage.extend_from_slice(&self.expiry_unix_ts.to_be_bytes());
        preimage.extend_from_slice(&self.relayer_fee.to_be_bytes());
        preimage.extend_from_slice(&self.public_sol_amount.unwrap_or(0).to_be_bytes());
        preimage.extend_from_slice(&self.public_spl_amount.unwrap_or(0).to_be_bytes());
        preimage.extend_from_slice(self.user_sol_account);
        preimage.extend_from_slice(self.user_spl_token_account);
        preimage.extend_from_slice(self.spl_token_interface);
        preimage.extend_from_slice(&self.data_hash.unwrap_or([0u8; 32]));
        preimage.extend_from_slice(&self.zone_data_hash.unwrap_or([0u8; 32]));
        // Length-prefix both vectors (and each `data`) so the preimage is
        // unambiguous: no bytes can shift across a vector or `data` boundary and
        // yield the same hash for distinct instructions.
        preimage.extend_from_slice(&(self.output_utxo_hashes.len() as u16).to_be_bytes());
        for hash in self.output_utxo_hashes {
            preimage.extend_from_slice(hash);
        }
        preimage.extend_from_slice(&(self.output_ciphertexts.len() as u16).to_be_bytes());
        for ciphertext in self.output_ciphertexts {
            preimage.extend_from_slice(ciphertext.view_tag());
            preimage.extend_from_slice(&(ciphertext.data().len() as u16).to_be_bytes());
            preimage.extend_from_slice(ciphertext.data());
        }
        Sha256BE::hash(&preimage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eddsa_proof() -> TransactProof {
        TransactProof::Eddsa {
            a: [1u8; 32],
            b: [2u8; 64],
            c: [3u8; 32],
        }
    }

    fn p256_proof() -> TransactProof {
        TransactProof::P256 {
            a: [1u8; 32],
            b: [2u8; 64],
            c: [3u8; 32],
            commitment: [4u8; 32],
            commitment_pok: [5u8; 32],
        }
    }

    #[test]
    fn transact_proof_round_trips_both_rails() {
        for proof in [eddsa_proof(), p256_proof()] {
            let bytes = wincode::serialize(&proof).unwrap();
            let decoded: TransactProof = wincode::deserialize_exact(&bytes).unwrap();
            assert_eq!(decoded, proof);
        }
    }

    /// The eddsa rail omits the 64-byte BSB22 commitment, so its serialized proof
    /// is exactly 64 bytes shorter than the P256 rail (the 1-byte tag is shared).
    #[test]
    fn eddsa_proof_is_64_bytes_shorter_than_p256() {
        let eddsa = wincode::serialize(&eddsa_proof()).unwrap();
        let p256 = wincode::serialize(&p256_proof()).unwrap();
        assert_eq!(eddsa.len() + 64, p256.len());
        // 1-byte tag + a(32) + b(64) + c(32).
        assert_eq!(eddsa.len(), 1 + 128);
    }

    fn ix_data(proof: TransactProof) -> TransactIxData {
        TransactIxData {
            proof,
            expiry_unix_ts: 7,
            relayer_fee: 11,
            private_tx_hash: [9u8; 32],
            p256_signing_pk_field: None,
            inputs: vec![InputUtxo {
                nullifier_hash: [1u8; 32],
                nullifier_tree_root_index: 2,
                utxo_tree_root_index: 3,
                tree_index: 0,
                eddsa_signer_index: 0,
            }],
            public_sol_amount: Some(-5),
            public_spl_amount: None,
            data_hash: None,
            zone_data_hash: None,
            tx_viewing_pk: [4u8; 33],
            salt: [6u8; 16],
            output_utxo_hashes: vec![[8u8; 32]],
            output_ciphertexts: vec![OutputCiphertext {
                view_tag: [0u8; 32],
                data: vec![1, 2, 3],
            }],
        }
    }

    #[test]
    fn ix_data_round_trips_both_rails_owned_and_ref() {
        for proof in [eddsa_proof(), p256_proof()] {
            let owned = ix_data(proof);
            let bytes = owned.serialize().unwrap();
            assert_eq!(TransactIxData::deserialize(&bytes).unwrap(), owned);
            let view = TransactIxDataRef::from_bytes(&bytes).unwrap();
            assert_eq!(view.proof, proof);
            assert_eq!(view.output_ciphertexts.len(), 1);
        }
    }

    /// The eddsa rail's serialized `TransactIxData` is 64 bytes smaller than the
    /// P256 rail's: the only difference is the omitted BSB22 commitment.
    #[test]
    fn ix_data_eddsa_is_64_bytes_smaller() {
        let eddsa = ix_data(eddsa_proof()).serialize().unwrap();
        let p256 = ix_data(p256_proof()).serialize().unwrap();
        assert_eq!(eddsa.len() + 64, p256.len());
    }

    fn hash_of(
        output_utxo_hashes: &[[u8; 32]],
        output_ciphertexts: &[OutputCiphertext],
    ) -> [u8; 32] {
        ExternalDataHash {
            spp_instruction_discriminator: 0,
            expiry_unix_ts: 0,
            relayer_fee: 0,
            public_sol_amount: None,
            public_spl_amount: None,
            user_sol_account: &[0u8; 32],
            user_spl_token_account: &[0u8; 32],
            spl_token_interface: &[0u8; 32],
            data_hash: None,
            zone_data_hash: None,
            output_utxo_hashes,
            output_ciphertexts,
        }
        .hash()
        .unwrap()
    }

    /// Both vectors are length-prefixed, so a 32-byte value cannot shift between
    /// the hash vector and a ciphertext `data` to forge the same preimage.
    #[test]
    fn external_data_hash_is_injective_across_vector_splits() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let two_hashes = hash_of(
            &[a, b],
            &[OutputCiphertext {
                view_tag: [0u8; 32],
                data: Vec::new(),
            }],
        );
        let one_hash_b_in_data = hash_of(
            &[a],
            &[OutputCiphertext {
                view_tag: [0u8; 32],
                data: b.to_vec(),
            }],
        );
        assert_ne!(two_hashes, one_hash_b_in_data);
    }
}
