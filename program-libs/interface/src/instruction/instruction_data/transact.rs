use light_hasher::{sha256::Sha256BE, Hasher, HasherError};
use wincode::containers;
use wincode::len::FixIntLen;
use wincode::{SchemaRead, SchemaWrite};

use super::deposit::CpiSignerData;
pub use zolana_event::OutputUtxo;

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
    pub proof: [u8; 192],
    pub expiry_unix_ts: u64,
    pub relayer_fee: u16,
    pub private_tx_hash: [u8; 32],
    #[wincode(with = "containers::Vec<InputUtxo, FixIntLen<u8>>")]
    pub inputs: Vec<InputUtxo>,
    /// Signed public amount: positive deposits into the pool, negative
    /// withdraws. `None` for a pure shielded transfer.
    pub public_sol_amount: Option<i64>,
    pub public_spl_amount: Option<i64>,
    pub cpi_signer: Option<CpiSignerData>,
    /// SEC1-compressed P256 viewing key shared by every output ciphertext in
    /// this transaction; copied verbatim into the logged `GeneralEvent` so an
    /// indexer need not parse the per-output `data`.
    pub tx_viewing_pk: [u8; 33],
    /// Per-transaction encryption salt shared by every output ciphertext;
    /// copied into the logged `GeneralEvent` so wallets can derive the AES
    /// key/nonce without parsing the per-output `data`.
    pub salt: [u8; 16],
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
    pub proof: &'a [u8; 192],
    pub expiry_unix_ts: u64,
    pub relayer_fee: u16,
    pub private_tx_hash: &'a [u8; 32],
    #[wincode(with = "containers::Vec<InputUtxo, FixIntLen<u8>>")]
    pub inputs: Vec<InputUtxo>,
    pub public_sol_amount: Option<i64>,
    pub public_spl_amount: Option<i64>,
    pub cpi_signer: Option<CpiSignerData>,
    pub tx_viewing_pk: &'a [u8; 33],
    pub salt: &'a [u8; 16],
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
    pub cpi_signer: Option<CpiSignerData>,
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
        match &self.cpi_signer {
            Some(signer) => {
                preimage.extend_from_slice(&signer.program_id);
                preimage.push(signer.bump);
            }
            None => preimage.extend_from_slice(&[0u8; 33]),
        }
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
            cpi_signer: None,
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
