use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
pub use zolana_event::{MessageData, OutputUtxo};
use zolana_hasher::{sha256::Sha256BE, Hasher, HasherError};

use crate::error::ShieldedPoolError;

/// The BSB22-committed Groth16 proof of the P256 rail: `a || b || c ||
/// commitment || commitment_pok`, 192 bytes on the wire (compressed points,
/// G1 -> 32 bytes, G2 -> 64 bytes). This is the single definition of that
/// layout: `transact` carries it as [`TransactProof::P256`] and `merge_transact`
/// embeds it directly (the merge circuit is P256-only, so its proof is always
/// this five-tuple).
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct P256Proof {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

impl P256Proof {
    /// Serialized length: the five points back to back, no tag.
    pub const LEN: usize = 192;

    /// A zeroed proof, used as a placeholder before the real proof is attached
    /// and as a dummy in tests.
    pub const fn zeroed() -> Self {
        Self {
            a: [0u8; 32],
            b: [0u8; 64],
            c: [0u8; 32],
            commitment: [0u8; 32],
            commitment_pok: [0u8; 32],
        }
    }
}

/// Zero-copy view of [`P256Proof`]: every point aliases the instruction buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct P256ProofRef<'a> {
    pub a: &'a [u8; 32],
    pub b: &'a [u8; 64],
    pub c: &'a [u8; 32],
    pub commitment: &'a [u8; 32],
    pub commitment_pok: &'a [u8; 32],
}

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
    /// P256 rail: BSB22-committed Groth16 ([`P256Proof::LEN`] bytes).
    P256(P256Proof),
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

/// How an output's owner tag is carried on the wire (spec: `transact`
/// `OwnerTag`). The resolved 32-byte value is hashed into the OWNER public input
/// and republished as the event `view_tag`. `Inline` embeds the tag directly
/// (recipient signing pubkey, zone HKDF tag, dummy tag); `Account` indexes the
/// raw account list (same convention as [`InputUtxo::eddsa_signer_index`]) so an
/// address-lookup table can compress self-owned outputs; `P256SigningKey`
/// resolves to the transaction-level shared P256 signing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u8")]
pub enum OwnerTag {
    Inline([u8; 32]),
    Account(u8),
    P256SigningKey,
}

/// One output slot in `transact` instruction data (spec: `transact`
/// `TransactOutput`): the output commitment, its owner tag, and an optional
/// ciphertext. `data: None` marks a slot covered by a preceding `Some` bundle
/// (a client/wallet placement convention); the program does not parse `data`.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactOutput {
    pub utxo_hash: [u8; 32],
    pub owner_tag: OwnerTag,
    #[wincode(with = "Option<containers::Vec<u8, FixIntLen<u16>>>")]
    pub data: Option<Vec<u8>>,
}

/// `transact` instruction data (spec: SPP `transact`).
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactIxData {
    pub expiry_unix_ts: u64,
    pub relayer_fee: u16,
    pub private_tx_hash: [u8; 32],
    // TODO: explore lifting the one-shared-P256-key-per-tx limit. P256 ownership
    // stays in-circuit (never program-native/precompile), so the circuit shape
    // gains a dimension K = max distinct P256 signing keys, each costing one more
    // emulated ECDSA gadget (the dominant constraint component; proving time and
    // key count scale with K). This field becomes a K-element key list, inputs
    // route to a key via a generalized signer index (`eddsa_signer_index` ->
    // Solana account or P256 key-list index), and the output `OwnerTag` variant
    // generalizes from `P256SigningKey` to `P256Key(u8)`. The zone rail is
    // equally affected in-circuit (its P256 variants carry the same single
    // gadget, so K applies to zone keys too); only its instruction-data surface
    // is unchanged, since zone keys stay private witnesses. Consumer is
    // multi-party transactions (e.g. two P256 owners co-spending in a swap),
    // not single wallets.
    /// Confidential variant: the raw x-coordinate of the shared P256 signing key
    /// (`owner_pk_field` before hashing). The program derives the public input by
    /// hashing it on-chain, so P256-owned inputs route by equality and a
    /// `P256SigningKey` output tag resolves to this value. `None` on the eddsa
    /// rail (folded as `0` into the public-input hash).
    pub p256_signing_pk_x: Option<[u8; 32]>,
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
    /// All `M` outputs in tree-append order (SPL change, SOL change, then
    /// recipients / dummies). Each carries its commitment, owner tag, and an
    /// optional ciphertext. Commitments are appended to the UTXO tree and folded
    /// into the proof's output hash chain; dummy outputs carry real-looking
    /// hashes and ciphertexts, so the vector does not reveal the recipient count.
    /// A `None` `data` marks a slot covered by a preceding bundle.
    #[wincode(with = "containers::Vec<TransactOutput, FixIntLen<u8>>")]
    pub outputs: Vec<TransactOutput>,
    /// Published ciphertexts bound to no output commitment. Folded into
    /// `external_data_hash` and republished verbatim in the `GeneralEvent`.
    #[wincode(with = "containers::Vec<MessageData, FixIntLen<u8>>")]
    pub messages: Vec<MessageData>,
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
/// (`TransactOutput::data`, `MessageData::data`) the owned structs write with
/// `FixIntLen<u16>`, while the element vectors keep their explicit `FixIntLen<u8>`
/// override.
type RefConfig = wincode::config::Configuration<
    true,
    { wincode::config::DEFAULT_PREALLOCATION_SIZE_LIMIT },
    FixIntLen<u16>,
>;

/// Borrowed view of a [`TransactOutput`]; `data` aliases the instruction buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct TransactOutputRef<'a> {
    pub utxo_hash: &'a [u8; 32],
    pub owner_tag: OwnerTag,
    pub data: Option<&'a [u8]>,
}

/// Borrowed view of a [`zolana_event::MessageData`]; `data` aliases the buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct OutputDataRef<'a> {
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
    pub p256_signing_pk_x: Option<[u8; 32]>,
    pub tx_viewing_pk: &'a [u8; 33],
    pub salt: &'a [u8; 16],
    pub proof: TransactProof,
    #[wincode(with = "containers::Vec<InputUtxo, FixIntLen<u8>>")]
    pub inputs: Vec<InputUtxo>,
    pub public_sol_amount: Option<i64>,
    pub public_spl_amount: Option<i64>,
    pub data_hash: Option<[u8; 32]>,
    pub zone_data_hash: Option<[u8; 32]>,
    #[wincode(with = "containers::Vec<TransactOutputRef<'a>, FixIntLen<u8>>")]
    pub outputs: Vec<TransactOutputRef<'a>>,
    #[wincode(with = "containers::Vec<OutputDataRef<'a>, FixIntLen<u8>>")]
    pub messages: Vec<OutputDataRef<'a>>,
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

/// Failure resolving an [`OwnerTag`] against the transaction context.
/// Resolve an [`OwnerTag`] to its concrete 32-byte owner tag. The interface
/// crate has no account access, so callers pass the transaction's
/// `p256_signing_pk_x` and an account-address lookup; both the program and the
/// client resolve through this one function so the OWNER public input, the
/// event `view_tag`, and `external_data_hash` agree.
pub fn fetch_tag(
    tag: &OwnerTag,
    p256_signing_pk_x: Option<&[u8; 32]>,
    account_address: impl Fn(u8) -> Option<[u8; 32]>,
) -> Result<[u8; 32], ShieldedPoolError> {
    match tag {
        OwnerTag::Inline(bytes) => Ok(*bytes),
        OwnerTag::Account(index) => {
            account_address(*index).ok_or(ShieldedPoolError::OwnerTagAccountMissing)
        }
        OwnerTag::P256SigningKey => p256_signing_pk_x
            .copied()
            .ok_or(ShieldedPoolError::MissingP256SigningKey),
    }
}

/// An output whose owner tag has been resolved to concrete bytes: the only form
/// [`ExternalDataHash`] accepts, so the hash covers the resolved tag rather than
/// its wire encoding and stays fail-closed against account-list tampering.
pub struct ResolvedOutput<'a> {
    pub utxo_hash: &'a [u8; 32],
    pub owner_tag: [u8; 32],
    pub data: Option<&'a [u8]>,
}

impl TransactOutput {
    /// Resolve this output's owner tag against the transaction context.
    pub fn into_resolved(
        &self,
        p256_signing_pk_x: Option<&[u8; 32]>,
        account_address: impl Fn(u8) -> Option<[u8; 32]>,
    ) -> Result<ResolvedOutput<'_>, ShieldedPoolError> {
        Ok(ResolvedOutput {
            utxo_hash: &self.utxo_hash,
            owner_tag: fetch_tag(&self.owner_tag, p256_signing_pk_x, account_address)?,
            data: self.data.as_deref(),
        })
    }
}

impl<'a> TransactOutputRef<'a> {
    /// Resolve this output's owner tag against the transaction context. The
    /// resolved output aliases the same instruction buffer as `self`.
    pub fn into_resolved(
        &self,
        p256_signing_pk_x: Option<&[u8; 32]>,
        account_address: impl Fn(u8) -> Option<[u8; 32]>,
    ) -> Result<ResolvedOutput<'a>, ShieldedPoolError> {
        Ok(ResolvedOutput {
            utxo_hash: self.utxo_hash,
            owner_tag: fetch_tag(&self.owner_tag, p256_signing_pk_x, account_address)?,
            data: self.data,
        })
    }
}

/// `view_tag`/`data` byte accessors shared by the owned [`MessageData`] and the
/// borrowed [`OutputDataRef`], so [`ExternalDataHash`] hashes either message
/// representation.
pub trait OutputDataBytes {
    fn view_tag(&self) -> &[u8; 32];
    fn data(&self) -> &[u8];
}

impl OutputDataBytes for MessageData {
    fn view_tag(&self) -> &[u8; 32] {
        &self.view_tag
    }
    fn data(&self) -> &[u8] {
        &self.data
    }
}

impl OutputDataBytes for OutputDataRef<'_> {
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
/// instruction's external fields, the resolved outputs, and the messages, but
/// never `private_tx_hash` (which already commits this hash) or the input UTXOs
/// (bound through `private_tx_hash`). Used in both the program and the client.
pub struct ExternalDataHash<'a, M: OutputDataBytes> {
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
    pub outputs: &'a [ResolvedOutput<'a>],
    pub messages: &'a [M],
}

impl<M: OutputDataBytes> ExternalDataHash<'_, M> {
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
        // Count and per-datum length prefixes plus a strict {0,1} `data` presence
        // byte keep the preimage injective: no bytes can shift across an output,
        // a message, or a `data` boundary and forge the same hash for distinct
        // instructions, and `None` never collides with `Some(&[])`.
        preimage.extend_from_slice(&(self.outputs.len() as u16).to_be_bytes());
        for output in self.outputs {
            preimage.extend_from_slice(output.utxo_hash);
            preimage.extend_from_slice(&output.owner_tag);
            match output.data {
                None => preimage.push(0),
                Some(data) => {
                    preimage.push(1);
                    preimage.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    preimage.extend_from_slice(data);
                }
            }
        }
        preimage.extend_from_slice(&(self.messages.len() as u16).to_be_bytes());
        for message in self.messages {
            preimage.extend_from_slice(message.view_tag());
            preimage.extend_from_slice(&(message.data().len() as u16).to_be_bytes());
            preimage.extend_from_slice(message.data());
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
        TransactProof::P256(P256Proof {
            a: [1u8; 32],
            b: [2u8; 64],
            c: [3u8; 32],
            commitment: [4u8; 32],
            commitment_pok: [5u8; 32],
        })
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

    fn mixed_outputs() -> Vec<TransactOutput> {
        vec![
            TransactOutput {
                utxo_hash: [10u8; 32],
                owner_tag: OwnerTag::Inline([11u8; 32]),
                data: Some(vec![1, 2, 3]),
            },
            TransactOutput {
                utxo_hash: [12u8; 32],
                owner_tag: OwnerTag::Account(2),
                data: None,
            },
            TransactOutput {
                utxo_hash: [13u8; 32],
                owner_tag: OwnerTag::P256SigningKey,
                data: Some(vec![4, 5, 6, 7]),
            },
        ]
    }

    fn ix_data(proof: TransactProof) -> TransactIxData {
        TransactIxData {
            proof,
            expiry_unix_ts: 7,
            relayer_fee: 11,
            private_tx_hash: [9u8; 32],
            p256_signing_pk_x: Some([20u8; 32]),
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
            outputs: mixed_outputs(),
            messages: vec![MessageData {
                view_tag: [30u8; 32],
                data: vec![8, 9],
            }],
        }
    }

    /// Every field of the borrowed view aliases the same bytes the owned struct
    /// serialized, so the swap program's owned-reserialize CPI path is byte-exact.
    fn assert_ref_matches_owned(view: &TransactIxDataRef, owned: &TransactIxData) {
        assert_eq!(view.expiry_unix_ts, owned.expiry_unix_ts);
        assert_eq!(view.relayer_fee, owned.relayer_fee);
        assert_eq!(view.private_tx_hash, &owned.private_tx_hash);
        assert_eq!(view.p256_signing_pk_x, owned.p256_signing_pk_x);
        assert_eq!(view.tx_viewing_pk, &owned.tx_viewing_pk);
        assert_eq!(view.salt, &owned.salt);
        assert_eq!(view.proof, owned.proof);
        assert_eq!(view.inputs, owned.inputs);
        assert_eq!(view.public_sol_amount, owned.public_sol_amount);
        assert_eq!(view.public_spl_amount, owned.public_spl_amount);
        assert_eq!(view.data_hash, owned.data_hash);
        assert_eq!(view.zone_data_hash, owned.zone_data_hash);
        assert_eq!(view.outputs.len(), owned.outputs.len());
        for (got, want) in view.outputs.iter().zip(owned.outputs.iter()) {
            assert_eq!(got.utxo_hash, &want.utxo_hash);
            assert_eq!(got.owner_tag, want.owner_tag);
            assert_eq!(got.data, want.data.as_deref());
        }
        assert_eq!(view.messages.len(), owned.messages.len());
        for (got, want) in view.messages.iter().zip(owned.messages.iter()) {
            assert_eq!(got.view_tag, &want.view_tag);
            assert_eq!(got.data, want.data.as_slice());
        }
    }

    #[test]
    fn ix_data_round_trips_both_rails_owned_and_ref() {
        for proof in [eddsa_proof(), p256_proof()] {
            let owned = ix_data(proof);
            let bytes = owned.serialize().unwrap();
            assert_eq!(TransactIxData::deserialize(&bytes).unwrap(), owned);
            let view = TransactIxDataRef::from_bytes(&bytes).unwrap();
            assert_ref_matches_owned(&view, &owned);
        }
    }

    /// Serialize owned, parse the borrowed view, and confirm every field matches:
    /// the owned and Ref encodings are byte-identical, guarding the swap program's
    /// owned-reserialize CPI path.
    #[test]
    fn owned_serialize_matches_ref_parse() {
        let owned = ix_data(p256_proof());
        let bytes = owned.serialize().unwrap();
        let view = TransactIxDataRef::from_bytes(&bytes).unwrap();
        assert_ref_matches_owned(&view, &owned);
    }

    /// The eddsa rail's serialized `TransactIxData` is 64 bytes smaller than the
    /// P256 rail's: the only difference is the omitted BSB22 commitment.
    #[test]
    fn ix_data_eddsa_is_64_bytes_smaller() {
        let eddsa = ix_data(eddsa_proof()).serialize().unwrap();
        let p256 = ix_data(p256_proof()).serialize().unwrap();
        assert_eq!(eddsa.len() + 64, p256.len());
    }

    /// Per-`OwnerTag` serialized size of a single `None`-data output:
    /// utxo_hash(32) || enum tag(1) [+32 Inline / +1 Account / +0 P256] ||
    /// Option presence(1).
    #[test]
    fn transact_output_serialized_sizes_per_owner_tag() {
        let inline = TransactOutput {
            utxo_hash: [0u8; 32],
            owner_tag: OwnerTag::Inline([0u8; 32]),
            data: None,
        };
        let account = TransactOutput {
            utxo_hash: [0u8; 32],
            owner_tag: OwnerTag::Account(0),
            data: None,
        };
        let p256 = TransactOutput {
            utxo_hash: [0u8; 32],
            owner_tag: OwnerTag::P256SigningKey,
            data: None,
        };
        assert_eq!(wincode::serialize(&inline).unwrap().len(), 32 + 34);
        assert_eq!(wincode::serialize(&account).unwrap().len(), 32 + 3);
        assert_eq!(wincode::serialize(&p256).unwrap().len(), 32 + 2);

        // Some(data) adds the enum presence byte's 1 plus u16 length prefix and
        // the payload on top of the None cases above.
        let inline_some = TransactOutput {
            utxo_hash: [0u8; 32],
            owner_tag: OwnerTag::Inline([0u8; 32]),
            data: Some(vec![1, 2, 3]),
        };
        assert_eq!(
            wincode::serialize(&inline_some).unwrap().len(),
            32 + 33 + 1 + 2 + 3
        );
    }

    #[test]
    fn fetch_tag_resolves_every_variant() {
        let x = [21u8; 32];
        let accounts = |i: u8| if i == 2 { Some([22u8; 32]) } else { None };

        assert_eq!(
            fetch_tag(&OwnerTag::Inline([7u8; 32]), None, accounts),
            Ok([7u8; 32])
        );
        assert_eq!(
            fetch_tag(&OwnerTag::Account(2), None, accounts),
            Ok([22u8; 32])
        );
        assert_eq!(
            fetch_tag(&OwnerTag::P256SigningKey, Some(&x), accounts),
            Ok(x)
        );
        assert_eq!(
            fetch_tag(&OwnerTag::Account(5), None, accounts),
            Err(ShieldedPoolError::OwnerTagAccountMissing)
        );
        assert_eq!(
            fetch_tag(&OwnerTag::P256SigningKey, None, accounts),
            Err(ShieldedPoolError::MissingP256SigningKey)
        );
    }

    fn hash_of(outputs: &[ResolvedOutput], messages: &[MessageData]) -> [u8; 32] {
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
            outputs,
            messages,
        }
        .hash()
        .unwrap()
    }

    /// A length-prefixed message vector means a 32-byte value cannot shift from a
    /// resolved output's `data` into a message to forge the same preimage.
    #[test]
    fn external_data_hash_is_injective_across_output_message_boundary() {
        let hash32 = [1u8; 32];
        let tag = [2u8; 32];
        let value = [3u8; 32];

        let value_in_output = hash_of(
            &[ResolvedOutput {
                utxo_hash: &hash32,
                owner_tag: tag,
                data: Some(&value),
            }],
            &[],
        );
        let value_in_message = hash_of(
            &[ResolvedOutput {
                utxo_hash: &hash32,
                owner_tag: tag,
                data: None,
            }],
            &[MessageData {
                view_tag: tag,
                data: value.to_vec(),
            }],
        );
        assert_ne!(value_in_output, value_in_message);
    }

    /// The strict {0,1} presence byte keeps `Some(&[])` distinct from `None`.
    #[test]
    fn external_data_hash_distinguishes_empty_data_from_none() {
        let hash32 = [1u8; 32];
        let tag = [2u8; 32];
        let some_empty = hash_of(
            &[ResolvedOutput {
                utxo_hash: &hash32,
                owner_tag: tag,
                data: Some(&[]),
            }],
            &[],
        );
        let none = hash_of(
            &[ResolvedOutput {
                utxo_hash: &hash32,
                owner_tag: tag,
                data: None,
            }],
            &[],
        );
        assert_ne!(some_empty, none);
    }

    /// The owner tag is a fixed 32-byte field and `data` is length-prefixed, so a
    /// 32-byte value cannot shift between the resolved owner tag and `data`.
    #[test]
    fn external_data_hash_is_injective_across_owner_tag_data_boundary() {
        let hash32 = [1u8; 32];
        let value = [3u8; 32];
        let value_in_tag = hash_of(
            &[ResolvedOutput {
                utxo_hash: &hash32,
                owner_tag: value,
                data: None,
            }],
            &[],
        );
        let value_in_data = hash_of(
            &[ResolvedOutput {
                utxo_hash: &hash32,
                owner_tag: [0u8; 32],
                data: Some(&value),
            }],
            &[],
        );
        assert_ne!(value_in_tag, value_in_data);
    }
}
