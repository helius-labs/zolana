use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct ProoflessOutput {
    pub owner: [u8; 32],
    pub blinding: [u8; 32],
    pub asset: [u8; 32],
    pub amount: u64,
    pub data_hash: Option<[u8; 32]>,
    pub utxo_data: Option<Vec<u8>>,
    pub zone_program_id: Option<[u8; 32]>,
    pub zone_data_hash: Option<[u8; 32]>,
    pub zone_data: Option<Vec<u8>>,
    /// Optional free-form memo, emitted in the clear. Not committed into any
    /// hash, so it is informational only.
    pub memo: Option<Vec<u8>>,
}

/// Borrowed serialization view of [`ProoflessOutput`].
///
/// This has the same Borsh representation as the owned type while allowing an
/// on-chain processor to write instruction-backed payloads directly into the
/// final encoded output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize)]
pub struct ProoflessOutputRef<'a> {
    pub owner: &'a [u8; 32],
    pub blinding: &'a [u8; 32],
    pub asset: &'a [u8; 32],
    pub amount: u64,
    pub data_hash: Option<&'a [u8; 32]>,
    pub utxo_data: Option<&'a [u8]>,
    pub zone_program_id: Option<&'a [u8; 32]>,
    pub zone_data_hash: Option<&'a [u8; 32]>,
    pub zone_data: Option<&'a [u8]>,
    pub memo: Option<&'a [u8]>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub enum OutputDataEncoding {
    Plaintext(Vec<u8>),
    Encrypted(Vec<u8>),
}

impl OutputDataEncoding {
    pub const PLAINTEXT_TAG: u8 = 0;
    pub const ENCRYPTED_TAG: u8 = 1;
}

/// Enum tag byte.
const PLAINTEXT_TAG_LEN: usize = 1;
/// Enum tag plus the `u32` body length prefix; the body starts here.
const PLAINTEXT_BODY_OFFSET: usize = PLAINTEXT_TAG_LEN + 4;
/// Bytes an [`OutputDataEncoding::Plaintext`] payload needs before the variable
/// `utxo_data` / `zone_data` / `memo` contents: the enum tag, the body length
/// prefix, the scheme byte, and every fixed [`ProoflessOutput`] field with its
/// options present. Pinned by `plaintext_fixed_len_covers_every_option`.
pub const PLAINTEXT_OUTPUT_FIXED_LEN: usize = 224;

/// Serializes to the same bytes as `borsh(OutputDataEncoding::Plaintext(blob))`
/// where `blob` is the scheme byte followed by `borsh(ProoflessOutput)`, but
/// writes the body once into one buffer instead of serializing it into a `Vec`
/// and copying that `Vec` into the enum's length-prefixed payload.
pub fn encode_output_data(data: ProoflessOutput) -> Vec<u8> {
    encode_output_data_ref(ProoflessOutputRef {
        owner: &data.owner,
        blinding: &data.blinding,
        asset: &data.asset,
        amount: data.amount,
        data_hash: data.data_hash.as_ref(),
        utxo_data: data.utxo_data.as_deref(),
        zone_program_id: data.zone_program_id.as_ref(),
        zone_data_hash: data.zone_data_hash.as_ref(),
        zone_data: data.zone_data.as_deref(),
        memo: data.memo.as_deref(),
    })
}

/// Borrowed counterpart of [`encode_output_data`].
pub fn encode_output_data_ref(data: ProoflessOutputRef<'_>) -> Vec<u8> {
    let variable_len = data.utxo_data.map_or(0, <[u8]>::len)
        + data.zone_data.map_or(0, <[u8]>::len)
        + data.memo.map_or(0, <[u8]>::len);
    let mut out = Vec::with_capacity(PLAINTEXT_OUTPUT_FIXED_LEN + variable_len);
    out.push(OutputDataEncoding::PLAINTEXT_TAG);
    // Body length, patched in below once the body is written.
    out.extend_from_slice(&0u32.to_le_bytes());
    // Plaintext scheme byte, the first byte of the enum's payload.
    out.push(0);
    data.serialize(&mut out)
        .expect("shielded-pool output data serialization is infallible");

    let body_len = u32::try_from(out.len() - PLAINTEXT_BODY_OFFSET)
        .expect("shielded-pool output data length fits in u32");
    out.get_mut(PLAINTEXT_TAG_LEN..PLAINTEXT_BODY_OFFSET)
        .expect("length placeholder written above")
        .copy_from_slice(&body_len.to_le_bytes());
    out
}
